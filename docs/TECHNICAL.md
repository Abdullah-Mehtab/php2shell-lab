# Technical Analysis: CVE-2026-109618 / CVE-2026-109619

## Overview

Two critical use-after-free vulnerabilities in PHP's core, affecting PHP 5.4.0 through 8.5.11. Both achieve unauthenticated remote code execution independent of the application running on PHP. Default configuration is vulnerable.

- **CVE-2026-109618:** RCE via OOM corruption (GHSA-w8hw-w9fx-j79w)
- **CVE-2026-109619:** RCE via stale global state across requests (GHSA-6wmf-4rv5-p3rp)
- **CVSS v4.0:** 9.2 (Critical) -- both CVEs
- **Patches:** PHP 8.2.35, 8.3.36, 8.4.27, 8.5.12 (released 2026-10-21)

## Discovery

Found independently by:
- **Ryan Austin (Calif)** -- reported to PHP on 2026-08-11, as part of OpenAI's "Patch the Planet" project, using GPT-5.6 Sol
- **Wiz Research** (Sagi Tzadik, Shir Tamari, Nir Ohfeld, Tomer Schwartz) -- reported 2026-08-24, using Gemini 4 Argon, GPT-5.6 Sol, and Wiz Atlas

A PHP core developer had flagged the underlying OOM bug during a 2024 audit, but it was never prioritized for a fix.

## CVE-2026-109618: OOM Corruption

### Root cause

When PHP exhausts `memory_limit`, it calls `longjmp()` to abort request processing immediately. This skips cleanup code that was about to run, leaving request-owned memory in a partially-initialized state. Subsequent request cleanup (RSHUTDOWN) then operates on invalid data -- pointers to freed memory, uninitialized zvals, corrupted bookkeeping structures.

### Attack mechanism

1. Attacker sends a crafted `multipart/form-data` request that exhausts `memory_limit`
2. PHP's `longjmp()` abort skips the cleanup path in the session upload progress handler
3. Bookkeeping structures (zval tracking, var_hash) retain pointers to freed memory
4. Request cleanup reads/writes through these dangling pointers

### SAPI differences

- **Apache mod_php (highest risk):** Cleanup runs even when request startup fails. RCE is achievable before any application code executes. Confirmed on multi-worker prefork deployments. This is the primary attack path.
- **PHP-FPM:** Worker terminates on startup failure (blocks the mod_php sequence). However, FPM is susceptible after successful startup -- an application operation that allocates memory based on attacker input can trigger OOM post-startup.
- **FrankenPHP, php-cgi, LiteSpeed:** Also affected. Risk varies by architecture.

### Memory disclosure

CVE-2026-109618 can also leak worker memory (passwords, session tokens, API keys, TLS private keys from other requests) inside `PHPSESSID` response cookies -- even when the application never calls `session_start()`. Sansec compares this to Heartbleed-style disclosure.

### Weaponization

The full exploit (per Calif's demonstration):
1. Trigger OOM via crafted multipart to corrupt bookkeeping
2. Heap spray to reclaim freed bins with attacker-controlled data
3. Session write-back invokes serialize on a forged object
4. Attacker controls RIP (instruction pointer) via fake vtable/function pointer
5. Achieve arbitrary code execution as the web worker

Demonstrated unauthenticated RCE against: Magento 2.4.9, WordPress 7.1.2, Drupal 11.4.3, Joomla 6.1.4, MediaWiki 1.46.2, Roundcube 1.7.4, phpMyAdmin 5.2.3, Nextcloud 35.0.1, Laravel 13.11, Symfony 8.1, WHMCS.

## CVE-2026-109619: Stale Global State

### Root cause

PHP reuses worker processes across requests. Internal state from one request can survive into the next request on the same worker. When a fatal error (OOM, timeout) interrupts state cleanup, pointers to freed request memory remain in persistent worker globals. The next request reads these stale pointers before initialization clears them.

### Confirmed attack paths

1. **Session upload progress (mod_php and FPM):** Upload progress handler consumes stale session/decoder state before normal initialization. Does not require `session_start()` in application code. Enabled by default.

2. **Fatal error backtraces (PHP 8.5 mod_php):** `fatal_error_backtraces` is enabled by default on PHP 8.5. A later initialization diagnostic accesses stale backtrace state from the previous request's fatal error.

3. **OPcache type confusion:** Stale state in OPcache shared memory is corrupted across workers. Less documented.

### Trigger sequence (FPM)

1. Request A on worker W: application operation leaves state behind after successful startup
2. Request A: fatal error occurs (OOM, timeout)
3. Request B on worker W: upload progress handler consumes stale state from Request A
4. Multiple workers and worker recycling (`pm.max_requests`) reduce success rate but do not eliminate the condition

## The session.upload_progress attack surface

Both CVEs are reachable through the session upload progress feature, which has been enabled by default since PHP 5.4 (2012). The attack surface has these properties:

1. **No authentication required.** The handler fires in PHP core before any userland script.
2. **No application vulnerability required.** Unlike Chain 1 (session injection + LFI), the OOM and stale-state paths do not need an LFI or any other application bug.
3. **Session fixation.** `PHPSESSID` cookie is accepted without validation when `use_strict_mode=0` (default). Session file path is predictable.
4. **Filename injection.** `add_assoc_string_ex()` stores the multipart filename into session data without sanitization.
5. **Deserialization trust.** The session file is unserialized before any script runs. The decoder does not verify that content came from PHP.

## What the patch does

Per JFrog's analysis of the fix:

1. **OOM handling:** Out-of-memory becomes a soft error at the next VM safe point instead of `longjmp()`. Above a higher threshold, `_exit()` is called. Cleanup always runs before memory is freed.
2. **Shutdown reset:** All long-lived state (backtrace, OPcache, session, error state) is reset at shutdown, regardless of how the request ended.
3. **Upload progress decode safety:** Decoded objects become `__PHP_Incomplete_Class`, preventing `__destruct()` and autoload execution during upload progress. This closes the object-injection path.

## Affected versions

| Branch | Vulnerable | Fixed |
|--------|-----------|-------|
| 5.4 - 5.6 | 5.4.0+ | EOL, no official fix |
| 7.0 - 7.3 | All | EOL, no fix |
| 7.4 | All | Source-only backport (EOL) |
| 8.0 | All | Source-only backport (EOL) |
| 8.1 | All | Source-only backport (EOL) |
| 8.2 | 8.2.0 - 8.2.34 | 8.2.35 |
| 8.3 | 8.3.0 - 8.3.35 | 8.3.36 |
| 8.4 | 8.4.0 - 8.4.26 | 8.4.27 |
| 8.5 | 8.5.0 - 8.5.11 | 8.5.12 |

## Default configuration is vulnerable

```ini
session.upload_progress.enabled = 1    ; On since PHP 5.4
session.upload_progress.cleanup = On   ; Does not prevent OOM/stale-state paths
session.use_strict_mode = 0            ; Attacker controls session ID
memory_limit = 128M                    ; Finite limit enables OOM trigger
```

## Mitigations (partial, update PHP is the only full fix)

| Mitigation | Covers | Risk |
|-----------|--------|------|
| Update PHP | Both CVEs fully | None |
| `session.upload_progress.enabled = 0` | Session-related paths only | Does not cover OPcache or backtrace paths |
| `memory_limit = -1` | Removes OOM trigger for CVE-2026-109618 | Allows unbounded memory consumption |
| `fatal_error_backtraces = 0` (PHP 8.5) | Backtrace path of CVE-2026-109619 | Only one path |
| `pm.max_requests = 1` (FPM) | Breaks cross-request stale state | Performance impact |
| Block `multipart/form-data` at WAF/proxy | All known triggers | Breaks file uploads |

None of these individually addresses both CVEs completely. Patching is the only full remediation.

## References

- PHP Advisory (OOM): GHSA-w8hw-w9fx-j79w
- PHP Advisory (stale state): GHSA-6wmf-4rv5-p3rp
- CISA Alert: https://www.cisa.gov/news-events/alerts/2026/10/21/critical-vulnerabilities-php-require-immediate-patching
- Rapid7 ETR: https://www.rapid7.com/blog/post/etr-cve-2026-109618-and-cve-2026-109619/
- JFrog Research: https://research.jfrog.com/post/php2shell-all-you-need-to-know-about-cve-2026-109618-and-cve-2026-109619/
- Sansec Research: https://sansec.io/research/php2shell
- Amazon Threat Intelligence: https://aws.amazon.com/blogs/security/amazon-threat-intelligence-identifies-php2shell-exploitation-prior-to-public-disclosure-in-madpot/
- Wikipedia: https://en.wikipedia.org/wiki/PHP2Shell
