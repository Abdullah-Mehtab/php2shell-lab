# Chain 2: OOM Corruption (CVE-2026-109618)

**Status:** The novel vulnerability. GHSA-w8hw-w9fx-j79w.

## Root cause

When PHP exhausts `memory_limit` during multipart request processing, it calls `longjmp()` to abort immediately. This skips cleanup code, leaving request-owned memory (bookkeeping zvals, var_hash structures) in a partially-initialized state with dangling pointers. Subsequent request cleanup (RSHUTDOWN) reads and writes through these pointers -- a use-after-free.

This is NOT the same as the `VAR_ENTRIES_MAX` overflow described in some early research. The official advisory (GHSA-w8hw-w9fx-j79w) describes OOM corruption as the root cause.

## SAPI impact

- **Apache mod_php (highest risk):** Cleanup runs even when request startup fails. RCE is achievable before any application code executes. Confirmed on prefork MPM.
- **PHP-FPM:** Worker terminates on startup failure (blocks the mod_php path). Susceptible after successful startup when an application operation triggers OOM.
- **FrankenPHP, php-cgi, LiteSpeed:** Also affected.

## Memory disclosure

CVE-2026-109618 also enables Heartbleed-style memory disclosure: worker memory (passwords, session tokens, API keys, TLS private keys from other requests) can leak inside `PHPSESSID` response cookies, even without `session_start()`.

## Weaponized RCE (not included)

Calif demonstrated unauthenticated RCE against 11 major applications (WordPress, Drupal, Joomla, Magento, etc.). The full exploit:
1. Trigger OOM via crafted multipart to corrupt bookkeeping
2. Heap spray to reclaim freed bins with attacker-controlled data
3. Session write-back invokes serialize on a forged object
4. Attacker controls instruction pointer via fake vtable
5. Arbitrary code execution as web worker

This requires build-specific heap layout knowledge and is NOT included in this lab.

## What we demonstrate

### OOM trigger (`trigger_oom.py`)

Sends a crafted multipart request designed to exhaust `memory_limit`. Observes PHP's crash behavior and checks for memory disclosure in response cookies.

```bash
# Against the mod_php lab (Apache)
python3 trigger_oom.py --host 127.0.0.1 --port 8899

# Against the FPM lab (nginx)
python3 trigger_oom.py --host 127.0.0.1 --port 8898
```

### ASAN verification (`verify_asan.sh`)

Builds PHP from source with AddressSanitizer to observe the heap UAF. Uses the `unserialize()` var_destroy path (one of multiple UAF triggers described in early research).

```bash
./verify_asan.sh           # PHP 8.4.26
./verify_asan.sh 8.2.34    # specific version
```

## References

- PHP Advisory: GHSA-w8hw-w9fx-j79w
- CISA Alert: https://www.cisa.gov/news-events/alerts/2026/10/21/critical-vulnerabilities-php-require-immediate-patching
- Rapid7 ETR: https://www.rapid7.com/blog/post/etr-cve-2026-109618-and-cve-2026-109619/
- JFrog Research: https://research.jfrog.com/post/php2shell-all-you-need-to-know-about-cve-2026-109618-and-cve-2026-109619/
