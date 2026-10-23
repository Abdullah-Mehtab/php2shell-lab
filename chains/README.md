# Attack Chains

CVE-2026-109618 and CVE-2026-109619 ("php2shell") affect PHP's core, reachable through the `session.upload_progress` attack surface. The vulnerable code is in `ext/session/session.c` and `ext/standard/var_unserializer.re`. Research has identified multiple attack paths.

## Chain 1: Session Injection + LFI (Known since 2018)

**Directory:** `chain1_session_lfi/`
**Novelty:** Known since 2018 (Orange Tsai, HITCON CTF)
**Requires:** LFI vulnerability in target application
**Reliability:** Deterministic (cleanup=Off) or probabilistic race (cleanup=On)

The upload progress handler writes the multipart filename into a session file without sanitization. Combined with an LFI vulnerability, this yields RCE. This technique predates the CVEs but uses the same code path.

**This is what our lab demonstrates end-to-end with working RCE.**

## Chain 2: OOM Corruption (CVE-2026-109618)

**Directory:** `chain2_oom/`
**Novelty:** The actual novel vulnerability
**Requires:** Nothing beyond default PHP config (no application bug needed)
**SAPI:** mod_php is highest risk; FPM susceptible after successful startup
**Reliability:** Requires build-specific heap calibration; memory disclosure is reliable on calibrated builds

When PHP hits `memory_limit` during multipart processing, `longjmp()` skips cleanup, leaving session progress structures with stale pointers. The next request on the same Apache worker reads the stale PS(id), causing the PHPSESSID Set-Cookie header to contain heap memory.

**Our lab has a verified ASLR bypass PoC:** `poc_info_leak.py` leaks both the Zend MM chunk base (4096-byte cookie) and the libphp.so load base (16-byte cookie). Tested 6/6 reliable on php:8.4.26-apache. Negative control on 8.4.27 confirmed (no leak).

## Chain 3: Stale Global State (CVE-2026-109619)

**Directory:** `chain3_stale_state/`
**Novelty:** Novel (2026)
**Requires:** Persistent worker process (mod_php or FPM with max_requests > 1)
**Confirmed paths:** Session upload progress, fatal_error_backtraces (PHP 8.5)

State from one request survives into the next on the same worker after a fatal error interrupts cleanup. The upload progress handler consumes stale decoder state before normal initialization.

**Our lab provides a cross-request stale state demonstration.**

## Chain 4: Handler Mismatch (Deserialization)

**Directory:** `chain4_handler_mismatch/`
**Novelty:** Documented alongside the CVEs
**Requires:** Directories with different `session.serialize_handler` + exploitable gadget chain
**Reliability:** Deterministic if prerequisites met

A pipe in the upload filename causes the `php` handler to deserialize attacker data when another directory uses `php_serialize`. `__destruct` fires even on decode failure.

**Placeholder -- lab not yet built.**

## Honest framing

- **Chain 1** is a 2018 technique (Orange Tsai). We label it as such. It requires an LFI in the target application.
- **Chain 2** has a verified information disclosure PoC (ASLR bypass via PHPSESSID heap leak). This is the genuine CVE-2026-109618 vulnerability. The full RCE chain (stage 3: fake HashTable to redirect pDestructor to zif_system) requires additional per-build calibration not included here.
- **Chain 3** is demonstrable as a trigger (OOM on mod_php, crash on FPM) but not yet weaponized.
- **Chain 4** is a placeholder.

Our contribution: a working info disclosure PoC for the novel CVE, ASAN UAF verification, mitigation verification suite, mod_php lab, nginx buffering analysis, and detection rules.
