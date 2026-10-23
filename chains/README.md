# Attack Chains

CVE-2026-109618 and CVE-2026-109619 affect PHP's session upload progress handler (`ext/session/session.c`). The vulnerable code path is reachable through `session.upload_progress`, which is enabled by default in all PHP installations since 5.4.

## Chain 1: Session Injection + LFI (2018)

**Directory:** `chain1_session_lfi/`
**CVE:** Pre-CVE (Orange Tsai, HITCON CTF 2018)
**Requires:** LFI vulnerability in target application
**Reliability:** Deterministic (cleanup=Off) or race condition (cleanup=On)

The upload progress handler writes the multipart filename into a session file without sanitization. Combined with an LFI vulnerability, this yields RCE. This is a known technique that predates the CVEs but uses the same code path.

## Chain 2: OOM Corruption RCE (CVE-2026-109618)

**Directory:** `chain2_oom/`
**CVE:** CVE-2026-109618 (GHSA-w8hw-w9fx-j79w)
**Requires:** Default PHP config + `post_max_size >= memory_limit + 12M`
**Reliability:** Reliable with build-specific calibration

When PHP hits `memory_limit` during multipart processing, `longjmp()` skips cleanup, leaving stale pointers in session progress structures. The next request on the same Apache worker leaks heap memory via the PHPSESSID cookie, enabling ASLR bypass and RCE.

**This is the primary contribution of this repository.** Verified full RCE via three-stage chain: heap base leak, libphp.so base leak, fake HashTable pDestructor hijack. See `chain2_oom/README.md`.

## Chain 3: Stale Global State (CVE-2026-109619)

**Directory:** `chain3_stale_state/`
**CVE:** CVE-2026-109619 (GHSA-6wmf-4rv5-p3rp)
**Requires:** Persistent worker process (mod_php or FPM with `max_requests > 1`)
**Reliability:** Trigger demonstrated, not weaponized

Global state from one request survives into the next on the same worker after a fatal error interrupts cleanup. Multiple producers (OOM, `max_execution_time`, parse failures) and consumers (INI diagnostics, session upload_progress).

## Chain 4: Handler Mismatch (Deserialization)

**Directory:** `chain4_handler_mismatch/`
**CVE:** Related to CVE-2026-109619
**Requires:** Directories with different `session.serialize_handler` + exploitable gadget chain
**Reliability:** Deterministic if prerequisites met

A pipe in the upload filename causes the `php` handler to deserialize attacker-controlled data when another directory uses `php_serialize`. This triggers `__destruct` on arbitrary objects.

## Summary

| Chain | CVE | Auth required | App vuln required | SAPI | Status |
|-------|-----|---------------|-------------------|------|--------|
| 1 | Pre-CVE | No | Yes (LFI) | Any | Working PoC |
| 2 | CVE-2026-109618 | No | No | mod_php only | Verified RCE |
| 3 | CVE-2026-109619 | No | No | mod_php, FPM | Trigger demo |
| 4 | Related | No | No (needs config) | Any | Research notes |
