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
**Reliability:** Requires heap spray and build-specific offsets for RCE; memory disclosure is more reliable

When PHP hits `memory_limit` during multipart processing, `longjmp()` skips cleanup, leaving bookkeeping structures pointing at freed memory. Request cleanup operates on this invalid data. On mod_php, cleanup runs even when request startup fails -- RCE before application code executes.

Also enables Heartbleed-style memory disclosure via `PHPSESSID` response cookies.

**Our lab provides an OOM trigger script and an ASAN verification script.**

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

This repository's working RCE lab demonstrates **Chain 1**, the oldest and simplest chain that requires an LFI. We label it honestly as a 2018 technique. The novel CVEs (Chains 2 and 3) are demonstrable as triggers (OOM crash, stale state observation) but the weaponized exploit requires per-build heap layout knowledge and is not included. Our contribution is the mitigation verification suite, the OOM trigger demonstration, the nginx buffering analysis, and the honest educational framing.
