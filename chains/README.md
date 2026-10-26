# Attack Chain

## Chain 2: OOM Corruption RCE (CVE-2026-109618)

**Directory:** `chain2_oom/`
**CVE:** CVE-2026-109618 (GHSA-w8hw-w9fx-j79w)
**Requires:** Apache mod_php + `post_max_size >= memory_limit + 12M`
**Reliability:** Reliable with build-specific calibration

When PHP hits `memory_limit` during multipart processing, `longjmp()` skips cleanup, leaving stale pointers in session progress structures. The next request on the same Apache worker leaks heap memory via the PHPSESSID cookie, enabling ASLR bypass and RCE through fake HashTable pDestructor hijack.

See `chain2_oom/README.md` for full documentation.
