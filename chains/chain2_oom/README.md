# Chain 2: OOM Corruption (CVE-2026-109618)

GHSA-w8hw-w9fx-j79w.

## Root cause

When PHP hits `memory_limit` during multipart request processing, `longjmp()` aborts to a setjmp point, skipping cleanup. Session progress structures retain stale pointers. The next request on the same Apache worker reads these stale pointers, leaking heap memory via the PHPSESSID Set-Cookie header.

## What we have

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

The info disclosure PoC requires:
- `php:8.4.26-apache` (mod_php, Apache prefork)
- Single-worker prefork (`MaxRequestWorkers 1`) for deterministic same-worker targeting
- `memory_limit = 8M` (the OOM trigger is sized as `memory_limit + 12M`)
- `post_max_size = 256M` (allow the large OOM body)
- `display_errors = On`
- `session.upload_progress.enabled = On`
- `session.use_strict_mode = 0`

These are laboratory conditions. The heap calibration values are specific to this exact libphp.so build.

## What this is NOT

This PoC demonstrates the information disclosure primitive (ASLR bypass via heap leak). The full RCE chain adds a stage 3 that constructs a fake HashTable to redirect pDestructor to zif_system. Stage 3 requires additional per-build heap calibration not included here.

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
