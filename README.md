# php2shell-lab

Weaponized PoC and lab for **CVE-2026-109618** (GHSA-w8hw-w9fx-j79w) -- unauthenticated remote code execution via PHP's session upload progress handler.

**CVSS 9.2** | Unauthenticated RCE | No application vulnerability required | Apache mod_php

Patched in PHP 8.2.35, 8.3.36, 8.4.27, 8.5.12 (2026-10-21).

## What this is

A working three-stage RCE exploit against unpatched Apache mod_php, with a Docker lab to reproduce it safely.

```bash
cd lab/
docker-compose -f docker-compose.modphp.yml up -d

python3 chains/chain2_oom/poc_rce.py -u http://127.0.0.1:8896/index.php \
  -c "id>/tmp/pwned" --container modphp-vuln
```

```
[5/6] Exploit chain (attempt 1/3)
  Stage 1: chunk base leak
    chunk_base = 0x7fdace000000
  Stage 2: libphp base leak
    libphp_base = 0x7fdacffcb000
    zif_system  = 0x7fdad0430370
  Stage 3: RCE
    [+] RCE CONFIRMED: uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

A non-exploitative `--check` mode tests whether a target is vulnerable without attempting RCE.

## Root cause

When PHP hits `memory_limit` during multipart request parsing, `longjmp()` aborts to a `setjmp` recovery point, skipping cleanup of session upload progress structures. These structures retain stale pointers. The next request on the same Apache worker reads the stale `PS(id)`, causing the `PHPSESSID` `Set-Cookie` header to contain arbitrary heap memory.

## Three-stage chain

| Stage | Goal | Technique | Result |
|-------|------|-----------|--------|
| 1 | Leak Zend MM chunk base | OOM + groomed 4096B zend_string | ASLR bypass (heap) |
| 2 | Leak libphp.so base | OOM + groomed sub-array with pDestructor | ASLR bypass (code) |
| 3 | Code execution | OOM + fake HashTable spray (pDestructor = zif_system) | RCE as www-data |

Each stage sends two HTTP requests to the same Apache worker: an OOM trigger that corrupts state, then a groomed follow-up that reads or exploits the stale pointer.

## Real-world constraints

The OOM trigger requires a multipart body larger than `memory_limit + ~12MB`. Apache's `post_max_size` rejects oversized bodies before PHP sees them:

```
post_max_size >= memory_limit + 12M    (required for exploitation)
```

PHP defaults (`post_max_size=8M`, `memory_limit=128M`) block this. Vulnerable configurations have high `post_max_size` relative to `memory_limit` -- file upload apps, CMS instances with custom php.ini, Docker labs. Servers with `memory_limit=-1` are immune.

FPM workers crash on OOM (exit 70), breaking the cross-request chain. This exploit is mod_php only.

## CVE-2026-109619

CVE-2026-109619 (GHSA-6wmf-4rv5-p3rp) affects the same `session.upload_progress` code path but targets cross-request and intra-request stale state on PHP-FPM. The UAF primitive is confirmed but application-independent RCE on FPM remains unproven by all public researchers. See [syrex1013/php2shell](https://github.com/syrex1013/php2shell) and [dinosn/php-cve-2026-10961x-lab-poc](https://github.com/dinosn/php-cve-2026-10961x-lab-poc) for FPM stale-state analysis.

## Repository structure

```
chains/chain2_oom/
  poc_rce.py             Weaponized RCE exploit with auto-calibration
  poc_info_leak.py       Information disclosure only (stages 1+2)
  Dockerfile.asan        ASAN-instrumented PHP build
  verify_uaf.php         UAF trigger for ASAN verification
  verify_asan.sh         Build and run ASAN verification

lab/
  docker-compose.modphp.yml   Vulnerable + patched Apache mod_php
  php-modphp.ini              8M memory_limit, 256M post_max_size
  prefork.conf                5 prefork workers
  www/                        Target PHP scripts
```

## Usage

```bash
# Non-exploitative vulnerability check
python3 chains/chain2_oom/poc_rce.py --check -u http://TARGET/index.php

# Full RCE (lab)
python3 chains/chain2_oom/poc_rce.py -u http://127.0.0.1:8896/index.php \
  -c "id>/tmp/pwned" --container modphp-vuln

# Extract offsets from an unlisted PHP build
python3 chains/chain2_oom/poc_rce.py -u http://127.0.0.1:8896/index.php \
  -c "id>/tmp/pwned" --container modphp-vuln --extract-offsets
```

Exit codes for `--check`: `0` = VULNERABLE, `1` = NOT VULNERABLE, `2` = INCONCLUSIVE.

## Mitigations

| Priority | Mitigation |
|----------|-----------|
| 1 | **Update PHP** (8.2.35+, 8.3.36+, 8.4.27+, 8.5.12+) |
| 2 | `session.upload_progress.enabled = Off` |
| 3 | `memory_limit = -1` (prevents OOM trigger) |

## Lab setup

```bash
cd lab/
docker-compose -f docker-compose.modphp.yml up -d
# http://127.0.0.1:8896 -- vulnerable (PHP 8.4.26, 8M memory_limit, 256M post_max_size)
# http://127.0.0.1:8899 -- patched (latest PHP 8.4, negative control)
```

## Credits

- PHP Security Team for advisory and patches
- Ryan Austin (Calif/OpenAI) and Wiz Research for independent discovery
- eness, 9bie, and OffSec for EDB-52704
- Ahmed Sultan (syrex1013) for stall-based UAF analysis
- dinosn for stock-config chain research
- Orange Tsai for the 2018 session injection technique
- Amazon Threat Intelligence for pre-disclosure IoCs

## References

- [GHSA-w8hw-w9fx-j79w](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w) (CVE-2026-109618)
- [GHSA-6wmf-4rv5-p3rp](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp) (CVE-2026-109619)
- [EDB-52704](https://www.exploit-db.com/exploits/52704)

## License

MIT. See [LICENSE](LICENSE) and [DISCLAIMER.md](DISCLAIMER.md).

For authorized security research and education only.
