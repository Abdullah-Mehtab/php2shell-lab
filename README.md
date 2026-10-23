# php2shell-lab

Educational lab and weaponized PoC for **CVE-2026-109618** and **CVE-2026-109619** -- two critical use-after-free vulnerabilities in PHP's session upload progress handler, collectively known as "php2shell."

**CVSS 9.2** | Unauthenticated RCE | No application vulnerability required | Affects PHP 5.4 through 8.5.11

Patched in PHP 8.2.35, 8.3.36, 8.4.27, 8.5.12 (2026-10-21).

## What this repo provides

- A **verified RCE exploit** (`poc_rce.py`) that chains ASLR bypass via PHPSESSID heap leak with fake HashTable pDestructor hijack
- A **non-exploitative vulnerability checker** (`--check` mode) for authorized assessments
- Docker labs to safely reproduce the full attack chain
- Mitigation verification suite and detection rules for defenders
- Honest documentation of real-world exploitability constraints

## Quick start

```bash
# Start the vulnerable mod_php lab
cd lab/
docker-compose -f docker-compose.modphp.yml up -d

# Check if a target is vulnerable (non-exploitative)
python3 chains/chain2_oom/poc_rce.py --check -u http://127.0.0.1:8896/index.php

# Full RCE (lab only -- requires build-specific offsets)
python3 chains/chain2_oom/poc_rce.py -u http://127.0.0.1:8896/index.php \
  -c "id>/tmp/pwned" --container modphp-vuln
```

## Repository structure

```
php2shell-lab/
  README.md
  LICENSE                              # MIT
  DISCLAIMER.md                        # Authorized use only

  lab/                                 # Docker lab environments
    docker-compose.yml                 #   PHP-FPM + nginx
    docker-compose.modphp.yml          #   Apache mod_php (highest risk)
    php.ini / php-modphp.ini           #   PHP configurations
    nginx.conf                         #   fastcgi_request_buffering off
    www/                               #   Target PHP scripts

  chains/                              # Attack chain implementations
    chain1_session_lfi/                #   Session injection + LFI (2018)
    chain2_oom/                        #   CVE-2026-109618: OOM corruption RCE
      poc_rce.py                       #     Weaponized RCE exploit
      poc_info_leak.py                 #     Information disclosure (stages 1+2)
      poc_stale_bytes.py               #     Alternative: stale pointer exploit
      trigger_oom.py                   #     OOM trigger demonstration
      Dockerfile.asan                  #     ASAN-instrumented build
      verify_uaf.php / verify_asan.sh  #     UAF verification
    chain3_stale_state/                #   CVE-2026-109619: cross-request UAF
    chain4_handler_mismatch/           #   Deserialization via handler mismatch

  mitigations/                         # Mitigation verification tests
    verify_all.sh                      #   Run all tests
    test_*.py                          #   Individual mitigation tests

  detection/                           # Blue team resources
    sigma_php_child_shell.yml          #   Sigma rule
    suricata_multipart.rules           #   Suricata rule
    check_exposure.sh                  #   Exposure check script

  docs/                                # Technical documentation
    TECHNICAL.md                       #   Full technical analysis
    NGINX_BUFFERING.md                 #   fastcgi_request_buffering finding
    NON_TECHNICAL.md                   #   Executive summary
    TIMELINE.md                        #   Disclosure timeline
```

## The exploit: three-stage RCE chain

CVE-2026-109618 allows unauthenticated remote code execution against Apache mod_php with default PHP configuration. The exploit requires no application vulnerability -- only PHP itself.

### Root cause

When PHP hits `memory_limit` during multipart request parsing, `longjmp()` aborts to a `setjmp` recovery point, skipping cleanup of session upload progress structures. These structures retain stale pointers. The next request on the same Apache worker reads the stale `PS(id)`, causing the `PHPSESSID` `Set-Cookie` header to contain arbitrary heap memory.

### Attack stages

| Stage | Goal | Technique | Result |
|-------|------|-----------|--------|
| 1 | Leak Zend MM chunk base | OOM + groomed 4096B zend_string | ASLR bypass (heap) |
| 2 | Leak libphp.so base | OOM + groomed sub-array with pDestructor | ASLR bypass (code) |
| 3 | Code execution | OOM + fake HashTable spray (pDestructor = zif_system) | RCE as www-data |

Each stage sends two HTTP requests to the same Apache worker: an OOM trigger (request A) that corrupts state, then a carefully groomed follow-up (request B) that reads or exploits the stale pointer.

### Exploit capabilities

| Feature | Status |
|---------|--------|
| Multi-worker Apache prefork | Auto-detects and pins N-1 workers |
| Memory limit detection | Probes from OOM error messages |
| Auto-calibration | Discovers heap grooming params at runtime |
| Build profiles | Lookup table for php:*-apache image offsets |
| ELF offset extraction | `--extract-offsets` parses container's libphp.so |
| SSL/TLS targets | Transparent HTTPS support |
| Non-exploitative check | `--check` mode for authorized assessments |
| Negative control | Detects patched PHP and refuses to proceed |

### Verified results

```
$ python3 poc_rce.py -u http://127.0.0.1:8896/index.php -c "id>/tmp/pwned" --container modphp-vuln

[5/6] Exploit chain (attempt 1/3)
  Stage 1: chunk base leak
    chunk_base = 0x7fdace000000
  Stage 2: libphp base leak
    libphp_base = 0x7fdacffcb000
    zif_system  = 0x7fdad0430370
  Stage 3: RCE
    [+] RCE CONFIRMED: uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Tested on php:8.4.26-apache (amd64) with 1, 5, and 10 worker configurations.
Negative control on PHP 8.4.27: patched version detected, exploit refuses.

## Real-world exploitability

The exploit works reliably in lab conditions. Real-world exploitation is constrained by a configuration requirement that most production servers do not meet.

### The post_max_size gate

The OOM trigger requires sending a multipart body larger than `memory_limit + ~12MB`. Apache's `post_max_size` directive rejects oversized bodies before PHP's multipart parser runs. For exploitation:

```
post_max_size >= memory_limit + 12M
```

PHP defaults: `post_max_size = 8M`, `memory_limit = 128M`. The OOM body (140MB) is rejected at 8MB. This is the inverse of what the exploit needs.

### Vulnerable configurations

Servers vulnerable in practice have high `post_max_size` and low `memory_limit`:
- File upload applications with `post_max_size = 256M` and default `memory_limit = 128M`
- CMS instances with `post_max_size = 128M` and `memory_limit = 32M`
- Docker images using custom php.ini (many CTF/lab setups)
- Servers with `memory_limit = -1` (unlimited) are immune -- OOM never fires

### What we tested

| Target | Server | Blocker |
|--------|--------|---------|
| Lab (127.0.0.1:8896) | php:8.4.26-apache, 8M memory, 256M post | RCE achieved |
| Production site A | Apache/mod_php, 64M post, 128M+ memory | post_max_size < memory_limit |
| Production site B | Apache/mod_php, PHP 7.2.34, memory_limit=-1 | OOM impossible |
| Production site C | Cloudflare WAF | WAF blocks upload_progress field |

The EDB-52704 exploit (eness/9bie/OffSec) has the same limitation -- their lab uses `memory_limit=8M` specifically to enable exploitation.

### Comparison with EDB-52704

Our exploit and the Exploit-DB verified exploit (ID 52704) implement the same three-stage chain. Key differences:

| Feature | php2shell-lab (ours) | EDB-52704 |
|---------|---------------------|-----------|
| Multi-worker support | Auto-detect + pin N-1 | Single-worker only |
| Memory limit detection | Auto-probe from OOM error | Hardcoded |
| Auto-calibration | Runtime discovery of N, T, forge_len | Hardcoded per profile |
| SSL/TLS | Transparent | Not supported |
| Vulnerability check | `--check` mode (non-exploitative) | Not available |
| Build profiles | 7 profiles + ELF extraction | 2 profiles |
| Lines of code | ~1100 | ~620 |

Both require the same `post_max_size >= memory_limit + 12M` condition.

## Vulnerability check mode

The `--check` flag performs a non-exploitative assessment:

```bash
# Check a target (sends upload_progress requests, does not attempt RCE)
python3 chains/chain2_oom/poc_rce.py --check -u http://TARGET/index.php

# Check with known memory_limit
python3 chains/chain2_oom/poc_rce.py --check -u http://TARGET/index.php --memory-limit 32

# HTTPS target
python3 chains/chain2_oom/poc_rce.py --check -u https://TARGET/index.php
```

The checker tests six conditions:
1. PHP version (patched or unpatched)
2. SAPI type (mod_php vs FPM)
3. `session.upload_progress.enabled`
4. `session.use_strict_mode`
5. `memory_limit` value
6. OOM disclosure (attempts to leak heap bytes via PHPSESSID)

Exit codes: `0` = VULNERABLE, `1` = NOT VULNERABLE, `2` = NOT CONFIRMED (inconclusive).

## Four attack chains

| Chain | CVE | Requires | Status |
|-------|-----|----------|--------|
| 1. Session injection + LFI | Pre-CVE (2018) | LFI in target app | Working PoC |
| 2. OOM corruption | CVE-2026-109618 | Default config + post_max_size gate | Verified RCE |
| 3. Stale global state | CVE-2026-109619 | Persistent workers | Trigger demo |
| 4. Handler mismatch | Related | Mismatched handlers + gadget chain | Research notes |

## Mitigations

| Priority | Mitigation | Covers |
|----------|-----------|--------|
| 1 | **Update PHP** (8.2.35+, 8.3.36+, 8.4.27+, 8.5.12+) | Both CVEs |
| 2 | `session.upload_progress.enabled = Off` | Session-based chains |
| 3 | `memory_limit = -1` (temporary) | Removes OOM trigger |
| 4 | Block `multipart/form-data` at WAF | All known triggers |
| 5 | `pm.max_requests = 1` (FPM) | CVE-2026-109619 cross-request |

No single workaround covers both CVEs. Patching is the only complete fix.

```bash
# Verify mitigations
cd mitigations/
./verify_all.sh
```

## Lab setup

### Prerequisites
- Docker and docker-compose
- Python 3.10+
- No additional dependencies (stdlib only)

### Start the labs

```bash
cd lab/

# Vulnerable mod_php (highest risk, required for RCE)
docker-compose -f docker-compose.modphp.yml up -d
# -> http://127.0.0.1:8896 (mod_php, 8M memory_limit, 256M post_max_size)

# FPM + nginx (demonstrates FPM crash behavior)
docker-compose up -d
# -> http://127.0.0.1:8898 (FPM via nginx, 16M memory_limit)
```

### Patched comparison

The mod_php compose file also starts a patched container (php:8.4-apache, latest) on port 8899 for negative control testing.

## Credits

- PHP Security Team for advisory and patches
- Ryan Austin (Calif/OpenAI) and Wiz Research for independent discovery
- eness, 9bie, and OffSec for EDB-52704 (verified exploit, reference implementation)
- Orange Tsai for the 2018 HITCON CTF session injection technique
- ikow for public chain analysis
- Amazon Threat Intelligence for pre-disclosure IoCs (MadPot, 2026-10-17)

## References

- [GHSA-w8hw-w9fx-j79w](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w) (CVE-2026-109618)
- [GHSA-6wmf-4rv5-p3rp](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp) (CVE-2026-109619)
- [EDB-52704](https://www.exploit-db.com/exploits/52704) (eness/9bie/OffSec verified exploit)

## License

MIT. See [LICENSE](LICENSE) and [DISCLAIMER.md](DISCLAIMER.md).

This repository is for authorized security research and education only.
