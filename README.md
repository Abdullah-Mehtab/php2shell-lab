# php2shell-lab

Educational lab, PoC demonstrations, mitigation verification suite, and detection rules for **CVE-2026-109618** and **CVE-2026-109619** ("php2shell").

Two critical (CVSS 9.2) use-after-free vulnerabilities in PHP's core, affecting PHP 5.4.0 through 8.5.11. Default configuration is vulnerable. No authentication or application vulnerability required for exploitation.

**Patched** in PHP 8.2.35, 8.3.36, 8.4.27, 8.5.12 (released 2026-10-21). Exploitation observed in the wild since 2026-10-17 (pre-disclosure).

## What this repo is

- A verified CVE-2026-109618 information disclosure PoC: ASLR bypass via PHPSESSID cookie heap leak (stages 1 and 2 of the exploit chain)
- Docker labs (nginx+FPM and Apache mod_php) to safely reproduce the attack surface
- A working Chain 1 PoC (session injection + LFI, the 2018 technique) for educational comparison
- ASAN verification of the var_destroy reentry UAF
- A mitigation verification suite that tests whether your defenses work
- Detection rules (Sigma, Suricata) for blue teams
- An analysis of nginx `fastcgi_request_buffering` and its effect on exploitability
- Honest documentation distinguishing old techniques from the novel CVEs

## What this repo is NOT

- A full RCE exploit (stage 3 -- fake HashTable to redirect pDestructor -- is not included)
- A "push button, get shell" tool

## Quick start

```bash
# Start the vulnerable FPM lab
cd lab/
docker-compose up -d

# Start the mod_php lab (highest risk SAPI for CVE-2026-109618)
docker-compose -f docker-compose.modphp.yml up -d

# Chain 1 PoC: session injection + LFI (2018 technique, requires LFI)
python3 chains/chain1_session_lfi/race.py id

# Chain 2: ASLR bypass via PHPSESSID heap leak (CVE-2026-109618)
# Requires: modphp-vuln container (8.4.26, single-worker, 8M memory_limit)
python3 chains/chain2_oom/poc_info_leak.py 8896

# Chain 3: Stale state demo (CVE-2026-109619, against mod_php lab)
python3 chains/chain3_stale_state/stale_state_demo.py --port 8899

# Run mitigation verification
cd mitigations/
./verify_all.sh

# Check exposure
cd detection/
./check_exposure.sh --container lab-php-1
```

## Repository structure

```
php2shell-lab/
  README.md                              # This file
  LICENSE                                # MIT
  DISCLAIMER.md                          # Authorized use only

  lab/                                   # Docker lab environments
    docker-compose.yml                   #   PHP 8.4-fpm + nginx
    docker-compose.modphp.yml            #   Apache mod_php (highest risk SAPI)
    php.ini                              #   FPM config
    php-modphp.ini                       #   mod_php config (low memory_limit)
    nginx.conf                           #   With fastcgi_request_buffering off
    www/index.php                        #   phpinfo() target
    www/vuln_lfi.php                     #   Simulated LFI vulnerability
    pinned_digest.txt                    #   Pre-patch image digest

  chains/                                # Attack chain demonstrations
    README.md                            #   Overview: four chains, old vs new
    chain1_session_lfi/                  #   Known since 2018 (Orange Tsai)
      poc.py                             #     cleanup=Off, two-step RCE
      race.py                            #     cleanup=On, race condition RCE
    chain2_oom/                          #   CVE-2026-109618: OOM corruption
      trigger_oom.py                     #     OOM trigger + disclosure check
      Dockerfile.asan                    #     ASAN-instrumented PHP build
      verify_uaf.php                     #     UAF verification (ASAN)
      verify_asan.sh                     #     Build and run helper
    chain3_stale_state/                  #   CVE-2026-109619: cross-request UAF
      stale_state_demo.py                #     Two-request stale state demo
    chain4_handler_mismatch/             #   Deserialization via handler mismatch
      README.md                          #     Research notes (placeholder)

  mitigations/                           # Mitigation verification tests
    verify_all.sh                        #   Run all tests
    test_upload_progress_off.py          #   Verify upload_progress disabled
    test_strict_mode.py                  #   Verify strict_mode enabled
    test_nginx_block.py                  #   Verify WAF/proxy blocking rule
    test_patched_php.py                  #   Verify PHP version is patched

  detection/                             # Detection rules
    sigma_php_child_shell.yml            #   Sigma: PHP spawns shell
    suricata_multipart.rules             #   Suricata: upload_progress abuse
    check_exposure.sh                    #   Quick exposure check script

  docs/                                  # Documentation
    TECHNICAL.md                         #   Full technical analysis (corrected)
    NGINX_BUFFERING.md                   #   fastcgi_request_buffering finding
    NON_TECHNICAL.md                     #   Explanation for non-technical leads
    TIMELINE.md                          #   Full disclosure timeline with IoCs
```

## Four attack chains

| Chain | CVE | Technique | Requires |
|-------|-----|-----------|----------|
| 1. Session injection + LFI | Pre-CVE (2018) | Filename injection into session file | LFI in target app |
| 2. OOM corruption | CVE-2026-109618 | longjmp() skips cleanup on OOM; heap leak via PHPSESSID | Nothing (default config) |
| 3. Stale global state | CVE-2026-109619 | Cross-request UAF in persistent workers | Nothing (default config) |
| 4. Handler mismatch | Related | Serializer deserialization via .user.ini mismatch | Mismatched handlers + gadget chain |

See [chains/README.md](chains/README.md) for details.

## Key facts (updated 2026-10-22)

- **Discovered by:** Ryan Austin (Calif/OpenAI) and Wiz Research, independently, August 2026
- **In the wild:** Amazon MadPot detected exploitation 2026-10-17, 4 days before disclosure
- **RCE demonstrated:** Unauthenticated against WordPress, Drupal, Joomla, Magento, and 7 other apps
- **Memory disclosure:** CVE-2026-109618 can leak worker memory (passwords, keys) via PHPSESSID cookies
- **mod_php is highest risk:** Cleanup runs even on startup failure -- RCE before app code
- **Impact:** Governments (NL, FI, FR) took sites offline; NSA recommended going offline; Wikipedia services shut down
- **Fake PoCs:** JFrog warns of trojanized PoCs on GitHub with hidden payloads

## Mitigations

| Priority | Mitigation | Covers |
|----------|-----------|--------|
| 1 | **Update PHP** (8.2.35, 8.3.36, 8.4.27, 8.5.12) + restart workers | Both CVEs fully |
| 2 | `session.upload_progress.enabled = Off` | Session paths only |
| 3 | `memory_limit = -1` (temporary, monitor memory) | Removes OOM trigger |
| 4 | Block `multipart/form-data` at WAF | All known triggers (breaks uploads) |
| 5 | `pm.max_requests = 1` (FPM) | CVE-2026-109619 cross-request path |

**No single workaround covers both CVEs. Patching is the only full fix.**

See [mitigations/README.md](mitigations/README.md) for verification tests.

## Existing work and differentiation

| Repo | Focus | Our addition |
|------|-------|-------------|
| eness/php2shell | Weaponized UAF exploit + mitigation configs | Verification tests, not just configs |
| ikow/php2shell-poc | Three-chain research analysis | Lab + honest educational framing |
| mikensec/php2shell-lab | Offline analysis + YARA/Sigma | Live PoC + OOM trigger + stale state demo |
| RemiPelloux/php-session-upload-progress-uaf | Heap layout study + exposure scanner | Mitigation verification + mod_php lab |

Our contribution: verified CVE-2026-109618 info disclosure PoC (ASLR bypass via PHPSESSID heap leak), ASAN UAF verification, OOM trigger and stale-state demos, mitigation verification suite, mod_php lab (highest risk SAPI), nginx buffering analysis, and honest labeling of old vs. new techniques.

## Credits

- PHP Security Team for advisory and patches
- Ryan Austin (Calif) and Wiz Research for discovery
- OpenAI for the Patch the Planet program
- Orange Tsai for the 2018 HITCON CTF technique
- eness and ikow for public research
- Amazon Threat Intelligence for pre-disclosure IoCs
- CERT-EU for advisory 2026-018
- CISA for the immediate patching alert

## License

MIT. See [LICENSE](LICENSE) and [DISCLAIMER.md](DISCLAIMER.md).
