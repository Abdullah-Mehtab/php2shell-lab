# Timeline

All times UTC.

## Discovery and disclosure

| Date | Event | Source |
|------|-------|--------|
| 2024 | PHP core developer flags OOM bug during audit; team does not prioritize fix | Wikipedia |
| 2026-08-01 | Ryan Austin (Calif) finds multiple RCE paths | Sansec |
| 2026-08-11 | Calif reports first bug to PHP, begins coordinated disclosure | Sansec |
| 2026-08-24 | Wiz Research independently reports the vulnerabilities to PHP | Sansec |
| 2026-10-17 | Amazon MadPot honeypot detects exploitation attempt (4 days before disclosure) | Amazon TI |
| 2026-10-20 | Existence publicly announced; details leak via Hacker News, watchTowr post on X | Wikipedia |
| 2026-10-20 | Calif accidentally releases PoC video | Wikipedia |
| 2026-10-20 | watchTowr confirms RCE in PHP lab | Sansec |
| 2026-10-20 | PHP security team publishes advance advisory (CVSS 9.2, patch scheduled Oct 21 14:00) | php.net |
| 2026-10-20 | CERT-EU publishes security advisory 2026-018 | CERT-EU |
| 2026-10-20 | Qualys publishes advisory | Qualys |

## Patch day (2026-10-21)

| Time (UTC) | Event | Source |
|------------|-------|--------|
| 02:00-08:00 | Multiple exploitation attempts against MadPot from varied infrastructure | Amazon TI |
| 07:43 | Cloudflare reports early attacks, deploys temporary WAF rules | Cloudflare |
| ~13:00 | Chainguard releases patched containers early, exposing code changes | Wikipedia |
| 13:34 | GitHub security advisories published (26 min before announced release time) | Wikipedia |
| 14:00 | PHP releases 8.2.35, 8.3.36, 8.4.27, 8.5.12 | php.net |
| 14:00+ | Calif, Wiz, OpenAI, and PHP formally disclose | Multiple |
| Post-release | Multiple public PoC exploits appear; used against sensors almost immediately | Amazon TI |
| 21:03 | CISA says not yet on KEV as of this time | CISA |

## Impact responses

| Date | Event |
|------|-------|
| 2026-10-20/21 | Dutch government portal taken offline as precaution |
| 2026-10-20/21 | Finnish government web services taken offline |
| 2026-10-20/21 | French Interior Ministry websites taken offline |
| 2026-10-20/21 | NSA recommends taking websites offline if unable to update immediately |
| 2026-10-20/21 | Wikimedia Foundation shuts down several services |
| 2026-10-20/21 | 4chan and Something Awful go offline |
| 2026-10-20/21 | Internet Archive briefly shuts down |
| 2026-10-21 | AlmaLinux pushes patched packages |
| 2026-10-21 | CISA publishes alert urging immediate patching |
| 2026-10-21 | AWS publishes security bulletin 2026-143 |
| 2026-10-21 | CloudLinux Imunify360 deploys ruleset 8.83 blocking exploit shape |

## In-the-wild IoCs (from Amazon Threat Intelligence)

| IP Address | First Observed |
|-----------|---------------|
| 103.216.220.92 | 2026-10-17 (pre-disclosure) |
| 31.223.184.166 | 2026-10-21 |
| 37.19.200.5 | 2026-10-21 |
| 134.209.159.64 | 2026-10-21 |
| 103.114.163.188 | 2026-10-21 |
| 95.217.98.37 | 2026-10-21 |

All IPs are from commercial anonymization networks (shared infrastructure). Amazon recommends investigating activity from these IPs rather than blocking outright, and starting investigations from October 17, not the disclosure date.

## Pre-CVE history

The session.upload_progress injection technique (our Chain 1) predates the CVEs:

| Date | Event |
|------|-------|
| 2012 | PHP 5.4 introduces session.upload_progress (enabled by default) |
| 2018-10 | Orange Tsai uses session upload progress + LFI at HITCON CTF |
| 2018-12 | Writeup published (spyclub.tech) |
| Various | Technique documented in HackTricks, PayloadsAllTheThings |
