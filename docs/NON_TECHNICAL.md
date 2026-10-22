# php2shell: Non-Technical Summary

## What happened

On October 20, 2026, two critical vulnerabilities in PHP were publicly disclosed. PHP powers approximately 69% of websites with a known server-side language, including WordPress, Drupal, Joomla, Magento, and countless custom applications.

The vulnerabilities, nicknamed "php2shell" (CVE-2026-109618 and CVE-2026-109619), allow an attacker to take control of a web server without any login credentials and without any bug in the website's own code. The flaw is in PHP itself.

## How bad is it

**Severity: Critical (9.2 out of 10)**

- No login or authentication is needed
- No bug in the website's own code is needed
- The attacker can run any command as the web server user
- The attacker can steal passwords, session tokens, API keys, and even TLS private keys from server memory
- The vulnerable feature has been on by default for 14 years (since PHP 5.4, released 2012)
- Exploitation was observed in the wild 4 days before public disclosure

The researchers who found it demonstrated unauthenticated takeover of 11 major applications: WordPress, Drupal, Joomla, Magento, MediaWiki, Roundcube, phpMyAdmin, Nextcloud, Laravel, Symfony, and WHMCS.

Multiple governments (Dutch, Finnish, French) took websites offline. The NSA recommended taking sites offline if they could not update immediately. Wikimedia shut down services. 4chan and the Internet Archive briefly went offline.

## Who found it

The vulnerabilities were independently discovered in August 2026 by:
- **Ryan Austin** at Calif, as part of OpenAI's "Patch the Planet" project
- **Wiz Research** (a Google Cloud subsidiary)

Both used AI tools (GPT-5.6 Sol, Gemini 4 Argon) to assist in finding the bugs. A PHP developer had actually flagged the underlying issue in a 2024 audit, but it was never fixed.

## What exactly is wrong

There are two separate bugs:

**Bug 1 (CVE-2026-109618): Memory corruption when PHP runs out of memory.** When a web request causes PHP to use too much memory, PHP crashes in a way that leaves internal data structures in a broken state. An attacker can exploit this broken state to run commands on the server. On Apache with mod_php (common on shared hosting), the attack works before any website code even runs.

**Bug 2 (CVE-2026-109619): Leftover data between web requests.** PHP reuses worker processes to handle multiple requests. Data from one request can accidentally survive into the next request. An attacker can trigger a crash in one request and then exploit the leftover data in a follow-up request to take control.

Both bugs are triggered through file upload requests, which PHP processes automatically before the website's own code runs.

## Who is affected

Any server running PHP 5.4 through 8.5.11 with default settings. This includes:
- WordPress, Drupal, Joomla, Magento, and other CMS/ecommerce platforms
- Laravel, Symfony, and framework-based applications
- XAMPP, WAMP, MAMP development environments
- cPanel, Plesk, and shared hosting environments
- Any custom PHP application

**Apache mod_php deployments are at highest risk** (common on shared hosting and cPanel servers).

## What to do

1. **Update PHP immediately** to 8.2.35, 8.3.36, 8.4.27, or 8.5.12
2. **Restart all PHP workers** after updating (the old code stays loaded until restart)
3. If you cannot update, these **partial** workarounds buy time:
   - Add `session.upload_progress.enabled = Off` to php.ini (does NOT fix everything)
   - Block `multipart/form-data` requests at your WAF/reverse proxy (breaks file uploads)
   - Consider taking the site offline until patched
4. PHP 5.x, 7.x, 8.0, and 8.1 are end-of-life. Source-only backports exist for 7.4-8.1 but no official releases. Upgrade to a supported branch.
5. **Investigate from October 17, 2026** (not the disclosure date) per Amazon's recommendation

## What this repository contains

An educational lab that demonstrates the attack surface:
- A Docker lab to safely reproduce the session injection technique and OOM trigger
- Tests that verify whether your mitigations are working
- Detection rules for monitoring systems (Sigma, Suricata)
- Technical documentation explaining how both vulnerabilities work

This repository does NOT contain a weaponized exploit.
