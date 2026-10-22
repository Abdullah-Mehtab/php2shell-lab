# Detection Rules

Detection rules and exposure checks for CVE-2026-109618/109619.

## Sigma rule: PHP-FPM spawns shell

`sigma_php_child_shell.yml` detects PHP worker processes spawning shells. This indicates successful code execution through any PHP RCE, including php2shell.

Import into your SIEM (Splunk, Elastic, Sentinel) via the Sigma converter:
```bash
sigma convert -t splunk sigma_php_child_shell.yml
```

## Suricata rules

`suricata_multipart.rules` contains three rules:
1. PHP code (`<?php`) in multipart request body alongside `PHP_SESSION_UPLOAD_PROGRESS`
2. Short PHP tags (`<?=`) in the same context
3. Rapid multipart uploads (10+ in 5 seconds) suggesting race condition exploitation

Add to `/etc/suricata/rules/local.rules` and reload.

## Exposure check

`check_exposure.sh` quickly checks if a PHP server has the vulnerable configuration:

```bash
./check_exposure.sh http://target/phpinfo.php      # via phpinfo page
./check_exposure.sh --container lab-php-1            # via Docker container
```

Checks: PHP version, `session.upload_progress.enabled`, `session.use_strict_mode`.
