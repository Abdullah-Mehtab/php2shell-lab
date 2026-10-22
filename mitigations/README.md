# Mitigation Verification Suite

Automated tests that verify whether specific mitigations for CVE-2026-109618/109619 are effective. Run against your lab or staging environment to confirm your defenses work.

## Quick start

```bash
./verify_all.sh                          # test against default lab
./verify_all.sh 127.0.0.1 8898 lab-php-1 # explicit host/port/container
```

## Individual tests

| Script | Mitigation | What it checks |
|--------|-----------|----------------|
| `test_upload_progress_off.py` | `session.upload_progress.enabled = Off` | Session file NOT created on multipart POST |
| `test_strict_mode.py` | `session.use_strict_mode = 1` | Attacker-chosen session ID rejected |
| `test_nginx_block.py` | nginx/WAF blocking rule | Requests with `PHP_SESSION_UPLOAD_PROGRESS` return 403 |
| `test_patched_php.py` | Patched PHP version | PHP version at or above the fixed release |

## Patched versions

| Branch | Fixed in |
|--------|----------|
| 8.2.x  | 8.2.35   |
| 8.3.x  | 8.3.36   |
| 8.4.x  | 8.4.27   |
| 8.5.x  | 8.5.12   |
| 7.4, 8.0, 8.1 | Source-only backports (EOL, no official binary release) |
| 5.x, 7.0-7.3 | No fix available |

## Full mitigation matrix

**Updating PHP is the only complete fix.** Everything else is partial.

| Mitigation | CVE-2026-109618 (OOM) | CVE-2026-109619 (stale state) | Side effects |
|-----------|----------------------|------------------------------|-------------|
| **Update PHP** | Full fix | Full fix | None |
| `session.upload_progress.enabled = 0` | Blocks session path | Blocks session path | Does NOT cover OPcache or backtrace paths |
| `memory_limit = -1` | Removes OOM trigger | No effect | Allows unbounded memory use -- monitor closely |
| `fatal_error_backtraces = 0` (8.5) | No effect | Blocks backtrace path | Only one CVE-2026-109619 path |
| `pm.max_requests = 1` (FPM) | No effect | Breaks cross-request req. | Performance impact (no worker reuse) |
| Block `multipart/form-data` at WAF | Blocks all known triggers | Blocks all known triggers | Breaks all file uploads |

## Mitigation application notes

- `session.upload_progress.enabled` must be set in `php.ini`, FPM pool config, or Apache server config. `.user.ini` and `ini_set()` are too late -- the handler fires before application code.
- **Restart all PHP workers** after any configuration change. The old code/config stays loaded in running workers.
- `memory_limit = -1` is dangerous -- it allows a single request to consume all server memory. Use only as a temporary measure and monitor memory usage.
- Do NOT use `RLIMIT_AS` or `RLIMIT_DATA` as an alternative to `memory_limit` -- they can trigger the vulnerable allocation-failure path.

## Priority order

1. **Update PHP** to a patched version and restart workers
2. If you cannot update immediately: set `session.upload_progress.enabled = 0` AND consider `memory_limit = -1`
3. Block `multipart/form-data` at WAF/proxy if your application can tolerate no file uploads
4. Enable `session.use_strict_mode = 1` (defense in depth for session fixation)
5. Set `pm.max_requests = 1` in FPM (defense in depth against CVE-2026-109619)
