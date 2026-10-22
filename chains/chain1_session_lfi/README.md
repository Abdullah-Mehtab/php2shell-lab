# Chain 1: Session Upload Progress Injection + LFI

**Status:** Known technique since 2018 (Orange Tsai, HITCON CTF)

This chain uses the same code path targeted by CVE-2026-109618/109619 but is **not** the novel heap use-after-free. It demonstrates the session.upload_progress attack surface that the CVEs exploit at a deeper level.

## How it works

1. Attacker sends a multipart POST with a `PHP_SESSION_UPLOAD_PROGRESS` field
2. PHP's `php_session_rfc1867_callback()` writes the upload filename into a session file at `<save_path>/sess_<PHPSESSID>` without sanitization
3. Attacker sets `PHPSESSID` cookie to a known value, making the session file path predictable
4. An LFI vulnerability in the target application includes the session file, executing the injected PHP code

## Prerequisites

- `session.upload_progress.enabled = 1` (default since PHP 5.4)
- `session.use_strict_mode = 0` (default)
- An LFI vulnerability in the target application
- Knowledge of session save path

## Two variants

### `poc.py` -- cleanup=Off (trivial)

When `session.upload_progress.cleanup = Off`, the progress data persists after the upload. Two-step: inject, then include. 100% reliable.

```bash
python3 poc.py --host 127.0.0.1 --port 8898 id
```

### `race.py` -- cleanup=On (production default)

When cleanup is On, the payload exists only during upload processing. A slow-drip upload (large Content-Length, small chunks) widens the window while concurrent LFI threads catch the file.

```bash
python3 race.py --host 127.0.0.1 --port 8898 --threads 5 id
```

**Critical:** For nginx+php-fpm, `fastcgi_request_buffering off` must be set. Without it, nginx buffers the entire request before forwarding, collapsing the race window to zero. See [docs/NGINX_BUFFERING.md](../../docs/NGINX_BUFFERING.md).

## References

- [Orange Tsai -- HITCON CTF 2018 One Line PHP Challenge](https://blog.orange.tw/posts/2018-10-hitcon-ctf-2018-one-line-php-challenge/)
- [PHP Manual -- Session Upload Progress](https://www.php.net/manual/en/session.upload-progress.php)
