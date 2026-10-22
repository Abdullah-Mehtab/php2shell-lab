# nginx fastcgi_request_buffering and the Race Window

## Finding

The `fastcgi_request_buffering` directive in nginx is the single most important factor in whether the session.upload_progress race condition (Chain 1, cleanup=On) succeeds against PHP-FPM targets.

This is not well-documented in existing CVE-2026-109618 writeups.

## Background

When `session.upload_progress.cleanup = On` (the production default), the injected payload exists in the session file only during the upload processing window. The race exploitation strategy is:

1. Declare a large `Content-Length` (e.g., 256KB)
2. Send the multipart header (containing the payload filename) quickly
3. Trickle the remaining body data slowly ("slow-drip")
4. While the upload streams, PHP has written the progress data to the session file
5. Concurrent LFI requests hit the session file before the upload completes and cleanup fires

## The problem: nginx buffering

nginx's `fastcgi_request_buffering` directive (default: **on**) controls whether nginx buffers the entire request body in memory/disk before forwarding it to the FastCGI backend.

When **on** (default):
- nginx reads the complete request body
- Only then forwards it to PHP-FPM
- PHP receives the entire body at once
- The progress data is written and cleaned up in a single, near-instant pass
- The race window collapses to microseconds
- Exploitation is practically impossible

When **off**:
- nginx streams the request body to PHP-FPM as it arrives
- The slow-drip reaches PHP directly
- PHP writes progress data on the first multipart boundary
- Cleanup fires only after the last byte arrives
- The race window can be seconds or minutes
- Exploitation is reliable

## Test results

Against our lab (PHP 8.4.26-fpm + nginx:alpine):

| Setting | 50 attempts | Result |
|---------|-------------|--------|
| `fastcgi_request_buffering on` (default) | 0 wins | Race practically impossible |
| `fastcgi_request_buffering off` | ~3-4 wins per 5 runs | Reliable exploitation |

## Who is affected

- **nginx + PHP-FPM with default config:** Accidentally protected by buffering. The race is very difficult.
- **nginx + PHP-FPM with `fastcgi_request_buffering off`:** Vulnerable to the race. This is set for performance reasons (large uploads, streaming) and in some PHP framework deployment guides.
- **Apache mod_php:** No buffering layer. PHP receives the body directly. Fully vulnerable.
- **PHP built-in server:** No buffering. Fully vulnerable (dev environments).
- **Caddy, LiteSpeed, etc.:** Depends on their buffering behavior. Test case by case.

## nginx configuration

To check your nginx config:
```bash
nginx -T 2>/dev/null | grep fastcgi_request_buffering
```

If no output, the default (`on`) is in effect, which accidentally mitigates the race.

## Implications for defenders

- Do NOT rely on nginx buffering as a security control. It is a performance setting that happens to affect the race timing.
- The heap UAF (Chain 2, CVE-2026-109618) does NOT depend on this race window and is NOT mitigated by buffering.
- The correct fix is patching PHP or disabling `session.upload_progress.enabled`.

## Implications for testers

- If testing the race against an nginx+FPM target and getting zero wins, check `fastcgi_request_buffering`.
- Against Apache mod_php or the PHP built-in server, the race works without this consideration.
- When reporting, note the web server configuration as it materially affects exploitability of this specific chain.
