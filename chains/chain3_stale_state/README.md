# Chain 3: Stale Global State Across Requests (CVE-2026-109619)

**Status:** Novel vulnerability. GHSA-6wmf-4rv5-p3rp.

## Root cause

PHP reuses worker processes (mod_php children, FPM workers) across requests. Internal state from one request -- session decoder pointers, error backtrace data, OPcache structures -- can survive into the next request on the same worker when a fatal error (OOM, timeout) interrupts the normal shutdown/cleanup sequence.

The next request reads these stale pointers before initialization clears them. Since the memory they point to was freed at the end of the previous request, this is a cross-request use-after-free.

## Confirmed attack paths

1. **Session upload progress (mod_php and FPM):** The upload progress handler consumes stale session/decoder state before normal initialization. Does not require `session_start()` in application code. Enabled by default.

2. **Fatal error backtraces (PHP 8.5 mod_php):** `fatal_error_backtraces` is enabled by default on PHP 8.5. A later initialization diagnostic accesses stale backtrace state from the previous request's fatal error.

3. **OPcache type confusion:** Stale state in OPcache shared memory corrupted across workers. Less documented.

## FPM trigger sequence

1. Request A on worker W: application operation leaves state in worker globals
2. Request A: fatal error occurs (OOM, timeout), interrupting cleanup
3. Request B hits worker W: upload progress handler consumes stale state from Request A before normal initialization clears it
4. Stale pointers read freed memory -> UAF

Multiple workers and `pm.max_requests` recycling reduce success rate but do not eliminate the condition.

## Demonstration (`stale_state_demo.py`)

Sends two sequential requests to the same PHP-FPM worker:
1. First request triggers a fatal error (memory exhaustion or timeout)
2. Second request with upload progress checks for anomalous behavior

```bash
python3 stale_state_demo.py --host 127.0.0.1 --port 8898
```

This demonstrates the trigger condition. Observable effects depend on the PHP build and what state was left behind. On an ASAN build, you would see heap-use-after-free reports.

## Mitigations

| Mitigation | Effect |
|-----------|--------|
| Update PHP | Fixes root cause |
| `session.upload_progress.enabled = 0` | Blocks session path only |
| `fatal_error_backtraces = 0` (PHP 8.5) | Blocks backtrace path only |
| `pm.max_requests = 1` (FPM) | Breaks cross-request requirement (performance cost) |

None individually covers all paths. Patching is the only full fix.

## References

- PHP Advisory: GHSA-6wmf-4rv5-p3rp
- Rapid7 ETR: https://www.rapid7.com/blog/post/etr-cve-2026-109618-and-cve-2026-109619/
