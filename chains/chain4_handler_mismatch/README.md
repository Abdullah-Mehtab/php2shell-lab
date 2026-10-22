# Chain 3: Session Handler Mismatch (Deserialization)

**Status:** Research-stage, documented by ikow

This chain exploits a mismatch between PHP session serialization handlers across directories on the same server. It leads to arbitrary object deserialization without directly exploiting the heap UAF.

## How it works

1. Two directories on the same server use different `session.serialize_handler` values via `.user.ini`:
   - `/app/` uses `php_serialize` (stores data as `serialize()` output)
   - `/api/` uses `php` (stores data as `key|serialized_value`)

2. Attacker uploads via the `php_serialize` endpoint with a pipe `|` character in the filename
3. The `php_serialize` handler stores the filename verbatim, including the pipe
4. When the `php` handler reads the same session, it splits at `|` and deserializes everything after it
5. If the deserialized data contains an object with an exploitable `__destruct` or `__wakeup`, code execution follows

## Key detail

PHP fires `__destruct` on decoded objects even when `var_unserialize` returns **FAILURE** (due to trailing data). This means the attacker does not need a perfectly formed serialized payload -- partial deserialization is sufficient to trigger gadget chains.

## Prerequisites

- Two directories with different `session.serialize_handler` values
- Shared `session.save_path`
- A class with an exploitable `__destruct` or `__wakeup` autoloaded in the `php` handler's context

## Lab setup (placeholder)

This chain requires a more complex lab with per-directory `.user.ini` files. See `ikow/php2shell-poc` lab/setup.sh for a reference implementation.

A full lab for this chain is planned but not yet built.

## References

- [ikow/php2shell-poc -- Handler Mismatch Analysis](https://github.com/ikow/php2shell-poc/blob/main/docs/ANALYSIS.md)
- [PHP Manual -- Session Serialization Handlers](https://www.php.net/manual/en/session.configuration.php#ini.session.serialize-handler)
