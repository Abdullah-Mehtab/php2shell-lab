#!/usr/bin/env python3
"""
Mitigation test: session.use_strict_mode = 1

Verifies that strict mode rejects attacker-supplied session IDs.
With strict mode on, PHP generates its own session ID and ignores
the PHPSESSID cookie if it doesn't match an existing server-side session.

This breaks the predictable-path requirement of the injection chain.

Expected result when mitigated: attacker's chosen session ID is rejected,
session file is created with a server-generated ID (not attacker-controlled).
"""

import argparse
import socket
import subprocess
import sys


def inject_session(host, port, path, session_id):
    boundary = "----StrictModeTest"
    payload = "test-strict-mode"

    body = b""
    body += f"--{boundary}\r\n".encode()
    body += b'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n'
    body += b"test\r\n"
    body += f"--{boundary}\r\n".encode()
    body += f'Content-Disposition: form-data; name="file"; filename="{payload}"\r\n'.encode()
    body += b"Content-Type: application/octet-stream\r\n\r\n"
    body += b"x\r\n"
    body += f"--{boundary}--\r\n".encode()

    req = f"POST {path} HTTP/1.1\r\n".encode()
    req += f"Host: {host}:{port}\r\n".encode()
    req += f"Cookie: PHPSESSID={session_id}\r\n".encode()
    req += f"Content-Type: multipart/form-data; boundary={boundary}\r\n".encode()
    req += f"Content-Length: {len(body)}\r\n".encode()
    req += b"Connection: close\r\n\r\n"
    req += body

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10)
    sock.connect((host, port))
    sock.sendall(req)
    resp = b""
    while True:
        try:
            chunk = sock.recv(4096)
            if not chunk:
                break
            resp += chunk
        except socket.timeout:
            break
    sock.close()


def main():
    ap = argparse.ArgumentParser(
        description="Verify session.use_strict_mode=1 mitigation")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8898)
    ap.add_argument("--path", default="/index.php")
    ap.add_argument("--container", default="lab-php-1",
                    help="Docker container name to check session files")
    args = ap.parse_args()

    session_id = "attacker-chosen-strict-test"
    session_file = f"/tmp/sess_{session_id}"

    print("[*] Testing: session.use_strict_mode = 1")
    print(f"    Target: http://{args.host}:{args.port}")
    print()

    inject_session(args.host, args.port, args.path, session_id)

    result = subprocess.run(
        ["docker", "exec", args.container, "test", "-f", session_file],
        capture_output=True)

    if result.returncode != 0:
        print("[PASS] Attacker-chosen session ID was rejected.")
        print("       strict_mode=1 prevents predictable session file paths.")
        return 0
    else:
        print("[FAIL] Session file created with attacker-chosen ID.")
        print(f"       Check that session.use_strict_mode = 1 is active.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
