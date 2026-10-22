#!/usr/bin/env python3
"""
Mitigation test: session.upload_progress.enabled = Off

Verifies that disabling upload_progress prevents session file creation
via the multipart upload mechanism. This is the primary mitigation for
CVE-2026-109618.

Expected result when mitigated: no session file created.
"""

import argparse
import socket
import subprocess
import sys


def inject_session(host, port, path, session_id):
    boundary = "----MitigationTest"
    payload = "<?php echo 'SHOULD_NOT_EXIST'; ?>"

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
        description="Verify session.upload_progress.enabled=Off mitigation")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8898)
    ap.add_argument("--path", default="/index.php")
    ap.add_argument("--container", default="lab-php-1",
                    help="Docker container name to check session files")
    args = ap.parse_args()

    session_id = "mitigation-test-upload-off"
    session_file = f"/tmp/sess_{session_id}"

    print("[*] Testing: session.upload_progress.enabled = Off")
    print(f"    Target: http://{args.host}:{args.port}")
    print()

    inject_session(args.host, args.port, args.path, session_id)

    result = subprocess.run(
        ["docker", "exec", args.container, "test", "-f", session_file],
        capture_output=True)

    if result.returncode != 0:
        print("[PASS] Session file was NOT created.")
        print("       upload_progress.enabled=Off prevents the injection primitive.")
        return 0
    else:
        print("[FAIL] Session file was created despite mitigation.")
        print(f"       Check that session.upload_progress.enabled = Off is active.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
