#!/usr/bin/env python3
"""
Mitigation test: nginx location block rejecting PHP_SESSION_UPLOAD_PROGRESS

Verifies that a WAF/proxy rule blocks requests containing the
PHP_SESSION_UPLOAD_PROGRESS field in the POST body.

Example nginx rule to test:
  location ~ \.php$ {
      if ($request_body ~* "PHP_SESSION_UPLOAD_PROGRESS") {
          return 403;
      }
      # ... fastcgi_pass ...
  }

Expected result when mitigated: HTTP 403 Forbidden.
"""

import argparse
import socket
import sys


def send_upload_progress(host, port, path):
    boundary = "----NginxBlockTest"

    body = b""
    body += f"--{boundary}\r\n".encode()
    body += b'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n'
    body += b"test\r\n"
    body += f"--{boundary}\r\n".encode()
    body += b'Content-Disposition: form-data; name="file"; filename="test.txt"\r\n'.encode()
    body += b"Content-Type: application/octet-stream\r\n\r\n"
    body += b"x\r\n"
    body += f"--{boundary}--\r\n".encode()

    req = f"POST {path} HTTP/1.1\r\n".encode()
    req += f"Host: {host}:{port}\r\n".encode()
    req += f"Cookie: PHPSESSID=nginx-block-test\r\n".encode()
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
    return resp


def main():
    ap = argparse.ArgumentParser(
        description="Verify nginx blocks PHP_SESSION_UPLOAD_PROGRESS requests")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8898)
    ap.add_argument("--path", default="/index.php")
    args = ap.parse_args()

    print("[*] Testing: nginx PHP_SESSION_UPLOAD_PROGRESS blocking rule")
    print(f"    Target: http://{args.host}:{args.port}")
    print()

    resp = send_upload_progress(args.host, args.port, args.path)
    status_line = resp.split(b"\r\n")[0].decode("latin-1", "replace") if resp else ""

    if "403" in status_line:
        print(f"[PASS] Request blocked: {status_line}")
        print("       The WAF/proxy rule rejects upload_progress requests.")
        return 0
    elif "200" in status_line:
        print(f"[FAIL] Request allowed: {status_line}")
        print("       No blocking rule is active. The upload_progress field was accepted.")
        return 1
    else:
        print(f"[WARN] Unexpected response: {status_line}")
        print("       Manual review required.")
        return 2


if __name__ == "__main__":
    sys.exit(main())
