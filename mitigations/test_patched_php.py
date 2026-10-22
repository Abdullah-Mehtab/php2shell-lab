#!/usr/bin/env python3
"""
Mitigation test: patched PHP version

Verifies that the running PHP version is at or above the patched release.
Fixed versions: 8.2.35, 8.3.36, 8.4.27, 8.5.12
PHP 5.x, 7.x, 8.0, 8.1 are EOL with no official fix.

Expected result when mitigated: PHP version >= patched release.
"""

import argparse
import re
import subprocess
import sys
import urllib.request


PATCHED_VERSIONS = {
    (8, 2): (8, 2, 35),
    (8, 3): (8, 3, 36),
    (8, 4): (8, 4, 27),
    (8, 5): (8, 5, 12),
}

EOL_BRANCHES = [(5,), (7,), (8, 0), (8, 1)]


def parse_version(version_str):
    match = re.search(r'(\d+)\.(\d+)\.(\d+)', version_str)
    if match:
        return tuple(int(x) for x in match.groups())
    return None


def check_version(version_tuple):
    major, minor, patch = version_tuple
    branch = (major, minor)

    for eol in EOL_BRANCHES:
        if (major,) == eol or branch == eol:
            return "EOL", f"PHP {major}.{minor} is end-of-life. No official fix available."

    if branch in PATCHED_VERSIONS:
        required = PATCHED_VERSIONS[branch]
        if version_tuple >= required:
            return "PATCHED", f"PHP {'.'.join(map(str, version_tuple))} >= {'.'.join(map(str, required))}"
        else:
            return "VULNERABLE", f"PHP {'.'.join(map(str, version_tuple))} < {'.'.join(map(str, required))}"

    return "UNKNOWN", f"PHP {'.'.join(map(str, version_tuple))} branch not in known affected list"


def main():
    ap = argparse.ArgumentParser(description="Check PHP version against patched releases")
    ap.add_argument("--container", default="lab-php-1",
                    help="Docker container to check")
    ap.add_argument("--url", default=None,
                    help="Alternatively, URL to a phpinfo() page")
    args = ap.parse_args()

    print("[*] Testing: PHP version against patched releases")
    print()

    version_str = None

    if args.url:
        try:
            resp = urllib.request.urlopen(args.url, timeout=5)
            body = resp.read().decode(errors="replace")
            match = re.search(r'PHP Version (\d+\.\d+\.\d+)', body)
            if match:
                version_str = match.group(1)
        except Exception as e:
            print(f"[-] Could not fetch phpinfo: {e}")
            return 2
    else:
        result = subprocess.run(
            ["docker", "exec", args.container, "php", "-v"],
            capture_output=True, text=True)
        if result.returncode == 0:
            version_str = result.stdout.strip()
        else:
            print(f"[-] Could not get PHP version from container: {result.stderr}")
            return 2

    if not version_str:
        print("[-] Could not determine PHP version")
        return 2

    version = parse_version(version_str)
    if not version:
        print(f"[-] Could not parse version from: {version_str}")
        return 2

    status, message = check_version(version)

    if status == "PATCHED":
        print(f"[PASS] {message}")
        return 0
    elif status == "VULNERABLE":
        print(f"[FAIL] {message}")
        print("       Update to the patched release.")
        return 1
    elif status == "EOL":
        print(f"[FAIL] {message}")
        print("       Upgrade to a supported PHP branch and apply the patch.")
        return 1
    else:
        print(f"[WARN] {message}")
        return 2


if __name__ == "__main__":
    sys.exit(main())
