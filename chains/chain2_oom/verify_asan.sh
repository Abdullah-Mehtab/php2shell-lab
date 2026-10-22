#!/bin/bash
# Build and run the ASAN-instrumented PHP to verify CVE-2026-109618 UAF
#
# This builds PHP from source with -fsanitize=address, then runs the
# UAF trigger script. ASAN will report heap-use-after-free if the
# vulnerability is present.
#
# Usage: ./verify_asan.sh [php_version]
# Default PHP version: 8.4.26 (last pre-patch release)

set -e

PHP_VERSION="${1:-8.4.26}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "[*] Building PHP ${PHP_VERSION} with AddressSanitizer..."
echo "[*] This will take several minutes on first run."
echo

docker build \
    -f "${SCRIPT_DIR}/Dockerfile.asan" \
    --build-arg "PHP_VERSION=${PHP_VERSION}" \
    -t "php-asan:${PHP_VERSION}" \
    "${SCRIPT_DIR}"

echo
echo "[*] Running UAF verification..."
echo "============================================================"
docker run --rm "php-asan:${PHP_VERSION}" 2>&1
EXIT_CODE=$?
echo "============================================================"
echo

if [ $EXIT_CODE -ne 0 ]; then
    echo "[+] ASAN detected memory errors (exit code ${EXIT_CODE})"
    echo "    This confirms the heap use-after-free vulnerability."
else
    echo "[*] Clean exit. Either:"
    echo "    - This PHP version is patched"
    echo "    - The UAF did not trigger (check ASAN output above)"
fi
