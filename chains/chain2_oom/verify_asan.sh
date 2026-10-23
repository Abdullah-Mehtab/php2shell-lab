#!/bin/bash
# Build and run ASAN-instrumented PHP to verify CVE-2026-109618 UAF
#
# Builds PHP from source with -fsanitize=address, runs the UAF trigger.
# ASAN reports heap-use-after-free if the vulnerability is present.
#
# Usage: ./verify_asan.sh [php_version]
# Default: 8.4.26 (last vulnerable release)

set -e

PHP_VERSION="${1:-8.4.26}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

DOCKER_CMD="docker"
if ! docker info >/dev/null 2>&1; then
    DOCKER_CMD="sg docker -c docker"
fi

echo "[*] Building PHP ${PHP_VERSION} with AddressSanitizer..."
echo "[*] This takes several minutes on first run."
echo

$DOCKER_CMD build \
    -f "${SCRIPT_DIR}/Dockerfile.asan" \
    --build-arg "PHP_VERSION=${PHP_VERSION}" \
    -t "php-asan:${PHP_VERSION}" \
    "${SCRIPT_DIR}"

echo
echo "[*] Running UAF verification..."
echo "============================================================"
$DOCKER_CMD run --rm "php-asan:${PHP_VERSION}" 2>&1
EXIT_CODE=$?
echo "============================================================"
echo

if [ $EXIT_CODE -ne 0 ]; then
    echo "[+] ASAN detected memory errors (exit code ${EXIT_CODE})"
else
    echo "[*] Clean exit -- either patched or UAF did not fire."
fi
