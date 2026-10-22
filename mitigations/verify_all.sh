#!/bin/bash
# Run all mitigation verification tests
#
# Each test exits 0 (PASS), 1 (FAIL), or 2 (WARN/ERROR).
# This script runs against the current lab configuration and reports
# which mitigations are active.
#
# Usage: ./verify_all.sh [--host HOST] [--port PORT] [--container NAME]

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
HOST="${1:-127.0.0.1}"
PORT="${2:-8898}"
CONTAINER="${3:-lab-php-1}"

echo "============================================================"
echo "php2shell Mitigation Verification Suite"
echo "============================================================"
echo
echo "Target:    http://${HOST}:${PORT}"
echo "Container: ${CONTAINER}"
echo
echo "------------------------------------------------------------"

PASS=0
FAIL=0
WARN=0

run_test() {
    local name="$1"
    local script="$2"
    echo
    echo "--- ${name} ---"
    if python3 "${SCRIPT_DIR}/${script}" --host "${HOST}" --port "${PORT}" --container "${CONTAINER}" 2>/dev/null; then
        PASS=$((PASS + 1))
    else
        rc=$?
        if [ $rc -eq 1 ]; then
            FAIL=$((FAIL + 1))
        else
            WARN=$((WARN + 1))
        fi
    fi
}

run_test "upload_progress.enabled = Off" "test_upload_progress_off.py"
run_test "use_strict_mode = 1" "test_strict_mode.py"
run_test "nginx blocking rule" "test_nginx_block.py"

echo
echo "--- PHP Version Check ---"
if python3 "${SCRIPT_DIR}/test_patched_php.py" --container "${CONTAINER}" 2>/dev/null; then
    PASS=$((PASS + 1))
else
    rc=$?
    if [ $rc -eq 1 ]; then
        FAIL=$((FAIL + 1))
    else
        WARN=$((WARN + 1))
    fi
fi

echo
echo "============================================================"
echo "Results: ${PASS} PASS / ${FAIL} FAIL / ${WARN} WARN"
echo "============================================================"

if [ $FAIL -gt 0 ]; then
    exit 1
fi
exit 0
