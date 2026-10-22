#!/bin/bash
# Quick exposure check for CVE-2026-109618/109619
#
# Checks a target PHP server for the vulnerable configuration:
#   - session.upload_progress.enabled = On
#   - session.use_strict_mode = Off
#   - PHP version in affected range
#
# Requires a phpinfo() endpoint or CLI access.
#
# Usage: ./check_exposure.sh <phpinfo_url>
#    or: ./check_exposure.sh --container <container_name>

set -e

if [ "$1" = "--container" ]; then
    CONTAINER="${2:-lab-php-1}"
    echo "[*] Checking container: ${CONTAINER}"
    echo

    VERSION=$(docker exec "${CONTAINER}" php -r 'echo PHP_VERSION;' 2>/dev/null)
    UPLOAD_PROGRESS=$(docker exec "${CONTAINER}" php -r 'echo ini_get("session.upload_progress.enabled");' 2>/dev/null)
    STRICT_MODE=$(docker exec "${CONTAINER}" php -r 'echo ini_get("session.use_strict_mode");' 2>/dev/null)
    CLEANUP=$(docker exec "${CONTAINER}" php -r 'echo ini_get("session.upload_progress.cleanup");' 2>/dev/null)

    echo "  PHP Version:             ${VERSION}"
    echo "  upload_progress.enabled: ${UPLOAD_PROGRESS}"
    echo "  upload_progress.cleanup: ${CLEANUP}"
    echo "  use_strict_mode:         ${STRICT_MODE}"
    echo

    EXPOSED=0
    if [ "${UPLOAD_PROGRESS}" = "1" ] || [ "${UPLOAD_PROGRESS}" = "On" ]; then
        echo "[!] upload_progress is ENABLED -- session injection primitive is available"
        EXPOSED=1
    else
        echo "[+] upload_progress is disabled"
    fi

    if [ "${STRICT_MODE}" = "0" ] || [ "${STRICT_MODE}" = "" ]; then
        echo "[!] strict_mode is OFF -- attacker can choose session IDs"
        EXPOSED=1
    else
        echo "[+] strict_mode is on"
    fi

    if [ $EXPOSED -eq 1 ]; then
        echo
        echo "[!] This server is EXPOSED to the session injection chain."
        echo "    Apply mitigations from mitigations/README.md"
        exit 1
    else
        echo
        echo "[+] Basic mitigations appear active."
        exit 0
    fi

elif [ -n "$1" ]; then
    URL="$1"
    echo "[*] Checking phpinfo at: ${URL}"
    echo

    BODY=$(curl -s "${URL}" 2>/dev/null)

    VERSION=$(echo "${BODY}" | grep -oP 'PHP Version </td><td class="v">\K[0-9.]+' | head -1)
    if [ -z "${VERSION}" ]; then
        VERSION=$(echo "${BODY}" | grep -oP 'PHP Version \K[0-9.]+' | head -1)
    fi

    echo "  PHP Version: ${VERSION:-unknown}"

    if echo "${BODY}" | grep -q 'session.upload_progress.enabled.*On'; then
        echo "  upload_progress.enabled: On"
        echo "[!] Session injection primitive is available"
    elif echo "${BODY}" | grep -q 'session.upload_progress.enabled.*Off'; then
        echo "  upload_progress.enabled: Off"
        echo "[+] Primary mitigation is active"
    else
        echo "  upload_progress.enabled: unknown (not found in phpinfo)"
    fi

    if echo "${BODY}" | grep -q 'session.use_strict_mode.*Off\|session.use_strict_mode.*0'; then
        echo "  use_strict_mode: Off"
        echo "[!] Attacker can choose session IDs"
    elif echo "${BODY}" | grep -q 'session.use_strict_mode.*On\|session.use_strict_mode.*1'; then
        echo "  use_strict_mode: On"
        echo "[+] Strict mode is active"
    fi

else
    echo "Usage: $0 <phpinfo_url>"
    echo "   or: $0 --container <container_name>"
    exit 2
fi
