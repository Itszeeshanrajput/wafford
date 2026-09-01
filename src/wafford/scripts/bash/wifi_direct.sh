#!/usr/bin/env bash
# WiFi Direct / P2P discovery
# Usage: wifi_direct.sh <interface> <action> [args]
# Actions: discover, connect, monitor

set -euo pipefail

_log()   { echo "$*" >&2; }
_json()  { printf '%s\n' "$*"; }
_die()   { _json "{\"status\":\"error\",\"message\":\"$1\"}"; exit 1; }

cleanup() {
    if [[ -n "${WPA_CLI_PID:-}" ]]; then
        kill "$WPA_CLI_PID" 2>/dev/null || true
    fi
    if [[ -n "${SCAN_BG_PID:-}" ]]; then
        kill "$SCAN_BG_PID" 2>/dev/null || true
    fi
    exit "${EXIT_RC:-0}"
}
trap cleanup EXIT

# ── Dependency check ──────────────────────────────────────────────────
for cmd in wpa_cli; do
    if ! command -v "$cmd" &>/dev/null; then
        _die "$cmd not found. Install wpa_supplicant."
    fi
done

# ── Args ──────────────────────────────────────────────────────────────
IFACE="${1:-}"
ACTION="${2:-discover}"
EXTRA_ARG="${3:-}"

if [[ -z "$IFACE" ]]; then
    _die "Usage: wifi_direct.sh <interface> <action> [args]"
fi

if [[ ! -d "/sys/class/net/$IFACE" ]]; then
    _die "Interface '$IFACE' does not exist"
fi

case "$ACTION" in
    discover|connect|monitor)
        ;;
    *)
        _die "Invalid action '$ACTION'. Valid: discover|connect|monitor"
        ;;
esac

# ── Discover P2P peers ────────────────────────────────────────────────
discover_peers() {
    _log "[*] Starting P2P discovery on $IFACE..."

    # Try to enable P2P
    local ctrl_path="/var/run/wpa_supplicant"
    local ctrl_ok=false

    # Check if wpa_supplicant control socket exists
    if [[ -S "${ctrl_path}/${IFACE}" ]]; then
        # Check P2P capability
        if wpa_cli -i "$IFACE" p2p_find 2>/dev/null | grep -q "OK"; then
            ctrl_ok=true
            _log "[*] P2P find started..."
            sleep 10

            # Get found peers
            local peer_lines
            peer_lines=$(wpa_cli -i "$IFACE" p2p_peers 2>/dev/null || true)

            local peers_json="["
            local first=true
            if [[ -n "$peer_lines" ]]; then
                for peer in $peer_lines; do
                    [[ "$peer" == "Selected"* || "$peer" == "OK" ]] && continue
                    # Get peer info
                    local peer_info
                    peer_info=$(wpa_cli -i "$IFACE" p2p_peer "$peer" 2>/dev/null || true)
                    local peer_name=""
                    local peer_dev=""
                    if [[ -n "$peer_info" ]]; then
                        peer_name=$(echo "$peer_info" | grep -i "device_name=" | cut -d= -f2)
                        peer_dev=$(echo "$peer_info" | grep -i "device_address=" | cut -d= -f2)
                    fi

                    if [[ "$first" == true ]]; then
                        first=false
                    else
                        peers_json="${peers_json},"
                    fi
                    peers_json="${peers_json}{\"mac\":\"${peer}\",\"name\":\"${peer_name:-Unknown}\",\"device_address\":\"${peer_dev:-}\"}"
                done
            fi
            peers_json="${peers_json}]"

            # Stop discovery
            wpa_cli -i "$IFACE" p2p_stop_find 2>/dev/null || true

            _json "{\"status\":\"success\",\"action\":\"discover\",\"peers_found\":${peers_json},\"peer_count\":$(echo "$peers_json" | python3 -c "import sys,json; print(len([p for p in json.load(sys.stdin) if p.get('mac')]))" 2>/dev/null || echo 0)}"
            return 0
        fi
    fi

    # Fallback: try to start wpa_supplicant with P2P
    _log "[*] Falling back to manual wpa_supplicant..."

    if ! pgrep -x wpa_supplicant > /dev/null; then
        wpa_supplicant -B -i "$IFACE" -c /dev/null -D nl80211 2>/dev/null || true
        sleep 2
    fi

    if wpa_cli -i "$IFACE" p2p_find 2>/dev/null | grep -q "OK"; then
        _log "[*] P2P find started..."
        sleep 10

        local peer_lines
        peer_lines=$(wpa_cli -i "$IFACE" p2p_peers 2>/dev/null || true)

        local peers_json="["
        local first=true
        if [[ -n "$peer_lines" ]]; then
            for peer in $peer_lines; do
                [[ "$peer" == "Selected"* || "$peer" == "OK" ]] && continue
                local peer_info
                peer_info=$(wpa_cli -i "$IFACE" p2p_peer "$peer" 2>/dev/null || true)
                local peer_name=""
                if [[ -n "$peer_info" ]]; then
                    peer_name=$(echo "$peer_info" | grep -i "device_name=" | cut -d= -f2)
                fi

                if [[ "$first" == true ]]; then
                    first=false
                else
                    peers_json="${peers_json},"
                fi
                peers_json="${peers_json}{\"mac\":\"${peer}\",\"name\":\"${peer_name:-Unknown}\"}"
            done
        fi
        peers_json="${peers_json}]"

        wpa_cli -i "$IFACE" p2p_stop_find 2>/dev/null || true

        _json "{\"status\":\"success\",\"action\":\"discover\",\"peers_found\":${peers_json},\"peer_count\":$(echo "$peers_json" | python3 -c "import sys,json; print(len([p for p in json.load(sys.stdin) if p.get('mac')]))" 2>/dev/null || echo 0)}"
        return 0
    fi

    _die "P2P not available on this interface or wpa_supplicant not running"
}

# ── Connect to a peer ────────────────────────────────────────────────
connect_peer() {
    local peer_mac="$EXTRA_ARG"
    if [[ -z "$peer_mac" ]]; then
        _die "Usage: wifi_direct.sh <interface> connect <peer_mac>"
    fi

    _log "[*] Connecting to P2P peer $peer_mac..."

    local result
    result=$(wpa_cli -i "$IFACE" p2p_connect "$peer_mac" pbc 2>/dev/null || true)

    if echo "$result" | grep -q "OK"; then
        _json "{\"status\":\"success\",\"action\":\"connect\",\"peer_mac\":\"${peer_mac}\",\"method\":\"pbc\"}"
        return 0
    fi

    # Try PIN method
    result=$(wpa_cli -i "$IFACE" p2p_connect "$peer_mac" pin 12345670 2>/dev/null || true)
    if echo "$result" | grep -q "PIN"; then
        local pin
        pin=$(echo "$result" | grep -oP '\d{8}')
        _json "{\"status\":\"success\",\"action\":\"connect\",\"peer_mac\":\"${peer_mac}\",\"method\":\"pin\",\"pin\":\"${pin}\"}"
        return 0
    fi

    _die "Failed to connect to peer $peer_mac"
}

# ── Monitor P2P events ───────────────────────────────────────────────
monitor_p2p() {
    _log "[*] Monitoring P2P events on $IFACE..."

    # Start wpa_cli in listen mode
    wpa_cli -i "$IFACE" p2p_listen 2>/dev/null || true

    # Run interactive monitor
    (
        wpa_cli -i "$IFACE" -a /dev/null 2>/dev/null &
    ) &
    WPA_CLI_PID=$!

    _log "[*] P2P monitoring started. Listening for events..."

    sleep 3

    _json "{\"status\":\"success\",\"action\":\"monitor\",\"interface\":\"${IFACE}\",\"monitoring\":true}"
    return 0
}

# ── Main ──────────────────────────────────────────────────────────────
_log "[*] WiFi Direct action: $ACTION on $IFACE"

case "$ACTION" in
    discover) discover_peers ;;
    connect)  connect_peer ;;
    monitor)  monitor_p2p ;;
esac
