#!/usr/bin/env bash
# Bluetooth scanning
# Usage: bluetooth_scan.sh <scan_type> [duration]
# Types: ble, classic, both

set -euo pipefail

_log()   { echo "$*" >&2; }
_json()  { printf '%s\n' "$*"; }
_die()   { _json "{\"status\":\"error\",\"message\":\"$1\"}"; exit 1; }

cleanup() {
    if [[ -n "${LESCAN_PID:-}" ]]; then
        kill "$LESCAN_PID" 2>/dev/null || true
    fi
    if [[ -n "${HCITOOL_PID:-}" ]]; then
        kill "$HCITOOL_PID" 2>/dev/null || true
    fi
    # Restore interface if we powered it on
    if [[ -n "${POWERED_UP:-}" ]]; then
        hciconfig hci0 power off 2>/dev/null || true
    fi
    exit "${EXIT_RC:-0}"
}
trap cleanup EXIT

# ── Root check ────────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
    _die "Root privileges required"
fi

# ── Args ──────────────────────────────────────────────────────────────
SCAN_TYPE="${1:-both}"
DURATION="${2:-15}"

case "$SCAN_TYPE" in
    ble|classic|both)
        ;;
    *)
        _die "Invalid scan type '$SCAN_TYPE'. Valid: ble|classic|both"
        ;;
esac

# ── Determine HCI interface ──────────────────────────────────────────
HCI_IFACE="hci0"
if command -v hciconfig &>/dev/null; then
    HCI_LIST=$(hciconfig 2>/dev/null | grep -oP '^hci\d+' || echo "hci0")
    HCI_IFACE=$(echo "$HCI_LIST" | head -1)
fi

_log "[*] Bluetooth scan: type=$SCAN_TYPE duration=${DURATION}s iface=$HCI_IFACE"

# ── Ensure adapter is up ─────────────────────────────────────────────
if command -v hciconfig &>/dev/null; then
    if ! hciconfig "$HCI_IFACE" 2>/dev/null | grep -q "UP RUNNING"; then
        hciconfig "$HCI_IFACE" up 2>/dev/null || true
        POWERED_UP=true
    fi
fi

# ── BLE scan ──────────────────────────────────────────────────────────
scan_ble() {
    _log "[*] Starting BLE scan..."

    if ! command -v hcitool &>/dev/null; then
        if command -v bluetoothctl &>/dev/null; then
            # Fallback to bluetoothctl
            _log "[*] Using bluetoothctl..."
            bluetoothctl scan on &
            LESCAN_PID=$!
            sleep "$DURATION"
            bluetoothctl scan off 2>/dev/null || true
            local devices
            devices=$(bluetoothctl devices 2>/dev/null || true)
            echo "$devices"
        else
            _log "[!] hcitool and bluetoothctl not found, cannot scan BLE"
            echo ""
        fi
        return
    fi

    # Use hcitool lescan
    hcitool -i "$HCI_IFACE" lescan --passive 2>/dev/null &
    LESCAN_PID=$!
    sleep "$DURATION"
    kill "$LESCAN_PID" 2>/dev/null || true
    wait "$LESCAN_PID" 2>/dev/null || true
    LESCAN_PID=""
}

# ── Classic scan ─────────────────────────────────────────────────────
scan_classic() {
    _log "[*] Starting classic scan..."

    if ! command -v hcitool &>/dev/null; then
        if command -v bluetoothctl &>/dev/null; then
            bluetoothctl scan on &
            HCITOOL_PID=$!
            sleep "$DURATION"
            bluetoothctl scan off 2>/dev/null || true
            local devices
            devices=$(bluetoothctl devices 2>/dev/null || true)
            echo "$devices"
        else
            _log "[!] hcitool and bluetoothctl not found, cannot scan classic"
            echo ""
        fi
        return
    fi

    hcitool -i "$HCI_IFACE" scan 2>/dev/null &
    HCITOOL_PID=$!
    sleep "$DURATION"
    kill "$HCITOOL_PID" 2>/dev/null || true
    wait "$HCITOOL_PID" 2>/dev/null || true
    HCITOOL_PID=""
}

# ── Parse results ────────────────────────────────────────────────────
parse_results() {
    local scan_type="$1"
    local results="["
    local first=true

    # Method 1: hcitool lescan output parsing
    local lescan_out=""
    if [[ "$scan_type" == "ble" || "$scan_type" == "both" ]]; then
        lescan_out=$(hcitool -i "$HCI_IFACE" lerand 2>/dev/null || \
                     hcitool -i "$HCI_IFACE" ledev 2>/dev/null || true)
        if [[ -z "$lescan_out" ]]; then
            # Try previous scan results from cache
            lescan_out=$(journalctl --no-pager -n 200 ua 2>/dev/null | grep "LE Scan" || true)
        fi
    fi

    # Method 2: bluetoothctl devices
    local btctl_devices=""
    if command -v bluetoothctl &>/dev/null; then
        btctl_devices=$(bluetoothctl devices 2>/dev/null || true)
    fi

    # Build device list from bluetoothctl
    if [[ -n "$btctl_devices" ]]; then
        while IFS= read -r line; do
            # Format: Device AA:BB:CC:DD:EE:FF Device Name
            local mac name
            mac=$(echo "$line" | awk '{print $2}')
            name=$(echo "$line" | sed 's/^Device [0-9A-F:]* //')
            [[ -z "$mac" ]] && continue

            # Get RSSI if available
            local rssi="-60"
            if command -v bluetoothctl &>/dev/null; then
                rssi=$(bluetoothctl info "$mac" 2>/dev/null | grep -i "RSSI:" | awk '{print $2}' || echo "-60")
            fi

            if [[ "$first" == true ]]; then
                first=false
            else
                results="${results},"
            fi
            results="${results}{\"mac\":\"${mac}\",\"name\":\"${name}\",\"type\":\"${scan_type}\",\"rssi\":${rssi:-0}}"
        done <<< "$btctl_devices"
    fi

    # Add devices from lescan cache
    if [[ -n "$lescan_out" ]]; then
        while IFS= read -r line; do
            local mac name
            mac=$(echo "$line" | awk '{print $1}')
            name=$(echo "$line" | awk '{$1=""; print $0}' | sed 's/^ *//')
            [[ -z "$mac" ]] && continue
            # Skip duplicates from bluetoothctl
            if echo "$results" | grep -q "$mac"; then
                continue
            fi
            if [[ "$first" == true ]]; then
                first=false
            else
                results="${results},"
            fi
            results="${results}{\"mac\":\"${mac}\",\"name\":\"${name}\",\"type\":\"le\"}"
        done <<< "$lescan_out"
    fi

    results="${results}]"
    echo "$results"
}

# ── Service enumeration ──────────────────────────────────────────────
enumerate_services() {
    local device_mac="$1"
    _log "[*] Enumerating services for $device_mac..."

    if command -v sdptool &>/dev/null; then
        sdptool browse "$device_mac" 2>/dev/null || true
    fi
}

# ── Main ──────────────────────────────────────────────────────────────
json_results="["
first_result=true

if [[ "$SCAN_TYPE" == "ble" || "$SCAN_TYPE" == "both" ]]; then
    scan_ble
    DEVICES=$(parse_results "le")

    # Filter to BLE-only if both (remove duplicates already handled)
    if [[ "$SCAN_TYPE" == "both" ]]; then
        DEVICES=$(echo "$DEVICES" | python3 -c "
import sys, json
devs = json.load(sys.stdin)
ble = [d for d in devs if d.get('type') == 'le']
print(json.dumps(ble, indent=2))
" 2>/dev/null || echo "[]")
    fi

    if [[ "$SCAN_TYPE" == "ble" ]] || [[ "$SCAN_TYPE" == "both" ]]; then
        if [[ "$json_results" == "[" ]]; then
            json_results="$DEVICES"
        else
            json_results=$(echo "$json_results" | sed 's/]$/,/') 
            json_results="${json_results}$(echo "$DEVICES" | sed 's/^\[//')"
        fi
    fi
fi

if [[ "$SCAN_TYPE" == "classic" || "$SCAN_TYPE" == "both" ]]; then
    scan_classic
    DEVICES=$(parse_results "classic")

    if [[ "$SCAN_TYPE" == "classic" ]]; then
        json_results="$DEVICES"
    else
        # Merge classic devices into results
        json_results=$(echo "$json_results" | sed 's/]$/,/')
        CLASSIC_DEVICES=$(echo "$DEVICES" | sed 's/^\[//')
        json_results=$(echo "${json_results}${CLASSIC_DEVICES}")
    fi
fi

# Enumerate services for classic devices (if sdptool available)
if command -v sdptool &>/dev/null; then
    while IFS= read -r line; do
        local mac
        mac=$(echo "$line" | grep -oP '"[^"]*"' | head -1 | tr -d '"')
        if [[ -n "$mac" ]]; then
            enumerate_services "$mac" || true
        fi
    done < <(echo "$json_results" | tr '{' '\n' | grep mac) 2>/dev/null || true
fi

# Count devices
DEVICE_COUNT=$(echo "$json_results" | python3 -c "import sys,json; print(len(json.load(sys.stdin)))" 2>/dev/null || echo "0")

# Output
_json "{\"status\":\"success\",\"scan_type\":\"${SCAN_TYPE}\",\"interface\":\"${HCI_IFACE}\",\"devices\":${json_results},\"count\":${DEVICE_COUNT},\"duration\":${DURATION}}"
