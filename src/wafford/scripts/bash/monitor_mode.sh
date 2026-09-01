#!/usr/bin/env bash
# Enable/disable monitor mode on a wireless interface
# Usage: monitor_mode.sh <interface> [on|off]
# Handles: process killing, airmon-ng, mode verification, injection test

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── Logging & JSON helpers ────────────────────────────────────────────
_log()   { echo "$*" >&2; }
_json()  { printf '%s\n' "$*"; }
_die()   { _json "{\"status\":\"error\",\"message\":\"$1\"}"; exit 1; }

cleanup() {
    local rc=$?
    if [[ -n "${MONITOR_PID:-}" ]]; then
        kill "$MONITOR_PID" 2>/dev/null || true
    fi
    if [[ -n "${TMPDIR_WORK:-}" && -d "${TMPDIR_WORK:-}" ]]; then
        rm -rf "$TMPDIR_WORK"
    fi
    exit "$rc"
}
trap cleanup EXIT

# ── Root check ────────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
    _die "Root privileges required"
fi

# ── Argument parsing ──────────────────────────────────────────────────
IFACE="${1:-}"
ACTION="${2:-on}"

if [[ -z "$IFACE" ]]; then
    _die "Usage: monitor_mode.sh <interface> [on|off]"
fi

if [[ "$ACTION" != "on" && "$ACTION" != "off" ]]; then
    _die "Action must be 'on' or 'off', got: $ACTION"
fi

# ── Interface validation ──────────────────────────────────────────────
validate_interface() {
    local iface="$1"
    if [[ ! -d "/sys/class/net/$iface" ]]; then
        _die "Interface '$iface' does not exist"
    fi
    local iface_type
    iface_type=$(cat "/sys/class/net/$iface/type" 2>/dev/null || echo "unknown")
    if [[ "$iface_type" != "1" && "$iface_type" != "803" ]]; then
        _log "[warn] Interface type $iface_type may not be wireless"
    fi
}

validate_interface "$IFACE"

# ── Kill conflicting processes ────────────────────────────────────────
kill_conflicting() {
    _log "[*] Killing conflicting processes..."
    local procs=("NetworkManager" "wpa_supplicant" "dhclient" "dhcpcd" "plymouthd")
    for proc in "${procs[@]}"; do
        pkill -f "$proc" 2>/dev/null && _log "[*] Killed $proc" || true
    done
    sleep 1
}

# ── Find monitor interface ────────────────────────────────────────────
find_monitor_iface() {
    local iface="$1"
    # Check if already in monitor mode
    local mode
    mode=$(iw "$iface" info 2>/dev/null | awk '/type/{print $2}')
    if [[ "$mode" == "monitor" ]]; then
        echo "$iface"
        return
    fi
    # Check for mon suffix
    if [[ -d "/sys/class/net/${iface}mon" ]]; then
        echo "${iface}mon"
        return
    fi
    echo ""
}

# ── Verify monitor mode ──────────────────────────────────────────────
verify_monitor() {
    local iface="$1"
    local mode
    mode=$(iw "$iface" info 2>/dev/null | awk '/type/{print $2}')
    if [[ "$mode" == "monitor" ]]; then
        return 0
    fi
    return 1
}

# ── Injection test ────────────────────────────────────────────────────
test_injection() {
    local iface="$1"
    if command -v aireplay-ng &>/dev/null; then
        _log "[*] Testing injection capability on $iface..."
        if aireplay-ng --test "$iface" 2>&1 | grep -q "Injection is working"; then
            _log "[+] Injection test passed"
            return 0
        else
            _log "[!] Injection test failed or inconclusive"
            return 1
        fi
    fi
    _log "[!] aireplay-ng not found, skipping injection test"
    return 0
}

# ── Enable monitor mode ──────────────────────────────────────────────
enable_monitor() {
    kill_conflicting

    # Check for existing monitor interface
    local mon_iface
    mon_iface=$(find_monitor_iface "$IFACE")
    if [[ -n "$mon_iface" ]] && verify_monitor "$mon_iface"; then
        _log "[+] $mon_iface is already in monitor mode"
        _json "{\"status\":\"success\",\"action\":\"on\",\"interface\":\"$mon_iface\",\"method\":\"existing\",\"injection_test\":false}"
        return 0
    fi

    # Try airmon-ng first
    if command -v airmon-ng &>/dev/null; then
        _log "[*] Enabling monitor mode via airmon-ng..."
        local output
        output=$(airmon-ng check kill 2>&1) || true
        _log "$output"

        output=$(airmon-ng start "$IFACE" 2>&1) || true
        _log "$output"

        # Determine new interface name from output or fallback
        local new_iface="${IFACE}mon"
        if echo "$output" | grep -qE "monitor mode.*enabled|monitor mode vif"; then
            local extracted
            extracted=$(echo "$output" | grep -oP '(?:on|enabled on)\s+\K\S+' | head -1)
            if [[ -n "$extracted" ]]; then
                new_iface="$extracted"
            fi
        fi

        sleep 2

        # Check various possible interface names
        for candidate in "${IFACE}mon" "${IFACE}" "${IFACE}_mon"; do
            if [[ -d "/sys/class/net/$candidate" ]]; then
                if verify_monitor "$candidate"; then
                    new_iface="$candidate"
                    break
                fi
            fi
        done

        if verify_monitor "$new_iface"; then
            test_injection "$new_iface" || true
            _json "{\"status\":\"success\",\"action\":\"on\",\"interface\":\"$new_iface\",\"method\":\"airmon-ng\",\"injection_test\":$?}"
            return 0
        fi
    fi

    # Fallback: manual iw commands
    _log "[*] Enabling monitor mode via iw..."
    ip link set "$IFACE" down 2>/dev/null || true
    iw dev "$IFACE" set type monitor 2>/dev/null || true
    ip link set "$IFACE" up 2>/dev/null || true
    sleep 1

    if verify_monitor "$IFACE"; then
        test_injection "$IFACE" || true
        _json "{\"status\":\"success\",\"action\":\"on\",\"interface\":\"$IFACE\",\"method\":\"iw\",\"injection_test\":$?}"
        return 0
    fi

    _die "Failed to enable monitor mode on $IFACE"
}

# ── Disable monitor mode ─────────────────────────────────────────────
disable_monitor() {
    local mon_iface
    mon_iface=$(find_monitor_iface "$IFACE")

    if [[ -z "$mon_iface" ]]; then
        # Already managed
        _json "{\"status\":\"success\",\"action\":\"off\",\"interface\":\"$IFACE\",\"method\":\"none\"}"
        return 0
    fi

    # Try airmon-ng stop
    if command -v airmon-ng &>/dev/null; then
        _log "[*] Disabling monitor mode via airmon-ng..."
        airmon-ng stop "$mon_iface" 2>&1 || true
        sleep 2

        # Restart NetworkManager
        if command -v systemctl &>/dev/null; then
            systemctl start NetworkManager 2>/dev/null || true
        elif command -v service &>/dev/null; then
            service NetworkManager start 2>/dev/null || true
        fi

        _json "{\"status\":\"success\",\"action\":\"off\",\"interface\":\"$IFACE\",\"method\":\"airmon-ng\"}"
        return 0
    fi

    # Manual fallback
    _log "[*] Disabling monitor mode via iw..."
    ip link set "$mon_iface" down 2>/dev/null || true
    iw dev "$mon_iface" set type managed 2>/dev/null || \
        iw dev "$IFACE" set type managed 2>/dev/null || true
    ip link set "$IFACE" up 2>/dev/null || true
    sleep 1

    _json "{\"status\":\"success\",\"action\":\"off\",\"interface\":\"$IFACE\",\"method\":\"iw\"}"
    return 0
}

# ── Main ──────────────────────────────────────────────────────────────
_log "[*] Monitor mode action: $ACTION on $IFACE"

if [[ "$ACTION" == "on" ]]; then
    enable_monitor
else
    disable_monitor
fi
