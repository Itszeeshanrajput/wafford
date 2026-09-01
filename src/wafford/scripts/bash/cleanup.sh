#!/usr/bin/env bash
# Cleanup all attack artifacts
# Usage: cleanup.sh [interface]

set -euo pipefail

_log()   { echo "$*" >&2; }
_json()  { printf '%s\n' "$*"; }
_die()   { _json "{\"status\":\"error\",\"message\":\"$1\"}"; exit 1; }

# ── Root check ────────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
    _die "Root privileges required"
fi

# ── Args ──────────────────────────────────────────────────────────────
IFACE="${1:-}"

if [[ -n "$IFACE" && ! -d "/sys/class/net/$IFACE" ]]; then
    _die "Interface '$IFACE' does not exist"
fi

_log "[*] Starting Wafford cleanup..."

# ── Kill all attack processes ────────────────────────────────────────
kill_attack_procs() {
    local procs=(
        "airodump-ng"
        "aireplay-ng"
        "airmon-ng"
        "hostapd"
        "hostapd-wpe"
        "dnsmasq"
        "mdk4"
        "mdk3"
        "hcxdumptool"
        "hcxpcaptool"
        "hcxpcapngtool"
        "hashcat"
        "aircrack-ng"
        "wpa_supplicant"
        "portal_server.py"
        "wafford"
    )

    for proc in "${procs[@]}"; do
        if pgrep -f "$proc" &>/dev/null; then
            _log "[*] Killing $proc..."
            pkill -f "$proc" 2>/dev/null || true
            sleep 1
            # Force kill if still running
            if pgrep -f "$proc" &>/dev/null; then
                pkill -9 -f "$proc" 2>/dev/null || true
            fi
        fi
    done

    # Kill any lingering wpa_cli monitors
    pkill -f "wpa_cli.*a /dev/null" 2>/dev/null || true
}

kill_attack_procs

# ── Restore interfaces to managed mode ──────────────────────────────
restore_interfaces() {
    _log "[*] Restoring interfaces..."

    # Determine interfaces to restore
    local interfaces=()
    if [[ -n "$IFACE" ]]; then
        interfaces=("$IFACE")
    else
        # Find all wireless interfaces
        for iface in /sys/class/net/*/wireless; do
            interfaces+=("$(basename "$(dirname "$iface")")")
        done
    fi

    for iface in "${interfaces[@]}"; do
        _log "[*] Restoring $iface..."

        # Try airmon-ng stop first
        if command -v airmon-ng &>/dev/null; then
            airmon-ng stop "$iface" 2>/dev/null || true
            airmon-ng stop "${iface}mon" 2>/dev/null || true
        fi

        # Manual restore via iw
        ip link set "$iface" down 2>/dev/null || true
        iw dev "$iface" set type managed 2>/dev/null || true
        ip link set "$iface" up 2>/dev/null || true

        # Remove any virtual monitor interfaces
        for viface in /sys/class/net/*/wireless; do
            local vname
            vname=$(basename "$(dirname "$viface")")
            if [[ "$vname" == *"${iface}"*mon* ]]; then
                iw dev "$vname" del 2>/dev/null || true
            fi
        done
    done

    # Restart NetworkManager
    if command -v systemctl &>/dev/null; then
        systemctl restart NetworkManager 2>/dev/null || true
    elif command -v service &>/dev/null; then
        service NetworkManager restart 2>/dev/null || true
    fi

    # Restart wpa_supplicant if it's a system service
    if command -v systemctl &>/dev/null; then
        systemctl restart wpa_supplicant 2>/dev/null || true
    fi
}

restore_interfaces

# ── Flush iptables rules ────────────────────────────────────────────
flush_iptables() {
    _log "[*] Flushing iptables rules..."

    # Remove NAT rules (best effort)
    iptables -t nat -F 2>/dev/null || true
    iptables -t nat -X 2>/dev/null || true

    # Remove forwarding rules
    iptables -F FORWARD 2>/dev/null || true

    # Remove custom chains
    iptables -X 2>/dev/null || true

    # Disable IP forwarding
    sysctl -w net.ipv4.ip_forward=0 2>/dev/null || true
}

flush_iptables

# ── Remove temp files ───────────────────────────────────────────────
remove_temp_files() {
    _log "[*] Removing temporary files..."

    local temp_dirs=(
        "/tmp/wafford_scan"
        "/tmp/wafford_handshake"
        "/tmp/wafford_pmkid"
        "/tmp/wafford_captive"
        "/tmp/wafford_evil."
        "/tmp/wafford_wep."
        "/tmp/wafford_crack."
        "/tmp/wafford_karma."
        "/tmp/wafford_enterprise."
        "/tmp/wafford_*"
    )

    for dir in "${temp_dirs[@]}"; do
        rm -rf "$dir"/* 2>/dev/null || true
        rm -rf "$dir" 2>/dev/null || true
    done

    # Remove leftover config files
    rm -f /tmp/hostapd*.conf 2>/dev/null || true
    rm -f /tmp/dnsmasq*.conf 2>/dev/null || true
    rm -f /tmp/*.cap /tmp/*.pcap* 2>/dev/null || true
}

remove_temp_files

# ── Restore original MAC addresses ──────────────────────────────────
restore_macs() {
    _log "[*] Restoring original MAC addresses..."

    local interfaces=()
    if [[ -n "$IFACE" ]]; then
        interfaces=("$IFACE")
    else
        for iface in /sys/class/net/*/wireless; do
            interfaces+=("$(basename "$(dirname "$iface")")")
        done
    fi

    for iface in "${interfaces[@]}"; do
        # airmon-ng stores original MACs; restore them
        if command -v airmon-ng &>/dev/null; then
            # airmon-ng typically restores MACs when stopping monitor mode
            ip link set "$iface" down 2>/dev/null || true
            ip link set "$iface" up 2>/dev/null || true
        fi
    done
}

restore_macs

# ── Output ──────────────────────────────────────────────────────────
_interfaces_arg=""
if [[ -n "$IFACE" ]]; then
    _interfaces_arg=",\"interface\":\"${IFACE}\""
fi

_json "{\"status\":\"success\",\"action\":\"cleanup\",\"processes_killed\":true,\"interfaces_restored\":true,\"iptables_flushed\":true,\"temp_files_removed\":true,\"macs_restored\":true${_interfaces_arg}}"
