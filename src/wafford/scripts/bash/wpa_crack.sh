#!/usr/bin/env bash
# WPA/WPA2 offline password cracking
# Usage: wpa_crack.sh <capture_file> <wordlist> <engine> <mode> [rules] [mask]

set -euo pipefail

_log()   { echo "$*" >&2; }
_json()  { printf '%s\n' "$*"; }
_die()   { _json "{\"status\":\"error\",\"message\":\"$1\"}"; exit 1; }

cleanup() {
    _log "[*] Cleaning up cracking session..."
    if [[ -n "${CRACK_PID:-}" ]]; then
        kill "$CRACK_PID" 2>/dev/null || true
        wait "$CRACK_PID" 2>/dev/null || true
    fi
    # Remove potfile backup
    rm -f "${TMPDIR_WORK:-}/potfile_backup" 2>/dev/null || true
    exit "${EXIT_RC:-0}"
}
trap cleanup EXIT

# ── Root check ────────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
    _die "Root privileges required"
fi

# ── Args ──────────────────────────────────────────────────────────────
CAPTURE_FILE="${1:-}"
WORDLIST="${2:-/usr/share/wordlists/rockyou.txt}"
ENGINE="${3:-hashcat}"
MODE="${4:-dictionary}"
RULES="${5:-}"
MASK="${6:-}"

if [[ -z "$CAPTURE_FILE" ]]; then
    _die "Usage: wpa_crack.sh <capture_file> <wordlist> <engine> <mode> [rules] [mask]"
fi

if [[ ! -f "$CAPTURE_FILE" ]]; then
    _die "Capture file not found: $CAPTURE_FILE"
fi

# ── Validate engine ───────────────────────────────────────────────────
case "$ENGINE" in
    hashcat|aircrack)
        ;;
    *)
        _die "Invalid engine '$ENGINE'. Use 'hashcat' or 'aircrack'"
        ;;
esac

# ── Validate wordlist ─────────────────────────────────────────────────
if [[ "$MODE" == "dictionary" && "$ENGINE" == "hashcat" ]]; then
    if [[ ! -f "$WORDLIST" ]]; then
        _die "Wordlist not found: $WORDLIST"
    fi
fi

# ── Setup ─────────────────────────────────────────────────────────────
TMPDIR_WORK=$(mktemp -d /tmp/wafford_crack.XXXXXX)
START_TIME=$(date +%s)

_log "[*] WPA cracking: engine=$ENGINE mode=$MODE"
_log "[*] Capture: $CAPTURE_FILE"
_log "[*] Wordlist: $WORDLIST"

# ── Determine hashcat mode number ─────────────────────────────────────
get_hashcat_mode() {
    local file="$1"
    # Check for hc22000 format (modern hashcat)
    if [[ "$file" == *.hc22000 ]]; then
        echo "22000"
        return
    fi
    # Check for hccapx format
    if [[ "$file" == *.hccapx ]]; then
        echo "22000"
        return
    fi
    # Check for .cap file — use aircrack
    if [[ "$file" == *.cap ]]; then
        echo "cap"
        return
    fi
    # Try to detect hash mode from first line
    if [[ -f "$file" ]]; then
        local first_line
        first_line=$(head -1 "$file")
        if echo "$first_line" | grep -q "WPA*01"; then
            echo "22000"
            return
        fi
    fi
    echo "22000"
}

# ── Convert capture if needed ────────────────────────────────────────
PREPARED_FILE="$CAPTURE_FILE"

if [[ "$ENGINE" == "hashcat" ]]; then
    FILE_EXT="${CAPTURE_FILE##*.}"

    if [[ "$FILE_EXT" == "cap" || "$FILE_EXT" == "pcap" || "$FILE_EXT" == "pcapng" ]]; then
        _log "[*] Converting capture file to hashcat format..."
        HC22000="${TMPDIR_WORK}/converted.hc22000"

        if command -v hcxpcapngtool &>/dev/null; then
            hcxpcapngtool -o "$HC22000" "$CAPTURE_FILE" 2>/dev/null || true
            if [[ -s "$HC22000" ]]; then
                PREPARED_FILE="$HC22000"
                _log "[+] Converted to hc22000 format"
            else
                _die "Failed to convert capture file. Ensure it contains a valid WPA handshake."
            fi
        elif command -v airpcap &>/dev/null; then
            # Fallback: convert to hccapx via aircrack-ng
            HCCAPX="${TMPDIR_WORK}/converted.hccapx"
            aircrack-ng -j "$HCCAPX" "$CAPTURE_FILE" 2>/dev/null || true
            if [[ -s "$HCCAPX" ]]; then
                PREPARED_FILE="$HCCAPX"
            else
                _die "Failed to convert capture file"
            fi
        else
            _die "No conversion tool found (hcxpcapngtool or aircrack-ng)"
        fi
    fi
fi

# ── Run cracking ──────────────────────────────────────────────────────
PASSWORD_FOUND="false"
PASSWORD=""
SPEED="0"
ATTEMPTS="0"

run_hashcat() {
    local hc_mode
    hc_mode=$(get_hashcat_mode "$PREPARED_FILE")

    local hashcat_args=""
    local potfile="${TMPDIR_WORK}/hashcat.potfile"
    local status_file="${TMPDIR_WORK}/hashcat.status"

    case "$MODE" in
        dictionary)
            hashcat_args="-m $hc_mode -a 0"
            if [[ -n "$RULES" ]]; then
                hashcat_args="$hashcat_args -r $RULES"
            fi
            hashcat_args="$hashcat_args --potfile-path $potfile --status --status-timer 5"
            hashcat_args="$hashcat_args $PREPARED_FILE $WORDLIST"
            ;;
        mask)
            if [[ -z "$MASK" ]]; then
                _die "Mask mode requires a mask argument"
            fi
            hashcat_args="-m $hc_mode -a 3"
            hashcat_args="$hashcat_args --potfile-path $potfile --status --status-timer 5"
            hashcat_args="$hashcat_args $PREPARED_FILE $MASK"
            ;;
        brute)
            hashcat_args="-m $hc_mode -a 3"
            hashcat_args="$hashcat_args --potfile-path $potfile --status --status-timer 5"
            hashcat_args="$hashcat_args $PREPARED_FILE ?a?a?a?a?a?a?a?a"
            ;;
        *)
            _die "Invalid mode '$MODE' for hashcat"
            ;;
    esac

    _log "[*] Running: hashcat $hashcat_args"

    # Run hashcat in background
    hashcat $hashcat_args 2>&1 &
    CRACK_PID=$!

    # Monitor progress
    while kill -0 "$CRACK_PID" 2>/dev/null; do
        sleep 5

        # Check potfile for found password
        if [[ -f "$potfile" ]]; then
            local pot_line
            pot_line=$(tail -1 "$potfile" 2>/dev/null)
            if [[ -n "$pot_line" ]]; then
                PASSWORD=$(echo "$pot_line" | cut -d: -f2-)
                if [[ -n "$PASSWORD" ]]; then
                    PASSWORD_FOUND="true"
                    _log "[+] Password found: $PASSWORD"
                    kill "$CRACK_PID" 2>/dev/null || true
                    break
                fi
            fi
        fi

        # Get status from hashcat
        if [[ -f "$status_file" ]]; then
            SPEED=$(grep -oP 'Speed|#' "$status_file" 2>/dev/null | head -1 || echo "0")
        fi

        local elapsed=$(( $(date +%s) - START_TIME ))
        _log "[*] Cracking... elapsed: ${elapsed}s"
    done

    wait "$CRACK_PID" 2>/dev/null || true
    CRACK_PID=""

    # Final check
    if [[ -f "$potfile" ]]; then
        local pot_line
        pot_line=$(head -1 "$potfile" 2>/dev/null)
        if [[ -n "$pot_line" ]]; then
            PASSWORD=$(echo "$pot_line" | cut -d: -f2-)
            if [[ -n "$PASSWORD" ]]; then
                PASSWORD_FOUND="true"
            fi
        fi
    fi
}

run_aircrack() {
    local aircrack_args="-w $WORDLIST -b"

    # Extract BSSID from capture file
    local bssid=""
    if command -v tshark &>/dev/null; then
        bssid=$(tshark -r "$CAPTURE_FILE" -Y "wlan.bssid" -T fields -e wlan.bssid 2>/dev/null | head -1 || true)
    fi

    if [[ -n "$bssid" ]]; then
        aircrack_args="$aircrack_args $bssid"
    fi

    aircrack_args="$aircrack_args $CAPTURE_FILE"

    _log "[*] Running: aircrack-ng $aircrack_args"

    aircrack-ng $aircrack_args 2>&1 | while IFS= read -r line; do
        _log "$line"

        # Parse speed
        if echo "$line" | grep -q "keys/s"; then
            SPEED=$(echo "$line" | grep -oP '[\d.]+ keys/s' || echo "0 keys/s")
        fi

        # Parse attempts
        if echo "$line" | grep -q "keys tested"; then
            ATTEMPTS=$(echo "$line" | grep -oP '[\d,]+(?= keys tested)' | tr -d ',' || echo "0")
        fi

        # Check for found key
        if echo "$line" | grep -q "KEY FOUND"; then
            PASSWORD=$(echo "$line" | grep -oP 'KEY FOUND!\s*\[\s*\K[^]\s]+' || true)
            if [[ -n "$PASSWORD" ]]; then
                PASSWORD_FOUND="true"
                _log "[+] Password found: $PASSWORD"
            fi
        fi
    done || true
}

# ── Execute ───────────────────────────────────────────────────────────
case "$ENGINE" in
    hashcat)
        if ! command -v hashcat &>/dev/null; then
            _die "hashcat not found"
        fi
        run_hashcat
        ;;
    aircrack)
        run_aircrack
        ;;
esac

# ── Calculate duration ────────────────────────────────────────────────
END_TIME=$(date +%s)
DURATION=$(( END_TIME - START_TIME ))

# ── Output ────────────────────────────────────────────────────────────
RESULT="{\"status\":\"success\",\"engine\":\"${ENGINE}\",\"mode\":\"${MODE}\",\"capture_file\":\"${CAPTURE_FILE}\",\"password_found\":${PASSWORD_FOUND},\"duration\":${DURATION}}"
if [[ -n "$PASSWORD" ]]; then
    RESULT=$(echo "$RESULT" | sed "s/}$/,\"password\":\"$(echo "$PASSWORD" | sed 's/"/\\"/g')\"}/")
fi
if [[ -n "$SPEED" ]]; then
    RESULT=$(echo "$RESULT" | sed "s/}$/,\"speed\":\"${SPEED}\"}/")
fi
if [[ "$ATTEMPTS" -gt 0 ]]; then
    RESULT=$(echo "$RESULT" | sed "s/}$/,\"attempts\":${ATTEMPTS}}/")
fi

_json "$RESULT"
