#!/usr/bin/env bash
# Aircrack-ng utility functions
# Usage: source aircrack_utils.sh
# Provides: check_injection, get_monitor_interfaces, verify_handshake, convert_cap

set -euo pipefail

_log()   { echo "$*" >&2; }
_json()  { printf '%s\n' "$*"; }

# ── Injection test ───────────────────────────────────────────────────
# Usage: check_injection <interface>
# Returns 0 if injection works, 1 otherwise
check_injection() {
    local iface="${1:-}"

    if [[ -z "$iface" ]]; then
        _json "{\"status\":\"error\",\"message\":\"Usage: check_injection <interface>\"}"
        return 1
    fi

    if ! command -v aireplay-ng &>/dev/null; then
        _json "{\"status\":\"error\",\"message\":\"aireplay-ng not found\"}"
        return 1
    fi

    if [[ ! -d "/sys/class/net/$iface" ]]; then
        _json "{\"status\":\"error\",\"message\":\"Interface $iface not found\"}"
        return 1
    fi

    local mode
    mode=$(iw "$iface" info 2>/dev/null | awk '/type/{print $2}' || echo "unknown")
    if [[ "$mode" != "monitor" ]]; then
        _json "{\"status\":\"error\",\"message\":\"Interface $iface is not in monitor mode\",\"mode\":\"$mode\"}"
        return 1
    fi

    _log "[*] Testing injection on $iface..."

    local output
    output=$(aireplay-ng --test "$iface" 2>&1 || true)

    if echo "$output" | grep -q "Injection is working"; then
        _json "{\"status\":\"success\",\"interface\":\"$iface\",\"injection_working\":true}"
        return 0
    else
        _json "{\"status\":\"success\",\"interface\":\"$iface\",\"injection_working\":false}"
        return 1
    fi
}

# ── Monitor interface detection ─────────────────────────────────────
# Usage: get_monitor_interfaces
# Prints JSON array of monitor-capable interfaces
get_monitor_interfaces() {
    local results="["
    local first=true

    for iface in /sys/class/net/*/; do
        local name
        name=$(basename "$iface")
        [[ "$name" == "lo" ]] && continue

        local mode
        mode=$(iw "$name" info 2>/dev/null | awk '/type/{print $2}' || echo "")

        if [[ "$mode" == "monitor" ]]; then
            if [[ "$first" == true ]]; then
                first=false
            else
                results="${results},"
            fi
            results="${results}{\"interface\":\"${name}\",\"mode\":\"${mode}\"}"
        fi
    done

    # Also list all wireless interfaces
    if command -v iw &>/dev/null; then
        while IFS= read -r iface; do
            [[ -z "$iface" ]] && continue
            if ! echo "$results" | grep -q "\"${iface}\""; then
                local mode2
                mode2=$(iw "$iface" info 2>/dev/null | awk '/type/{print $2}' || echo "unknown")
                if [[ "$first" == true ]]; then
                    first=false
                else
                    results="${results},"
                fi
                results="${results}{\"interface\":\"${iface}\",\"mode\":\"${mode2}\"}"
            fi
        done < <(iw dev 2>/dev/null | grep Interface | awk '{print $2}')
    fi

    results="${results}]"
    echo "$results"
}

# ── Handshake validation ─────────────────────────────────────────────
# Usage: verify_handshake <capture_file> [bssid]
# Returns 0 if a valid handshake exists
verify_handshake() {
    local capture_file="${1:-}"
    local bssid="${2:-}"

    if [[ -z "$capture_file" ]]; then
        _json "{\"status\":\"error\",\"message\":\"Usage: verify_handshake <capture_file> [bssid]\"}"
        return 1
    fi

    if [[ ! -f "$capture_file" ]]; then
        _json "{\"status\":\"error\",\"message\":\"Capture file not found: $capture_file\"}"
        return 1
    fi

    # Use tshark for precise EAPOL counting
    if command -v tshark &>/dev/null; then
        local eapol_count
        if [[ -n "$bssid" ]]; then
            eapol_count=$(tshark -r "$capture_file" \
                -Y "eapol && (wlan.da == $bssid || wlan.sa == $bssid)" 2>/dev/null | wc -l || echo "0")
        else
            eapol_count=$(tshark -r "$capture_file" -Y "eapol" 2>/dev/null | wc -l || echo "0")
        fi

        if [[ "$eapol_count" -ge 4 ]]; then
            _json "{\"status\":\"success\",\"handshake_valid\":true,\"eapol_packets\":${eapol_count},\"capture_file\":\"${capture_file}\"}"
            return 0
        else
            _json "{\"status\":\"success\",\"handshake_valid\":false,\"eapol_packets\":${eapol_count},\"capture_file\":\"${capture_file}\"}"
            return 1
        fi
    fi

    # Fallback: use aircrack-ng
    if command -v aircrack-ng &>/dev/null; then
        local output
        output=$(aircrack-ng "$capture_file" 2>&1 || true)

        if echo "$output" | grep -q "1 handshake"; then
            _json "{\"status\":\"success\",\"handshake_valid\":true,\"capture_file\":\"${capture_file}\"}"
            return 0
        else
            _json "{\"status\":\"success\",\"handshake_valid\":false,\"capture_file\":\"${capture_file}\"}"
            return 1
        fi
    fi

    _json "{\"status\":\"error\",\"message\":\"No validation tool available (tshark or aircrack-ng)\"}"
    return 1
}

# ── Capture conversion ───────────────────────────────────────────────
# Usage: convert_cap <input_file> <output_dir> [output_format]
# Formats: hc22000, hccapx, pcapng, all
convert_cap() {
    local input_file="${1:-}"
    local output_dir="${2:-/tmp}"
    local format="${3:-hc22000}"

    if [[ -z "$input_file" || ! -f "$input_file" ]]; then
        _json "{\"status\":\"error\",\"message\":\"Input file not found: ${input_file}\"}"
        return 1
    fi

    mkdir -p "$output_dir"
    local base
    base=$(basename "$input_file")
    base="${base%.*}"

    case "$format" in
        hc22000|hashcat)
            if command -v hcxpcapngtool &>/dev/null; then
                local out
                out="${output_dir}/${base}.hc22000"
                hcxpcapngtool -o "$out" "$input_file" 2>/dev/null || true
                if [[ -s "$out" ]]; then
                    _json "{\"status\":\"success\",\"format\":\"hc22000\",\"output_file\":\"${out}\"}"
                    return 0
                else
                    _json "{\"status\":\"error\",\"message\":\"No PMKID/handshake found in capture\",\"output_file\":\"${out}\"}"
                    return 1
                fi
            fi
            ;;
        hccapx)
            if command -v aircrack-ng &>/dev/null; then
                local out
                out="${output_dir}/${base}.hccapx"
                aircrack-ng -j "$out" "$input_file" 2>/dev/null || true
                if [[ -f "$out" ]]; then
                    _json "{\"status\":\"success\",\"format\":\"hccapx\",\"output_file\":\"${out}\"}"
                    return 0
                fi
            fi
            ;;
        pcapng)
            if command -v tcpdump &>/dev/null; then
                local out
                out="${output_dir}/${base}.pcapng"
                tcpdump -r "$input_file" -n -w "$out" 2>/dev/null || true
                if [[ -s "$out" ]]; then
                    _json "{\"status\":\"success\",\"format\":\"pcapng\",\"output_file\":\"${out}\"}"
                    return 0
                fi
            fi
            ;;
        all)
            convert_cap "$input_file" "$output_dir" "hc22000" || true
            convert_cap "$input_file" "$output_dir" "hccapx" || true
            _json "{\"status\":\"success\",\"format\":\"all\",\"output_dir\":\"${output_dir}\"}"
            return 0
            ;;
        *)
            _json "{\"status\":\"error\",\"message\":\"Unsupported format: $format\"}"
            return 1
            ;;
    esac

    _json "{\"status\":\"error\",\"message\":\"No conversion tool available for format: $format\"}"
    return 1
}

# ── WEP-related helpers ─────────────────────────────────────────────
# Usage: parse_band <interface>
# Returns "2.4" or "5"
get_band() {
    local iface="${1:-}"
    if [[ -z "$iface" ]]; then
        echo "2.4"
        return
    fi
    local freq
    freq=$(iw "$iface" info 2>/dev/null | grep -oP 'channel \K\d+' | head -1)
    if [[ -n "$freq" && "$freq" -ge 36 ]]; then
        echo "5"
    else
        echo "2.4"
    fi
}

# ── MAC address helpers ─────────────────────────────────────────────
random_mac() {
    # Generate a locally administered random MAC
    printf '02:%02x:%02x:%02x:%02x:%02x' \
        $((RANDOM % 256)) $((RANDOM % 256)) $((RANDOM % 256)) \
        $((RANDOM % 256)) $((RANDOM % 256))
}

# Export all functions for sourcing
export -f check_injection get_monitor_interfaces verify_handshake convert_cap get_band random_mac 2>/dev/null || true
