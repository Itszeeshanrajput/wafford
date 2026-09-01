#!/usr/bin/env bash
# Network scanning using airodump-ng
# Usage: scan.sh <interface> <channels> <duration> <output_dir>
# Outputs JSON array of discovered networks

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

_log()   { echo "$*" >&2; }
_json()  { printf '%s\n' "$*"; }
_die()   { _json "{\"status\":\"error\",\"message\":\"$1\"}"; exit 1; }

cleanup() {
    _log "[*] Cleaning up scan..."
    if [[ -n "${AIRODUMP_PID:-}" ]]; then
        kill "$AIRODUMP_PID" 2>/dev/null || true
        wait "$AIRODUMP_PID" 2>/dev/null || true
    fi
    if [[ -n "${CHANNEL_HOP_PID:-}" ]]; then
        kill "$CHANNEL_HOP_PID" 2>/dev/null || true
    fi
    # Restore interface
    if [[ -n "${ORIG_CHANNEL:-}" && -n "${IFACE:-}" ]]; then
        iw "$IFACE" set channel "$ORIG_CHANNEL" 2>/dev/null || true
    fi
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

# ── Args ──────────────────────────────────────────────────────────────
IFACE="${1:-}"
CHANNELS="${2:-1-14}"
DURATION="${3:-30}"
OUTPUT_DIR="${4:-/tmp/wafford_scan}"

if [[ -z "$IFACE" ]]; then
    _die "Usage: scan.sh <interface> <channels> <duration> <output_dir>"
fi

if ! [[ "$DURATION" =~ ^[0-9]+$ ]]; then
    _die "Duration must be a positive integer"
fi

mkdir -p "$OUTPUT_DIR"

# ── Validate interface ────────────────────────────────────────────────
if [[ ! -d "/sys/class/net/$IFACE" ]]; then
    _die "Interface '$IFACE' does not exist"
fi

MODE=$(iw "$IFACE" info 2>/dev/null | awk '/type/{print $2}' || echo "unknown")
if [[ "$MODE" != "monitor" ]]; then
    _die "Interface $IFACE is not in monitor mode (current: $MODE)"
fi

# ── Save original channel ────────────────────────────────────────────
ORIG_CHANNEL=$(iw "$IFACE" info 2>/dev/null | awk '/channel/{print $2}' || echo "1")

# ── Build channel list ───────────────────────────────────────────────
build_channel_list() {
    local ch_spec="$1"
    local channels=()

    if [[ "$ch_spec" == *-* ]]; then
        local start end
        start=$(echo "$ch_spec" | cut -d'-' -f1)
        end=$(echo "$ch_spec" | cut -d'-' -f2)
        for ((ch=start; ch<=end; ch++)); do
            channels+=("$ch")
        done
    elif [[ "$ch_spec" == *,* ]]; then
        IFS=',' read -ra channels <<< "$ch_spec"
    else
        channels=("$ch_spec")
    fi

    echo "${channels[@]}"
}

CHANNEL_LIST=($(build_channel_list "$CHANNELS"))
NUM_CHANNELS=${#CHANNEL_LIST[@]}

_log "[*] Scanning $NUM_CHANNELS channels for $DURATION seconds on $IFACE"

# ── Channel hopping script ──────────────────────────────────────────
start_channel_hopping() {
    local channels=("$@")
    local num=${#channels[@]}

    (
        local idx=0
        while true; do
            iw "$IFACE" set channel "${channels[$idx]}" 2>/dev/null || true
            idx=$(( (idx + 1) % num ))
            sleep 0.25
        done
    ) &
    CHANNEL_HOP_PID=$!
}

# ── Parse airodump CSV ──────────────────────────────────────────────
parse_csv() {
    local csv_file="$1"
    local results=()

    if [[ ! -s "$csv_file" ]]; then
        echo "[]"
        return
    fi

    # Find the AP section (between first blank line after header and second blank line)
    local in_ap_section=false
    local in_station_section=false
    local ap_header_found=false
    local station_header_found=false
    local ap_lines=()
    local station_lines=()
    local current_section=""

    while IFS= read -r line || [[ -n "$line" ]]; do
        # Trim
        line=$(echo "$line" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')

        # Blank lines separate sections
        if [[ -z "$line" ]]; then
            if [[ "$ap_header_found" == true && "$in_ap_section" == true ]]; then
                in_ap_section=false
                in_station_section=true
                current_section="station"
            fi
            continue
        fi

        # Detect AP section header
        if echo "$line" | grep -q "BSSID.*ESSID\|BSSID.*First.*Last"; then
            in_ap_section=true
            ap_header_found=true
            current_section="ap"
            continue
        fi

        # Detect Station section header
        if echo "$line" | grep -q "Station.*Probes\|STATION.*Probe"; then
            in_station_section=true
            station_header_found=true
            current_section="station"
            continue
        fi

        if [[ "$current_section" == "ap" ]]; then
            ap_lines+=("$line")
        elif [[ "$current_section" == "station" ]]; then
            station_lines+=("$line")
        fi
    done < "$csv_file"

    # Build JSON from parsed AP lines
    local json_array="["
    local first=true
    local ap_idx=0

    for ap_line in "${ap_lines[@]}"; do
        # CSV format: BSSID, First time seen, Last time seen, channel, Speed, Privacy, Cipher, Authentication, Power, # beacons, # IV, LAN IP, ID-length, ESSID, ...
        IFS=',' read -ra fields <<< "$ap_line"

        local bssid="${fields[0]:-}"
        local channel="${fields[3]:-}"
        local privacy="${fields[5]:-}"
        local cipher="${fields[6]:-}"
        local auth="${fields[7]:-}"
        local power="${fields[8]:-}"
        local beacons="${fields[9]:-}"
        local ivs="${fields[10]:-}"
        local essid="${fields[13]:-}"

        # Trim whitespace
        bssid=$(echo "$bssid" | tr -d ' ')
        channel=$(echo "$channel" | tr -d ' ')
        privacy=$(echo "$privacy" | tr -d ' ')
        cipher=$(echo "$cipher" | tr -d ' ')
        auth=$(echo "$auth" | tr -d ' ')
        power=$(echo "$power" | tr -d ' ')
        beacons=$(echo "$beacons" | tr -d ' ')
        ivs=$(echo "$ivs" | tr -d ' ')
        essid=$(echo "$essid" | sed 's/^ *//;s/ *$//')

        [[ -z "$bssid" || "$bssid" == "BSSID" ]] && continue

        # Detect WPS
        local wps="false"
        if echo "$privacy" | grep -qi "WPA"; then
            # WPS is often indicated in extended fields
            local full_line="$ap_line"
            if echo "$full_line" | grep -qi "wps\|WPS"; then
                wps="true"
            fi
        fi

        # Build encryption string
        local encryption="${privacy}"
        if [[ -n "$cipher" ]]; then
            encryption="${privacy}/${cipher}"
        fi

        # Collect clients for this AP
        local clients="[]"
        local client_list=""
        for station_line in "${station_lines[@]}"; do
            IFS=',' read -ra sfields <<< "$station_line"
            local st_mac="${sfields[0]:-}"
            local st_ap="${sfields[5]:-}"
            st_mac=$(echo "$st_mac" | tr -d ' ')
            st_ap=$(echo "$st_ap" | tr -d ' ')
            if [[ "$st_ap" == "$bssid" ]]; then
                if [[ -n "$client_list" ]]; then
                    client_list="${client_list},\"$(echo "$st_mac" | sed 's/"//g')\""
                else
                    client_list="\"$(echo "$st_mac" | sed 's/"//g')\""
                fi
            fi
        done
        if [[ -n "$client_list" ]]; then
            clients="[${client_list}]"
        fi

        if [[ "$first" == true ]]; then
            first=false
        else
            json_array="${json_array},"
        fi

        json_array="${json_array}{\"bssid\":\"${bssid}\",\"channel\":\"${channel}\",\"essid\":\"${essid}\",\"encryption\":\"${encryption}\",\"authentication\":\"${auth}\",\"power\":\"${power}\",\"beacons\":\"${beacons}\",\"ivs\":\"${ivs}\",\"wps\":${wps},\"clients\":${clients}}"
        ap_idx=$((ap_idx + 1))
    done

    json_array="${json_array}]"
    echo "$json_array"
}

# ── Main scan ─────────────────────────────────────────────────────────
CSV_PREFIX="${OUTPUT_DIR}/scan"

# Start channel hopping
if [[ "$NUM_CHANNELS" -gt 1 ]]; then
    start_channel_hopping "${CHANNEL_LIST[@]}"
fi

# Start airodump-ng
_log "[*] Starting airodump-ng..."
if [[ "$NUM_CHANNELS" -le 1 ]]; then
    airomon_args="-c ${CHANNEL_LIST[0]}"
else
    airomon_args="--channel $(IFS=,; echo "${CHANNEL_LIST[*]}")"
fi

airodump-ng \
    $airomon_args \
    --write "${CSV_PREFIX}" \
    --output-format csv \
    "$IFACE" \
    2>/dev/null &
AIRODUMP_PID=$!

# Wait for duration
_log "[*] Scanning for $DURATION seconds..."
sleep "$DURATION" || true

# Stop airodump
kill "$AIRODUMP_PID" 2>/dev/null || true
wait "$AIRODUMP_PID" 2>/dev/null || true
AIRODUMP_PID=""

# Stop channel hopping
if [[ -n "${CHANNEL_HOP_PID:-}" ]]; then
    kill "$CHANNEL_HOP_PID" 2>/dev/null || true
    CHANNEL_HOP_PID=""
fi

# Find the CSV file (airodump-ng appends .csv)
CSV_FILE="${CSV_PREFIX}-01.csv"
if [[ ! -f "$CSV_FILE" ]]; then
    CSV_FILE=$(find "$OUTPUT_DIR" -name "*.csv" -type f 2>/dev/null | head -1)
fi

if [[ -z "$CSV_FILE" || ! -s "$CSV_FILE" ]]; then
    _json '{"status":"success","networks":[],"count":0,"duration":'"$DURATION"',"interface":"'"$IFACE"'"}'
    exit 0
fi

_log "[*] Parsing results from $CSV_FILE"

# Parse the CSV
NETWORKS=$(parse_csv "$CSV_FILE")

# Copy CSV to output
cp "$CSV_FILE" "${OUTPUT_DIR}/scan_results.csv" 2>/dev/null || true

# Count networks
COUNT=$(echo "$NETWORKS" | python3 -c "import sys,json; print(len(json.load(sys.stdin)))" 2>/dev/null || echo "0")

# Output final JSON
_json "{\"status\":\"success\",\"networks\":${NETWORKS},\"count\":${COUNT},\"duration\":${DURATION},\"interface\":\"${IFACE}\",\"channels\":\"${CHANNELS}\",\"csv_file\":\"${OUTPUT_DIR}/scan_results.csv\"}"
