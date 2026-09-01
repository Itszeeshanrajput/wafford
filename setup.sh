#!/usr/bin/env bash
# Wafford Setup Script

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}=========================================="
echo -e "       Wafford Setup & Installer          "
echo -e "==========================================${NC}"

# Check Python version
if ! command -v python3 &>/dev/null; then
    echo -e "${RED}[!] python3 could not be found. Please install Python 3.12+ first.${NC}"
    exit 1
fi

PY_VERSION=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
echo -e "${GREEN}[+] Found Python ${PY_VERSION}${NC}"

# Check Python version >= 3.12
MIN_VERSION="3.12"
if [ "$(printf '%s\n' "$MIN_VERSION" "$PY_VERSION" | sort -V | head -n1)" != "$MIN_VERSION" ]; then
    echo -e "${YELLOW}[!] Warning: Wafford recommends Python 3.12 or newer.${NC}"
fi

# Create virtual environment if not present
if [ ! -d ".venv" ]; then
    echo -e "${BLUE}[*] Creating Python virtual environment in .venv ...${NC}"
    python3 -m venv .venv
fi

echo -e "${BLUE}[*] Activating virtual environment...${NC}"
source .venv/bin/activate

echo -e "${BLUE}[*] Upgrading pip and wheel...${NC}"
pip install --upgrade pip setuptools wheel --quiet

echo -e "${BLUE}[*] Installing Wafford and dependencies...${NC}"
pip install -e ".[dev]"

# System tools verification
echo -e "\n${BLUE}=========================================="
echo -e "      System Tool Verification            "
echo -e "==========================================${NC}"

TOOLS=("aircrack-ng" "hashcat" "reaver" "hostapd" "dnsmasq" "mdk4" "macchanger" "hcxdumptool" "iw")

for tool in "${TOOLS[@]}"; do
    if command -v "$tool" &>/dev/null; then
        echo -e "  [${GREEN}FOUND${NC}] $tool"
    else
        echo -e "  [${YELLOW}MISSING${NC}] $tool (optional/recommended for full auditing features)"
    fi
done

echo -e "\n${GREEN}=========================================="
echo -e "      Setup Completed Successfully!       "
echo -e "==========================================${NC}"
echo -e "To start Wafford:"
echo -e "  1. Activate venv: ${BLUE}source .venv/bin/activate${NC}"
echo -e "  2. Run command:   ${BLUE}wafford${NC}"
