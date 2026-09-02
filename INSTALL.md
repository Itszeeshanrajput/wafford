# Installation Guide for Wafford

Wafford is a professional WiFi auditing framework with a modern TUI interface and rich tool integration.

---

## 📋 System Requirements & Prerequisites

### Supported Operating Systems
- **Linux** (Kali Linux, Parrot OS, Ubuntu, Debian, Arch Linux)
- *Note*: Wireless auditing tools (`aircrack-ng`, `iw`, etc.) require Linux kernel and monitor mode wireless adapter support.

### Prerequisites & Dependencies
- **Python**: Version 3.12 or higher
- **Core System Utilities**:
  - `aircrack-ng`
  - `hashcat`
  - `reaver` / `pixiewps`
  - `hostapd`, `dnsmasq`
  - `mdk4`
  - `macchanger`
  - `hcxdumptool`, `hcxtools`
  - `iw`, `wireless-tools`, `net-tools`, `rfkill`

#### Installing System Dependencies (Debian / Kali / Ubuntu)
```bash
sudo apt update
sudo apt install -y \
    python3 python3-pip python3-venv \
    aircrack-ng hashcat reaver hostapd dnsmasq mdk4 \
    macchanger hcxdumptool hcxtools iw wireless-tools net-tools rfkill
```

---

## ⚡ Quick Start: Automated Installation

You can set up Wafford in one command using the included setup script:

```bash
chmod +x setup.sh
./setup.sh
```

The script will:
1. Verify Python version (>= 3.12 required)
2. Create and activate a virtual environment (`.venv`)
3. Upgrade `pip`, `setuptools`, and `wheel`
4. Install Wafford and all Python dependencies (`aiosqlite`, `aiofiles`, `textual`, etc.)
5. Check for recommended system tools

---

## 🛠️ Manual Installation

If you prefer step-by-step setup:

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/Itszeeshanrajput/wafford.git
   cd wafford
   ```

2. **Create and Activate Virtual Environment**:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   ```

3. **Install Dependencies and Wafford**:
   ```bash
   pip install --upgrade pip
   pip install -e ".[dev]"
   ```

4. **Verify Installation**:
   ```bash
   wafford --version
   ```

---

## 🐳 Docker Setup

Wafford can also be run in a Docker container:

```bash
docker build -t wafford .
docker run --rm -it --net=host --privileged wafford
```

Or using Docker Compose:

```bash
docker compose up -d
```

---

## 🚀 Running Wafford

Activate your virtual environment and launch Wafford:

```bash
source .venv/bin/activate
wafford
```

For help and CLI options:
```bash
wafford --help
```
