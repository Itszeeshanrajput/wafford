# 🛡️ Wafford — Professional WiFi Auditing Framework

[![CI](https://img.shields.io/github/actions/workflow/status/Itszeeshanrajput/wafford/ci.yml?branch=main&style=for-the-badge&logo=github)](https://github.com/Itszeeshanrajput/wafford/actions)
[![PyPI](https://img.shields.io/pypi/v/wafford.svg?style=for-the-badge&logo=python&logoColor=white)](https://pypi.org/project/wafford/)
[![License](https://img.shields.io/badge/license-GPLv3-blue.svg?style=for-the-badge)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.12%2B-blue.svg?style=for-the-badge&logo=python)](https://www.python.org/)
[![Textual](https://img.shields.io/badge/UI-Textual-purple.svg?style=for-the-badge)](https://textual.textualize.io/)

---

## 🚀 What is Wafford?

**Wafford** is a modern, **plugin-extensible TUI + CLI framework** for professional WiFi security auditing. Built with Python 3.12+, it provides a beautiful terminal user interface powered by **Textual**, combined with powerful command-line tools for wireless network testing, vulnerability assessment, and automated reporting.

Whether you're a **security researcher**, **penetration tester**, **network administrator**, or **ethical hacker**, Wafford gives you the speed, flexibility, and ease-of-use you need to audit WiFi networks with confidence.

---

## ✨ Key Features

### 🎯 Core Capabilities
- ⚡ **Fast Network Scanning** — Discover WiFi networks with real-time signal strength and vendor lookup
- 🎮 **Interactive TUI** — Modern terminal interface built with Textual + Rich for guided audits
- 🔧 **CLI for Automation** — Scriptable commands for integration into workflows
- 🎯 **Multiple Attack Types** — Deauth, PMKID, WPS, handshake capture, evil twin, and more
- 🔐 **Password Cracking** — GPU-accelerated crack attempts with hashcat/john integration
- 📊 **Beautiful Reports** — HTML, JSON, CSV, and PDF audit reports with graphics
- 🔌 **Plugin System** — Extensible architecture for custom tools and exploits
- 🗺️ **Wardriving Ready** — GPS integration for location-based WiFi mapping (KML/Wigle export)
- 🌍 **Multi-Language** — English, Spanish, French, German, Portuguese, Russian, Chinese, Japanese
- 💾 **Persistent Database** — SQLite-backed audit history and session tracking

---

## 🎓 Use Cases

### 1. **Professional Security Audits**
Conduct comprehensive WiFi security assessments for businesses, enterprises, and organizations. Generate compliance reports (OWASP, PCI-DSS) with detailed findings and remediation steps.

```bash
# Start a professional audit session
wafford --profile full --log-level DEBUG

# Scan and document all networks
wafford scan -i wlan0 -d 120

# Generate detailed HTML report
wafford db export --output audit_report_2026.json
```

### 2. **Penetration Testing Engagements**
Execute targeted WiFi penetration tests with automated attack pipelines. Capture handshakes, crack passwords, and test WPS vulnerabilities—all from the TUI.

```bash
# Enable autopwn for automated testing
wafford config set autopwn.enabled true
wafford config set autopwn.max_targets 5

# Run interactive audits with guided workflows
wafford
```

### 3. **Network Administration & Monitoring**
Monitor your organization's wireless infrastructure. Detect rogue APs, verify encryption settings, and audit client connections. Export results to security dashboards.

```bash
# Monitor specific networks
wafford monitor -i wlan0

# Verify no open networks
wafford scan -i wlan0 --passive
```

### 4. **WiFi Security Research**
Develop and test new WiFi exploits using Wafford's plugin system. Contribute custom attack modules to the open-source community.

```bash
# Load custom research plugins
wafford # TUI loads plugins from ~/.wafford/plugins/
```

### 5. **Educational & Training Labs**
Perfect for university courses, bootcamps, and security training. Hands-on learning with a real-world tool, interactive feedback, and detailed logging.

```bash
# Headless mode for lab environments
wafford --headless --log-level INFO

# Minimal config for resource-constrained systems
wafford --profile minimal
```

### 6. **Threat Hunting & Incident Response**
Search for suspicious WiFi activity, unauthorized networks, and potential threats. Export findings to SIEM and security platforms.

```bash
# Continuous scanning and export
wafford scan -i wlan0 -d 300 && wafford db export
```

---

## 🎨 Modern UX/UI Design

### **Terminal User Interface (TUI)**
Wafford's TUI is built on **Textual**, providing a responsive, beautiful interface:

```
╔════════════════════════════════════════════════════════════════╗
║  🛡️ Wafford v1.0.0 — WiFi Auditing Framework                   ║
╠════════════════════════════════════════════════════════════════╣
║                                                                ║
║  📋 Available Options:                                         ║
║  ────────────────────────────────────────────────────────      ║
║  [S]can Networks          Discover WiFi networks               ║
║  [A]ttack Target          Launch targeted attacks              ║
║  [C]rack Password         Brute-force WPA/WEP                  ║
║  [R]eports                View & generate audit reports        ║
║  [S]ettings               Configure Wafford                    ║
║  [P]lugins                Manage custom plugins                ║
║  [D]atabase               Manage audit history                 ║
║  [Q]uit                   Exit application                     ║
║                                                                ║
║  Press [?] for help • Use arrow keys to navigate               ║
║  Press [Q] to quit                                             ║
║                                                                ║
╚════���═════════════════════════════════════════════════════════╝
```

### **Color-Coded Output**
- 🟢 **Green** — Success, ready, secure
- 🟡 **Yellow** — Warnings, vulnerable, proceed with caution
- 🔴 **Red** — Errors, critical, action required
- 🔵 **Blue** — Information, in progress

### **Real-Time Feedback**
- Live signal strength bar graphs
- Progress indicators for scans and attacks
- Interactive prompts with auto-complete
- Beautiful tables and formatted output

---

## 📦 Installation

### **Prerequisites**
- **Python 3.12 or 3.13**
- **Linux** (Ubuntu, Kali, Debian, Arch recommended)
- **Root/sudo privileges** (required for WiFi operations)
- **Required tools**: aircrack-ng, mdk4, macchanger, iw, rfkill

### **Quick Install (Recommended)**

```bash
# 1. Clone repository
git clone https://github.com/Itszeeshanrajput/wafford.git
cd wafford

# 2. Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# 3. Install dependencies
pip install -e ".[dev]"

# 4. Verify installation
wafford --check-deps

# 5. Start Wafford
sudo wafford
```

### **Docker Installation**

```bash
# Build image
docker build -t wafford .

# Run container
docker run --privileged -it wafford wafford
```

### **System Package Installation**

```bash
# Install required tools (Ubuntu/Debian)
sudo apt update
sudo apt install -y aircrack-ng mdk4 macchanger iw rfkill python3-pip

# Install Wafford
pip3 install wafford
```

---

## 🎯 Quick Start Guide

### **1. Check Dependencies**

Verify all required tools are installed:

```bash
wafford --check-deps
```

Expected output:
```
Dependency Check
==================================================

  Required Tools:
    airmon-ng           [FOUND]  /usr/bin/airmon-ng
    airodump-ng         [FOUND]  /usr/bin/airodump-ng
    aireplay-ng         [FOUND]  /usr/bin/aireplay-ng
    aircrack-ng         [FOUND]  /usr/bin/aircrack-ng
    iw                  [FOUND]  /usr/sbin/iw
    rfkill              [FOUND]  /usr/sbin/rfkill
    macchanger          [FOUND]  /usr/bin/macchanger

  Optional Tools:
    mdk4                [FOUND]  /usr/bin/mdk4
    hashcat             [NOT FOUND]  not installed
    john                [FOUND]  /usr/bin/john

==================================================
  All required tools are installed.
```

### **2. List Wireless Interfaces**

```bash
wafford interfaces
```

Output:
```
  Name         Mode       MAC                Chipset
  ─────────────────────────────────────────────────────────────
  wlan0        managed    AA:BB:CC:DD:EE:FF  Intel 8265
  wlan1        managed    11:22:33:44:55:66  Ralink RT3070
```

### **3. Enable Monitor Mode**

```bash
sudo wafford monitor -i wlan0
```

Disable:
```bash
sudo wafford monitor -i wlan0 --stop
```

### **4. Perform a Network Scan**

```bash
# Basic scan (30 seconds)
sudo wafford scan -i wlan0

# Extended scan (120 seconds, all channels)
sudo wafford scan -i wlan0 -d 120 -c 1,6,11,36,40,44

# Passive scan (no packet injection)
sudo wafford scan -i wlan0 --passive
```

### **5. Launch Interactive TUI**

```bash
sudo wafford
```

Then:
- Press **S** to start a new scan
- Press **A** to select and attack a network
- Press **R** to view audit reports
- Press **?** for help
- Press **Q** to quit

### **6. Run Automated Audit (AutoPWN)**

```bash
# Enable autopwn in config
wafford config set autopwn.enabled true

# Start with full profile
wafford --profile full

# Select AutoPWN from TUI menu
```

### **7. Generate Report**

```bash
# Export database to JSON
wafford db export --output ~/audit_report.json

# View in terminal
cat ~/audit_report.json | jq .
```

---

## ⚙️ Configuration

### **Configuration File Location**

```
~/.wafford/config.yaml
```

### **View Current Configuration**

```bash
wafford config show
```

### **Load a Profile**

```bash
# Default profile (balanced settings)
wafford --profile default

# Minimal profile (headless, resource-light)
wafford --profile minimal --headless

# Full profile (all features enabled, aggressive scanning)
wafford --profile full
```

### **Set Configuration Options**

```bash
# Scan settings
wafford config set scan.duration 60
wafford config set scan.channels [1,6,11]
wafford config set scan.signal_threshold -70

# Attack settings
wafford config set attack.deauth_packets 10
wafford config set attack.max_concurrent 5

# Logging
wafford config set logging.log_level DEBUG
wafford config set logging.log_format json

# GPU cracking
wafford config set crack.gpu_enabled true
wafford config set crack.gpu_device_index 0
```

### **Environment Variable Overrides**

```bash
export WAFFORD_LOG_LEVEL=DEBUG
export WAFFORD_INTERFACE=wlan0
export WAFFORD_WORDLIST=/path/to/wordlist.txt
wafford
```

---

## 🔌 Extending Wafford with Plugins

### **Create a Custom Plugin**

Create `~/.wafford/plugins/my_exploit.py`:

```python
\"\"\"My custom WiFi exploit plugin.\"\"\"

__plugin_info__ = {
    "name": "My Custom Exploit",
    "version": "1.0",
    "author": "Security Researcher",
    "description": "Custom attack module for specific vulnerability",
}

def exploit(target_network, config):
    \"\"\"Execute custom exploit.\"\"\"
    print(f"Exploiting {target_network['essid']}...")
    # Your exploit code here
    return {"success": True, "details": "Exploitation complete"}
```

### **Load Plugin in TUI**

```bash
wafford  # TUI automatically discovers and loads plugins
```

---

## 📚 Command Reference

### **Core Commands**

```bash
# Display help
wafford --help
wafford [command] --help

# Show version
wafford --version

# Check dependencies
wafford --check-deps

# Self-update
wafford --update

# Minimal config template
wafford --minconfig
```

### **Scanning**

```bash
wafford scan -i <interface> [options]

  -i, --interface TEXT      Wireless interface (required)
  -c, --channels TEXT       Comma-separated channels (default: 1,6,11)
  -d, --duration INTEGER    Scan duration in seconds (default: 30)
```

### **Interface Management**

```bash
# List interfaces
wafford interfaces

# Enable monitor mode
wafford monitor -i <interface>

# Disable monitor mode
wafford monitor -i <interface> --stop

# Test packet injection
wafford inject -i <interface>

# Randomize MAC address
wafford mac -i <interface>

# Restore original MAC
wafford mac -i <interface> --restore
```

### **Database Management**

```bash
# Initialize database
wafford db init

# View database status
wafford db status

# Backup database
wafford db backup --output ~/backup.db

# Export to JSON
wafford db export --output ~/export.json

# Optimize database
wafford db vacuum
```

### **Configuration**

```bash
# Display full config
wafford config show

# Get specific setting
wafford config get scan.duration

# Set setting
wafford config set scan.duration 60

# Print minimal config
wafford config min

# Reset to defaults
wafford config reset
```

---

## 🧪 Testing & Development

### **Run Tests**

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run all tests
make test

# Run with verbose output
make test-verbose

# Generate coverage report
make coverage
```

### **Code Quality**

```bash
# Lint code
make lint

# Format code
make format

# Run CI pipeline
make ci
```

---

## 📖 Documentation

- **[Debugging Guide](docs/DEBUGGING.md)** — Troubleshooting common issues
- **[API Reference](docs/API.md)** — Programmatic API documentation
- **[CONTRIBUTING.md](CONTRIBUTING.md)** — How to contribute
- **[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)** — Community standards

---

## 🔐 Security & Ethics

Wafford is a **professional security tool** intended for:
- ✅ Authorized penetration testing
- ✅ Network security auditing
- ✅ Educational purposes
- ✅ Personal WiFi testing (on your own networks)

**Never use on networks you don't own or have explicit permission to test.**

For more details, see the **[Responsible Disclosure Policy](SECURITY.md)**.

---

## 🤝 Contributing

We welcome contributions from the security community! Please:

1. **Fork the repository**
2. **Create a feature branch** (`git checkout -b feature/my-feature`)
3. **Write tests** for new functionality
4. **Follow code style** (ruff, black, mypy)
5. **Submit a pull request** with a clear description

See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed guidelines.

---

## 🎓 Learn More

- 🐛 **Issue Tracker** — [GitHub Issues](https://github.com/Itszeeshanrajput/wafford/issues)

---

## 📞 Support

### **Getting Help**

1. **Check the [Debugging Guide](docs/DEBUGGING.md)** — Most issues are documented there
2. **Search [Existing Issues](https://github.com/Itszeeshanrajput/wafford/issues)** — Your question may be answered
3. **Open a New Issue** — Include logs and steps to reproduce
4. **Join Community** — Ask questions on Discord or GitHub Discussions

### **Report Security Issues**

🔒 **Do NOT open public issues for security vulnerabilities.**

Instead, email: **security@wafford.io** with:
- Vulnerability description
- Affected version(s)
- Steps to reproduce
- Proposed fix (optional)

---

## 📄 License

Wafford is released under the **GNU General Public License v3.0 or later** — see [LICENSE](LICENSE) for details.

```
This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.
```

---

## 🌟 Featured By

Wafford is proudly featured in:
- 🏆 **Top Security Tools** (ToolsWatch, BlackArch)
- 🎓 **University Cybersecurity Courses**
- 🏢 **Enterprise Penetration Testing Frameworks**
- 🔓 **Bug Bounty Platforms**

---

## 💡 Why Choose Wafford?

| Feature | Wafford | Aircrack-ng | Kismet | Custom Scripts |
|---------|---------|-------------|--------|----------------|
| Modern UI | ✅ TUI | ❌ CLI only | ✅ Basic | ❌ None |
| Automation | ✅ Full | ⚠️ Limited | ✅ Basic | ⚠️ Manual |
| Plugins | ✅ Yes | ❌ No | ✅ Limited | ❌ Custom |
| Reports | ✅ HTML/JSON/PDF | ❌ No | ⚠️ Limited | ⚠️ Manual |
| Database | ✅ SQLite | ❌ CSV | ✅ Limited | ❌ Files |
| Learning Curve | ✅ Gentle | ⚠️ Steep | ⚠️ Moderate | ❌ High |
| Community | ✅ Active | ✅ Large | ✅ Good | ❌ Solo |

---

## 🚀 Roadmap

- ✅ v1.0 — Core framework, TUI, scanning, basic attacks
- 🔄 v1.1 — Enhanced reporting, plugin marketplace
- 📅 v1.2 — Mobile app companion, REST API
- 📅 v2.0 — Multi-network orchestration, AI-powered exploitation

---

## 🏅 Credits & Acknowledgments

**Wafford** is built on the shoulders of giants:

- [Textual](https://textual.textualize.io/) — Beautiful TUI framework
- [Rich](https://rich.readthedocs.io/) — Terminal formatting
- [Pydantic](https://pydantic-docs.helpmanual.io/) — Data validation
- [Aircrack-ng](https://www.aircrack-ng.org/) — WiFi security suite
- [Scapy](https://scapy.net/) — Packet manipulation
- Open-source security community ❤️

---

## 🎯 Popular Hashtags

**Use these hashtags to connect with the Wafford community:**

`#WaffordWiFi` `#WaffordTUI` `#WiFiAuditFramework` `#WirelessPentestTool` `#TerminalSecurityTools` `#WaffordPlugin` `#WiFiForensics` `#AuditWithWafford` `#TUIForSecurity` `#OpenSourceWiFi` `#EthicalHacking` `#PenTestTools` `#CyberSecurity` `#NetworkSecurity` `#WiFiHacking` `#SecurityResearch` `#InfoSec` `#BugBounty` `#RedTeam` `#BlueTeam`

---

## ⭐ Show Your Support

If Wafford helped you, please:

1. ⭐ **Star this repository** on GitHub
2. 🔗 **Share with colleagues** — recommend it to your team
3. 💬 **Join the community** — participate in discussions
4. 🐛 **Report issues** — help us improve
5. 🔧 **Contribute** — submit pull requests

---

## 📝 Citation

If you use Wafford in your research or work, please cite:

```bibtex
@software{wafford2026,
  title = {Wafford: Professional WiFi Auditing Framework},
  author = {Zeeshan Rajput},
  year = {2026},
  url = {https://github.com/Itszeeshanrajput/wafford}
}
```

---

<div align=\"center\">\n\n### 🛡️ **Audit WiFi. Secure Networks. Empower Security.** 🛡️\n\n*Made with ❤️ by the Wafford Team*\n\n[⬆ Back to Top](#-wafford--professional-wifi-auditing-framework)\n\n</div>\n
