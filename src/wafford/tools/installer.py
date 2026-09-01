"""Dependency installation for the Wafford framework."""

from __future__ import annotations

import hashlib
import logging
import stat
import subprocess
from collections.abc import Callable
from pathlib import Path

from wafford.tools.detector import OPTIONAL_TOOLS, REQUIRED_TOOLS, ToolDetector

logger = logging.getLogger(__name__)

ProgressCallback = Callable[[str, float, str], None] | None

PACKAGE_MAPS: dict[str, dict[str, str]] = {
    "apt": {
        "aircrack-ng": "aircrack-ng",
        "aireplay-ng": "aircrack-ng",
        "airodump-ng": "aircrack-ng",
        "airmon-ng": "aircrack-ng",
        "hashcat": "hashcat",
        "hostapd": "hostapd",
        "dnsmasq": "dnsmasq",
        "mdk4": "mdk4",
        "macchanger": "macchanger",
        "hcxdumptool": "hcxdumptool",
        "hcxtools": "hcxtools",
        "iw": "iw",
        "rfkill": "rfkill",
        "iwlist": "wireless-tools",
        "reaver": "reaver",
        "bully": "bully",
        "pixiewps": "pixiewps",
        "john": "john",
        "nmap": "nmap",
        "mdk3": "mdk3",
        "ettercap": "ettercap-text-only",
        "mitmproxy": "mitmproxy",
    },
    "pacman": {
        "aircrack-ng": "aircrack-ng",
        "aireplay-ng": "aircrack-ng",
        "airodump-ng": "aircrack-ng",
        "airmon-ng": "aircrack-ng",
        "hashcat": "hashcat",
        "hostapd": "hostapd",
        "dnsmasq": "dnsmasq",
        "mdk4": "mdk4",
        "macchanger": "macchanger",
        "hcxdumptool": "hcxdumptool",
        "hcxtools": "hcxtools",
        "iw": "iw",
        "rfkill": "util-linux",
        "iwlist": "wireless_tools",
        "reaver": "reaver",
        "bully": "bully",
        "pixiewps": "pixiewps",
        "john": "john",
        "nmap": "nmap",
        "mdk3": "mdk3",
        "ettercap": "ettercap",
        "mitmproxy": "mitmproxy",
    },
    "dnf": {
        "aircrack-ng": "aircrack-ng",
        "aireplay-ng": "aircrack-ng",
        "airodump-ng": "aircrack-ng",
        "airmon-ng": "aircrack-ng",
        "hashcat": "hashcat",
        "hostapd": "hostapd",
        "dnsmasq": "dnsmasq",
        "mdk4": "mdk4",
        "macchanger": "macchanger",
        "hcxdumptool": "hcxdumptool",
        "hcxtools": "hcxtools",
        "iw": "iw",
        "rfkill": "rfkill",
        "iwlist": "wireless-tools",
        "reaver": "reaver",
        "bully": "bully",
        "pixiewps": "pixiewps",
        "john": "john",
        "nmap": "nmap",
        "mdk3": "mdk3",
        "ettercap": "ettercap",
        "mitmproxy": "mitmproxy",
    },
    "brew": {
        "aircrack-ng": "aircrack-ng",
        "hashcat": "hashcat",
        "nmap": "nmap",
        "john": "john",
        "reaver": "reaver",
        "macchanger": "macchanger",
        "dnsmasq": "dnsmasq",
    },
}


class DependencyInstaller:
    """Installs and manages external tool dependencies."""

    def __init__(self, progress_callback: ProgressCallback = None) -> None:
        self._detector = ToolDetector()
        self._package_manager: str | None = None
        self._progress_callback = progress_callback

    def _report_progress(self, name: str, progress: float, message: str) -> None:
        if self._progress_callback:
            try:
                self._progress_callback(name, progress, message)
            except Exception:
                logger.debug("Progress callback failed", exc_info=True)

    def detect_package_manager(self) -> str:
        if self._package_manager is not None:
            return self._package_manager

        candidates = [
            ("apt", ["apt-get", "--version"]),
            ("pacman", ["pacman", "--version"]),
            ("dnf", ["dnf", "--version"]),
            ("brew", ["brew", "--version"]),
        ]
        for name, cmd in candidates:
            try:
                result = subprocess.run(
                    cmd, capture_output=True, text=True, timeout=10
                )
                if result.returncode == 0:
                    self._package_manager = name
                    return name
            except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
                continue

        self._package_manager = "unknown"
        return self._package_manager

    def install_tool(self, name: str, force: bool = False) -> bool:
        pkg_mgr = self.detect_package_manager()
        if pkg_mgr == "unknown":
            logger.error("No supported package manager found")
            self._report_progress(name, 0.0, "No package manager available")
            return False

        if not force:
            status = self._detector.detect_tool(name)
            if status.get("found"):
                logger.info("Tool '%s' already installed at %s", name, status["path"])
                self._report_progress(name, 1.0, "Already installed")
                return True

        pkg_map = PACKAGE_MAPS.get(pkg_mgr, {})
        package_name = pkg_map.get(name)
        if not package_name:
            logger.error("No package mapping for '%s' with package manager '%s'", name, pkg_mgr)
            self._report_progress(name, 0.0, f"No package mapping for {pkg_mgr}")
            return False

        self._report_progress(name, 0.1, f"Installing {package_name} via {pkg_mgr}")
        logger.info("Installing package '%s' for tool '%s'", package_name, name)

        cmd = self._get_install_command(pkg_mgr, package_name)
        if cmd is None:
            return False

        try:
            self._report_progress(name, 0.3, f"Running: {' '.join(cmd)}")
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,
            )
            if result.returncode != 0:
                logger.error(
                    "Failed to install '%s': %s",
                    package_name,
                    result.stderr.strip(),
                )
                self.handle_errors(name, result.stderr)
                self._report_progress(name, 0.0, f"Installation failed: {result.stderr[:200]}")
                return False

            self._report_progress(name, 0.8, "Verifying installation")
            status = self._detector.detect_tool(name)
            if status.get("found"):
                self._report_progress(name, 1.0, f"Installed: {status['version'] or 'ok'}")
                logger.info("Successfully installed '%s' at %s", name, status["path"])
                return True
            self._report_progress(name, 0.0, "Installed but binary not found")
            logger.warning("Package installed but binary '%s' not found", name)
            return False

        except subprocess.TimeoutExpired:
            logger.error("Installation of '%s' timed out", package_name)
            self._report_progress(name, 0.0, "Installation timed out")
            self.handle_errors(name, "Installation timed out after 300 seconds")
            return False
        except OSError as exc:
            logger.error("OS error installing '%s': %s", package_name, exc)
            self._report_progress(name, 0.0, str(exc))
            return False

    @staticmethod
    def _get_install_command(pkg_mgr: str, package_name: str) -> list[str] | None:
        commands: dict[str, list[str]] = {
            "apt": ["sudo", "apt-get", "install", "-y", package_name],
            "pacman": ["sudo", "pacman", "-S", "--noconfirm", package_name],
            "dnf": ["sudo", "dnf", "install", "-y", package_name],
            "brew": ["brew", "install", package_name],
        }
        return commands.get(pkg_mgr)

    def install_multiple(
        self, names: list[str], force: bool = False
    ) -> dict[str, bool]:
        results: dict[str, bool] = {}
        total = len(names)
        for idx, name in enumerate(names, 1):
            self._report_progress(
                name,
                (idx - 1) / total,
                f"[{idx}/{total}] Installing {name}",
            )
            results[name] = self.install_tool(name, force=force)
            self._report_progress(
                name,
                idx / total,
                f"[{idx}/{total}] {'OK' if results[name] else 'FAILED'}",
            )
        return results

    def install_all_missing(self, include_optional: bool = False) -> dict[str, bool]:
        missing: list[str] = []
        for name in REQUIRED_TOOLS:
            status = self._detector.detect_tool(name)
            if not status.get("found"):
                missing.append(name)
        if include_optional:
            for name in OPTIONAL_TOOLS:
                status = self._detector.detect_tool(name)
                if not status.get("found"):
                    missing.append(name)

        if not missing:
            return {}
        return self.install_multiple(missing)

    def download_binary(
        self, name: str, url: str, dest_dir: Path | str | None = None
    ) -> Path | None:
        dest = Path(dest_dir) if dest_dir else Path("/usr/local/bin")
        dest.mkdir(parents=True, exist_ok=True)

        output_path = dest / name
        self._report_progress(name, 0.0, f"Downloading {url}")

        try:
            import httpx

            with httpx.Client(follow_redirects=True, timeout=120) as client:
                with client.stream("GET", url) as response:
                    response.raise_for_status()
                    total = int(response.headers.get("content-length", 0))
                    downloaded = 0
                    with output_path.open("wb") as f:
                        for chunk in response.iter_bytes(chunk_size=8192):
                            f.write(chunk)
                            downloaded += len(chunk)
                            if total > 0:
                                self._report_progress(
                                    name,
                                    downloaded / total,
                                    f"Downloaded {downloaded}/{total} bytes",
                                )
        except ImportError:
            try:
                cmd = ["curl", "-fSL", "-o", str(output_path), url]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
                if result.returncode != 0:
                    logger.error("curl failed for '%s': %s", name, result.stderr)
                    self.handle_errors(name, result.stderr)
                    return None
            except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as exc:
                logger.error("Failed to download '%s': %s", name, exc)
                self.handle_errors(name, str(exc))
                return None
        except Exception as exc:
            logger.error("Failed to download '%s': %s", name, exc)
            self.handle_errors(name, str(exc))
            return None

        output_path.chmod(output_path.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
        self._report_progress(name, 1.0, f"Installed to {output_path}")
        logger.info("Downloaded binary '%s' to %s", name, output_path)
        return output_path

    def download_wordlist(
        self,
        name: str,
        url: str,
        sha256: str | None = None,
        dest_dir: Path | str | None = None,
    ) -> Path | None:
        dest = Path(dest_dir) if dest_dir else Path.home() / ".wafford" / "wordlists"
        dest.mkdir(parents=True, exist_ok=True)

        output_path = dest / name
        self._report_progress(name, 0.0, f"Downloading wordlist from {url}")

        try:
            import httpx

            with httpx.Client(follow_redirects=True, timeout=300) as client:
                with client.stream("GET", url) as response:
                    response.raise_for_status()
                    total = int(response.headers.get("content-length", 0))
                    downloaded = 0
                    sha256_hash = hashlib.sha256()
                    with output_path.open("wb") as f:
                        for chunk in response.iter_bytes(chunk_size=65536):
                            f.write(chunk)
                            sha256_hash.update(chunk)
                            downloaded += len(chunk)
                            if total > 0:
                                self._report_progress(
                                    name,
                                    downloaded / total,
                                    f"Downloaded {downloaded}/{total} bytes",
                                )
        except ImportError:
            try:
                cmd = ["curl", "-fSL", "-o", str(output_path), url]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
                if result.returncode != 0:
                    logger.error("curl failed for wordlist '%s': %s", name, result.stderr)
                    return None
                sha256_hash = hashlib.sha256()
                sha256_hash.update(output_path.read_bytes())
            except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as exc:
                logger.error("Failed to download wordlist '%s': %s", name, exc)
                return None
        except Exception as exc:
            logger.error("Failed to download wordlist '%s': %s", name, exc)
            return None

        if sha256:
            actual = sha256_hash.hexdigest()
            if actual.lower() != sha256.lower():
                logger.error(
                    "Checksum mismatch for '%s': expected %s, got %s",
                    name, sha256, actual,
                )
                output_path.unlink(missing_ok=True)
                self._report_progress(name, 0.0, f"Checksum mismatch: {actual}")
                return None
            logger.info("Checksum verified for '%s'", name)

        self._report_progress(name, 1.0, f"Downloaded to {output_path}")
        return output_path

    def handle_errors(self, name: str, error: str) -> None:
        suggestions: list[str] = []
        error_lower = error.lower()

        if "permission denied" in error_lower or "eacc" in error_lower:
            suggestions.append("Try running with sudo or as root")
        if "not found" in error_lower or "no such package" in error_lower:
            suggestions.append(f"Package may not be in your repositories for '{name}'")
            suggestions.append("Try adding the appropriate PPA or third-party repo")
        if "unable to locate" in error_lower:
            suggestions.append("Run 'sudo apt-get update' first")
        if "timeout" in error_lower or "timed out" in error_lower:
            suggestions.append("Check your network connection")
            suggestions.append("Try again later or use a mirror")
        if "could not resolve" in error_lower or "network" in error_lower:
            suggestions.append("Check your DNS settings and network connection")
        if "dpkg" in error_lower or "lock" in error_lower:
            suggestions.append("Another package manager process may be running")
            suggestions.append("Wait and try again, or kill the blocking process")

        if not suggestions:
            pkg_mgr = self.detect_package_manager()
            suggestions.append(f"Check if '{name}' is available in {pkg_mgr} repositories")
            suggestions.append("Alternatively, try building from source")

        logger.error("Error installing '%s': %s", name, error)
        for suggestion in suggestions:
            logger.info("Suggestion: %s", suggestion)
