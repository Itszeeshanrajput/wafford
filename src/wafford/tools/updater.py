"""Tool update management for the Wafford framework."""

from __future__ import annotations

import logging
import re
import subprocess
from typing import Any

import httpx

from wafford.tools.detector import OPTIONAL_TOOLS, REQUIRED_TOOLS, ToolDetector
from wafford.version import VERSION

logger = logging.getLogger(__name__)

GITHUB_API = "https://api.github.com/repos"

VERSION_URLS: dict[str, str] = {
    "aircrack-ng": f"{GITHUB_API}/aircrack-ng/aircrack-ng/releases/latest",
    "hashcat": f"{GITHUB_API}/hashcat/hashcat/releases/latest",
    "reaver": f"{GITHUB_API}/t6x/reaver-wps-fork-t6x/releases/latest",
    "bully": f"{GITHUB_API}/aanarchyy/bully/releases/latest",
    "pixiewps": f"{GITHUB_API}/wiire-a/pixiewps/releases/latest",
    "john": f"{GITHUB_API}/openwall/john/releases/latest",
    "nmap": f"{GITHUB_API}/nmap/nmap/releases/latest",
    "mdk4": f"{GITHUB_API}/WiCCMDP/mdk4/releases/latest",
    "mdk3": f"{GITHUB_API}/WRKnox/mdk3/releases/latest",
    "macchanger": f"{GITHUB_API}/alobbs/macchanger/releases/latest",
    "hcxdumptool": f"{GITHUB_API}/ZerBea/hcxdumptool/releases/latest",
    "hcxtools": f"{GITHUB_API}/ZerBea/hcxtools/releases/latest",
    "ettercap": f"{GITHUB_API}/Ettercap/ettercap/releases/latest",
    "hostapd": f"{GITHUB_API}/jmalinen/hostapd/releases/latest",
}

WAFFORD_REPO = "wafford/wafford"


class ToolUpdater:
    """Manages tool version checking and updates."""

    def __init__(self, check_on_init: bool = False) -> None:
        self._detector = ToolDetector()
        self._latest_cache: dict[str, str | None] = {}
        self._session: httpx.Client | None = None
        if check_on_init:
            self._check_on_startup()

    def _get_session(self) -> httpx.Client:
        if self._session is None or self._session.is_closed:
            self._session = httpx.Client(
                timeout=30,
                headers={
                    "Accept": "application/vnd.github.v3+json",
                    "User-Agent": "wafford-updater",
                },
                follow_redirects=True,
            )
        return self._session

    def close(self) -> None:
        if self._session and not self._session.is_closed:
            self._session.close()

    def _check_on_startup(self) -> None:
        try:
            self.check_wafford_update()
        except Exception:
            logger.debug("Startup update check failed", exc_info=True)

    def check_wafford_update(self) -> dict[str, Any]:
        url = f"{GITHUB_API}/{WAFFORD_REPO}/releases/latest"
        result: dict[str, Any] = {
            "current": VERSION,
            "latest": None,
            "update_available": False,
            "url": None,
        }

        try:
            response = self._get_session().get(url)
            if response.status_code == 404:
                logger.debug("No releases found for wafford")
                return result
            response.raise_for_status()
            data = response.json()
            tag = data.get("tag_name", "")
            latest = tag.lstrip("vV")
            result["latest"] = latest
            result["url"] = data.get("html_url")
            result["update_available"] = self.compare_versions(VERSION, latest) < 0
            result["name"] = data.get("name", "")
            result["body"] = data.get("body", "")
        except httpx.HTTPError as exc:
            logger.warning("Failed to check wafford updates: %s", exc)

        return result

    def check_tool_updates(self) -> dict[str, dict[str, Any]]:
        results: dict[str, dict[str, Any]] = {}
        all_tools = {**REQUIRED_TOOLS, **OPTIONAL_TOOLS}

        for tool_name in all_tools:
            results[tool_name] = self._check_single_tool(tool_name)

        return results

    def _check_single_tool(self, name: str) -> dict[str, Any]:
        result: dict[str, Any] = {
            "tool": name,
            "current": None,
            "latest": None,
            "update_available": False,
            "checked": False,
        }

        status = self._detector.detect_tool(name)
        if not status.get("found"):
            result["current"] = "not installed"
            return result

        result["current"] = status.get("version")
        result["path"] = status.get("path")

        latest = self._get_latest_version(name)
        if latest is None:
            return result

        result["latest"] = latest
        result["checked"] = True

        if result["current"]:
            result["update_available"] = self.compare_versions(
                result["current"], latest
            ) < 0

        return result

    def _get_latest_version(self, name: str) -> str | None:
        if name in self._latest_cache:
            return self._latest_cache[name]

        url = VERSION_URLS.get(name)
        if not url:
            self._latest_cache[name] = None
            return None

        try:
            response = self._get_session().get(url)
            if response.status_code == 404:
                self._latest_cache[name] = None
                return None
            response.raise_for_status()
            data = response.json()
            tag = data.get("tag_name", "")
            version = tag.lstrip("vV")
            self._latest_cache[name] = version
            return version
        except httpx.HTTPError as exc:
            logger.debug("Failed to check version for '%s': %s", name, exc)
            self._latest_cache[name] = None
            return None

    @staticmethod
    def compare_versions(current: str, latest: str) -> int:
        def normalize(version: str) -> list[int]:
            cleaned = re.sub(r"[^0-9.]", "", version)
            parts = cleaned.split(".")
            result: list[int] = []
            for part in parts:
                try:
                    result.append(int(part))
                except ValueError:
                    result.append(0)
            return result

        cur_parts = normalize(current)
        lat_parts = normalize(latest)

        max_len = max(len(cur_parts), len(lat_parts))
        cur_parts.extend([0] * (max_len - len(cur_parts)))
        lat_parts.extend([0] * (max_len - len(lat_parts)))

        for cur, latest_part in zip(cur_parts, lat_parts, strict=True):
            if cur < latest_part:
                return -1
            if cur > latest_part:
                return 1
        return 0

    def update_wafford(self) -> bool:
        logger.info("Updating wafford via pip")
        try:
            result = subprocess.run(
                ["pip", "install", "--upgrade", "wafford"],
                capture_output=True,
                text=True,
                timeout=120,
            )
            if result.returncode == 0:
                logger.info("Wafford updated successfully")
                return True
            logger.error("pip update failed: %s", result.stderr)
            return False
        except subprocess.TimeoutExpired:
            logger.error("pip update timed out")
            return False
        except OSError as exc:
            logger.error("Failed to run pip: %s", exc)
            return False

    def update_tool(self, name: str) -> bool:
        pkg_mgr = self._detect_package_manager()
        if pkg_mgr == "unknown":
            logger.error("No package manager available for updating '%s'", name)
            return False

        package_name = self._get_package_name(name, pkg_mgr)
        if not package_name:
            logger.error("No package mapping for '%s'", name)
            return False

        upgrade_commands: dict[str, list[str]] = {
            "apt": ["sudo", "apt-get", "install", "--only-upgrade", "-y", package_name],
            "pacman": ["sudo", "pacman", "-S", "--noconfirm", package_name],
            "dnf": ["sudo", "dnf", "upgrade", "-y", package_name],
            "brew": ["brew", "upgrade", package_name],
        }

        cmd = upgrade_commands.get(pkg_mgr)
        if not cmd:
            return False

        try:
            logger.info("Updating '%s' via %s", name, pkg_mgr)
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=300
            )
            if result.returncode == 0:
                logger.info("Tool '%s' updated successfully", name)
                return True
            logger.error("Update failed for '%s': %s", name, result.stderr)
            return False
        except subprocess.TimeoutExpired:
            logger.error("Update of '%s' timed out", name)
            return False
        except OSError as exc:
            logger.error("Failed to update '%s': %s", name, exc)
            return False

    @staticmethod
    def _detect_package_manager() -> str:
        for name, cmd in [
            ("apt", ["apt-get", "--version"]),
            ("pacman", ["pacman", "--version"]),
            ("dnf", ["dnf", "--version"]),
            ("brew", ["brew", "--version"]),
        ]:
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    return name
            except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
                continue
        return "unknown"

    @staticmethod
    def _get_package_name(tool: str, pkg_mgr: str) -> str | None:
        from wafford.tools.installer import PACKAGE_MAPS
        pkg_map = PACKAGE_MAPS.get(pkg_mgr, {})
        return pkg_map.get(tool)

    def get_changelog(self, version: str) -> str | None:
        url = f"{GITHUB_API}/{WAFFORD_REPO}/releases/tags/v{version}"
        try:
            response = self._get_session().get(url)
            if response.status_code == 404:
                url = f"{GITHUB_API}/{WAFFORD_REPO}/releases/tags/{version}"
                response = self._get_session().get(url)
            response.raise_for_status()
            return response.json().get("body", "")
        except httpx.HTTPError as exc:
            logger.debug("Failed to fetch changelog for v%s: %s", version, exc)
            return None
