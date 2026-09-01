"""Wordlist downloading for the Wafford framework."""

from __future__ import annotations

import hashlib
import logging
import shutil
from collections.abc import Callable
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

ProgressCallback = Callable[[str, float, str], None] | None

AVAILABLE_WORDLISTS: dict[str, dict[str, Any]] = {
    "rockyou": {
        "url": "https://github.com/danielmiessler/SecLists/raw/master/Passwords/Common-Credentials/10k-most-common.txt",
        "sha256": "ef775c53f1fa20c77e1d80d6e0a7a1c48a4a64c9fc3f1c2b5ea77d8d6a7c1b0f",
        "size": 176223,
        "description": "10,000 most common passwords (subset of rockyou)",
        "filename": "10k_most_common.txt",
    },
    "seclists_10k": {
        "url": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10k-most-common.txt",
        "sha256": None,
        "size": 176223,
        "description": "SecLists 10,000 most common passwords",
        "filename": "10k_most_common.txt",
    },
    "seclists_100k": {
        "url": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/100k-most-used-passwords.txt",
        "sha256": None,
        "size": 977555,
        "description": "SecLists 100,000 most used passwords",
        "filename": "100k_most_used.txt",
    },
    "wifi_common": {
        "url": None,
        "sha256": None,
        "size": 0,
        "description": "Built-in common WiFi passwords",
        "filename": "common.txt",
        "builtin": True,
    },
    "wifi_numeric": {
        "url": None,
        "sha256": None,
        "size": 0,
        "description": "Built-in common numeric passwords",
        "filename": "numeric.txt",
        "builtin": True,
    },
    "wifi_alpha_numeric": {
        "url": None,
        "sha256": None,
        "size": 0,
        "description": "Built-in common alphanumeric passwords",
        "filename": "alpha_numeric.txt",
        "builtin": True,
    },
    "fern_wifi_common": {
        "url": "https://raw.githubusercontent.com/s0cr4t3/Fern-WiFi-Cracker/master/wordlists/common.txt",
        "sha256": None,
        "size": 0,
        "description": "Fern WiFi Cracker common wordlist",
        "filename": "fern_wifi_common.txt",
    },
    "darkweb2019": {
        "url": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Leaked-Databases/darkweb2019-top10000.txt",
        "sha256": None,
        "size": 117891,
        "description": "Top 10,000 passwords from 2019 dark web leak",
        "filename": "darkweb2019_top10000.txt",
    },
}


class WordlistDownloader:
    """Downloads and manages wordlist files."""

    def __init__(
        self,
        download_dir: Path | str | None = None,
        progress_callback: ProgressCallback = None,
    ) -> None:
        if download_dir:
            self._download_dir = Path(download_dir)
        else:
            self._download_dir = Path.home() / ".wafford" / "wordlists"
        self._download_dir.mkdir(parents=True, exist_ok=True)
        self._progress_callback = progress_callback

    @property
    def download_dir(self) -> Path:
        return self._download_dir

    def _report_progress(self, name: str, progress: float, message: str) -> None:
        if self._progress_callback:
            try:
                self._progress_callback(name, progress, message)
            except Exception:
                logger.debug("Progress callback failed", exc_info=True)

    def download(
        self, name: str, output_dir: Path | str | None = None
    ) -> Path | None:
        meta = AVAILABLE_WORDLISTS.get(name)
        if not meta:
            logger.error("Unknown wordlist: '%s'", name)
            return None

        if meta.get("builtin"):
            return self._install_builtin(name, meta, output_dir)

        url = meta.get("url")
        if not url:
            logger.error("No download URL for '%s'", name)
            return None

        dest_dir = Path(output_dir) if output_dir else self._download_dir
        dest_dir.mkdir(parents=True, exist_ok=True)

        filename = meta.get("filename", name)
        output_path = dest_dir / filename

        if output_path.exists():
            logger.info("Wordlist '%s' already exists at %s", name, output_path)
            self._report_progress(name, 1.0, "Already downloaded")
            return output_path

        self._report_progress(name, 0.0, f"Downloading from {url}")
        logger.info("Downloading wordlist '%s' from %s", name, url)

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

            expected_sha256 = meta.get("sha256")
            if expected_sha256:
                actual_sha256 = sha256_hash.hexdigest()
                if not self.verify_checksum(output_path, expected_sha256):
                    logger.error(
                        "Checksum mismatch for '%s': expected %s, got %s",
                        name, expected_sha256, actual_sha256,
                    )
                    output_path.unlink(missing_ok=True)
                    self._report_progress(name, 0.0, "Checksum verification failed")
                    return None
                logger.info("Checksum verified for '%s'", name)

        except ImportError:
            try:
                cmd = ["curl", "-fSL", "-o", str(output_path), url]
                import subprocess
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
                if result.returncode != 0:
                    logger.error("curl failed: %s", result.stderr)
                    self._report_progress(name, 0.0, "Download failed")
                    return None
            except Exception as exc:
                logger.error("Failed to download '%s': %s", name, exc)
                self._report_progress(name, 0.0, str(exc))
                return None
        except Exception as exc:
            logger.error("Failed to download '%s': %s", name, exc)
            self._report_progress(name, 0.0, str(exc))
            return None

        self._report_progress(name, 1.0, f"Downloaded to {output_path}")
        logger.info("Downloaded '%s' to %s", name, output_path)
        return output_path

    def _install_builtin(
        self,
        name: str,
        meta: dict[str, Any],
        output_dir: Path | str | None = None,
    ) -> Path | None:
        dest_dir = Path(output_dir) if output_dir else self._download_dir
        dest_dir.mkdir(parents=True, exist_ok=True)

        filename = meta.get("filename", name)
        output_path = dest_dir / filename

        builtin_dir = Path(__file__).parent / "builtin"
        source = builtin_dir / filename

        if not source.exists():
            logger.error("Built-in wordlist not found: %s", source)
            return None

        if output_path.exists():
            logger.info("Built-in wordlist already installed: %s", output_path)
            return output_path

        shutil.copy2(source, output_path)
        self._report_progress(name, 1.0, f"Installed built-in: {output_path}")
        logger.info("Installed built-in wordlist '%s' to %s", name, output_path)
        return output_path

    @staticmethod
    def verify_checksum(file_path: Path | str, expected_sha256: str) -> bool:
        path = Path(file_path)
        if not path.exists():
            return False

        sha256 = hashlib.sha256()
        with path.open("rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                sha256.update(chunk)

        return sha256.hexdigest().lower() == expected_sha256.lower()

    def list_available(self) -> dict[str, dict[str, Any]]:
        result: dict[str, dict[str, Any]] = {}
        for name, meta in AVAILABLE_WORDLISTS.items():
            entry = dict(meta)
            entry["downloaded"] = self.is_downloaded(name)
            if entry["downloaded"]:
                entry["local_path"] = str(self.get_path(name))
            result[name] = entry
        return result

    def is_downloaded(self, name: str) -> bool:
        meta = AVAILABLE_WORDLISTS.get(name)
        if not meta:
            return False
        path = self.get_path(name)
        return path.exists() if path else False

    def get_path(self, name: str) -> Path | None:
        meta = AVAILABLE_WORDLISTS.get(name)
        if not meta:
            return None

        filename = meta.get("filename", name)
        path = self._download_dir / filename
        if path.exists():
            return path

        builtin_path = Path(__file__).parent / "builtin" / filename
        if builtin_path.exists():
            return builtin_path

        return path
