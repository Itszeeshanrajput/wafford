"""Configuration management for the Wafford framework."""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator

from wafford.constants import (
    BACKUP_DIR,
    DATA_DIR,
    LOG_DIR,
    PLUGIN_DIR,
    REPORT_DIR,
    TEMP_DIR,
    WAFFORD_HOME,
)

logger = logging.getLogger(__name__)

LogFormat = Literal["json", "console", "detailed"]
ReportFormat = Literal["html", "pdf", "json", "csv", "txt", "markdown", "kml", "wigle"]
Language = Literal["en", "es", "fr", "de", "pt", "ru", "zh", "ja"]
ProfileName = Literal["default", "minimal", "full"]


# ── Hardcoded sane defaults ──────────────────────────────────────────────
DEFAULT_GPS_PORT: int = 2947
DEFAULT_GPS_BAUDRATE: int = 4800
DEFAULT_MITM_PROXY_HOST: str = "127.0.0.1"
DEFAULT_MITM_PROXY_PORT: int = 8080
DEFAULT_MITM_PROXY_ENABLED: bool = False
DEFAULT_GPU_DEVICE_INDEX: int = 0
DEFAULT_CHANNEL_HOP_DWELL_MS: int = 50
DEFAULT_EAPOL_TIMEOUT_MS: int = 5000
DEFAULT_EAPOL_MAX_RETRIES: int = 3
DEFAULT_EAPOL_VALIDATION_ENABLED: bool = True


class ScanSettings(BaseModel):
    """Scanning configuration."""

    duration: int = Field(default=30, ge=5, le=600, description="Default scan duration in seconds")
    channels: list[int] = Field(default_factory=lambda: [1, 6, 11])
    auto_channels: bool = Field(default=True, description="Auto-detect channels")
    signal_threshold: int = Field(default=-80, ge=-100, le=0)
    passive: bool = Field(default=False, description="Passive scan by default")
    vendor_lookup: bool = Field(default=True)
    channel_hop_dwell_ms: int = Field(
        default=DEFAULT_CHANNEL_HOP_DWELL_MS,
        ge=10,
        le=1000,
        description="Channel hop dwell time in milliseconds",
    )


class AttackSettings(BaseModel):
    """Attack configuration."""

    deauth_packets: int = Field(default=5, ge=1, le=100)
    attack_timeout: int = Field(default=60, ge=10, le=600)
    retry_count: int = Field(default=3, ge=0, le=10)
    retry_delay: float = Field(default=2.0, ge=0.5, le=30.0)
    max_concurrent: int = Field(default=3, ge=1, le=10)
    safety_checks: bool = Field(default=True, description="Enable pre-flight safety checks")
    confirm_attacks: bool = Field(default=True, description="Confirm before launching attacks")


class CrackSettings(BaseModel):
    """Password cracking configuration."""

    wordlist_path: str = Field(default="")
    rules_path: str = Field(default="")
    hashcat_path: str = Field(default="/usr/bin/hashcat")
    john_path: str = Field(default="/usr/bin/john")
    gpu_enabled: bool = Field(default=False)
    gpu_device_index: int = Field(
        default=DEFAULT_GPU_DEVICE_INDEX,
        ge=0,
        le=15,
        description="GPU device index for hashcat/john",
    )
    cpu_threads: int = Field(default=4, ge=1, le=64)
    attack_mode: Literal["dictionary", "brute", "mask", "hybrid"] = "dictionary"


class UISettings(BaseModel):
    """User interface configuration."""

    theme: str = "DARK"
    language: Language = "en"
    show_bssid: bool = True
    show_signal: bool = True
    show_channel: bool = True
    show_encryption: bool = True
    show_vendor: bool = True
    color_output: bool = True
    table_style: str = "rounded"
    compact_mode: bool = False
    refresh_rate_ms: int = Field(default=1000, ge=100, le=5000)


class NetworkSettings(BaseModel):
    """Network and interface settings."""

    interface_timeout: int = Field(default=10, ge=1, le=60)
    channel_hop_interval: float = Field(default=0.5, ge=0.1, le=5.0)
    monitor_mode_persist: bool = False
    mac_randomize: bool = False
    preferred_interface: str = ""


class GPSSettings(BaseModel):
    """Wardriving and GPS tracking settings."""

    enabled: bool = False
    device: str = "/dev/ttyUSB0"
    baudrate: int = Field(default=DEFAULT_GPS_BAUDRATE, ge=300, le=921600)
    host: str = "127.0.0.1"
    port: int = Field(default=DEFAULT_GPS_PORT, ge=1, le=65535)
    auto_tag_networks: bool = True
    export_wigle: bool = True
    export_kml: bool = True


class MITMSettings(BaseModel):
    """Man-in-the-middle / rogue-AP proxy settings."""

    enabled: bool = Field(default=DEFAULT_MITM_PROXY_ENABLED)
    proxy_host: str = Field(default=DEFAULT_MITM_PROXY_HOST)
    proxy_port: int = Field(default=DEFAULT_MITM_PROXY_PORT, ge=1, le=65535)
    ssl_intercept: bool = Field(default=False, description="Intercept TLS traffic")
    redirect_url: str = Field(default="", description="Captive-portal redirect URL")


class EAPOLSettings(BaseModel):
    """EAPOL / 4-way handshake validation thresholds."""

    enabled: bool = Field(default=DEFAULT_EAPOL_VALIDATION_ENABLED)
    timeout_ms: int = Field(default=DEFAULT_EAPOL_TIMEOUT_MS, ge=500, le=30000)
    max_retries: int = Field(default=DEFAULT_EAPOL_MAX_RETRIES, ge=0, le=10)
    min_mic_valid: bool = Field(default=True, description="Require valid MIC in handshake")


class AutoPWNSettings(BaseModel):
    """Automated audit pipeline settings."""

    enabled: bool = False
    auto_deauth: bool = True
    auto_pmkid: bool = True
    auto_crack: bool = True
    max_targets: int = Field(default=5, ge=1, le=50)
    dwell_time_sec: int = Field(default=45, ge=10, le=300)
    deauth_rounds: int = Field(default=3, ge=1, le=20)
    wordlist_path: str = "/usr/share/wordlists/rockyou.txt"


class LogSettings(BaseModel):
    """Logging configuration."""

    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"
    log_format: LogFormat = "detailed"
    log_to_file: bool = True
    log_to_console: bool = True
    max_log_size_mb: int = Field(default=50, ge=1, le=1000)
    log_rotation: int = Field(default=5, ge=1, le=100)
    scan_log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "DEBUG"


class ReportSettings(BaseModel):
    """Report generation configuration."""

    report_format: ReportFormat = "html"
    output_dir: str = str(REPORT_DIR)
    include_screenshots: bool = False
    include_raw_data: bool = False
    company_name: str = "Wafford Audit"
    author: str = ""


class UpdateSettings(BaseModel):
    """Auto-update configuration."""

    auto_update: bool = True
    check_interval_hours: int = Field(default=24, ge=1, le=168)
    notify_only: bool = False


class WaffordConfig(BaseModel):
    """Root configuration model for Wafford."""

    scan: ScanSettings = Field(default_factory=ScanSettings)
    attack: AttackSettings = Field(default_factory=AttackSettings)
    crack: CrackSettings = Field(default_factory=CrackSettings)
    ui: UISettings = Field(default_factory=UISettings)
    network: NetworkSettings = Field(default_factory=NetworkSettings)
    gps: GPSSettings = Field(default_factory=GPSSettings)
    mitm: MITMSettings = Field(default_factory=MITMSettings)
    eapol: EAPOLSettings = Field(default_factory=EAPOLSettings)
    autopwn: AutoPWNSettings = Field(default_factory=AutoPWNSettings)
    logging: LogSettings = Field(default_factory=LogSettings)
    report: ReportSettings = Field(default_factory=ReportSettings)
    update: UpdateSettings = Field(default_factory=UpdateSettings)

    plugin_dir: str = str(PLUGIN_DIR)
    data_dir: str = str(DATA_DIR)

    # Typos in a security-tool configuration must fail fast rather than
    # silently producing an unexpected audit run.
    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    @field_validator("plugin_dir", "data_dir", mode="before")
    @classmethod
    def _expand_path(cls, v: Any) -> str:
        return str(Path(v).expanduser().resolve())


# ── Named profiles ────────────────────────────────────────────────────────

_PROFILES: dict[ProfileName, dict[str, Any]] = {
    "default": {},
    "minimal": {
        "scan": {"duration": 20, "channels": [1, 6, 11], "vendor_lookup": False},
        "attack": {"deauth_packets": 3, "attack_timeout": 30, "safety_checks": True},
        "crack": {"gpu_enabled": False, "cpu_threads": 2},
        "ui": {"theme": "DEFAULT", "color_output": False, "compact_mode": True},
        "network": {"preferred_interface": ""},
        "gps": {"enabled": False},
        "mitm": {"enabled": False},
        "eapol": {"enabled": True},
        "logging": {"log_level": "WARNING", "log_to_file": False},
        "report": {"include_screenshots": False, "include_raw_data": False},
    },
    "full": {
        "scan": {"duration": 120, "channels": [1, 6, 11], "auto_channels": True},
        "attack": {"deauth_packets": 10, "attack_timeout": 120, "max_concurrent": 5},
        "crack": {"gpu_enabled": True, "cpu_threads": 8, "attack_mode": "hybrid"},
        "ui": {"theme": "DARK", "show_bssid": True, "show_signal": True, "show_channel": True},
        "network": {"monitor_mode_persist": True, "mac_randomize": True},
        "gps": {"enabled": True, "auto_tag_networks": True},
        "mitm": {"enabled": True, "ssl_intercept": True},
        "eapol": {"enabled": True, "max_retries": 5},
        "autopwn": {"enabled": True, "max_targets": 10},
        "logging": {"log_level": "DEBUG", "log_format": "detailed"},
    },
}

# ── Environment-variable → dotted-key mapping ─────────────────────────────
# Any WAFFORD_*(section)_(key) env-var is mapped automatically, but we
# keep an explicit alias table for short-form vars and legacy names.

_ENV_ALIAS_MAP: dict[str, str] = {
    "WAFFORD_HOME": "_home",
    "WAFFORD_CONFIG": "_config_path",
    "WAFFORD_LOG_LEVEL": "logging.log_level",
    "WAFFORD_THEME": "ui.theme",
    "WAFFORD_WORDLIST": "crack.wordlist_path",
    "WAFFORD_INTERFACE": "network.preferred_interface",
    "WAFFORD_GPS_PORT": "gps.port",
    "WAFFORD_GPS_HOST": "gps.host",
    "WAFFORD_MITM_HOST": "mitm.proxy_host",
    "WAFFORD_MITM_PORT": "mitm.proxy_port",
    "WAFFORD_GPU_INDEX": "crack.gpu_device_index",
    "WAFFORD_CHANNEL_DWELL": "scan.channel_hop_dwell_ms",
    "WAFFORD_EAPOL_TIMEOUT": "eapol.timeout_ms",
}


class ConfigManager:
    """Manages loading, saving, and accessing the Wafford configuration."""

    _instance: WaffordConfig | None = None

    def __init__(
        self,
        config_path: Path | str | None = None,
        profile: ProfileName | str = "default",
        *,
        headless: bool = False,
    ) -> None:
        self._env_overrides: dict[str, str] = {}
        self._env_key_map = dict(_ENV_ALIAS_MAP)
        self._load_env_overrides()

        if config_path is not None:
            self._config_path = Path(config_path)
        else:
            env_path = self._env_overrides.get("WAFFORD_CONFIG")
            self._config_path = Path(env_path) if env_path else WAFFORD_HOME / "config.yaml"

        self._profile: ProfileName = self._resolve_profile(profile)
        self._headless: bool = headless
        self._config: WaffordConfig | None = None

    # ── Profile resolution ───────────────────────────────────────────────
    @staticmethod
    def _resolve_profile(name: ProfileName | str) -> ProfileName:
        if name in _PROFILES:
            return name
        logger.warning("Unknown profile %r, falling back to 'default'", name)
        return "default"

    @classmethod
    def list_profiles(cls) -> list[str]:
        """Return the names of all registered profiles."""
        return list(_PROFILES)

    # ── Environment overrides ────────────────────────────────────────────
    def _load_env_overrides(self) -> None:
        for env_var, _key in self._env_key_map.items():
            val = os.environ.get(env_var)
            if val:
                self._env_overrides[env_var] = val

        # Generic WAFFORD_ prefix scan (section_key → section.key)
        prefix = "WAFFORD_"
        known = set(self._env_key_map)
        for env_key, env_val in os.environ.items():
            if env_key.startswith(prefix) and env_key not in known and env_val:
                rest = env_key[len(prefix):].lower()
                dotted = rest.replace("__", ".").replace("_", ".")
                self._env_overrides[env_key] = env_val
                self._env_key_map[env_key] = dotted

    # ── Core accessors ───────────────────────────────────────────────────
    @property
    def config(self) -> WaffordConfig:
        if self._config is None:
            raise RuntimeError("Configuration not loaded. Call load() first.")
        return self._config

    @property
    def profile(self) -> ProfileName:
        return self._profile

    @property
    def is_headless(self) -> bool:
        return self._headless

    @classmethod
    def get_instance(cls) -> WaffordConfig:
        if cls._instance is None:
            mgr = cls()
            mgr.load()
            cls._instance = mgr.config
        return cls._instance

    @classmethod
    def reset_instance(cls) -> None:
        cls._instance = None

    # ── Load / Save ──────────────────────────────────────────────────────
    def load(self) -> WaffordConfig:
        self._ensure_directories()

        if self._config_path.exists():
            try:
                raw = self._config_path.read_text(encoding="utf-8")
                data = yaml.safe_load(raw) or {}
                logger.debug("Loaded config from %s", self._config_path)
            except (yaml.YAMLError, OSError) as exc:
                logger.warning("Failed to load config from %s: %s", self._config_path, exc)
                data = {}
        else:
            data = {}
            logger.info("No config found, using defaults")

        # Layer: profile defaults → file → env overrides
        profile_data = dict(_PROFILES.get(self._profile, {}))
        merged = self._deep_merge(profile_data, data)
        merged = self._apply_env_overrides(merged)

        self._config = WaffordConfig(**merged)
        ConfigManager._instance = self._config
        return self._config

    def save(self) -> None:
        self._ensure_directories()
        data = self.config.model_dump(mode="json")
        try:
            self._config_path.parent.mkdir(parents=True, exist_ok=True)
            with self._config_path.open("w", encoding="utf-8") as fh:
                yaml.dump(data, fh, default_flow_style=False, sort_keys=False, allow_unicode=True)
            logger.info("Config saved to %s", self._config_path)
        except OSError as exc:
            logger.error("Failed to save config: %s", exc)
            raise

    def reset(self) -> WaffordConfig:
        self._config = WaffordConfig()
        if self._config_path.exists():
            self._config_path.unlink()
        self.save()
        logger.info("Config reset to defaults")
        return self._config

    # ── Validation ───────────────────────────────────────────────────────
    def validate(self) -> list[str]:
        """Validate the loaded config and return a list of warning messages.

        Pydantic already enforces type/range constraints at construction time.
        This method catches *semantic* issues (e.g. missing wordlist file,
        GPS device path unreachable) and returns human-readable warnings.
        """
        warnings: list[str] = []
        cfg = self.config

        # Wordlist existence
        wl = Path(cfg.crack.wordlist_path)
        if cfg.crack.wordlist_path and not wl.is_file():
            warnings.append(f"Wordlist not found: {wl}")

        # GPS device
        if cfg.gps.enabled:
            dev = Path(cfg.gps.device)
            if not dev.exists():
                warnings.append(f"GPS device not found: {dev}")

        # Report output dir
        out = Path(cfg.report.output_dir)
        if not out.is_dir():
            warnings.append(f"Report output directory missing: {out}")

        if warnings:
            for w in warnings:
                logger.warning("Config validation: %s", w)
        return warnings

    # ── Minconfig / headless ─────────────────────────────────────────────
    @classmethod
    def minconfig(cls) -> dict[str, Any]:
        """Return a minimal, lightweight configuration dictionary."""
        return {
            "scan": {
                "duration": 20,
                "channels": [1, 6, 11],
                "channel_hop_dwell_ms": DEFAULT_CHANNEL_HOP_DWELL_MS,
            },
            "attack": {"deauth_packets": 5, "attack_timeout": 30},
            "crack": {
                "wordlist_path": "/usr/share/wordlists/rockyou.txt",
                "gpu_enabled": False,
                "gpu_device_index": DEFAULT_GPU_DEVICE_INDEX,
            },
            "ui": {"theme": "DEFAULT", "language": "en", "color_output": False},
            "network": {"preferred_interface": ""},
            "gps": {"enabled": False},
            "mitm": {"enabled": False},
            "eapol": {
                "enabled": True,
                "timeout_ms": DEFAULT_EAPOL_TIMEOUT_MS,
                "max_retries": DEFAULT_EAPOL_MAX_RETRIES,
            },
            "logging": {"log_level": "INFO", "log_to_file": True},
        }

    @classmethod
    def load_headless(cls) -> WaffordConfig:
        """Load config in headless mode: minconfig merged with file + env."""
        mgr = cls(headless=True)
        return mgr.load()

    # ── Helpers ──────────────────────────────────────────────────────────
    def _apply_env_overrides(self, data: dict[str, Any]) -> dict[str, Any]:
        for env_var, dotted_key in self._env_key_map.items():
            if dotted_key in ("_home", "_config_path"):
                continue
            val = self._env_overrides.get(env_var)
            if val is None:
                continue
            keys = dotted_key.split(".")
            target: Any = data
            for k in keys[:-1]:
                target = target.setdefault(k, {})
            # coerce to int when the leaf field is numeric
            coerced: Any = val
            leaf = keys[-1]
            if coerced.isdigit() or (coerced.startswith("-") and coerced[1:].isdigit()):
                coerced = int(coerced)
            target[leaf] = coerced
        return data

    @staticmethod
    def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
        merged = dict(base)
        for key, val in override.items():
            if key in merged and isinstance(merged[key], dict) and isinstance(val, dict):
                merged[key] = ConfigManager._deep_merge(merged[key], val)
            else:
                merged[key] = val
        return merged

    @staticmethod
    def _ensure_directories() -> None:
        dirs = (WAFFORD_HOME, DATA_DIR, LOG_DIR, REPORT_DIR, PLUGIN_DIR, BACKUP_DIR, TEMP_DIR)
        for directory in dirs:
            directory.mkdir(parents=True, exist_ok=True)

    def get(self, dotted_key: str, default: Any = None) -> Any:
        """Access a nested config value using dot notation, e.g. 'scan.duration'."""
        keys = dotted_key.split(".")
        obj: Any = self.config
        for key in keys:
            if isinstance(obj, dict):
                obj = obj.get(key, None)
            elif hasattr(obj, key):
                obj = getattr(obj, key)
            else:
                return default
            if obj is None:
                return default
        return obj

    def set(self, dotted_key: str, value: Any) -> None:
        """Set a nested config value using dot notation."""
        keys = dotted_key.split(".")
        obj: Any = self.config
        for key in keys[:-1]:
            if hasattr(obj, key):
                obj = getattr(obj, key)
            else:
                raise KeyError(f"Invalid config path: {dotted_key}")
        final = keys[-1]
        if hasattr(obj, final):
            setattr(obj, final, value)
        else:
            raise KeyError(f"Unknown config key: {final}")

    def to_dict(self) -> dict[str, Any]:
        return self.config.model_dump(mode="json")

    def __repr__(self) -> str:
        return (
            f"ConfigManager(path={self._config_path}, "
            f"profile={self._profile!r}, headless={self._headless})"
        )
