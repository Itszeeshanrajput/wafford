"""Built-in plugin — Enrich scanned networks with GPS coordinates."""

from __future__ import annotations

import json
import logging
import threading
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from wafford.plugins.api import (
    PluginBase,
    PluginContext,
    register_hook,
    register_network_field,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class GPSCoordinate:
    latitude: float
    longitude: float
    altitude: float = 0.0
    accuracy: float = 0.0
    timestamp: str = field(default_factory=lambda: datetime.now(UTC).isoformat())

    def to_dict(self) -> dict[str, Any]:
        return {
            "latitude": self.latitude,
            "longitude": self.longitude,
            "altitude": self.altitude,
            "accuracy": self.accuracy,
            "timestamp": self.timestamp,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> GPSCoordinate:
        return cls(
            latitude=float(d.get("latitude", 0.0)),
            longitude=float(d.get("longitude", 0.0)),
            altitude=float(d.get("altitude", 0.0)),
            accuracy=float(d.get("accuracy", 0.0)),
            timestamp=d.get("timestamp", ""),
        )


@dataclass
class TaggedNetwork:
    bssid: str
    essid: str
    gps: GPSCoordinate
    signal_dbm: int = -100
    channel: int = 0
    encryption: str = ""
    first_seen: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    last_seen: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "bssid": self.bssid,
            "essid": self.essid,
            "gps": self.gps.to_dict(),
            "signal_dbm": self.signal_dbm,
            "channel": self.channel,
            "encryption": self.encryption,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "notes": self.notes,
        }


# ---------------------------------------------------------------------------
# GPS Source backends
# ---------------------------------------------------------------------------

class GPSSourceBase(PluginBase):
    """Minimal base for GPS provider plugins used by GPSTagger."""
    def get_location(self) -> GPSCoordinate | None:
        raise NotImplementedError


class NullGPSSource(GPSSourceBase):
    name = "null_gps"
    def get_location(self) -> GPSCoordinate | None:
        return None


class GPSTtySource(GPSSourceBase):
    """Read NMEA sentences from a serial TTY device."""

    name = "gps_tty"

    def __init__(self, device: str = "/dev/ttyUSB0", baud: int = 9600) -> None:
        super().__init__()
        self._device = device
        self._baud = baud
        self._lock = threading.Lock()

    def get_location(self) -> GPSCoordinate | None:
        try:
            import serial  # type: ignore[import-untyped]
        except ImportError:
            logger.warning("pyserial not installed — GPS TTY unavailable")
            return None

        with self._lock:
            try:
                with serial.Serial(self._device, self._baud, timeout=2) as ser:
                    for _ in range(30):
                        line = ser.readline().decode("ascii", errors="ignore").strip()
                        if line.startswith(("$GPGGA", "$GNGGA")):
                            return self._parse_gpgga(line)
            except Exception as exc:
                logger.error("GPS TTY read error: %s", exc)
        return None

    @staticmethod
    def _parse_gpgga(sentence: str) -> GPSCoordinate | None:
        parts = sentence.split(",")
        if len(parts) < 15:
            return None
        try:
            lat_raw = parts[2]
            lat_dir = parts[3]
            lon_raw = parts[4]
            lon_dir = parts[5]
            alt = float(parts[9]) if parts[9] else 0.0

            lat_deg = int(lat_raw[:2])
            lat_min = float(lat_raw[2:])
            latitude = lat_deg + lat_min / 60.0
            if lat_dir == "S":
                latitude = -latitude

            lon_deg = int(lon_raw[:3])
            lon_min = float(lon_raw[3:])
            longitude = lon_deg + lon_min / 60.0
            if lon_dir == "W":
                longitude = -longitude

            return GPSCoordinate(
                latitude=round(latitude, 8),
                longitude=round(longitude, 8),
                altitude=alt,
            )
        except (ValueError, IndexError):
            return None


class GPSFileSource(GPSSourceBase):
    """Read the latest GPS fix from a JSON file."""

    name = "gps_file"

    def __init__(self, path: str = "") -> None:
        super().__init__()
        self._path = Path(path)

    def get_location(self) -> GPSCoordinate | None:
        if not self._path.exists():
            return None
        try:
            data = json.loads(self._path.read_text(encoding="utf-8"))
            return GPSCoordinate.from_dict(data)
        except Exception as exc:
            logger.error("GPS file read error: %s", exc)
            return None


# ---------------------------------------------------------------------------
# Main plugin
# ---------------------------------------------------------------------------

class GPSTaggerPlugin(PluginBase):
    name = "gps_tagger"
    version = "1.0.0"
    author = "Wafford Core"
    description = "Tag scanned networks with GPS coordinates from multiple backends"
    min_wafford_version = "0.1.0"

    def __init__(self) -> None:
        super().__init__()
        self._tagged: dict[str, TaggedNetwork] = {}
        self._source: GPSSourceBase = NullGPSSource()
        self._output_path: str = ""
        self._auto_tag = True
        self._lock = threading.Lock()

    def on_load(self, context: PluginContext) -> None:
        super().on_load(context)
        self._output_path = context.config.get(
            "gps_tagger_output",
            str(Path.home() / ".wafford" / "data" / "tagged_networks.json"),
        )
        source_type = context.config.get("gps_source", "file")
        self._auto_tag = context.config.get("gps_auto_tag", True)
        self._source = self._create_source(source_type, context.config)
        self._load_existing()
        context.info("GPS Tagger loaded (source=%s, auto=%s)", source_type, self._auto_tag)

    def on_enable(self) -> None:
        super().on_enable()

    def on_disable(self) -> None:
        self._save()
        super().on_disable()

    def on_unload(self) -> None:
        self._save()
        super().on_unload()

    # -- source factory -----------------------------------------------------

    @staticmethod
    def _create_source(source_type: str, config: dict[str, Any]) -> GPSSourceBase:
        if source_type == "tty":
            return GPSTtySource(
                device=config.get("gps_tty_device", "/dev/ttyUSB0"),
                baud=config.get("gps_tty_baud", 9600),
            )
        if source_type == "file":
            return GPSFileSource(
                path=config.get("gps_file_path", "")
            )
        return NullGPSSource()

    # -- public API ---------------------------------------------------------

    def tag_network(
        self,
        bssid: str,
        essid: str = "",
        signal_dbm: int = -100,
        channel: int = 0,
        encryption: str = "",
        notes: str = "",
    ) -> TaggedNetwork | None:
        """Tag a network with the current GPS fix."""
        gps = self._source.get_location()
        if gps is None:
            logger.debug("No GPS fix available for tagging %s", bssid)
            return None

        bssid_norm = bssid.upper().replace("-", ":")
        now = datetime.now(UTC).isoformat()

        with self._lock:
            if bssid_norm in self._tagged:
                existing = self._tagged[bssid_norm]
                existing.gps = gps
                existing.last_seen = now
                existing.signal_dbm = signal_dbm
                if notes:
                    existing.notes = notes
                tagged = existing
            else:
                tagged = TaggedNetwork(
                    bssid=bssid_norm,
                    essid=essid,
                    gps=gps,
                    signal_dbm=signal_dbm,
                    channel=channel,
                    encryption=encryption,
                    first_seen=now,
                    last_seen=now,
                    notes=notes,
                )
                self._tagged[bssid_norm] = tagged

        self._save()
        return tagged

    def get_tagged(self, bssid: str) -> TaggedNetwork | None:
        bssid_norm = bssid.upper().replace("-", ":")
        with self._lock:
            return self._tagged.get(bssid_norm)

    def get_all_tagged(self) -> list[TaggedNetwork]:
        with self._lock:
            return list(self._tagged.values())

    def search_by_proximity(
        self, lat: float, lon: float, radius_m: float = 1000.0
    ) -> list[tuple[TaggedNetwork, float]]:
        """Return tagged networks within *radius_m* metres of (lat, lon)."""
        results: list[tuple[TaggedNetwork, float]] = []
        with self._lock:
            for net in self._tagged.values():
                dist = self._haversine(lat, lon, net.gps.latitude, net.gps.longitude)
                if dist <= radius_m:
                    results.append((net, dist))
        results.sort(key=lambda t: t[1])
        return results

    def export_geojson(self) -> dict[str, Any]:
        """Export all tagged networks as GeoJSON FeatureCollection."""
        features: list[dict[str, Any]] = []
        with self._lock:
            for net in self._tagged.values():
                features.append(
                    {
                        "type": "Feature",
                        "geometry": {
                            "type": "Point",
                            "coordinates": [
                                net.gps.longitude,
                                net.gps.latitude,
                                net.gps.altitude,
                            ],
                        },
                        "properties": {
                            "bssid": net.bssid,
                            "essid": net.essid,
                            "signal_dbm": net.signal_dbm,
                            "channel": net.channel,
                            "encryption": net.encryption,
                            "first_seen": net.first_seen,
                            "last_seen": net.last_seen,
                            "notes": net.notes,
                        },
                    }
                )
        return {"type": "FeatureCollection", "features": features}

    # -- hooks --------------------------------------------------------------

    @register_hook("scan_result", priority=10)
    def _on_scan_result(self, result: dict[str, Any]) -> None:
        if not self._auto_tag:
            return
        self.tag_network(
            bssid=result.get("bssid", ""),
            essid=result.get("essid", ""),
            signal_dbm=result.get("signal_dbm", -100),
            channel=result.get("channel", 0),
            encryption=result.get("encryption", ""),
        )

    @register_network_field("gps_location", label="GPS Location", order=50)
    def _network_field_gps(self, network: dict[str, Any]) -> str:
        bssid = network.get("bssid", "")
        tagged = self.get_tagged(bssid)
        if tagged:
            return f"{tagged.gps.latitude:.6f}, {tagged.gps.longitude:.6f}"
        return ""

    # -- persistence --------------------------------------------------------

    def _load_existing(self) -> None:
        p = Path(self._output_path)
        if not p.exists():
            return
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
            for item in data:
                tn = TaggedNetwork(
                    bssid=item["bssid"],
                    essid=item.get("essid", ""),
                    gps=GPSCoordinate.from_dict(item.get("gps", {})),
                    signal_dbm=item.get("signal_dbm", -100),
                    channel=item.get("channel", 0),
                    encryption=item.get("encryption", ""),
                    first_seen=item.get("first_seen", ""),
                    last_seen=item.get("last_seen", ""),
                    notes=item.get("notes", ""),
                )
                self._tagged[tn.bssid] = tn
            logger.info("Loaded %d previously tagged networks", len(self._tagged))
        except Exception as exc:
            logger.error("Failed to load tagged networks: %s", exc)

    def _save(self) -> None:
        p = Path(self._output_path)
        p.parent.mkdir(parents=True, exist_ok=True)
        with self._lock:
            data = [tn.to_dict() for tn in self._tagged.values()]
        p.write_text(json.dumps(data, indent=2), encoding="utf-8")

    # -- utilities ----------------------------------------------------------

    @staticmethod
    def _haversine(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
        """Distance in metres between two GPS coordinates."""
        import math
        r = 6_371_000
        phi1, phi2 = math.radians(lat1), math.radians(lat2)
        delta_phi = math.radians(lat2 - lat1)
        delta_lambda = math.radians(lon2 - lon1)
        a = math.sin(delta_phi / 2) ** 2 + math.cos(phi1) * math.cos(phi2) * math.sin(delta_lambda / 2) ** 2
        return r * 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
