"""Built-in plugin — Convert captured WPA handshakes to hashcat-compatible .hc22000 files."""

from __future__ import annotations

import struct
from pathlib import Path
from typing import Any

from wafford.plugins.api import (
    PluginBase,
    PluginContext,
)


class HandshakeToHashcatPlugin(PluginBase):
    name = "handshake_to_hashcat"
    version = "1.0.0"
    author = "Wafford Core"
    description = "Convert pcap/ng handshake captures to hashcat .hc22000 format"
    min_wafford_version = "0.1.0"

    SUPPORTED_EXTS = {".pcap", ".pcapng", ".cap"}
    OUTPUT_EXT = ".hc22000"

    def on_load(self, context: PluginContext) -> None:
        super().on_load(context)
        context.info("Handshake-to-hashcat converter loaded")

    def on_enable(self) -> None:
        super().on_enable()
        self._logger.info("Plugin enabled")

    def on_disable(self) -> None:
        super().on_disable()

    # ------------------------------------------------------------------
    # Core conversion logic
    # ------------------------------------------------------------------

    def convert(
        self,
        input_path: str,
        output_path: str | None = None,
        *,
        bssid: str | None = None,
        essid: str | None = None,
    ) -> str:
        """Convert a pcap capture to .hc22000. Returns the output path."""
        inp = Path(input_path)
        if not inp.exists():
            raise FileNotFoundError(f"Capture file not found: {input_path}")
        if inp.suffix.lower() not in self.SUPPORTED_EXTS:
            raise ValueError(
                f"Unsupported format '{inp.suffix}'. Expected one of {self.SUPPORTED_EXTS}"
            )

        if output_path is None:
            output_path = str(inp.with_suffix(self.OUTPUT_EXT))

        handshake_data = self._extract_handshake_data(inp)
        if not handshake_data:
            raise ValueError(
                "No valid WPA handshake found in the capture file. "
                "Ensure the capture contains a complete 4-way handshake."
            )

        hc22000_line = self._build_hashcat_line(
            handshake_data,
            bssid=bssid,
            essid=essid,
        )

        Path(output_path).write_text(hc22000_line + "\n", encoding="utf-8")
        self._logger.info("Converted %s -> %s", input_path, output_path)
        return output_path

    def _extract_handshake_data(self, pcap_path: Path) -> dict[str, Any] | None:
        """Parse pcap and extract EAPOL handshake messages.

        Returns a dict with keys: anonce, snonce, mic, eapol_frame, key_data
        or *None* if no complete handshake is found.
        """
        data = pcap_path.read_bytes()
        if len(data) < 24:
            return None

        # Detect pcap global header magic.
        magic = struct.unpack_from("<I", data, 0)[0]
        if magic == 0xA1B2C3D4:
            big_endian = False
            link_type_offset = 20
        elif magic == 0xD4C3B2A1:
            big_endian = True
            link_type_offset = 20
        elif data[:4] == b"\x0a\x0d\x0d\x0a":
            # pcapng — use simplified detection
            return self._parse_pcapng(data)
        else:
            return None

        link_type = struct.unpack_from(">I" if big_endian else "<I", data, link_type_offset)[0]
        if link_type != 105:
            # 105 = LINKTYPE_IEEE802_11_RADIOTAP
            return None

        return self._parse_radiotap_frames(data, big_endian)

    def _parse_pcapng(self, data: bytes) -> dict[str, Any] | None:
        """Minimal pcapng parser that extracts EAPOL frames."""
        pos = 0
        eapol_frames: list = []
        while pos + 8 <= len(data):
            block_type = struct.unpack_from("<I", data, pos)[0]
            block_len = struct.unpack_from("<I", data, pos + 4)[0]
            if block_len < 12 or pos + block_len > len(data):
                break
            if block_type == 6:  # Enhanced Packet Block
                epb = data[pos + 8 : pos + block_len]
                if len(epb) > 8:
                    cap_len = struct.unpack_from("<I", epb, 8)[0]
                    pkt = epb[12 : 12 + cap_len]
                    if self._is_eapol(pkt):
                        eapol_frames.append(pkt)
            pos += block_len
            # Blocks are 4-byte aligned.
            pos = (pos + 3) & ~3

        return self._frames_to_handshake(eapol_frames)

    def _parse_radiotap_frames(
        self, data: bytes, big_endian: bool
    ) -> dict[str, Any] | None:
        """Parse radiotap capture and find EAPOL frames."""
        pos = 24  # skip pcap global header
        eapol_frames: list = []
        fmt = ">" if big_endian else "<"

        while pos + 8 <= len(data):
            hdr = struct.unpack_from(f"{fmt}IhhiII", data, pos)
            incl_len = hdr[2]
            if incl_len <= 0 or pos + 8 + incl_len > len(data):
                break
            pkt_data = data[pos + 8 : pos + 8 + incl_len]
            if self._is_eapol(pkt_data):
                eapol_frames.append(pkt_data)
            pos += 8 + incl_len

        return self._frames_to_handshake(eapol_frames)

    def _is_eapol(self, frame: bytes) -> bool:
        """Check if a raw 802.11 frame contains an EAPOL payload."""
        if len(frame) < 30:
            return False
        # Radiotap header: check if there's enough for dot11 header
        try:
            rt_len = struct.unpack_from("<H", frame, 0)[0]
        except struct.error:
            return False
        if rt_len >= len(frame):
            return False
        dot11 = frame[rt_len:]
        if len(dot11) < 24:
            return False
        # Frame control: check for data frame (type 2)
        fc = struct.unpack_from("<H", dot11, 0)[0]
        frame_type = (fc >> 2) & 0x3
        if frame_type != 2:
            return False
        # Check for EAPOL Ethertype (0x888e) in the LLC/SNAP header
        # Skip 802.11 header (24 bytes) + possibly 4-byte QoS
        offset = 24
        fc_subtype = fc & 0xF
        if fc_subtype == 8:  # QoS data
            offset += 4
        # Check for IV in CCMP/TKIP
        if len(dot11) > offset + 8:
            snap = dot11[offset:]
            if len(snap) >= 8:
                dsap = snap[0]
                ssap = snap[1]
                if dsap == 0xAA and ssap == 0xAA:
                    # LLC/SNAP
                    ethertype = struct.unpack_from(">H", snap, 6)[0]
                    return ethertype == 0x888E
        return False

    def _frames_to_handshake(
        self, frames: list
    ) -> dict[str, Any] | None:
        """Extract EAPOL key data from collected frames."""
        if len(frames) < 2:
            return None
        results: dict[str, Any] = {
            "anonce": b"",
            "snonce": b"",
            "mic": b"",
            "eapol_frames": [],
        }
        for frame in frames:
            rt_len = struct.unpack_from("<H", frame, 0)[0]
            dot11 = frame[rt_len:]
            offset = 24
            if len(dot11) > offset + 8:
                snap = dot11[offset:]
                if len(snap) >= 8:
                    dsap = snap[0]
                    ssap = snap[1]
                    if dsap == 0xAA and ssap == 0xAA:
                        offset += 8  # skip LLC/SNAP
            eapol = dot11[offset:]
            if len(eapol) < 99:
                continue
            eapol_ver = eapol[0]
            pkt_type = eapol[1]
            if eapol_ver == 2 and pkt_type == 3:
                # EAPOL-Key
                key_info = struct.unpack_from(">H", eapol, 5)[0]
                key_mic_offset = 77
                anonce_offset = 13
                snonce_offset = 13
                if key_info & 0x8000:
                    # AP -> STA (ANonce)
                    results["anonce"] = eapol[anonce_offset : anonce_offset + 32]
                else:
                    # STA -> AP (SNonce + MIC)
                    results["snonce"] = eapol[snonce_offset : snonce_offset + 32]
                    results["mic"] = eapol[key_mic_offset : key_mic_offset + 16]
                results["eapol_frames"].append(eapol)

        if not results["anonce"] or not results["snonce"] or not results["mic"]:
            return None
        return results

    def _build_hashcat_line(
        self,
        data: dict[str, Any],
        *,
        bssid: str | None = None,
        essid: str | None = None,
    ) -> str:
        """Build the .hc22000 line: WPA*type*pmkid*mac*ssid*nonce*eapol*mic*icver*algo*keyver*keywrap."""
        eapol_combined = b""
        for frame in data["eapol_frames"]:
            eapol_combined = frame
            break

        eapol_hex = eapol_combined.hex()
        anonce_hex = data["anonce"].hex()
        snonce_hex = data["snonce"].hex()
        mic_hex = data["mic"].hex()
        bssid_hex = (bssid or "000000000000").replace(":", "")
        essid_field = essid or ""

        return (
            f"WPA*1*{mic_hex}*{bssid_hex}*{essid_field}*"
            f"{snonce_hex}*{eapol_hex}*{anonce_hex}*00*02*00"
        )

    def batch_convert(self, directory: str, **kwargs: Any) -> dict[str, str]:
        """Convert all supported files in *directory*."""
        results: dict[str, str] = {}
        d = Path(directory)
        for f in sorted(d.iterdir()):
            if f.suffix.lower() in self.SUPPORTED_EXTS:
                try:
                    out = self.convert(str(f), **kwargs)
                    results[f.name] = out
                except Exception as exc:
                    self._logger.error("Failed to convert %s: %s", f.name, exc)
                    results[f.name] = f"ERROR: {exc}"
        return results
