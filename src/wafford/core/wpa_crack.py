"""WPA/WPA2 password cracking module.

Orchestrates hashcat (and optionally aircrack-ng) to crack captured
handshakes using dictionary, brute-force, rule, and hybrid strategies.
Provides live progress monitoring with pause/resume/cancel and GPU
capability detection.
"""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

from wafford.constants import DEFAULT_WORDLISTS
from wafford.core.base import AttackPhase, AttackResult, BaseAttack
from wafford.exceptions import CrackError, ValidationError


@dataclass
class CrackProgress:
    """Live progress snapshot for a running crack session."""

    status: str = "idle"  # idle | running | paused | cracked | exhausted | cancelled
    cracked: bool = False
    password: str = ""
    speed_hs: float = 0.0            # guesses per second (hashcat)
    candidates_per_sec: float = 0.0  # candidates per second (aircrack)
    eta_seconds: float = 0.0
    progress_percent: float = 0.0
    guesses_total: int = 0
    guesses_checked: int = 0
    elapsed: float = 0.0
    device_name: str = ""
    recovered_hashes: int = 0

    @property
    def eta_str(self) -> str:
        if self.eta_seconds <= 0:
            return "n/a"
        hours = int(self.eta_seconds // 3600)
        minutes = int(self.eta_seconds) % 3600 // 60
        seconds = int(self.eta_seconds) % 60
        return f"{hours:02d}:{minutes:02d}:{seconds:02d}"


@dataclass
class GPUSpec:
    """A single detected compute device (GPU/CPU)."""

    index: int = 0
    name: str = ""
    device_type: str = "GPU"  # GPU | CPU
    backend: str = ""          # OpenCL/CPU
    vendor: str = ""
    devices: int = 1
    global_memory: int = 0


class WPACracker(BaseAttack):
    """Crack WPA handshake hashes with hashcat or aircrack-ng.

    The hash file can be either hc22000 (preferred) or a raw .cap.
    All strategies support an optional ``stop_password`` short-circuit and
    cooperative cancellation via :meth:`cancel`.
    """

    name = "wpa_cracker"

    HASH_MODES: dict[str, int] = {
        "wpa": 2500,
        "pmkid": 22000,
        "wpa_hc22000": 22000,
    }

    def __init__(self, hashes_file: str, *, hash_mode: str = "wpa") -> None:
        super().__init__("")  # no interface required
        self.hashes_file = hashes_file
        self.hash_mode = hash_mode
        self.progress = CrackProgress()
        self.backend: str = "hashcat"
        self._crack_task: asyncio.Task[Any] | None = None
        self._paused = asyncio.Event()
        self._paused.set()
        self._crack_proc: asyncio.subprocess.Process | None = None

    # ── Public API — dictionary attack ───────────────────────────────────

    async def dictionary_attack(
        self,
        wordlist: str | None = None,
        *,
        rules: list[str] | None = None,
        stop_password: str = "",
        max_candidates: int | None = None,
    ) -> AttackResult:
        """Run a dictionary attack against the captured hash."""
        wordlist = wordlist or self._first_available_wordlist()
        if not Path(wordlist).is_file():
            raise ValidationError(f"Wordlist not found: {wordlist}", field="wordlist")

        self._info("Dictionary attack: wordlist=%s", wordlist)
        self._emit("crack.dictionary_start", {"wordlist": wordlist})

        if self._has_hashcat():
            return await self._run_hashcat(
                self.HASH_MODES.get(self.hash_mode, 22000),
                wordlist=wordlist,
                rules=rules,
                stop_password=stop_password,
                max_candidates=max_candidates,
            )
        return await self._run_aircrack(
            wordlist,
            stop_password=stop_password,
            _max_candidates=max_candidates,
        )

    async def brute_force(
        self,
        charset: str = "abcdefghijklmnopqrstuvwxyz0123456789",
        min_length: int = 8,
        max_length: int = 8,
        *,
        stop_password: str = "",
    ) -> AttackResult:
        """Brute-force attack over *charset* for lengths min..max."""
        if min_length < 1 or max_length < min_length:
            raise ValidationError("Invalid length bounds", field="max_length")
        self._info(
            "Brute-force: charset=%d chars len=%d..%d",
            len(charset), min_length, max_length,
        )
        self._emit("crack.brute_start", {"charset": charset})

        if not self._has_hashcat():
            raise CrackError("Brute-force requires hashcat", code=41)

        mode = self.HASH_MODES.get(self.hash_mode, 22000)
        mask = "?a" * max_length  # hashcat mask covers up to max_length
        argv = self._hashcat_argv(mode, ["--increment", "--increment-min", str(min_length)]) + [
            "-a", "3", mask,
        ]
        if stop_password:
            argv += ["--potfile-disable", "--outfile-format", "2"]
        return await self._launch_hashcat(argv, stop_password)

    async def rule_attack(
        self,
        wordlist: str | None = None,
        rules_file: str = "best64",
        *,
        stop_password: str = "",
    ) -> AttackResult:
        """Apply a ruleset (best64/rockyou etc.) to a base wordlist."""
        wordlist = wordlist or self._first_available_wordlist()
        self._info("Rule attack: wordlist=%s rules=%s", wordlist, rules_file)
        self._emit("crack.rule_start", {"rules": rules_file})

        if not self._has_hashcat():
            raise CrackError("Rule attacks require hashcat", code=41)

        mode = self.HASH_MODES.get(self.hash_mode, 22000)
        argv = self._hashcat_argv(mode, []) + [
            "-a", "0", wordlist,
            "-r", rules_file,
        ]
        return await self._launch_hashcat(argv, stop_password)

    async def hybrid_attack(
        self,
        wordlist: str | None = None,
        mask: str = "?d",
        *,
        stop_password: str = "",
    ) -> AttackResult:
        """Hybrid attack — append *mask* to every known word (mode 6)."""
        wordlist = wordlist or self._first_available_wordlist()
        self._info("Hybrid attack: wordlist=%s mask=%s", wordlist, mask)
        self._emit("crack.hybrid_start", {"mask": mask})

        if not self._has_hashcat():
            raise CrackError("Hybrid attack requires hashcat", code=41)

        mode = self.HASH_MODES.get(self.hash_mode, 22000)
        argv = self._hashcat_argv(mode, []) + [
            "-a", "6", wordlist, mask,
        ]
        return await self._launch_hashcat(argv, stop_password)

    # ── Progress monitoring ───────────────────────────────────────────────

    async def monitor_progress(self) -> AsyncIterator[CrackProgress]:
        """Yield live progress snapshots until the crack ends."""
        while (self._crack_task is None or not self._crack_task.done()):
            if self._crack_proc and self._crack_proc.stdout:
                # Poll periodically; hashcat emits status lines to stderr-ish.
                pass
            self.progress.elapsed = self.status.elapsed
            yield self.progress_proxy()
            try:
                await asyncio.wait_for(self._paused.wait(), timeout=1.0)
            except TimeoutError:
                pass
        yield self.progress_proxy()

    def progress_proxy(self) -> CrackProgress:
        """Return a snapshot copy of the current progress (for UI/safety)."""
        import dataclasses as _dc

        return _dc.replace(self.progress)

    # ── Control ───────────────────────────────────────────────────────────

    async def pause(self) -> None:
        """Pause the running crack strategy."""
        self._paused.clear()
        self.progress.status = "paused"
        self._info("Crack paused")
        self._emit("crack.paused", {})

    async def resume(self) -> None:
        """Resume a paused crack strategy."""
        self._paused.set()
        self.progress.status = "running"
        self._info("Crack resumed")
        self._emit("crack.resumed", {})

    async def cancel(self) -> None:
        """Cancel the running crack strategy and kill subprocesses."""
        self._info("Cancelling crack…")
        self._cancel_event.set()
        self.progress.status = "cancelled"
        if self._crack_proc and self._crack_proc.returncode is None:
            self._crack_proc.terminate()
            try:
                await asyncio.wait_for(self._crack_proc.wait(), timeout=5)
            except TimeoutError:
                self._crack_proc.kill()
        self._emit("crack.cancelled", {})

    async def stop(self) -> None:
        await self.cancel()

    # ── Environment info ──────────────────────────────────────────────────

    async def benchmark(self, mode: int | None = None) -> AttackResult:
        """Run the hashcat benchmark for the relevant hash mode."""
        if not self._has_hashcat():
            raise CrackError("hashcat required for benchmark", code=41)
        mode = mode or self.HASH_MODES.get(self.hash_mode, 22000)
        self._info("Running hashcat benchmark (mode %d)", mode)

        argv = [
            "hashcat", "-b", "-m", str(mode),
            "--quiet", "--potfile-disable",
        ]
        rc, stdout, stderr = await self._run_cmd(argv, timeout=120)
        combined = stdout + stderr
        speed = 0.0
        m = re.search(r"(?:Speed\.dev#|Speed\.)\D*([\d.,]+)\s*([kMG]?H/s)", combined)
        if m:
            speed = self._parse_speed(m.group(1), m.group(2))
        self.progress.speed_hs = speed
        return AttackResult(
            success=rc == 0,
            message=f"Benchmark complete — {self._format_speed(speed)}",
            extra={"speed_hs": speed},
        )

    async def get_gpu_info(self) -> list[GPUSpec]:
        """Query available OpenCL devices via ``hashcat -I``."""
        if not self._has_hashcat():
            return []
        rc, stdout, stderr = await self._run_cmd(
            ["hashcat", "-I", "--quiet"], timeout=30
        )
        combined = stdout + stderr
        devices: list[GPUSpec] = []
        current: GPUSpec | None = None
        for line in combined.splitlines():
            m = re.match(r"^\s*#\s*(\d+):\s*(.+)", line)
            if m:
                if current:
                    devices.append(current)
                current = GPUSpec(index=int(m.group(1)), name=m.group(2).strip())
                continue
            m = re.search(r"Device type\s*:\s*(.+)", line, re.IGNORECASE)
            if m and current:
                current.device_type = m.group(1).strip()
            m = re.search(r"Vendor\s*:\s*(.+)", line, re.IGNORECASE)
            if m and current:
                current.vendor = m.group(1).strip()
            m = re.search(r"Global Memory size\s*:\s*([\d]+)\s*Bytes", line, re.IGNORECASE)
            if m and current:
                current.global_memory = int(m.group(1))
        if current:
            devices.append(current)
        self._info("Detected %d OpenCL device(s)", len(devices))
        return devices

    # ── Hashcat internals ─────────────────────────────────────────────────

    def _has_hashcat(self) -> bool:
        try:
            self._require_tool("hashcat")
            return True
        except Exception:
            return False

    def _hashcat_argv(self, mode: int, extra: list[str]) -> list[str]:
        return [
            "hashcat", "-m", str(mode),
            self.hashes_file,
            *extra,
            "--status", "--status-timer", "2",
            "--quiet", "--potfile-disable",
            "--force",
        ]

    async def _run_hashcat(
        self,
        mode: int,
        *,
        wordlist: str,
        rules: list[str] | None = None,
        stop_password: str = "",
        max_candidates: int | None = None,
    ) -> AttackResult:
        argv = self._hashcat_argv(mode, []) + ["-a", "0", wordlist]
        if rules:
            for r in rules:
                argv += ["-r", r]
        if stop_password:
            argv += ["--outfile-format", "2"]
        if max_candidates:
            argv += ["--skip", "0"]
        self._info("Launching hashcat: %s", " ".join(argv))
        return await self._launch_hashcat(argv, stop_password)

    async def _launch_hashcat(self, argv: list[str], stop_password: str) -> AttackResult:
        self._check_hash_file()
        self._cancel_event.clear()
        self._paused.set()
        self.status.phase = AttackPhase.RUNNING
        self._emit("attack.started")

        self._crack_proc = await asyncio.create_subprocess_exec(
            *argv,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        self._processes.append(self._crack_proc)

        password = ""
        cracked = False
        async with asyncio.timeout(3600):
            while True:
                await self._paused.wait()
                if self._cancel_event.is_set():
                    break
                if self._crack_proc.stdout is None:
                    break
                line = await self._crack_proc.stdout.readline()
                if not line:
                    break
                text = line.decode(errors="replace").strip()
                self._parse_hashcat_line(text, stop_password)
                if ":" in text and stop_password and stop_password in text.split(":")[-1]:
                    password = stop_password
                    cracked = True
                    self._info("Password found: %s", password)
                    await self._kill_crack_proc()
                    break
                if self.progress.cracked:
                    cracked = True
                    password = self.progress.password
                    await self._kill_crack_proc()
                    break

        if self._crack_proc.returncode is None:
            await self._kill_proc(self._crack_proc)
        self.progress.elapsed = self.status.elapsed
        self._emit("crack.finished", {"cracked": cracked})

        if not cracked and password and not self._cancel_event.is_set():
            cracked = True

        return AttackResult(
            success=cracked,
            message=f"Password recovered: {password}" if cracked else "Password not recovered",
            password=password,
            time_taken=self.progress.elapsed,
            extra={"progress": self.progress_proxy()},
        )

    def _parse_hashcat_line(self, line: str, _stop_password: str) -> None:
        """Parse one line of hashcat status output."""
        m = re.search(r"Speed\.\D*([\d.,]+)\s*([kMG]?H/s)", line)
        if m:
            self.progress.speed_hs = self._parse_speed(m.group(1), m.group(2))
        m = re.search(r"Time\.Estimated\.\D*\([^)]*\)\s*:\s*([\d]+)\s*sec", line)
        if m:
            self.progress.eta_seconds = float(m.group(1))
        m = re.search(r"Recovered\.\s*:\s*(\d+)/(\d+)", line)
        if m:
            self.progress.recovered_hashes = int(m.group(1))
        m = re.search(r"Progress\.\D*:\s*([\d.]+)/", line)
        if m:
            self.progress.guesses_checked = int(float(m.group(1)))
        m = re.search(r"\[(\d{1,3}(?:\.\d+)?)%\]", line)
        if m:
            self.progress.progress_percent = float(m.group(1))
        # A recovered candidate line looks like: HASH:plaintext
        m = re.match(r"^[0-9a-fA-F]{32,}:(.+)$", line.strip())
        if m:
            self.progress.password = m.group(1)
            self.progress.cracked = True
            self.progress.status = "cracked"

    async def _kill_crack_proc(self) -> None:
        if self._crack_proc and self._crack_proc.returncode is None:
            self._crack_proc.terminate()
            try:
                await asyncio.wait_for(self._crack_proc.wait(), timeout=5)
            except TimeoutError:
                self._crack_proc.kill()

    # ── aircrack fallback ─────────────────────────────────────────────────

    async def _run_aircrack(
        self,
        wordlist: str,
        *,
        stop_password: str = "",
        _max_candidates: int | None = None,
    ) -> AttackResult:
        self._require_tool("aircrack-ng")
        self._check_hash_file()
        argv = [
            "aircrack-ng", self.hashes_file,
            "-w", wordlist,
        ]
        if stop_password:
            argv += ["-n", "0"]  # no added complexity
        self._info("Launching aircrack-ng: %s", " ".join(argv))
        self.status.phase = AttackPhase.RUNNING
        self._emit("attack.started")

        rc, stdout, stderr = await self._run_cmd(argv, timeout=3600)
        combined = stdout + stderr
        password = ""
        m = re.search(r"KEY\s*FOUND!\s*\[\s*([^\]]+)\s*\]", combined, re.IGNORECASE)
        if m:
            password = m.group(1).strip()
        m = re.search(r"([0-9A-Fa-f]{8,})\s+KEY FOUND!", combined, re.IGNORECASE)
        if m and not password:
            password = m.group(1)
        cracked = bool(password)
        if cracked:
            self.progress.password = password
            self.progress.cracked = True
            self.progress.status = "cracked"
        self.progress.elapsed = self.status.elapsed
        return AttackResult(
            success=cracked,
            message=f"Password recovered: {password}" if cracked else "Password not recovered",
            password=password,
            time_taken=self.progress.elapsed,
            extra={"progress": self.progress_proxy(), "output": combined},
        )

    # ── Helpers ───────────────────────────────────────────────────────────

    def _check_hash_file(self) -> None:
        if not Path(self.hashes_file).is_file():
            raise ValidationError(f"Hash file not found: {self.hashes_file}", field="hashes_file")
        if Path(self.hashes_file).stat().st_size == 0:
            raise ValidationError(f"Hash file is empty: {self.hashes_file}", field="hashes_file")

    def _first_available_wordlist(self) -> str:
        for wl in DEFAULT_WORDLISTS:
            if Path(wl).is_file():
                return wl
        raise ValidationError(
            "No wordlists found. Use the wordlist manager or provide a path.",
            field="wordlist",
        )

    @staticmethod
    def _parse_speed(value: str, unit: str) -> float:
        multiplier = {"H/s": 1.0, "kH/s": 1e3, "MH/s": 1e6, "GH/s": 1e9}
        return float(value.replace(",", "")) * multiplier.get(unit, 1.0)

    @staticmethod
    def _format_speed(hps: float) -> str:
        if hps >= 1e9:
            return f"{hps / 1e9:.2f} GH/s"
        if hps >= 1e6:
            return f"{hps / 1e6:.2f} MH/s"
        if hps >= 1e3:
            return f"{hps / 1e3:.2f} kH/s"
        return f"{hps:.0f} H/s"

    async def _cleanup(self) -> None:
        await self._kill_crack_proc()
        await super()._cleanup()
