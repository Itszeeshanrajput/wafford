"""Shared base classes and infrastructure for all attack modules."""

from __future__ import annotations

import asyncio
import enum
import logging
import os
import shutil
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from wafford.constants import TOOL_PATHS
from wafford.exceptions import (
    AttackError,
    ToolNotFoundError,
    ValidationError,
)
from wafford.exceptions import (
    PermissionError as WaffordPermissionError,
)

logger = logging.getLogger("wafford.core")


# ── Event system ──────────────────────────────────────────────────────────────


class Event:
    """A single event emitted by an attack module."""

    __slots__ = ("source", "kind", "data", "timestamp")

    def __init__(self, source: str, kind: str, data: dict[str, Any] | None = None) -> None:
        self.source = source
        self.kind = kind
        self.data = data or {}
        self.timestamp = time.time()

    def __repr__(self) -> str:
        return f"Event({self.source!r}, {self.kind!r}, {self.data})"


EventCallback = Callable[[Event], Any]


class EventBus:
    """Lightweight synchronous pub/sub event bus shared across all modules."""

    _instance: EventBus | None = None

    def __init__(self) -> None:
        self._listeners: dict[str, list[EventCallback]] = {}
        self._wildcard: list[EventCallback] = []

    @classmethod
    def get(cls) -> EventBus:
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def on(self, kind: str, callback: EventCallback) -> None:
        self._listeners.setdefault(kind, []).append(callback)

    def on_all(self, callback: EventCallback) -> None:
        self._wildcard.append(callback)

    def off(self, kind: str, callback: EventCallback) -> None:
        cbs = self._listeners.get(kind, [])
        if callback in cbs:
            cbs.remove(callback)

    def emit(self, event: Event) -> None:
        for cb in self._listeners.get(event.kind, []):
            try:
                cb(event)
            except Exception:
                logger.exception("EventBus listener error for kind=%s", event.kind)
        for cb in self._wildcard:
            try:
                cb(event)
            except Exception:
                logger.exception("EventBus wildcard listener error")


# ── Enums and data models ─────────────────────────────────────────────────────


class AttackPhase(enum.Enum):
    """Lifecycle phases of an attack."""

    IDLE = "idle"
    VALIDATING = "validating"
    STARTING = "starting"
    RUNNING = "running"
    PAUSED = "paused"
    STOPPING = "stopping"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class AttackStatus:
    """Mutable status object shared with callers for live progress tracking."""

    phase: AttackPhase = AttackPhase.IDLE
    message: str = ""
    packets_sent: int = 0
    packets_received: int = 0
    clients_affected: set[str] = field(default_factory=set)
    ivs_captured: int = 0
    elapsed: float = 0.0
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def running(self) -> bool:
        return self.phase in (AttackPhase.RUNNING, AttackPhase.PAUSED)


@dataclass(frozen=True)
class AttackResult:
    """Immutable outcome returned after an attack completes."""

    success: bool
    message: str = ""
    password: str = ""
    capture_file: str = ""
    time_taken: float = 0.0
    extra: dict[str, Any] = field(default_factory=dict)


# ── Base attack class ─────────────────────────────────────────────────────────


class BaseAttack:
    """Abstract base shared by every attack module.

    Provides:
    * async subprocess helpers with cancellation
    * tool-existence validation
    * structured logging and event emission
    * a uniform ``run`` / ``stop`` lifecycle
    """

    name: str = "base"

    def __init__(self, interface: str = "") -> None:
        self.interface = interface
        self.status = AttackStatus()
        self.bus = EventBus.get()
        self._cancel_event = asyncio.Event()
        self._processes: list[asyncio.subprocess.Process] = []
        self._tasks: list[asyncio.Task[None]] = []
        self._start_time: float = 0.0
        self._running: bool = False

    # ── Logging helpers ───────────────────────────────────────────────────

    def _log(self, level: int, msg: str, *a: Any, **kw: Any) -> None:
        logger.log(level, "[%s] %s", self.name, msg, *a, **kw)

    def _info(self, msg: str, *a: Any) -> None:
        self._log(logging.INFO, msg, *a)

    def _warn(self, msg: str, *a: Any) -> None:
        self._log(logging.WARNING, msg, *a)

    def _error(self, msg: str, *a: Any) -> None:
        self._log(logging.ERROR, msg, *a)

    def _debug(self, msg: str, *a: Any, **kw: Any) -> None:
        self._log(logging.DEBUG, msg, *a, **kw)

    # ── Event helpers ─────────────────────────────────────────────────────

    def _emit(self, kind: str, data: dict[str, Any] | None = None) -> None:
        payload = {"phase": self.status.phase.value, **(data or {})}
        self.bus.emit(Event(self.name, kind, payload))

    # ── Preconditions ─────────────────────────────────────────────────────

    @staticmethod
    def _require_root() -> None:
        if os.geteuid() != 0:
            raise WaffordPermissionError("Root privileges are required for this operation")

    @staticmethod
    def _require_tool(tool: str) -> str:
        path = TOOL_PATHS.get(tool, shutil.which(tool) or "")
        if not path or not Path(path).is_file():
            raise ToolNotFoundError(f"Required tool not found: {tool}", tool=tool)
        return path

    async def _validate_interface(self) -> None:
        if not self.interface:
            raise ValidationError("No interface specified", field="interface")
        rc, _, _ = await self._run_cmd(
            ["iw", "dev", self.interface, "info"], timeout=5
        )
        if rc != 0:
            raise ValidationError(
                f"Interface {self.interface} is not valid",
                field="interface",
            )

    # ── Async subprocess helpers ──────────────────────────────────────────

    async def _run_cmd(
        self,
        argv: list[str],
        *,
        timeout: float | None = None,
        capture: bool = True,
    ) -> tuple[int, str, str]:
        """Run a command as an async subprocess with optional timeout.

        Returns (returncode, stdout, stderr).
        """
        self._debug("exec: %s", " ".join(argv))
        proc = await asyncio.create_subprocess_exec(
            *argv,
            stdout=asyncio.subprocess.PIPE if capture else asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.PIPE if capture else asyncio.subprocess.DEVNULL,
        )
        self._processes.append(proc)
        try:
            if timeout is not None:
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            else:
                stdout, stderr = await proc.communicate()
            out = (stdout or b"").decode(errors="replace")
            err = (stderr or b"").decode(errors="replace")
            return proc.returncode or 0, out, err
        except TimeoutError:
            self._warn("Command timed out after %.1fs: %s", timeout, " ".join(argv))
            await self._kill_proc(proc)
            return -1, "", "timeout"
        finally:
            if proc in self._processes:
                self._processes.remove(proc)

    async def _run_cmd_streaming(
        self,
        argv: list[str],
        line_callback: Callable[[str], Any] | None = None,
        timeout: float | None = None,
    ) -> int:
        """Run a command streaming stdout line-by-line. Returns returncode."""
        self._debug("exec (stream): %s", " ".join(argv))
        proc = await asyncio.create_subprocess_exec(
            *argv,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        self._processes.append(proc)
        start = time.monotonic()
        try:
            assert proc.stdout is not None
            while True:
                if self._cancel_event.is_set():
                    await self._kill_proc(proc)
                    return -1
                if timeout and (time.monotonic() - start) > timeout:
                    await self._kill_proc(proc)
                    return -1
                line = await asyncio.wait_for(proc.stdout.readline(), timeout=5.0)
                if not line:
                    break
                decoded = line.decode(errors="replace").rstrip("\n\r")
                if line_callback:
                    try:
                        line_callback(decoded)
                    except Exception:
                        self._debug("line_callback error", exc_info=True)
            await proc.wait()
            return proc.returncode or 0
        except TimeoutError:
            await self._kill_proc(proc)
            return -1
        finally:
            if proc in self._processes:
                self._processes.remove(proc)

    async def _kill_proc(self, proc: asyncio.subprocess.Process) -> None:
        try:
            if proc.returncode is None:
                proc.terminate()
                try:
                    await asyncio.wait_for(proc.wait(), timeout=3)
                except TimeoutError:
                    proc.kill()
                    await proc.wait()
        except ProcessLookupError:
            pass

    # ── Lifecycle ─────────────────────────────────────────────────────────

    async def _pre_validate(self) -> None:
        """Override to add custom pre-validation logic."""
        self._require_root()
        self._validate_interface()

    async def start(self, **kwargs: Any) -> AttackResult:
        """High-level entry point: validate → run → return result."""
        self._cancel_event.clear()
        self._running = True
        self.status = AttackStatus(phase=AttackPhase.VALIDATING)
        self._emit("attack.validating")
        try:
            await self._pre_validate()
            self.status.phase = AttackPhase.STARTING
            self._emit("attack.starting")
            self._start_time = time.monotonic()
            result = await self._execute(**kwargs)
            self.status.elapsed = time.monotonic() - self._start_time
            if self._cancel_event.is_set():
                self.status.phase = AttackPhase.CANCELLED
                self._emit("attack.cancelled")
                return AttackResult(
                    success=False, message="Cancelled by user", time_taken=self.status.elapsed
                )
            self.status.phase = AttackPhase.COMPLETED if result.success else AttackPhase.FAILED
            self._emit("attack.completed", {"success": result.success})
            return result
        except Exception as exc:
            self.status.phase = AttackPhase.FAILED
            self.status.message = str(exc)
            self._error("Attack failed: %s", exc)
            self._emit("attack.failed", {"error": str(exc)})
            raise AttackError(str(exc), attack_type=self.name) from exc
        finally:
            await self._cleanup()

    async def stop(self) -> None:
        """Signal cancellation and kill all running subprocesses."""
        self._info("Stopping attack…")
        self._running = False
        self._cancel_event.set()
        self.status.phase = AttackPhase.STOPPING
        self._emit("attack.stopping")
        for task in self._tasks:
            if not task.done():
                task.cancel()
        procs = list(self._processes)
        for proc in procs:
            await self._kill_proc(proc)
        await asyncio.gather(*self._tasks, return_exceptions=True)
        self._tasks.clear()

    async def _cleanup(self) -> None:
        """Kill lingering processes. Override for extra teardown."""
        self._running = False
        for proc in list(self._processes):
            await self._kill_proc(proc)
        self._processes.clear()

    async def _execute(self, **kwargs: Any) -> AttackResult:
        """Override in subclass. Run the actual attack and return a result."""
        raise NotImplementedError
