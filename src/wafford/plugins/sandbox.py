"""Plugin sandbox — isolate plugin execution with resource limits."""

from __future__ import annotations

import io
import logging
import resource
import sys
import threading
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Callable

logger = logging.getLogger(__name__)

_meta_path_lock = threading.Lock()

# ---------------------------------------------------------------------------
# Resource limit configuration
# ---------------------------------------------------------------------------

_OS_LINUX = sys.platform == "linux"


@dataclass
class SandboxLimits:
    """Resource constraints imposed on a plugin running inside the sandbox."""

    max_cpu_seconds: int = 30
    max_memory_bytes: int = 256 * 1024 * 1024  # 256 MB
    max_file_size_bytes: int = 50 * 1024 * 1024  # 50 MB
    max_open_files: int = 64
    max_output_bytes: int = 1 * 1024 * 1024  # 1 MB captured stdout
    allowed_modules: list | None = None  # None = all allowed
    blocked_modules: list = field(default_factory=lambda: ["subprocess", "ctypes", "shutil"])


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class SandboxTimeout(Exception):
    """Raised when a plugin exceeds the CPU time limit."""


class SandboxMemoryLimit(Exception):
    """Raised when a plugin exceeds the memory limit."""


class SandboxModuleBlocked(Exception):
    """Raised when a plugin tries to import a blocked module."""


class SandboxError(Exception):
    """General sandbox failure."""


# ---------------------------------------------------------------------------
# Import guard (optional)
# ---------------------------------------------------------------------------


class _ImportBlocker:
    """Meta-path finder that blocks disallowed imports."""

    def __init__(
        self,
        blocked: list,
        allowed: list | None,
    ) -> None:
        self._blocked = set(blocked)
        self._allowed = set(allowed) if allowed else None

    def find_module(self, fullname: str, path: Any = None, target: Any = None):  # noqa: ANN001
        top = fullname.split(".")[0]
        if top in self._blocked:
            return self
        if self._allowed is not None and top not in self._allowed:
            return self
        return None

    def load_module(self, fullname: str):  # noqa: ANN001
        raise SandboxModuleBlocked(f"Import of '{fullname}' is blocked by sandbox")


# ---------------------------------------------------------------------------
# PluginSandbox
# ---------------------------------------------------------------------------


class PluginSandbox:
    """Run untrusted plugin code with resource constraints."""

    def __init__(self, limits: SandboxLimits | None = None) -> None:
        self._limits = limits or SandboxLimits()

    @property
    def limits(self) -> SandboxLimits:
        return self._limits

    # -- main entry point ---------------------------------------------------

    def run_in_sandbox(
        self,
        fn: Callable[..., Any],
        *args: Any,
        timeout: int | None = None,
        **kwargs: Any,
    ) -> Any:
        """Execute *fn* inside the sandbox and return its result.

        A watchdog thread enforces ``max_cpu_seconds`` when ``resource`` limits
        are unavailable (i.e. non-Linux).  On Linux, ``setrlimit`` is used as
        a primary guard.
        """
        timeout = timeout or self._limits.max_cpu_seconds
        result_holder: dict[str, Any] = {}
        exception_holder: list = []

        blocker = _ImportBlocker(
            self._limits.blocked_modules, self._limits.allowed_modules
        )

        def _target() -> None:
            with _meta_path_lock:
                old_meta = sys.meta_path[:]
                sys.meta_path.insert(0, blocker)
            try:
                self._apply_rlimits()
                captured = io.StringIO()
                old_stdout = sys.stdout
                old_stderr = sys.stderr
                sys.stdout = captured
                sys.stderr = captured
                try:
                    ret = fn(*args, **kwargs)
                    result_holder["result"] = ret
                finally:
                    sys.stdout = old_stdout
                    sys.stderr = old_stderr
                    output = captured.getvalue()
                    if len(output) > self._limits.max_output_bytes:
                        output = output[: self._limits.max_output_bytes] + "\n... [truncated]"
                    result_holder["output"] = output
            except Exception as exc:
                exception_holder.append(exc)
            finally:
                with _meta_path_lock:
                    sys.meta_path[:] = old_meta

        worker = threading.Thread(target=_target, daemon=True)
        worker.start()
        worker.join(timeout=timeout)

        if worker.is_alive():
            logger.error("Plugin sandbox timed out after %ds", timeout)
            raise SandboxTimeout(
                f"Plugin exceeded {timeout}s CPU time limit"
            )

        if exception_holder:
            exc = exception_holder[0]
            raise SandboxError(f"Plugin raised inside sandbox: {exc}") from exc

        return result_holder.get("result")

    # -- helpers ------------------------------------------------------------

    def _apply_rlimits(self) -> None:
        """Apply POSIX resource limits (Linux only)."""
        if not _OS_LINUX:
            return
        try:
            # CPU time
            cpu = self._limits.max_cpu_seconds
            resource.setrlimit(resource.RLIMIT_CPU, (cpu, cpu + 5))
            # Address space
            mem = self._limits.max_memory_bytes
            resource.setrlimit(resource.RLIMIT_AS, (mem, mem))
            # File size
            fsize = self._limits.max_file_size_bytes
            resource.setrlimit(resource.RLIMIT_FSIZE, (fsize, fsize))
            # Open files
            nofile = self._limits.max_open_files
            resource.setrlimit(resource.RLIMIT_NOFILE, (nofile, nofile))
        except (OSError, ValueError):
            logger.debug("Could not set rlimits (may need root)")

    @staticmethod
    def get_limits_for(profile: str) -> SandboxLimits:
        """Return predefined limits for common profiles."""
        profiles: dict[str, SandboxLimits] = {
            "minimal": SandboxLimits(
                max_cpu_seconds=10,
                max_memory_bytes=64 * 1024 * 1024,
                max_output_bytes=512 * 1024,
                blocked_modules=["subprocess", "ctypes", "shutil", "os", "socket"],
            ),
            "default": SandboxLimits(),
            "permissive": SandboxLimits(
                max_cpu_seconds=120,
                max_memory_bytes=512 * 1024 * 1024,
                max_output_bytes=5 * 1024 * 1024,
                blocked_modules=[],
            ),
        }
        if profile not in profiles:
            logger.warning("Unknown sandbox profile '%s', using default", profile)
            return profiles["default"]
        return profiles[profile]
