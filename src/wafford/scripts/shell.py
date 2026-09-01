"""Subprocess management for Wafford."""

from __future__ import annotations

import os
import shutil
import signal
import shlex
import subprocess
import sys
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path


@dataclass
class Output:
    """Result of a shell command execution."""

    returncode: int = -1
    stdout: str = ""
    stderr: str = ""
    duration: float = 0.0
    command: str = ""
    timed_out: bool = False

    @property
    def ok(self) -> bool:
        return self.returncode == 0

    def __str__(self) -> str:
        return (
            f"Output(rc={self.returncode}, duration={self.duration:.2f}s, "
            f"stdout={self.stdout[:200]!r}, stderr={self.stderr[:200]!r})"
        )


class ShellRunner:
    """Unified subprocess manager for shell operations."""

    def __init__(self, log_fn: Callable[[str], None] | None = None) -> None:
        self._log = log_fn or (lambda _: None)

    # ------------------------------------------------------------------
    # Core execution
    # ------------------------------------------------------------------

    def run(
        self,
        command: str | list[str],
        timeout: int = 120,
        sudo: bool = False,
        capture_output: bool = True,
        env: dict[str, str] | None = None,
        cwd: str | Path | None = None,
    ) -> Output:
        """Execute a shell command and return an :class:`Output`."""
        if isinstance(command, list):
            command_str = shlex.join(command)
        else:
            command_str = command

        cmd_list = self._build_cmd(command, sudo)
        merged_env = {**os.environ, **(env or {})}
        start = time.monotonic()

        self._log(f"[shell] run: {command_str}" + (" (sudo)" if sudo else ""))

        try:
            proc = subprocess.run(
                cmd_list,
                # Argument lists never pass through a shell.  Callers handling
                # external input must use this form.
                shell=isinstance(cmd_list, str),
                capture_output=capture_output,
                text=True,
                timeout=timeout,
                env=merged_env,
                cwd=str(cwd) if cwd else None,
            )
            elapsed = time.monotonic() - start
            return Output(
                returncode=proc.returncode,
                stdout=proc.stdout if capture_output else "",
                stderr=proc.stderr if capture_output else "",
                duration=elapsed,
                command=command_str,
            )
        except subprocess.TimeoutExpired as exc:
            elapsed = time.monotonic() - start
            self._log(f"[shell] timeout after {timeout}s: {command_str}")
            return Output(
                returncode=-1,
                stdout=exc.stdout.decode(errors="replace") if exc.stdout else "",
                stderr=exc.stderr.decode(errors="replace") if exc.stderr else "",
                duration=elapsed,
                command=command_str,
                timed_out=True,
            )
        except Exception as exc:
            elapsed = time.monotonic() - start
            return Output(
                returncode=-1,
                stderr=str(exc),
                duration=elapsed,
                command=command_str,
            )

    def run_async(
        self,
        command: str,
        callback: Callable[[str], None] | None = None,
        sudo: bool = False,
        env: dict[str, str] | None = None,
    ) -> subprocess.Popen[str]:
        """Launch a command asynchronously, invoking *callback* for each stdout line."""
        cmd_list = self._build_cmd(command, sudo)
        merged_env = {**os.environ, **(env or {})}

        self._log(f"[shell] async: {command}" + (" (sudo)" if sudo else ""))

        def _reader(proc: subprocess.Popen[str], stream: str) -> None:
            assert proc.stdout is not None
            assert proc.stderr is not None
            out_stream = proc.stdout if stream == "stdout" else proc.stderr
            for line in iter(out_stream.readline, ""):
                if callback:
                    callback(line.rstrip("\n"))
            out_stream.close()

        proc = subprocess.Popen(  # noqa: S602 -- shell.py is an intentional shell-command runner
            cmd_list,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=merged_env,
        )

        import threading

        t_out = threading.Thread(target=_reader, args=(proc, "stdout"), daemon=True)
        t_err = threading.Thread(target=_reader, args=(proc, "stderr"), daemon=True)
        t_out.start()
        t_err.start()

        return proc

    def stream(
        self,
        command: str,
        callback: Callable[[str], None],
        sudo: bool = False,
        env: dict[str, str] | None = None,
        timeout: int = 600,
    ) -> Output:
        """Stream stdout line-by-line to *callback* until the process exits or times out."""
        cmd_list = self._build_cmd(command, sudo)
        merged_env = {**os.environ, **(env or {})}
        start = time.monotonic()

        self._log(f"[shell] stream: {command}" + (" (sudo)" if sudo else ""))

        try:
            proc = subprocess.Popen(  # noqa: S602 -- shell.py is an intentional shell-command runner
                cmd_list,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=merged_env,
            )
            assert proc.stdout is not None

            stdout_lines: list[str] = []
            stderr_lines: list[str] = []

            while True:
                elapsed = time.monotonic() - start
                if elapsed > timeout:
                    proc.kill()
                    proc.wait()
                    return Output(
                        returncode=-1,
                        stdout="".join(stdout_lines),
                        stderr="".join(stderr_lines),
                        duration=elapsed,
                        command=command,
                        timed_out=True,
                    )

                line = proc.stdout.readline()
                if not line:
                    break
                stripped = line.rstrip("\n")
                stdout_lines.append(line)
                callback(stripped)

            proc.wait()
            elapsed = time.monotonic() - start

            if proc.stderr:
                stderr_lines = proc.stderr.readlines()

            return Output(
                returncode=proc.returncode,
                stdout="".join(stdout_lines),
                stderr="".join(stderr_lines),
                duration=elapsed,
                command=command,
            )
        except Exception as exc:
            elapsed = time.monotonic() - start
            return Output(
                returncode=-1,
                stderr=str(exc),
                duration=elapsed,
                command=command,
            )

    # ------------------------------------------------------------------
    # Convenience helpers
    # ------------------------------------------------------------------

    def sudo_run(self, command: str | list[str], timeout: int = 120) -> Output:
        """Execute *command* with sudo."""
        return self.run(command, timeout=timeout, sudo=True)

    def check_output(self, command: str, sudo: bool = False) -> str:
        """Return stripped stdout of *command*, or empty string on failure."""
        result = self.run(command, sudo=sudo)
        return result.stdout.strip()

    # ------------------------------------------------------------------
    # System helpers
    # ------------------------------------------------------------------

    @staticmethod
    def is_root() -> bool:
        return os.geteuid() == 0

    def elevate(self) -> None:
        """Re-exec the current process under sudo."""
        if self.is_root():
            return
        os.execvp("sudo", ["sudo", *sys.argv])  # noqa: S606 -- deliberate sudo re-exec

    @staticmethod
    def find_binary(name: str) -> str | None:
        """Locate *name* in ``$PATH``."""
        return shutil.which(name)

    @staticmethod
    def kill_process(pid: int, sig: int = signal.SIGTERM) -> bool:
        """Send *sig* to *pid*. Returns True on success."""
        try:
            os.kill(pid, sig)
            return True
        except (ProcessLookupError, PermissionError):
            return False

    @staticmethod
    def get_pid(name: str) -> list[int]:
        """Find PIDs whose command matches *name* via ``pgrep``."""
        try:
            out = subprocess.check_output(
                ["pgrep", "-f", name], text=True, stderr=subprocess.DEVNULL
            )
            return [int(line) for line in out.strip().splitlines() if line.strip()]
        except (subprocess.CalledProcessError, ValueError):
            return []

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    @staticmethod
    def _build_cmd(command: str | list[str], sudo: bool) -> str | list[str]:
        """Build the process command without degrading argument lists to text."""
        if isinstance(command, list):
            return ["sudo", "--", *command] if sudo else command
        if sudo:
            return f"sudo {command}"
        return command
