"""Wafford formatter — produces plain, colored, and JSON log records."""

from __future__ import annotations

import json
import logging
import os
import sys
import traceback
from datetime import UTC, datetime
from typing import Any

# ---------------------------------------------------------------------------
# Custom log levels
# ---------------------------------------------------------------------------

# Base levels beyond the standard five
ATTACK_LEVEL = logging.INFO + 1  # severity 26
SCAN_LEVEL = logging.INFO  # 20
CRACK_LEVEL = logging.INFO + 2  # 27
AUDIT_LEVEL = logging.INFO + 3  # 28

_CUSTOM_LEVEL_NAMES: dict[int, str] = {
    ATTACK_LEVEL: "ATTACK",
    CRACK_LEVEL: "CRACK",
    AUDIT_LEVEL: "AUDIT",
}


def register_custom_levels() -> None:
    for num, name in _CUSTOM_LEVEL_NAMES.items():
        logging.addLevelName(num, name)


register_custom_levels()


# ---------------------------------------------------------------------------
# Log record class
# ---------------------------------------------------------------------------

class WaffordLogRecord:
    """Structured wrapper around a ``logging.LogRecord`` for easy formatting."""

    def __init__(self, record: logging.LogRecord) -> None:
        self.record = record

    def as_dict(self) -> dict[str, Any]:
        rec = self.record
        out: dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(
                rec.created, tz=UTC
            ).isoformat(),
            "level": rec.levelname,
            "levelno": rec.levelno,
            "logger": rec.name,
            "message": rec.getMessage(),
            "module": rec.module,
            "funcName": rec.funcName,
            "lineno": rec.lineno,
            "thread": rec.threadName,
            "process": rec.processName,
        }
        # Merge any extras provided via extra={...}
        keys = getattr(rec, "__dict__", {})
        for key in ("bssid", "essid", "channel", "target", "attack_type",
                    "crack_type", "duration", "success", "network"):
            if key in keys:
                out[key] = keys[key]
        if rec.exc_info and rec.exc_info[2] is not None:
            out["exc_info"] = "".join(
                traceback.format_exception(*rec.exc_info)
            ).strip()
        return out


# ---------------------------------------------------------------------------
# Terminal color helpers
# ---------------------------------------------------------------------------

RESET = "\x1b[0m"
_LEVEL_COLORS: dict[str, str] = {
    "DEBUG": "\x1b[90m",      # bright black
    "INFO": "\x1b[36m",       # cyan
    "ATTACK": "\x1b[33m",     # yellow
    "SCAN": "\x1b[36m",       # cyan
    "CRACK": "\x1b[35m",      # magenta
    "AUDIT": "\x1b[96m",      # bright cyan
    "WARNING": "\x1b[33m",    # yellow
    "ERROR": "\x1b[31m",      # red
    "CRITICAL": "\x1b[1;41m", # bold red background
}

_SUPPORTED_COLORS = ("black", "red", "green", "yellow", "blue", "magenta",
                     "cyan", "white")


def supports_color() -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("WAFFORD_NO_COLOR"):
        return False
    stream = sys.stderr if not hasattr(sys, "stdout") or not sys.stdout \
        else sys.stdout
    if hasattr(stream, "isatty"):
        try:
            return stream.isatty()
        except Exception:
            return False
    return False


# ---------------------------------------------------------------------------
# Format helpers
# ---------------------------------------------------------------------------

def plain_format(record: logging.LogRecord) -> str:
    ts = datetime.fromtimestamp(record.created, UTC).strftime("%Y-%m-%d %H:%M:%S")
    return (
        f"{ts} | {record.levelname:<7} | {record.name}"
        f" | {record.getMessage()}"
    )


def colored_format(record: logging.LogRecord) -> str:
    ts = datetime.fromtimestamp(record.created, UTC).strftime("%Y-%m-%d %H:%M:%S")
    color = _LEVEL_COLORS.get(record.levelname, "")
    return (
        f"\x1b[90m{ts}\x1b[0m | {color}{record.levelname:<7}\x1b[0m"
        f" | {record.name} | {record.getMessage()}"
    )


def json_format(record: logging.LogRecord) -> str:
    wr = WaffordLogRecord(record)
    return json.dumps(wr.as_dict(), ensure_ascii=False, default=str)


# ---------------------------------------------------------------------------
# Formatter class
# ---------------------------------------------------------------------------

class WaffordFormatter(logging.Formatter):
    """Configurable formatter supporting plain, colored, and JSON output."""

    def __init__(
        self,
        fmt: str = "plain",
        *,
        use_colors: bool | None = None,
        datefmt: str | None = None,
    ) -> None:
        super().__init__(fmt=fmt or "%(message)s", datefmt=datefmt)
        self._style = fmt if fmt in ("plain", "colored", "json") else "plain"
        if use_colors is None:
            use_colors = supports_color()
        self._use_colors = use_colors

    @property
    def style(self) -> str:
        return self._style

    def format(self, record: logging.LogRecord) -> str:
        # Let the base class populate exception text when needed.
        if self._style == "json":
            # Avoid base class mangling; build JSON directly.
            wr = WaffordLogRecord(record)
            payload = wr.as_dict()
            if record.exc_info and "exc_info" not in payload:
                payload["exc_info"] = "".join(
                    traceback.format_exception(*record.exc_info)
                ).strip()
            return json.dumps(payload, ensure_ascii=False, default=str)

        if self._style == "colored":
            message = colored_format(record)
        else:
            message = plain_format(record)

        if record.exc_info and record.exc_info[2] is not None:
            message += "\n" + "".join(
                traceback.format_exception(*record.exc_info)
            )
        return message
