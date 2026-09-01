"""Structured logging setup for Wafford."""

from __future__ import annotations

import json
import logging
import logging.handlers
from pathlib import Path
from typing import Any

from wafford.constants import LOG_DIR


class JSONFormatter(logging.Formatter):
    """JSON log formatter."""

    def format(self, record: logging.LogRecord) -> str:
        """Format log record as JSON."""
        log_data: dict[str, Any] = {
            "timestamp": self.formatTime(record),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)
        return json.dumps(log_data)


def setup_logging(
    level: str = "INFO",
    log_format: str = "detailed",
    log_to_file: bool = True,
    log_to_console: bool = True,
    max_log_size_mb: int = 50,
    log_rotation: int = 5,
) -> None:
    """Configure logging for Wafford.

    Args:
        level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL).
        log_format: Log format (json, console, detailed).
        log_to_file: Whether to log to file.
        log_to_console: Whether to log to console.
        max_log_size_mb: Maximum log file size in MB.
        log_rotation: Number of backup log files to keep.
    """
    logger = logging.getLogger()
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))

    # Clear existing handlers
    logger.handlers.clear()

    # Console handler
    if log_to_console:
        console_handler = logging.StreamHandler()
        if log_format == "json":
            console_handler.setFormatter(JSONFormatter())
        else:
            fmt = (
                "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
                if log_format == "detailed"
                else "[%(levelname)s] %(message)s"
            )
            console_handler.setFormatter(logging.Formatter(fmt))
        logger.addHandler(console_handler)

    # File handler with rotation
    if log_to_file:
        log_dir = Path(LOG_DIR)
        log_dir.mkdir(parents=True, exist_ok=True)
        log_file = log_dir / "wafford.log"

        file_handler = logging.handlers.RotatingFileHandler(
            str(log_file),
            maxBytes=max_log_size_mb * 1024 * 1024,
            backupCount=log_rotation,
        )
        if log_format == "json":
            file_handler.setFormatter(JSONFormatter())
        else:
            fmt = (
                "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
                if log_format == "detailed"
                else "[%(levelname)s] %(message)s"
            )
            file_handler.setFormatter(logging.Formatter(fmt))
        logger.addHandler(file_handler)
