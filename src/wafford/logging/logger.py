import logging
import threading
from pathlib import Path
from typing import Any

from wafford.logging.formatter import WaffordFormatter
from wafford.logging.handlers import (
    ColoredConsoleHandler,
    JSONFileHandler,
    RotatingFileHandler,
    SQLiteHandler,
    SyslogHandler,
)

LOG_LEVELS = {
    "DEBUG": logging.DEBUG,
    "INFO": logging.INFO,
    "WARNING": logging.WARNING,
    "ERROR": logging.ERROR,
    "CRITICAL": logging.CRITICAL,
}

ATTACK_LEVEL = 25
SCAN_LEVEL = 26
CRACK_LEVEL = 27
CREDENTIAL_LEVEL = 28


class _AsyncWriter:
    def __init__(self, file_handle):
        self._file = file_handle
        self._lock = threading.Lock()

    def write(self, data: str):
        with self._lock:
            self._file.write(data)

    def flush(self):
        with self._lock:
            self._file.flush()


class WaffordLogger:
    def __init__(self):
        self._root = logging.getLogger("wafford")
        self._root.setLevel(logging.DEBUG)
        self._root.propagate = False

        registry = logging.getLevelNamesMapping()
        registry.setdefault("ATTACK", ATTACK_LEVEL)
        registry.setdefault("SCAN", SCAN_LEVEL)
        registry.setdefault("CRACK", CRACK_LEVEL)
        registry.setdefault("CREDENTIAL", CREDENTIAL_LEVEL)

        self._handlers: dict[str, logging.Handler] = {}
        self._context: dict[str, Any] = {}
        self._structured = False
        self._async_mode = False
        self._writing = False

        logging.addLevelName(ATTACK_LEVEL, "ATTACK")
        logging.addLevelName(SCAN_LEVEL, "SCAN")
        logging.addLevelName(CRACK_LEVEL, "CRACK")
        logging.addLevelName(CREDENTIAL_LEVEL, "CREDENTIAL")

    def setup(
        self,
        level: str = "INFO",
        log_file: str | None = None,
        console_output: bool = True,
        structured: bool = False,
        use_json_file: bool = False,
        use_sqlite: bool = False,
        sqlite_path: str | None = None,
        use_syslog: bool = False,
        max_bytes: int = 10 * 1024 * 1024,
        backup_count: int = 5,
    ):
        level = level.upper()
        numeric_level = LOG_LEVELS.get(level, logging.INFO)
        self._root.setLevel(numeric_level)
        self._structured = structured
        self._sync_level = numeric_level

        self._remove_handlers()

        if console_output:
            handler = ColoredConsoleHandler()
            handler.setFormatter(WaffordFormatter(format_type="colored"))
            self._add_handler("console", handler)

        if log_file:
            handler = RotatingFileHandler(
                log_file,
                maxBytes=max_bytes,
                backupCount=backup_count,
                encoding="utf-8",
            )
            fmt = "json" if structured else "detailed"
            handler.setFormatter(WaffordFormatter(format_type=fmt))
            handler.setLevel(numeric_level)
            self._add_handler("file", handler)

        if use_json_file:
            json_path = log_file or "wafford.jsonl"
            if isinstance(json_path, (Path, str)) and not json_path.endswith(".jsonl"):
                json_path = str(Path(str(json_path)).with_suffix(".jsonl"))
            handler = JSONFileHandler(json_path)
            self._add_handler("json", handler)

        if use_sqlite:
            handler = SQLiteHandler(sqlite_path or "wafford_logs.db")
            self._add_handler("sqlite", handler)

        if use_syslog:
            handler = SyslogHandler()
            self._add_handler("syslog", handler)

    def _add_handler(self, name: str, handler: logging.Handler):
        handler.setLevel(getattr(self, "_sync_level", logging.INFO))
        self._root.addHandler(handler)
        self._handlers[name] = handler

    def _remove_handlers(self):
        for handler in list(self._handlers.values()):
            self._root.removeHandler(handler)
            try:
                handler.close()
            except Exception as exc:
                logging.getLogger("wafford").debug("Failed to close handler: %s", exc)
        self._handlers.clear()

    def get_logger(self, name: str) -> logging.Logger:
        logger = logging.getLogger(f"wafford.{name}")
        logger.setLevel(self._root.level)
        return logger

    def set_context(self, **kwargs):
        self._context.update(kwargs)

    def clear_context(self):
        self._context.clear()

    def set_session_id(self, session_id: str | None):
        if session_id:
            self._context["session_id"] = session_id
        else:
            self._context.pop("session_id", None)

    def set_attack_id(self, attack_id: str | None):
        if attack_id:
            self._context["attack_id"] = attack_id
        else:
            self._context.pop("attack_id", None)

    def get_context(self) -> dict[str, Any]:
        return dict(self._context)

    def attack(self, message: str, **kwargs):
        self._log(ATTACK_LEVEL, message, **kwargs)

    def scan(self, message: str, **kwargs):
        self._log(SCAN_LEVEL, message, **kwargs)

    def crack(self, message: str, **kwargs):
        self._log(CRACK_LEVEL, message, **kwargs)

    def credential(self, message: str, **kwargs):
        self._log(CREDENTIAL_LEVEL, message, **kwargs)

    def debug(self, message: str, **kwargs):
        self._log(logging.DEBUG, message, **kwargs)

    def info(self, message: str, **kwargs):
        self._log(logging.INFO, message, **kwargs)

    def warning(self, message: str, **kwargs):
        self._log(logging.WARNING, message, **kwargs)

    def error(self, message: str, **kwargs):
        self._log(logging.ERROR, message, **kwargs)

    def critical(self, message: str, **kwargs):
        self._log(logging.CRITICAL, message, **kwargs)

    def exception(self, message: str, **kwargs):
        self._root.exception(message, extra=self._extra(kwargs))

    def _log(self, level: int, message: str, **kwargs):
        record_kwargs = self._extra(kwargs)
        self._root.log(level, message, extra=record_kwargs)

    def _extra(self, kwargs: dict[str, Any]) -> dict[str, Any]:
        extra = dict(self._context)
        extra.update(kwargs)
        return {"_wafford_extra": extra}

    def shutdown(self):
        self._remove_handlers()


_default_logger: WaffordLogger | None = None


def setup(
    level: str = "INFO",
    log_file: str | None = None,
    console_output: bool = True,
    structured: bool = False,
    use_json_file: bool = False,
    use_sqlite: bool = False,
    sqlite_path: str | None = None,
    use_syslog: bool = False,
) -> WaffordLogger:
    global _default_logger
    _default_logger = WaffordLogger()
    _default_logger.setup(
        level=level,
        log_file=log_file,
        console_output=console_output,
        structured=structured,
        use_json_file=use_json_file,
        use_sqlite=use_sqlite,
        sqlite_path=sqlite_path,
        use_syslog=use_syslog,
    )
    return _default_logger


def get_logger(name: str) -> logging.Logger:
    global _default_logger
    if _default_logger is None:
        _default_logger = WaffordLogger()
    return _default_logger.get_logger(name)
