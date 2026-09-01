import json
import logging
import logging.handlers
import sqlite3
import sys
import threading
import time
from logging.handlers import RotatingFileHandler as _StdRotatingFileHandler
from pathlib import Path


class RotatingFileHandler(_StdRotatingFileHandler):
    def __init__(self, filename, mode="a", max_bytes=10 * 1024 * 1024,
                 backup_count=5, encoding="utf-8", delay=False):
        super().__init__(
            filename,
            mode=mode,
            maxBytes=max_bytes,
            backupCount=backup_count,
            encoding=encoding,
            delay=delay,
        )


class JSONFileHandler(logging.Handler):
    def __init__(self, filename, encoding="utf-8"):
        super().__init__()
        self.filename = Path(filename)
        self.encoding = encoding
        self._lock = threading.Lock()
        self._file = None
        self.filename.parent.mkdir(parents=True, exist_ok=True)

    def _open(self):
        if self._file is None:
            self._file = self.filename.open("a", encoding=self.encoding)
        return self._file

    def emit(self, record):
        try:
            entry = self._record_to_dict(record)
            line = json.dumps(entry, ensure_ascii=False, default=str)
            with self._lock:
                fh = self._open()
                fh.write(line + "\n")
                fh.flush()
        except Exception:
            self.handleError(record)

    def _record_to_dict(self, record):
        extra = getattr(record, "_wafford_extra", {}) or {}
        entry = {
            "timestamp": self._format_time(record.created),
            "created": record.created,
            "level": record.levelname,
            "levelno": record.levelno,
            "logger": record.name,
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
            "message": record.getMessage(),
            "thread": record.threadName,
        }
        if record.exc_info:
            entry["exc_info"] = self.formatException(record.exc_info)
        if extra:
            entry["context"] = extra
        return entry

    @staticmethod
    def _format_time(epoch):
        base = time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(epoch))
        millis = int((epoch % 1) * 1000)
        return f"{base}.{millis:03d}"

    def close(self):
        try:
            if self._file:
                with self._lock:
                    self._file.flush()
                    self._file.close()
                    self._file = None
        finally:
            super().close()


class SQLiteHandler(logging.Handler):
    def __init__(self, db_path="wafford_logs.db"):
        super().__init__()
        self.db_path = str(db_path)
        self._lock = threading.Lock()
        self._conn = None
        self._init_db()

    def _connect(self):
        if self._conn is None:
            self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
            self._conn.execute("PRAGMA journal_mode=WAL;")
        return self._conn

    def _init_db(self):
        conn = self._connect()
        conn.execute("""
            CREATE TABLE IF NOT EXISTS log_entries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL NOT NULL,
                level TEXT NOT NULL,
                logger TEXT,
                module TEXT,
                function TEXT,
                line INTEGER,
                message TEXT,
                session_id TEXT,
                attack_id TEXT,
                extra TEXT
            )
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_log_entries_level ON log_entries (level);
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_log_entries_timestamp ON log_entries (timestamp);
        """)
        conn.commit()

    def emit(self, record):
        try:
            extra = getattr(record, "_wafford_extra", {}) or {}
            session_id = extra.get("session_id")
            attack_id = extra.get("attack_id")
            extra_json = json.dumps(extra, ensure_ascii=False, default=str)
            with self._lock:
                conn = self._connect()
                conn.execute(
                    """
                    INSERT INTO log_entries
                        (timestamp, level, logger, module, function, line, message,
                         session_id, attack_id, extra)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        record.created,
                        record.levelname,
                        record.name,
                        record.module,
                        record.funcName,
                        record.lineno,
                        record.getMessage(),
                        session_id,
                        attack_id,
                        extra_json,
                    ),
                )
                conn.commit()
        except Exception:
            self.handleError(record)

    def close(self):
        try:
            with self._lock:
                if self._conn:
                    self._conn.commit()
                    self._conn.close()
                    self._conn = None
        finally:
            super().close()


class ConsoleHandler(logging.StreamHandler):
    def __init__(self, stream=None, min_level=logging.WARNING):
        super().__init__(stream or sys.stdout)
        self._min_level = min_level

    def emit(self, record):
        if record.levelno < self._min_level:
            return
        super().emit(record)


class ColoredConsoleHandler(ConsoleHandler):
    COLORS = {
        logging.DEBUG: "\033[90m",
        logging.INFO: "\033[36m",
        logging.WARNING: "\033[33m",
        logging.ERROR: "\033[31m",
        logging.CRITICAL: "\033[41;97m",
        "ATTACK": "\033[35m",
        "SCAN": "\033[32m",
        "CRACK": "\033[33m",
        "CREDENTIAL": "\033[36m",
    }
    RESET = "\033[0m"

    def emit(self, record):
        try:
            message = self.format(record)
            color = self.COLORS.get(record.levelname, self.COLORS.get(record.levelno, ""))
            if color:
                message = f"{color}{message}{self.RESET}"
            self.stream.write(message + "\n")
            self.flush()
        except Exception:
            self.handleError(record)


class SyslogHandler(logging.Handler):
    def __init__(self, address=("/dev/log", 0), facility=logging.handlers.SysLogHandler.LOG_USER):
        self._handler = logging.handlers.SysLogHandler(address=address, facility=facility)
        super().__init__()

    def emit(self, record):
        try:
            self._handler.emit(record)
        except Exception:
            self.handleError(record)

    def close(self):
        try:
            self._handler.close()
        finally:
            super().close()
