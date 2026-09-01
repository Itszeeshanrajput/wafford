"""Asynchronous SQLite database manager for Wafford."""

from __future__ import annotations

import json
import logging
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from wafford.constants import BACKUP_DIR, DB_PATH
from wafford.db.migrations import MigrationRunner

logger = logging.getLogger(__name__)


class _AsyncCursor:
    """Small awaitable facade for a SQLite cursor.

    SQLite operations in this manager are short, transactional operations.
    Keeping them on the application's event-loop thread avoids the fragile
    cross-thread connection hand-off used by aiosqlite while preserving the
    manager's async public API.
    """

    def __init__(self, cursor: sqlite3.Cursor) -> None:
        self._cursor = cursor

    @property
    def lastrowid(self) -> int | None:
        return self._cursor.lastrowid

    @property
    def rowcount(self) -> int:
        return self._cursor.rowcount

    async def fetchone(self) -> sqlite3.Row | None:
        return self._cursor.fetchone()

    async def fetchall(self) -> list[sqlite3.Row]:
        return self._cursor.fetchall()


class _AsyncConnection:
    """Async-compatible, single-threaded SQLite connection wrapper."""

    def __init__(self, path: Path) -> None:
        self._conn = sqlite3.connect(str(path), check_same_thread=False)

    @property
    def row_factory(self) -> type[sqlite3.Row] | None:
        return self._conn.row_factory

    @row_factory.setter
    def row_factory(self, factory: type[sqlite3.Row]) -> None:
        self._conn.row_factory = factory

    async def execute(
        self, sql: str, parameters: tuple[Any, ...] | list[Any] = ()
    ) -> _AsyncCursor:
        return _AsyncCursor(self._conn.execute(sql, parameters))

    async def commit(self) -> None:
        self._conn.commit()

    async def close(self) -> None:
        self._conn.close()


class DatabaseManager:
    """Async CRUD manager for all Wafford tables."""

    def __init__(self, db_path: Path | str | None = None) -> None:
        self._db_path = Path(db_path) if db_path else DB_PATH
        self._db: _AsyncConnection | None = None

    # ── Lifecycle ────────────────────────────────────────────────────────
    async def __aenter__(self) -> DatabaseManager:
        await self.init_db()
        return self

    async def __aexit__(self, *_: Any) -> None:
        await self.close()

    async def init_db(self) -> None:
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        # Migrations use a synchronous connection.  They must finish before
        # opening the long-lived async connection: changing journal mode on
        # the latter can hold an exclusive lock and make the migration
        # connection wait indefinitely on a fresh database.
        sync_conn = sqlite3.connect(str(self._db_path))
        try:
            MigrationRunner(sync_conn).run_pending()
        finally:
            sync_conn.close()

        self._db = _AsyncConnection(self._db_path)
        self._db.row_factory = sqlite3.Row
        await self._db.execute("PRAGMA journal_mode = WAL")
        await self._db.execute("PRAGMA foreign_keys = ON")
        await self._db.execute("PRAGMA busy_timeout = 5000")
        await self._db.commit()

        logger.info("Database initialised at %s", self._db_path)

    async def close(self) -> None:
        if self._db:
            await self._db.close()
            self._db = None
            logger.debug("Database connection closed")

    @property
    def db(self) -> _AsyncConnection:
        if self._db is None:
            raise RuntimeError("Database not initialised. Call init_db() first.")
        return self._db

    # ── Sessions ─────────────────────────────────────────────────────────
    async def create_session(
        self, name: str = "unnamed", notes: str = "", config_json: str = "{}"
    ) -> int:
        cursor = await self.db.execute(
            "INSERT INTO sessions (name, notes, config_json) VALUES (?, ?, ?)",
            (name, notes, config_json),
        )
        await self.db.commit()
        logger.info("Created session '%s' (id=%d)", name, cursor.lastrowid)
        return cursor.lastrowid  # type: ignore[return-value]

    async def end_session(self, session_id: int, status: str = "completed") -> None:
        now = datetime.now(UTC).isoformat()
        await self.db.execute(
            "UPDATE sessions SET ended_at = ?, status = ? WHERE id = ?",
            (now, status, session_id),
        )
        await self.db.commit()
        logger.info("Ended session %d with status '%s'", session_id, status)

    async def get_session(self, session_id: int) -> dict[str, Any] | None:
        cursor = await self.db.execute("SELECT * FROM sessions WHERE id = ?", (session_id,))
        row = await cursor.fetchone()
        return dict(row) if row else None

    async def get_sessions(
        self, status: str | None = None, limit: int = 50
    ) -> list[dict[str, Any]]:
        if status:
            cursor = await self.db.execute(
                "SELECT * FROM sessions WHERE status = ? ORDER BY started_at DESC LIMIT ?",
                (status, limit),
            )
        else:
            cursor = await self.db.execute(
                "SELECT * FROM sessions ORDER BY started_at DESC LIMIT ?", (limit,)
            )
        return [dict(r) for r in await cursor.fetchall()]

    async def delete_session(self, session_id: int) -> None:
        await self.db.execute("DELETE FROM sessions WHERE id = ?", (session_id,))
        await self.db.commit()

    # ── Interfaces ───────────────────────────────────────────────────────
    async def add_interface(
        self,
        session_id: int,
        name: str,
        mac_address: str = "",
        chipset: str = "",
        driver: str = "",
        physical_id: str = "",
        mode: str = "managed",
        supported_bands: str = "[]",
        is_primary: bool = False,
    ) -> int:
        cursor = await self.db.execute(
            """INSERT INTO interfaces
               (session_id, name, mac_address, chipset, driver, physical_id,
                mode, supported_bands, is_primary)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (session_id, name, mac_address, chipset, driver, physical_id,
             mode, supported_bands, int(is_primary)),
        )
        await self.db.commit()
        return cursor.lastrowid  # type: ignore[return-value]

    async def get_interfaces(self, session_id: int) -> list[dict[str, Any]]:
        cursor = await self.db.execute(
            "SELECT * FROM interfaces WHERE session_id = ? "
            "ORDER BY is_primary DESC, name",
            (session_id,),
        )
        return [dict(r) for r in await cursor.fetchall()]

    async def update_interface_mode(self, interface_id: int, mode: str) -> None:
        await self.db.execute("UPDATE interfaces SET mode = ? WHERE id = ?", (mode, interface_id))
        await self.db.commit()

    async def get_interface(self, interface_id: int) -> dict[str, Any] | None:
        cursor = await self.db.execute("SELECT * FROM interfaces WHERE id = ?", (interface_id,))
        row = await cursor.fetchone()
        return dict(row) if row else None

    # ── Networks ─────────────────────────────────────────────────────────
    async def add_network(
        self,
        session_id: int,
        bssid: str,
        essid: str = "",
        channel: int = 0,
        encryption: str = "Unknown",
        signal_dbm: int = -100,
        signal_percent: int = 0,
        wps: bool = False,
        vendor: str = "",
        is_hidden: bool = False,
        client_count: int = 0,
        latitude: float | None = None,
        longitude: float | None = None,
    ) -> int:
        now = datetime.now(UTC).isoformat()
        cursor = await self.db.execute(
            """INSERT INTO networks
               (session_id, bssid, essid, channel, encryption, signal_dbm, signal_percent,
                wps, vendor, first_seen, last_seen, is_hidden, client_count, latitude, longitude)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(session_id, bssid) DO UPDATE SET
                essid = excluded.essid,
                channel = excluded.channel,
                encryption = excluded.encryption,
                signal_dbm = excluded.signal_dbm,
                signal_percent = excluded.signal_percent,
                wps = excluded.wps,
                vendor = excluded.vendor,
                last_seen = excluded.last_seen,
                is_hidden = excluded.is_hidden,
                client_count = excluded.client_count""",
            (session_id, bssid, essid, channel, encryption, signal_dbm, signal_percent,
             int(wps), vendor, now, now, int(is_hidden), client_count, latitude, longitude),
        )
        await self.db.commit()
        return cursor.lastrowid  # type: ignore[return-value]

    async def get_networks(
        self,
        session_id: int,
        encryption: str | None = None,
        min_signal: int | None = None,
        limit: int = 200,
    ) -> list[dict[str, Any]]:
        conditions = ["session_id = ?"]
        params: list[Any] = [session_id]
        if encryption:
            conditions.append("encryption = ?")
            params.append(encryption)
        if min_signal is not None:
            conditions.append("signal_dbm >= ?")
            params.append(min_signal)
        params.append(limit)
        where = " AND ".join(conditions)
        cursor = await self.db.execute(
            f"SELECT * FROM networks WHERE {where} ORDER BY signal_dbm DESC LIMIT ?",  # noqa: S608
            params,
        )
        return [dict(r) for r in await cursor.fetchall()]

    async def get_network(self, network_id: int) -> dict[str, Any] | None:
        cursor = await self.db.execute("SELECT * FROM networks WHERE id = ?", (network_id,))
        row = await cursor.fetchone()
        return dict(row) if row else None

    async def get_network_by_bssid(self, session_id: int, bssid: str) -> dict[str, Any] | None:
        cursor = await self.db.execute(
            "SELECT * FROM networks WHERE session_id = ? AND bssid = ?",
            (session_id, bssid),
        )
        row = await cursor.fetchone()
        return dict(row) if row else None

    # ── Clients ──────────────────────────────────────────────────────────
    async def add_client(
        self,
        session_id: int,
        mac_address: str,
        network_id: int | None = None,
        vendor: str = "",
        signal_dbm: int = -100,
        probe_requests: str = "[]",
        is_connected: bool = False,
    ) -> int:
        now = datetime.now(UTC).isoformat()
        cursor = await self.db.execute(
            """INSERT INTO clients
               (session_id, network_id, mac_address, vendor, signal_dbm,
                probe_requests, is_connected, first_seen, last_seen)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (session_id, network_id, mac_address, vendor, signal_dbm,
             probe_requests, int(is_connected), now, now),
        )
        await self.db.commit()
        return cursor.lastrowid  # type: ignore[return-value]

    async def get_clients(
        self, session_id: int, network_id: int | None = None, limit: int = 500
    ) -> list[dict[str, Any]]:
        if network_id is not None:
            cursor = await self.db.execute(
                "SELECT * FROM clients WHERE session_id = ? AND network_id = ? "
                "ORDER BY signal_dbm DESC LIMIT ?",
                (session_id, network_id, limit),
            )
        else:
            cursor = await self.db.execute(
                "SELECT * FROM clients WHERE session_id = ? ORDER BY signal_dbm DESC LIMIT ?",
                (session_id, limit),
            )
        return [dict(r) for r in await cursor.fetchall()]

    async def get_client(self, client_id: int) -> dict[str, Any] | None:
        cursor = await self.db.execute("SELECT * FROM clients WHERE id = ?", (client_id,))
        row = await cursor.fetchone()
        return dict(row) if row else None

    # ── Attacks ──────────────────────────────────────────────────────────
    async def add_attack(
        self,
        session_id: int,
        attack_type: str,
        target_bssid: str,
        target_essid: str = "",
        interface: str = "",
        network_id: int | None = None,
        client_id: int | None = None,
    ) -> int:
        now = datetime.now(UTC).isoformat()
        cursor = await self.db.execute(
            """INSERT INTO attacks
               (session_id, network_id, client_id, attack_type, target_bssid,
                target_essid, interface, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (session_id, network_id, client_id, attack_type, target_bssid,
             target_essid, interface, now),
        )
        await self.db.commit()
        logger.info(
            "Attack '%s' created (id=%d) against %s",
            attack_type, cursor.lastrowid, target_bssid,
        )
        return cursor.lastrowid  # type: ignore[return-value]

    async def update_attack(
        self,
        attack_id: int,
        status: str | None = None,
        packets_sent: int | None = None,
        duration_sec: float | None = None,
        error_message: str | None = None,
        result_json: str | None = None,
        notes: str | None = None,
    ) -> None:
        sets: list[str] = []
        params: list[Any] = []
        now = datetime.now(UTC).isoformat()

        if status is not None:
            sets.append("status = ?")
            params.append(status)
            if status == "running":
                sets.append("started_at = ?")
                params.append(now)
            elif status in ("completed", "failed", "cancelled"):
                sets.append("completed_at = ?")
                params.append(now)
        if packets_sent is not None:
            sets.append("packets_sent = ?")
            params.append(packets_sent)
        if duration_sec is not None:
            sets.append("duration_sec = ?")
            params.append(duration_sec)
        if error_message is not None:
            sets.append("error_message = ?")
            params.append(error_message)
        if result_json is not None:
            sets.append("result_json = ?")
            params.append(result_json)
        if notes is not None:
            sets.append("notes = ?")
            params.append(notes)

        if not sets:
            return
        params.append(attack_id)
        await self.db.execute(
            f"UPDATE attacks SET {', '.join(sets)} WHERE id = ?", params  # noqa: S608
        )
        await self.db.commit()

    async def get_attacks(
        self, session_id: int, status: str | None = None, limit: int = 100
    ) -> list[dict[str, Any]]:
        if status:
            cursor = await self.db.execute(
                "SELECT * FROM attacks WHERE session_id = ? AND status = ? "
                "ORDER BY created_at DESC LIMIT ?",
                (session_id, status, limit),
            )
        else:
            cursor = await self.db.execute(
                "SELECT * FROM attacks WHERE session_id = ? ORDER BY created_at DESC LIMIT ?",
                (session_id, limit),
            )
        return [dict(r) for r in await cursor.fetchall()]

    async def get_attack(self, attack_id: int) -> dict[str, Any] | None:
        cursor = await self.db.execute("SELECT * FROM attacks WHERE id = ?", (attack_id,))
        row = await cursor.fetchone()
        return dict(row) if row else None

    # ── Handshakes ───────────────────────────────────────────────────────
    async def add_handshake(
        self,
        session_id: int,
        network_id: int,
        bssid: str,
        essid: str = "",
        file_path: str = "",
        file_format: str = "cap",
        eapol_count: int = 0,
        valid: bool = False,
        attack_id: int | None = None,
    ) -> int:
        now = datetime.now(UTC).isoformat()
        cursor = await self.db.execute(
            """INSERT INTO handshakes
               (session_id, network_id, attack_id, bssid, essid, file_path,
                file_format, eapol_count, valid, captured_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (session_id, network_id, attack_id, bssid, essid, file_path,
             file_format, eapol_count, int(valid), now),
        )
        await self.db.commit()
        logger.info("Handshake captured for %s (EAPOLs: %d)", bssid, eapol_count)
        return cursor.lastrowid  # type: ignore[return-value]

    async def get_handshakes(
        self, session_id: int, network_id: int | None = None, limit: int = 100
    ) -> list[dict[str, Any]]:
        if network_id is not None:
            cursor = await self.db.execute(
                "SELECT * FROM handshakes WHERE session_id = ? AND network_id = ? "
                "ORDER BY captured_at DESC LIMIT ?",
                (session_id, network_id, limit),
            )
        else:
            cursor = await self.db.execute(
                "SELECT * FROM handshakes WHERE session_id = ? ORDER BY captured_at DESC LIMIT ?",
                (session_id, limit),
            )
        return [dict(r) for r in await cursor.fetchall()]

    async def get_handshake(self, handshake_id: int) -> dict[str, Any] | None:
        cursor = await self.db.execute("SELECT * FROM handshakes WHERE id = ?", (handshake_id,))
        row = await cursor.fetchone()
        return dict(row) if row else None

    # ── Crack jobs ───────────────────────────────────────────────────────
    async def add_crack_job(
        self,
        session_id: int,
        handshake_id: int,
        attack_mode: str = "dictionary",
        wordlist_path: str = "",
        rules_path: str = "",
        mask: str = "",
        tool: str = "aircrack-ng",
    ) -> int:
        now = datetime.now(UTC).isoformat()
        cursor = await self.db.execute(
            """INSERT INTO crack_jobs
               (session_id, handshake_id, attack_mode, wordlist_path,
                rules_path, mask, tool, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (session_id, handshake_id, attack_mode, wordlist_path, rules_path, mask, tool, now),
        )
        await self.db.commit()
        return cursor.lastrowid  # type: ignore[return-value]

    async def update_crack_job(
        self,
        job_id: int,
        status: str | None = None,
        progress: float | None = None,
        speed: float | None = None,
        keyspace: int | None = None,
        elapsed_sec: float | None = None,
        error_message: str | None = None,
    ) -> None:
        sets: list[str] = []
        params: list[Any] = []
        now = datetime.now(UTC).isoformat()

        if status is not None:
            sets.append("status = ?")
            params.append(status)
            if status == "running" and not elapsed_sec:
                sets.append("started_at = ?")
                params.append(now)
            elif status in ("completed", "failed", "cancelled"):
                sets.append("completed_at = ?")
                params.append(now)
        if progress is not None:
            sets.append("progress = ?")
            params.append(progress)
        if speed is not None:
            sets.append("speed = ?")
            params.append(speed)
        if keyspace is not None:
            sets.append("keyspace = ?")
            params.append(keyspace)
        if elapsed_sec is not None:
            sets.append("elapsed_sec = ?")
            params.append(elapsed_sec)
        if error_message is not None:
            sets.append("error_message = ?")
            params.append(error_message)

        if not sets:
            return
        params.append(job_id)
        await self.db.execute(
            f"UPDATE crack_jobs SET {', '.join(sets)} WHERE id = ?", params  # noqa: S608
        )
        await self.db.commit()

    async def get_crack_jobs(self, session_id: int, limit: int = 50) -> list[dict[str, Any]]:
        cursor = await self.db.execute(
            "SELECT * FROM crack_jobs WHERE session_id = ? ORDER BY created_at DESC LIMIT ?",
            (session_id, limit),
        )
        return [dict(r) for r in await cursor.fetchall()]

    async def get_crack_job(self, job_id: int) -> dict[str, Any] | None:
        cursor = await self.db.execute("SELECT * FROM crack_jobs WHERE id = ?", (job_id,))
        row = await cursor.fetchone()
        return dict(row) if row else None

    # ── Credentials ──────────────────────────────────────────────────────
    async def add_credential(
        self,
        session_id: int,
        bssid: str,
        essid: str = "",
        password: str = "",
        psk: str = "",
        identity: str = "",
        algorithm: str = "",
        crack_job_id: int | None = None,
        network_id: int | None = None,
        notes: str = "",
    ) -> int:
        now = datetime.now(UTC).isoformat()
        cursor = await self.db.execute(
            """INSERT INTO credentials
               (session_id, crack_job_id, network_id, bssid, essid, password,
                psk, identity, algorithm, found_at, notes)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (session_id, crack_job_id, network_id, bssid, essid, password,
             psk, identity, algorithm, now, notes),
        )
        await self.db.commit()
        logger.info("Credential found for %s", bssid)
        return cursor.lastrowid  # type: ignore[return-value]

    async def get_credentials(self, session_id: int, limit: int = 100) -> list[dict[str, Any]]:
        cursor = await self.db.execute(
            "SELECT * FROM credentials WHERE session_id = ? ORDER BY found_at DESC LIMIT ?",
            (session_id, limit),
        )
        return [dict(r) for r in await cursor.fetchall()]

    async def get_credential(self, credential_id: int) -> dict[str, Any] | None:
        cursor = await self.db.execute("SELECT * FROM credentials WHERE id = ?", (credential_id,))
        row = await cursor.fetchone()
        return dict(row) if row else None

    # ── Plugins ──────────────────────────────────────────────────────────
    async def add_plugin(
        self,
        name: str,
        version: str = "0.0.0",
        author: str = "",
        description: str = "",
        file_path: str = "",
        enabled: bool = True,
    ) -> int:
        now = datetime.now(UTC).isoformat()
        cursor = await self.db.execute(
            """INSERT OR REPLACE INTO plugins
               (name, version, author, description, file_path, enabled, loaded_at, added_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (name, version, author, description, file_path, int(enabled), now, now),
        )
        await self.db.commit()
        return cursor.lastrowid  # type: ignore[return-value]

    async def get_plugins(self, enabled_only: bool = False) -> list[dict[str, Any]]:
        if enabled_only:
            cursor = await self.db.execute("SELECT * FROM plugins WHERE enabled = 1 ORDER BY name")
        else:
            cursor = await self.db.execute("SELECT * FROM plugins ORDER BY name")
        return [dict(r) for r in await cursor.fetchall()]

    async def toggle_plugin(self, plugin_id: int, enabled: bool) -> None:
        await self.db.execute(
            "UPDATE plugins SET enabled = ? WHERE id = ?", (int(enabled), plugin_id)
        )
        await self.db.commit()

    async def delete_plugin(self, plugin_id: int) -> None:
        await self.db.execute("DELETE FROM plugins WHERE id = ?", (plugin_id,))
        await self.db.commit()

    # ── Settings ─────────────────────────────────────────────────────────
    async def get_setting(self, key: str, default: str = "") -> str:
        cursor = await self.db.execute("SELECT value FROM settings WHERE key = ?", (key,))
        row = await cursor.fetchone()
        return row[0] if row else default

    async def set_setting(self, key: str, value: str) -> None:
        now = datetime.now(UTC).isoformat()
        await self.db.execute(
            "INSERT OR REPLACE INTO settings (key, value, updated_at) VALUES (?, ?, ?)",
            (key, value, now),
        )
        await self.db.commit()

    async def get_all_settings(self) -> dict[str, str]:
        cursor = await self.db.execute("SELECT key, value FROM settings")
        return {row[0]: row[1] for row in await cursor.fetchall()}

    # ── Log entries ──────────────────────────────────────────────────────
    async def add_log_entry(
        self,
        level: str,
        message: str,
        session_id: int | None = None,
        module: str = "",
        data_json: str = "{}",
    ) -> int:
        now = datetime.now(UTC).isoformat()
        cursor = await self.db.execute(
            "INSERT INTO log_entries "
            "(session_id, level, module, message, data_json, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (session_id, level, module, message, data_json, now),
        )
        await self.db.commit()
        return cursor.lastrowid  # type: ignore[return-value]

    async def get_log_entries(
        self,
        session_id: int | None = None,
        level: str | None = None,
        module: str | None = None,
        limit: int = 500,
    ) -> list[dict[str, Any]]:
        conditions: list[str] = []
        params: list[Any] = []
        if session_id is not None:
            conditions.append("session_id = ?")
            params.append(session_id)
        if level is not None:
            conditions.append("level = ?")
            params.append(level)
        if module is not None:
            conditions.append("module = ?")
            params.append(module)
        params.append(limit)

        where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        cursor = await self.db.execute(
            f"SELECT * FROM log_entries {where} ORDER BY created_at DESC LIMIT ?",  # noqa: S608
            params,
        )
        return [dict(r) for r in await cursor.fetchall()]

    # ── Wordlists ────────────────────────────────────────────────────────
    async def add_wordlist(
        self,
        name: str,
        file_path: str,
        word_count: int = 0,
        size_bytes: int = 0,
        md5_hash: str = "",
        is_default: bool = False,
    ) -> int:
        cursor = await self.db.execute(
            """INSERT OR IGNORE INTO wordlists
               (name, file_path, word_count, size_bytes, md5_hash, is_default)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (name, file_path, word_count, size_bytes, md5_hash, int(is_default)),
        )
        await self.db.commit()
        return cursor.lastrowid  # type: ignore[return-value]

    async def get_wordlists(self) -> list[dict[str, Any]]:
        cursor = await self.db.execute("SELECT * FROM wordlists ORDER BY is_default DESC, name")
        return [dict(r) for r in await cursor.fetchall()]

    async def mark_wordlist_used(self, wordlist_id: int) -> None:
        now = datetime.now(UTC).isoformat()
        await self.db.execute("UPDATE wordlists SET last_used = ? WHERE id = ?", (now, wordlist_id))
        await self.db.commit()

    async def delete_wordlist(self, wordlist_id: int) -> None:
        await self.db.execute("DELETE FROM wordlists WHERE id = ?", (wordlist_id,))
        await self.db.commit()

    # ── Reports ──────────────────────────────────────────────────────────
    async def add_report(
        self,
        session_id: int,
        title: str = "Audit Report",
        report_format: str = "html",
        file_path: str = "",
        file_size: int = 0,
        summary: str = "",
    ) -> int:
        now = datetime.now(UTC).isoformat()
        cursor = await self.db.execute(
            """INSERT INTO reports
               (session_id, title, format, file_path, file_size, summary, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (session_id, title, report_format, file_path, file_size, summary, now),
        )
        await self.db.commit()
        return cursor.lastrowid  # type: ignore[return-value]

    async def get_reports(self, session_id: int | None = None) -> list[dict[str, Any]]:
        if session_id is not None:
            cursor = await self.db.execute(
                "SELECT * FROM reports WHERE session_id = ? ORDER BY created_at DESC", (session_id,)
            )
        else:
            cursor = await self.db.execute("SELECT * FROM reports ORDER BY created_at DESC")
        return [dict(r) for r in await cursor.fetchall()]

    async def delete_report(self, report_id: int) -> None:
        await self.db.execute("DELETE FROM reports WHERE id = ?", (report_id,))
        await self.db.commit()

    # ── Maintenance ──────────────────────────────────────────────────────
    async def backup(self, dest: Path | str | None = None) -> Path:
        ts = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
        if dest is None:
            dest = BACKUP_DIR / f"wafford_backup_{ts}.db"
        else:
            dest = Path(dest)
        dest.parent.mkdir(parents=True, exist_ok=True)
        await self.db.execute("VACUUM INTO ?", (str(dest),))
        logger.info("Database backed up to %s", dest)
        return dest

    async def vacuum(self) -> None:
        await self.db.execute("VACUUM")
        logger.info("Database vacuumed")

    async def export_json(self, dest: Path | str) -> Path:
        dest = Path(dest)
        dest.parent.mkdir(parents=True, exist_ok=True)
        export: dict[str, list[dict[str, Any]]] = {}
        for table in (
            "sessions", "interfaces", "networks", "clients", "attacks",
            "handshakes", "crack_jobs", "credentials", "plugins",
            "settings", "log_entries", "wordlists", "reports",
        ):
            cursor = await self.db.execute(
                f"SELECT * FROM {table}"  # noqa: S608
            )
            export[table] = [dict(r) for r in await cursor.fetchall()]
        dest.write_text(json.dumps(export, indent=2, default=str), encoding="utf-8")
        logger.info("Database exported to %s", dest)
        return dest

    async def import_json(self, src: Path | str) -> None:
        src = Path(src)
        data = json.loads(src.read_text(encoding="utf-8"))
        allowed = {
            "sessions", "interfaces", "networks", "clients", "attacks",
            "handshakes", "crack_jobs", "credentials", "plugins",
            "settings", "log_entries", "wordlists", "reports",
        }
        for table, rows in data.items():
            if table not in allowed:
                logger.warning("Skipping unknown table '%s' during import", table)
                continue
            if not rows:
                continue
            cols = list(rows[0].keys())
            placeholders = ", ".join(["?"] * len(cols))
            col_names = ", ".join(cols)
            for row in rows:
                values = [row.get(c) for c in cols]
                await self.db.execute(
                    f"INSERT OR IGNORE INTO {table} ({col_names}) VALUES ({placeholders})",  # noqa: S608
                    values,
                )
        await self.db.commit()
        logger.info("Database imported from %s", src)

    async def cleanup_old_logs(self, days: int = 30) -> int:
        cutoff = datetime.now(UTC).isoformat()
        cursor = await self.db.execute(
            "DELETE FROM log_entries WHERE created_at < datetime(?, ?)",
            (cutoff, f"-{days} days"),
        )
        await self.db.commit()
        count = cursor.rowcount
        if count:
            logger.info("Cleaned up %d old log entries", count)
        return count

    def migration_status(self) -> dict[str, object]:
        if self._db is None:
            return {"error": "Migrations not initialised"}
        # The migration connection is intentionally short-lived, so create a
        # fresh read-only status connection instead of retaining a closed one.
        with sqlite3.connect(str(self._db_path)) as conn:
            return MigrationRunner(conn).status()
