"""Async database manager for Wafford."""

from __future__ import annotations

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any

import aiosqlite

from wafford.constants import DB_PATH
from wafford.exceptions import DatabaseError

logger = logging.getLogger(__name__)

SCHEMA_VERSION = 1


class DatabaseManager:
    """Manages async SQLite database operations."""

    def __init__(self, db_path: Path | None = None) -> None:
        """Initialize database manager.

        Args:
            db_path: Path to SQLite database file. Defaults to WAFFORD_HOME/data/wafford.db.
        """
        self.db_path = Path(db_path or DB_PATH)
        self.db: aiosqlite.Connection | None = None
        self._initialized = False

    async def init_db(self) -> None:
        """Initialize database connection and create schema if needed."""
        try:
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
            self.db = await aiosqlite.connect(str(self.db_path))
            await self.db.execute("PRAGMA foreign_keys = ON")
            await self._create_schema()
            await self.db.commit()
            self._initialized = True
            logger.info("Database initialized at %s", self.db_path)
        except Exception as exc:
            logger.error("Failed to initialize database: %s", exc)
            raise DatabaseError(f"Database initialization failed: {exc}") from exc

    async def _create_schema(self) -> None:
        """Create database schema if it doesn't exist."""
        if not self.db:
            raise DatabaseError("Database not initialized")

        await self.db.execute(
            """
            CREATE TABLE IF NOT EXISTS schema_version (
                version INTEGER PRIMARY KEY,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """
        )

        cursor = await self.db.execute("SELECT version FROM schema_version LIMIT 1")
        row = await cursor.fetchone()

        if row is None:
            await self.db.execute("INSERT INTO schema_version (version) VALUES (?)", (SCHEMA_VERSION,))
            await self._create_tables()
            logger.info("Created database schema version %d", SCHEMA_VERSION)

    async def _create_tables(self) -> None:
        """Create all required tables."""
        if not self.db:
            raise DatabaseError("Database not initialized")

        tables = [
            """
            CREATE TABLE IF NOT EXISTS sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                description TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id INTEGER NOT NULL,
                interface TEXT NOT NULL,
                channel INTEGER,
                duration INTEGER,
                results_json TEXT,
                started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                completed_at TIMESTAMP,
                FOREIGN KEY(session_id) REFERENCES sessions(id) ON DELETE CASCADE
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS networks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                bssid TEXT UNIQUE NOT NULL,
                essid TEXT,
                channel INTEGER,
                encryption TEXT,
                signal_dbm INTEGER,
                vendor TEXT,
                discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                metadata_json TEXT
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS attacks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id INTEGER NOT NULL,
                network_id INTEGER,
                attack_type TEXT NOT NULL,
                status TEXT DEFAULT 'pending',
                result_json TEXT,
                started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                completed_at TIMESTAMP,
                FOREIGN KEY(session_id) REFERENCES sessions(id) ON DELETE CASCADE,
                FOREIGN KEY(network_id) REFERENCES networks(id) ON DELETE SET NULL
            )
            """,
        ]

        for table_sql in tables:
            await self.db.execute(table_sql)

    async def create_session(self, name: str, description: str = "") -> int:
        """Create a new audit session.

        Args:
            name: Session name.
            description: Optional session description.

        Returns:
            Session ID.
        """
        if not self.db:
            raise DatabaseError("Database not initialized")
        try:
            cursor = await self.db.execute(
                "INSERT INTO sessions (name, description) VALUES (?, ?)",
                (name, description),
            )
            await self.db.commit()
            return cursor.lastrowid
        except Exception as exc:
            raise DatabaseError(f"Failed to create session: {exc}") from exc

    async def get_sessions(self) -> list[dict[str, Any]]:
        """Retrieve all sessions.

        Returns:
            List of session dictionaries.
        """
        if not self.db:
            raise DatabaseError("Database not initialized")
        try:
            cursor = await self.db.execute("SELECT * FROM sessions ORDER BY created_at DESC")
            rows = await cursor.fetchall()
            return [
                {
                    "id": r[0],
                    "name": r[1],
                    "description": r[2],
                    "created_at": r[3],
                    "updated_at": r[4],
                }
                for r in rows
            ]
        except Exception as exc:
            raise DatabaseError(f"Failed to retrieve sessions: {exc}") from exc

    async def save_scan(self, session_id: int, interface: str, results: dict[str, Any]) -> int:
        """Save scan results.

        Args:
            session_id: Session ID.
            interface: Interface name.
            results: Scan results dictionary.

        Returns:
            Scan ID.
        """
        if not self.db:
            raise DatabaseError("Database not initialized")
        try:
            cursor = await self.db.execute(
                """
                INSERT INTO scans (session_id, interface, results_json, completed_at)
                VALUES (?, ?, ?, ?)
                """,
                (session_id, interface, json.dumps(results), datetime.now().isoformat()),
            )
            await self.db.commit()
            return cursor.lastrowid
        except Exception as exc:
            raise DatabaseError(f"Failed to save scan: {exc}") from exc

    async def backup(self, output_path: Path | str | None = None) -> Path:
        """Create a database backup.

        Args:
            output_path: Output backup path. Defaults to WAFFORD_HOME/backups.

        Returns:
            Path to backup file.
        """
        if not self.db:
            raise DatabaseError("Database not initialized")
        try:
            from wafford.constants import BACKUP_DIR

            backup_dir = Path(output_path or BACKUP_DIR)
            backup_dir.mkdir(parents=True, exist_ok=True)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_path = backup_dir / f"wafford_backup_{timestamp}.db"

            await self.db.backup(str(backup_path))
            logger.info("Database backed up to %s", backup_path)
            return backup_path
        except Exception as exc:
            raise DatabaseError(f"Backup failed: {exc}") from exc

    async def export_json(self, output_path: Path | str) -> Path:
        """Export database to JSON.

        Args:
            output_path: Output JSON path.

        Returns:
            Path to exported file.
        """
        if not self.db:
            raise DatabaseError("Database not initialized")
        try:
            sessions = await self.get_sessions()
            export_data = {"sessions": sessions, "exported_at": datetime.now().isoformat()}

            output_path = Path(output_path)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(json.dumps(export_data, indent=2))
            logger.info("Database exported to %s", output_path)
            return output_path
        except Exception as exc:
            raise DatabaseError(f"Export failed: {exc}") from exc

    async def vacuum(self) -> None:
        """Optimize database by vacuuming."""
        if not self.db:
            raise DatabaseError("Database not initialized")
        try:
            await self.db.execute("VACUUM")
            await self.db.commit()
            logger.info("Database vacuumed")
        except Exception as exc:
            raise DatabaseError(f"Vacuum failed: {exc}") from exc

    def migration_status(self) -> dict[str, Any]:
        """Get migration status (synchronous for CLI use).

        Returns:
            Migration status dictionary.
        """
        return {
            "current_version": SCHEMA_VERSION,
            "target_version": SCHEMA_VERSION,
            "pending_count": 0,
        }

    async def close(self) -> None:
        """Close database connection."""
        if self.db:
            await self.db.close()
            logger.info("Database connection closed")
