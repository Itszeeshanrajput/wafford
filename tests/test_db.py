# ruff: noqa: SLF001, S105, S106, B018
"""Tests for the database layer: migrations, sessions, credential storage."""

from __future__ import annotations

import json
import sqlite3

import pytest

from wafford.db.manager import DatabaseManager
from wafford.db.migrations import MigrationRunner

# ── Migrations ──────────────────────────────────────────────────────────────

@pytest.fixture
def sync_conn(tmp_path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(tmp_path / "migrate.db"))
    try:
        yield conn
    finally:
        conn.close()


def test_migrations_run_pending_creates_schema(sync_conn) -> None:
    runner = MigrationRunner(sync_conn)
    applied = runner.run_pending()
    assert len(applied) == 3
    assert runner.current_version() == 3
    assert runner.target_version() == 3

    tables = {
        row[0]
        for row in sync_conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
    }
    for t in ("sessions", "networks", "attacks", "credentials", "wordlists", "reports"):
        assert t in tables


def test_migrations_idempotent(sync_conn) -> None:
    runner = MigrationRunner(sync_conn)
    runner.run_pending()
    applied_again = MigrationRunner(sync_conn).run_pending()
    assert applied_again == []
    assert MigrationRunner(sync_conn).current_version() == 3


def test_migrations_status(sync_conn) -> None:
    runner = MigrationRunner(sync_conn)
    runner.run_pending()
    status = runner.status()
    assert status["current_version"] == 3
    assert status["target_version"] == 3
    assert status["pending_count"] == 0
    assert status["applied"] == [1, 2, 3]


def test_migrations_pending_reports(sync_conn) -> None:
    runner = MigrationRunner(sync_conn)
    assert runner.current_version() == 0
    assert len(runner.pending()) == 3
    assert runner.migrate()


def test_migration_repr(sync_conn) -> None:
    runner = MigrationRunner(sync_conn)
    m = runner._migrations[0]
    assert "v1" in repr(m)


# ── DatabaseManager (async) ─────────────────────────────────────────────────

@pytest.fixture
async def db(tmp_path):
    mgr = DatabaseManager(db_path=tmp_path / "wafford.db")
    await mgr.init_db()
    try:
        yield mgr
    finally:
        await mgr.close()


async def test_init_db_and_migrations(db, tmp_path) -> None:
    assert db.db is not None
    status = db.migration_status()
    assert status["current_version"] == status["target_version"] == 3
    with sqlite3.connect(str(tmp_path / "wafford.db")) as conn:
        tables = {
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
    assert "sessions" in tables
    assert "networks" in tables
    assert "credentials" in tables


async def test_create_and_get_session(db) -> None:
    sid = await db.create_session(name="audit1", notes="n1")
    sess = await db.get_session(sid)
    assert sess is not None
    assert sess["name"] == "audit1"
    assert sess["status"] == "active"


async def test_end_session(db) -> None:
    sid = await db.create_session()
    await db.end_session(sid, status="completed")
    sess = await db.get_session(sid)
    assert sess["status"] == "completed"
    assert sess["ended_at"] is not None


async def test_get_sessions_filter(db) -> None:
    await db.create_session(name="one")
    s2 = await db.create_session(name="two")
    await db.end_session(s2, status="completed")
    sessions = await db.get_sessions()
    assert len(sessions) >= 2
    completed = await db.get_sessions(status="completed")
    assert all(s["status"] == "completed" for s in completed)


async def test_delete_session(db) -> None:
    sid = await db.create_session()
    await db.delete_session(sid)
    assert await db.get_session(sid) is None


async def test_add_network_and_query(db) -> None:
    sid = await db.create_session()
    await db.add_network(
        sid, "00:1B:2F:AA:BB:CC", essid="Home", channel=6,
        encryption="WPA2", signal_dbm=-60,
    )
    nets = await db.get_networks(sid)
    assert len(nets) == 1
    assert nets[0]["essid"] == "Home"

    encrypted = await db.get_networks(sid, encryption="WPA2")
    assert len(encrypted) == 1
    strong = await db.get_networks(sid, min_signal=-50)
    assert strong == []


async def test_add_network_upsert_same_bssid(db) -> None:
    sid = await db.create_session()
    await db.add_network(sid, "AA:BB:CC:DD:EE:FF", essid="A", channel=1)
    await db.add_network(sid, "AA:BB:CC:DD:EE:FF", essid="B", channel=11)
    nets = await db.get_networks(sid)
    assert len(nets) == 1
    assert nets[0]["essid"] == "B"
    assert nets[0]["channel"] == 11


async def test_credential_storage_and_retrieval(db) -> None:
    sid = await db.create_session()
    nid = await db.add_network(sid, "10:0C:6B:00:00:01", essid="Test")
    cid = await db.add_credential(
        sid, bssid="10:0C:6B:00:00:01", essid="Test",
        password="supersecret", psk="wpa2psk", network_id=nid,
    )
    creds = await db.get_credentials(sid)
    assert len(creds) == 1
    assert creds[0]["password"] == "supersecret"
    single = await db.get_credential(cid)
    assert single["psk"] == "wpa2psk"


async def test_attack_lifecycle(db) -> None:
    sid = await db.create_session()
    aid = await db.add_attack(sid, "deauth", "AA:BB:CC:DD:EE:FF", target_essid="X")
    await db.update_attack(aid, status="running", packets_sent=100)
    await db.update_attack(aid, status="completed", duration_sec=5.0)
    atk = await db.get_attack(aid)
    assert atk["status"] == "completed"
    assert atk["packets_sent"] == 100
    assert atk["duration_sec"] == 5.0


async def test_handshake_and_crack_jobs(db) -> None:
    sid = await db.create_session()
    nid = await db.add_network(sid, "00:1B:2F:AA:BB:CC")
    hid = await db.add_handshake(
        sid, nid, "00:1B:2F:AA:BB:CC", eapol_count=4, valid=True,
    )
    jid = await db.add_crack_job(sid, hid, tool="hashcat")
    await db.update_crack_job(jid, status="completed", progress=1.0)
    job = await db.get_crack_job(jid)
    assert job["progress"] == 1.0
    hs = await db.get_handshakes(sid)
    assert hs[0]["eapol_count"] == 4


async def test_settings_roundtrip(db) -> None:
    await db.set_setting("theme", "NORD")
    assert await db.get_setting("theme") == "NORD"
    assert await db.get_setting("missing", "dflt") == "dflt"
    assert (await db.get_all_settings())["theme"] == "NORD"


async def test_add_interface(db) -> None:
    sid = await db.create_session()
    iid = await db.add_interface(
        sid, "wlan0", mac_address="00:11:22:33:44:55", mode="monitor", is_primary=True,
    )
    ifaces = await db.get_interfaces(sid)
    assert len(ifaces) == 1
    assert ifaces[0]["mode"] == "monitor"
    await db.update_interface_mode(iid, "managed")
    assert (await db.get_interface(iid))["mode"] == "managed"


async def test_plugins(db) -> None:
    await db.add_plugin("gps", version="1.0.0", enabled=True)
    await db.add_plugin("disabled", version="0.1.0", enabled=False)
    all_plugs = await db.get_plugins()
    assert len(all_plugs) == 2
    enabled = await db.get_plugins(enabled_only=True)
    assert len(enabled) == 1
    assert enabled[0]["name"] == "gps"


async def test_backup_and_vacuum(db, tmp_path) -> None:
    await db.create_session()
    dest = tmp_path / "backup.db"
    out = await db.backup(dest)
    assert out.exists()
    await db.vacuum()


async def test_export_and_import_json(db, tmp_path) -> None:
    sid = await db.create_session()
    await db.add_network(sid, "AA:BB:CC:DD:EE:FF", essid="Net")
    dest = tmp_path / "export.json"
    out = await db.export_json(dest)
    data = json.loads(out.read_text(encoding="utf-8"))
    assert "sessions" in data
    assert "networks" in data
    assert len(data["networks"]) == 1

    new_db = DatabaseManager(db_path=tmp_path / "import.db")
    await new_db.init_db()
    await new_db.import_json(dest)
    await new_db.close()


async def test_log_entries(db) -> None:
    await db.add_log_entry("INFO", "hello")
    entries = await db.get_log_entries(level="INFO")
    assert len(entries) == 1
    assert entries[0]["message"] == "hello"
    count = await db.cleanup_old_logs()
    assert count is not None


def test_db_not_initialised_raises(tmp_path) -> None:
    mgr = DatabaseManager(db_path=tmp_path / "x.db")
    with pytest.raises(RuntimeError):
        mgr.db
