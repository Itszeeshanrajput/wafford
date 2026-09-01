-- Wafford Database Schema v3
-- SQLite / aiosqlite

PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;
PRAGMA busy_timeout = 5000;

-- ── Migration tracking ───────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS _migrations (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    version     INTEGER NOT NULL UNIQUE,
    name        TEXT    NOT NULL,
    applied_at  TEXT    NOT NULL DEFAULT (datetime('now'))
);

-- ── Sessions ─────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS sessions (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT    NOT NULL DEFAULT 'unnamed',
    started_at  TEXT    NOT NULL DEFAULT (datetime('now')),
    ended_at    TEXT,
    status      TEXT    NOT NULL DEFAULT 'active'
                        CHECK (status IN ('active', 'completed', 'aborted')),
    notes       TEXT    DEFAULT '',
    config_json TEXT    DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_sessions_status ON sessions(status);
CREATE INDEX IF NOT EXISTS idx_sessions_started ON sessions(started_at);

-- ── Interfaces ───────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS interfaces (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id      INTEGER NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    name            TEXT    NOT NULL,
    mac_address     TEXT,
    chipset         TEXT    DEFAULT '',
    driver          TEXT    DEFAULT '',
    physical_id     TEXT    DEFAULT '',
    mode            TEXT    NOT NULL DEFAULT 'managed'
                            CHECK (mode IN ('managed', 'monitor')),
    supported_bands TEXT    DEFAULT '[]',
    is_primary      INTEGER NOT NULL DEFAULT 0,
    added_at        TEXT    NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_interfaces_session ON interfaces(session_id);
CREATE INDEX IF NOT EXISTS idx_interfaces_name ON interfaces(name);

-- ── Networks ─────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS networks (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id      INTEGER NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    bssid           TEXT    NOT NULL,
    essid           TEXT    DEFAULT '',
    channel         INTEGER NOT NULL DEFAULT 0,
    encryption      TEXT    NOT NULL DEFAULT 'Unknown',
    signal_dbm      INTEGER DEFAULT -100,
    signal_percent  INTEGER DEFAULT 0,
    wps             INTEGER NOT NULL DEFAULT 0,
    vendor          TEXT    DEFAULT '',
    first_seen      TEXT    NOT NULL DEFAULT (datetime('now')),
    last_seen       TEXT    NOT NULL DEFAULT (datetime('now')),
    is_hidden       INTEGER NOT NULL DEFAULT 0,
    client_count    INTEGER DEFAULT 0,
    latitude        REAL,
    longitude       REAL,
    notes           TEXT    DEFAULT '',
    UNIQUE(session_id, bssid)
);
CREATE INDEX IF NOT EXISTS idx_networks_session ON networks(session_id);
CREATE INDEX IF NOT EXISTS idx_networks_bssid ON networks(bssid);
CREATE INDEX IF NOT EXISTS idx_networks_channel ON networks(channel);
CREATE INDEX IF NOT EXISTS idx_networks_encryption ON networks(encryption);
CREATE INDEX IF NOT EXISTS idx_networks_signal ON networks(signal_dbm);

-- ── Clients ──────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS clients (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id      INTEGER NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    network_id      INTEGER REFERENCES networks(id) ON DELETE SET NULL,
    mac_address     TEXT    NOT NULL,
    vendor          TEXT    DEFAULT '',
    signal_dbm      INTEGER DEFAULT -100,
    probe_requests  TEXT    DEFAULT '[]',
    is_connected    INTEGER NOT NULL DEFAULT 0,
    first_seen      TEXT    NOT NULL DEFAULT (datetime('now')),
    last_seen       TEXT    NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_clients_session ON clients(session_id);
CREATE INDEX IF NOT EXISTS idx_clients_network ON clients(network_id);
CREATE INDEX IF NOT EXISTS idx_clients_mac ON clients(mac_address);

-- ── Attacks ──────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS attacks (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id      INTEGER NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    network_id      INTEGER REFERENCES networks(id) ON DELETE SET NULL,
    client_id       INTEGER REFERENCES clients(id) ON DELETE SET NULL,
    attack_type     TEXT    NOT NULL,
    status          TEXT    NOT NULL DEFAULT 'pending'
                            CHECK (status IN ('pending', 'running', 'completed', 'failed', 'cancelled')),
    target_bssid    TEXT    NOT NULL,
    target_essid    TEXT    DEFAULT '',
    interface       TEXT    DEFAULT '',
    packets_sent    INTEGER DEFAULT 0,
    duration_sec    REAL    DEFAULT 0,
    started_at      TEXT,
    completed_at    TEXT,
    error_message   TEXT    DEFAULT '',
    result_json     TEXT    DEFAULT '{}',
    notes           TEXT    DEFAULT '',
    created_at      TEXT    NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_attacks_session ON attacks(session_id);
CREATE INDEX IF NOT EXISTS idx_attacks_network ON attacks(network_id);
CREATE INDEX IF NOT EXISTS idx_attacks_type ON attacks(attack_type);
CREATE INDEX IF NOT EXISTS idx_attacks_status ON attacks(status);

-- ── Handshakes ───────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS handshakes (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id      INTEGER NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    network_id      INTEGER NOT NULL REFERENCES networks(id) ON DELETE CASCADE,
    attack_id       INTEGER REFERENCES attacks(id) ON DELETE SET NULL,
    bssid           TEXT    NOT NULL,
    essid           TEXT    DEFAULT '',
    file_path       TEXT    NOT NULL DEFAULT '',
    file_format     TEXT    NOT NULL DEFAULT 'cap'
                            CHECK (file_format IN ('cap', 'pcap', 'hc22000', 'hccapx')),
    eapol_count     INTEGER DEFAULT 0,
    valid           INTEGER NOT NULL DEFAULT 0,
    captured_at     TEXT    NOT NULL DEFAULT (datetime('now')),
    notes           TEXT    DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_handshakes_session ON handshakes(session_id);
CREATE INDEX IF NOT EXISTS idx_handshakes_network ON handshakes(network_id);
CREATE INDEX IF NOT EXISTS idx_handshakes_bssid ON handshakes(bssid);

-- ── Crack jobs ───────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS crack_jobs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id      INTEGER NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    handshake_id    INTEGER NOT NULL REFERENCES handshakes(id) ON DELETE CASCADE,
    attack_mode     TEXT    NOT NULL DEFAULT 'dictionary'
                            CHECK (attack_mode IN ('dictionary', 'brute', 'mask', 'hybrid')),
    wordlist_path   TEXT    DEFAULT '',
    rules_path      TEXT    DEFAULT '',
    mask            TEXT    DEFAULT '',
    tool            TEXT    NOT NULL DEFAULT 'aircrack-ng'
                            CHECK (tool IN ('aircrack-ng', 'hashcat', 'john')),
    status          TEXT    NOT NULL DEFAULT 'pending'
                            CHECK (status IN ('pending', 'running', 'completed', 'failed', 'cancelled')),
    progress        REAL    DEFAULT 0.0,
    speed           REAL    DEFAULT 0.0,
    keyspace        INTEGER DEFAULT 0,
    elapsed_sec     REAL    DEFAULT 0.0,
    started_at      TEXT,
    completed_at    TEXT,
    error_message   TEXT    DEFAULT '',
    created_at      TEXT    NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_crack_jobs_session ON crack_jobs(session_id);
CREATE INDEX IF NOT EXISTS idx_crack_jobs_handshake ON crack_jobs(handshake_id);
CREATE INDEX IF NOT EXISTS idx_crack_jobs_status ON crack_jobs(status);

-- ── Credentials ──────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS credentials (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id      INTEGER NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    crack_job_id    INTEGER REFERENCES crack_jobs(id) ON DELETE SET NULL,
    network_id      INTEGER REFERENCES networks(id) ON DELETE SET NULL,
    bssid           TEXT    NOT NULL,
    essid           TEXT    DEFAULT '',
    password        TEXT    DEFAULT '',
    psk             TEXT    DEFAULT '',
    identity        TEXT    DEFAULT '',
    algorithm       TEXT    DEFAULT '',
    found_at        TEXT    NOT NULL DEFAULT (datetime('now')),
    notes           TEXT    DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_credentials_session ON credentials(session_id);
CREATE INDEX IF NOT EXISTS idx_credentials_bssid ON credentials(bssid);
CREATE INDEX IF NOT EXISTS idx_credentials_essid ON credentials(essid);

-- ── Plugins ──────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS plugins (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT    NOT NULL UNIQUE,
    version     TEXT    NOT NULL DEFAULT '0.0.0',
    author      TEXT    DEFAULT '',
    description TEXT    DEFAULT '',
    file_path   TEXT    NOT NULL DEFAULT '',
    enabled     INTEGER NOT NULL DEFAULT 1,
    settings    TEXT    DEFAULT '{}',
    loaded_at   TEXT,
    added_at    TEXT    NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_plugins_name ON plugins(name);
CREATE INDEX IF NOT EXISTS idx_plugins_enabled ON plugins(enabled);

-- ── Settings ─────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS settings (
    key         TEXT PRIMARY KEY,
    value       TEXT NOT NULL DEFAULT '',
    updated_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

-- ── Log entries ──────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS log_entries (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id  INTEGER REFERENCES sessions(id) ON DELETE SET NULL,
    level       TEXT    NOT NULL DEFAULT 'INFO'
                        CHECK (level IN ('DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL')),
    module      TEXT    DEFAULT '',
    message     TEXT    NOT NULL DEFAULT '',
    data_json   TEXT    DEFAULT '{}',
    created_at  TEXT    NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_log_entries_session ON log_entries(session_id);
CREATE INDEX IF NOT EXISTS idx_log_entries_level ON log_entries(level);
CREATE INDEX IF NOT EXISTS idx_log_entries_created ON log_entries(created_at);

-- ── Wordlists ────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS wordlists (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT    NOT NULL,
    file_path   TEXT    NOT NULL UNIQUE,
    word_count  INTEGER DEFAULT 0,
    size_bytes  INTEGER DEFAULT 0,
    md5_hash    TEXT    DEFAULT '',
    is_default  INTEGER NOT NULL DEFAULT 0,
    added_at    TEXT    NOT NULL DEFAULT (datetime('now')),
    last_used   TEXT
);
CREATE INDEX IF NOT EXISTS idx_wordlists_path ON wordlists(file_path);

-- ── Reports ──────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS reports (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id  INTEGER NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    title       TEXT    NOT NULL DEFAULT 'Audit Report',
    format      TEXT    NOT NULL DEFAULT 'html'
                        CHECK (format IN ('html', 'pdf', 'json', 'csv', 'txt')),
    file_path   TEXT    NOT NULL DEFAULT '',
    file_size   INTEGER DEFAULT 0,
    summary     TEXT    DEFAULT '',
    created_at  TEXT    NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_reports_session ON reports(session_id);
CREATE INDEX IF NOT EXISTS idx_reports_format ON reports(format);
