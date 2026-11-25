"""SQLite connection and schema (data contract section 6)."""

import sqlite3

SCHEMA = """
CREATE TABLE IF NOT EXISTS sources(
  source TEXT PRIMARY KEY, name TEXT, product_type TEXT, first_seen TEXT, last_seen TEXT);
CREATE TABLE IF NOT EXISTS samples(
  uuid TEXT PRIMARY KEY, type TEXT NOT NULL, kind TEXT NOT NULL,
  start TEXT NOT NULL, end TEXT NOT NULL, value REAL NOT NULL, value_label TEXT, unit TEXT,
  source TEXT NOT NULL REFERENCES sources(source), tz TEXT, metadata TEXT);
CREATE INDEX IF NOT EXISTS samples_type_start ON samples(type, start);
CREATE INDEX IF NOT EXISTS samples_type_source_start ON samples(type, source, start);
CREATE INDEX IF NOT EXISTS samples_end ON samples(end);
CREATE TABLE IF NOT EXISTS daily(
  type TEXT NOT NULL, source TEXT NOT NULL, day TEXT NOT NULL, tz TEXT,
  sum REAL, avg REAL, min REAL, max REAL, n REAL, unit TEXT, partial INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (type, source, day));
CREATE TABLE IF NOT EXISTS sleep_nights(
  night TEXT NOT NULL, source TEXT NOT NULL, tz TEXT, start TEXT, end TEXT,
  minutes TEXT, segments TEXT, PRIMARY KEY (night, source));
CREATE TABLE IF NOT EXISTS tombstones(uuid TEXT PRIMARY KEY, type TEXT, deleted_at TEXT);
CREATE TABLE IF NOT EXISTS batches(
  batch_id TEXT PRIMARY KEY, device_id TEXT NOT NULL, seq INTEGER NOT NULL,
  ciphertext_sha256 TEXT, received_at TEXT NOT NULL, status TEXT NOT NULL, flags TEXT);
CREATE TABLE IF NOT EXISTS devices(
  device_id TEXT PRIMARY KEY, name TEXT, signing_pk TEXT, paired_at TEXT, revoked_at TEXT);
CREATE TABLE IF NOT EXISTS seq_reports(
  device_id TEXT NOT NULL, seq INTEGER NOT NULL,
  kind TEXT NOT NULL CHECK(kind IN ('abandoned','dead_letter')),
  PRIMARY KEY (device_id, seq));
CREATE TABLE IF NOT EXISTS pair_tokens(
  token_hash TEXT PRIMARY KEY, key_epoch INTEGER NOT NULL, expires_at TEXT NOT NULL, used_at TEXT);
CREATE TABLE IF NOT EXISTS api_tokens(
  name TEXT PRIMARY KEY, token_hash TEXT NOT NULL UNIQUE, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS sink_queue(
  batch_id TEXT PRIMARY KEY, body TEXT NOT NULL, enqueued_at TEXT NOT NULL, failed_at TEXT);
"""


def connect(path, readonly: bool = False) -> sqlite3.Connection:
    if readonly:
        conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True, isolation_level=None)
    else:
        conn = sqlite3.connect(str(path), isolation_level=None)
    conn.execute("PRAGMA busy_timeout=5000")
    conn.execute("PRAGMA foreign_keys=ON")
    if not readonly:
        conn.execute("PRAGMA journal_mode=WAL")
        if conn.execute("PRAGMA user_version").fetchone()[0] < 1:
            conn.executescript(SCHEMA)
            conn.execute("PRAGMA user_version=1")
        if "failed_at" not in {r[1] for r in conn.execute("PRAGMA table_info(sink_queue)")}:
            conn.execute("ALTER TABLE sink_queue ADD COLUMN failed_at TEXT")  # stores created before parking existed
        # Future-dated sample count and last_seen repair (stores created before it: built once, then a no-op).
        conn.execute("CREATE INDEX IF NOT EXISTS samples_end ON samples(end)")
    return conn
