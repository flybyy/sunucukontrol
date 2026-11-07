import json
import os
import sqlite3
import threading
import time
from contextlib import contextmanager
from pathlib import Path

DATA_DIR = Path(os.environ.get("PANEL_DATA_DIR", "/srv/veribayt"))
DB_PATH = DATA_DIR / "serverhub.db"
_lock = threading.RLock()

SCHEMA = r'''
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS metrics (
    ts INTEGER PRIMARY KEY,
    cpu REAL NOT NULL,
    ram REAL NOT NULL,
    disk REAL NOT NULL,
    temp REAL,
    load1 REAL NOT NULL,
    net_sent INTEGER NOT NULL,
    net_recv INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts INTEGER NOT NULL,
    level TEXT NOT NULL,
    kind TEXT NOT NULL,
    message TEXT NOT NULL,
    detail TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts DESC);
CREATE TABLE IF NOT EXISTS internet_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at INTEGER NOT NULL,
    ended_at INTEGER,
    status TEXT NOT NULL,
    detail TEXT NOT NULL DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS projects (
    slug TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    compose_project TEXT NOT NULL,
    domain TEXT NOT NULL DEFAULT '',
    health_url TEXT NOT NULL DEFAULT '',
    db_engine TEXT NOT NULL DEFAULT 'none',
    db_service TEXT NOT NULL DEFAULT 'db',
    app_service TEXT NOT NULL DEFAULT 'app',
    uploads_path TEXT NOT NULL DEFAULT '/var/www/html/uploads',
    auto_backup INTEGER NOT NULL DEFAULT 1,
    backup_hour INTEGER NOT NULL DEFAULT 3,
    keep_backups INTEGER NOT NULL DEFAULT 7,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS releases (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_slug TEXT NOT NULL,
    release_path TEXT NOT NULL,
    version_label TEXT NOT NULL DEFAULT '',
    sha256 TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    deployed_at INTEGER,
    FOREIGN KEY(project_slug) REFERENCES projects(slug) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_releases_project ON releases(project_slug, created_at DESC);
CREATE TABLE IF NOT EXISTS deployments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_slug TEXT NOT NULL,
    release_id INTEGER,
    started_at INTEGER NOT NULL,
    ended_at INTEGER,
    status TEXT NOT NULL,
    output TEXT NOT NULL DEFAULT '',
    FOREIGN KEY(project_slug) REFERENCES projects(slug) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS backups (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_slug TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    path TEXT NOT NULL,
    bytes INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL,
    kind TEXT NOT NULL DEFAULT 'full',
    note TEXT NOT NULL DEFAULT '',
    FOREIGN KEY(project_slug) REFERENCES projects(slug) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_backups_project ON backups(project_slug, created_at DESC);
CREATE TABLE IF NOT EXISTS minecraft_servers (
    slug TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    server_type TEXT NOT NULL DEFAULT 'PAPER',
    version TEXT NOT NULL DEFAULT 'LATEST',
    memory_mb INTEGER NOT NULL DEFAULT 4096,
    max_players INTEGER NOT NULL DEFAULT 20,
    port INTEGER NOT NULL DEFAULT 25565,
    motd TEXT NOT NULL DEFAULT 'Veribayt Minecraft Server',
    difficulty TEXT NOT NULL DEFAULT 'normal',
    online_mode INTEGER NOT NULL DEFAULT 1,
    auto_start INTEGER NOT NULL DEFAULT 1,
    published INTEGER NOT NULL DEFAULT 1,
    access_mode TEXT NOT NULL DEFAULT 'public',
    access_password_hash TEXT NOT NULL DEFAULT '',
    public_host TEXT NOT NULL DEFAULT '',
    whitelist_enabled INTEGER NOT NULL DEFAULT 0,
    whitelist_players TEXT NOT NULL DEFAULT '',
    description TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_minecraft_port ON minecraft_servers(port);
CREATE TABLE IF NOT EXISTS kv (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
'''


def init_db():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    with connect() as c:
        c.executescript(SCHEMA)
        _migrate_minecraft(c)


def _migrate_minecraft(c):
    """Additive migration for installations created before ServerHub v1.3."""
    existing = {row[1] for row in c.execute("PRAGMA table_info(minecraft_servers)").fetchall()}
    columns = {
        "published": "INTEGER NOT NULL DEFAULT 1",
        "access_mode": "TEXT NOT NULL DEFAULT 'public'",
        "access_password_hash": "TEXT NOT NULL DEFAULT ''",
        "public_host": "TEXT NOT NULL DEFAULT ''",
        "whitelist_enabled": "INTEGER NOT NULL DEFAULT 0",
        "whitelist_players": "TEXT NOT NULL DEFAULT ''",
        "description": "TEXT NOT NULL DEFAULT ''",
    }
    for name, definition in columns.items():
        if name not in existing:
            c.execute(f"ALTER TABLE minecraft_servers ADD COLUMN {name} {definition}")


@contextmanager
def connect():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    with _lock:
        c = sqlite3.connect(DB_PATH, timeout=30)
        c.row_factory = sqlite3.Row
        try:
            yield c
            c.commit()
        finally:
            c.close()


def execute(sql: str, params=()):
    with connect() as c:
        cur = c.execute(sql, params)
        return cur.lastrowid


def query(sql: str, params=()):
    with connect() as c:
        return [dict(r) for r in c.execute(sql, params).fetchall()]


def one(sql: str, params=()):
    with connect() as c:
        row = c.execute(sql, params).fetchone()
        return dict(row) if row else None


def event(level: str, kind: str, message: str, detail=None):
    execute(
        "INSERT INTO events(ts,level,kind,message,detail) VALUES(?,?,?,?,?)",
        (int(time.time()), level, kind, message, json.dumps(detail or {}, ensure_ascii=False)),
    )


def set_kv(key: str, value):
    execute(
        "INSERT INTO kv(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        (key, json.dumps(value, ensure_ascii=False)),
    )


def get_kv(key: str, default=None):
    row = one("SELECT value FROM kv WHERE key=?", (key,))
    if not row:
        return default
    try:
        return json.loads(row["value"])
    except Exception:
        return default
