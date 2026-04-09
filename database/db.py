# database/db.py
"""
Async SQLite database layer.
Single file DB — no external dependencies, zero-config, Docker-friendly.
Tables: events, alerts, blocked_ips
"""

import aiosqlite
import asyncio
import json
import os

DB_PATH = os.environ.get("DB_PATH", "/data/hackzion.db")


CREATE_EVENTS_TABLE = """
CREATE TABLE IF NOT EXISTS events (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp        REAL    NOT NULL,
    ip               TEXT    NOT NULL,
    session_id       TEXT,
    attack_type      TEXT,
    attack_vector    TEXT,
    mitre_technique  TEXT,
    attack_phase     TEXT,
    severity         TEXT,
    confidence       REAL,
    risk_score       INTEGER,
    action_taken     TEXT,
    status           TEXT,
    honeypot         INTEGER DEFAULT 1,
    commands_executed TEXT,
    skill_level      TEXT
);
"""

CREATE_ALERTS_TABLE = """
CREATE TABLE IF NOT EXISTS alerts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp   REAL    NOT NULL,
    ip          TEXT,
    name        TEXT,
    severity    TEXT,
    mitre_ttps  TEXT,
    event_count INTEGER,
    raw         TEXT
);
"""

CREATE_BLOCKED_TABLE = """
CREATE TABLE IF NOT EXISTS blocked_ips (
    ip          TEXT PRIMARY KEY,
    blocked_at  REAL NOT NULL,
    reason      TEXT
);
"""

CREATE_INDEXES = [
    "CREATE INDEX IF NOT EXISTS idx_events_ip        ON events(ip);",
    "CREATE INDEX IF NOT EXISTS idx_events_ts        ON events(timestamp);",
    "CREATE INDEX IF NOT EXISTS idx_events_severity  ON events(severity);",
    "CREATE INDEX IF NOT EXISTS idx_alerts_ip        ON alerts(ip);",
]


async def init_db():
    """Create tables and indexes. Safe to call multiple times."""
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(CREATE_EVENTS_TABLE)
        await db.execute(CREATE_ALERTS_TABLE)
        await db.execute(CREATE_BLOCKED_TABLE)
        for idx in CREATE_INDEXES:
            await db.execute(idx)
        await db.commit()


async def insert_event(event: dict) -> int:
    async with aiosqlite.connect(DB_PATH) as db:
        cursor = await db.execute("""
            INSERT INTO events (
                timestamp, ip, session_id, attack_type, attack_vector,
                mitre_technique, attack_phase, severity, confidence,
                risk_score, action_taken, status, honeypot,
                commands_executed, skill_level
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, (
            event.get("timestamp"),
            event.get("ip"),
            event.get("session_id"),
            event.get("attack_type"),
            event.get("attack_vector"),
            event.get("mitre_technique"),
            event.get("attack_phase"),
            event.get("severity"),
            event.get("confidence"),
            event.get("risk_score"),
            event.get("action_taken"),
            event.get("status"),
            1 if event.get("honeypot") else 0,
            json.dumps(event.get("commands_executed", [])),
            event.get("skill_level"),
        ))
        await db.commit()
        return cursor.lastrowid


async def insert_alert(alert: dict) -> int:
    async with aiosqlite.connect(DB_PATH) as db:
        cursor = await db.execute("""
            INSERT INTO alerts (timestamp, ip, name, severity, mitre_ttps, event_count, raw)
            VALUES (?,?,?,?,?,?,?)
        """, (
            alert.get("timestamp", __import__("time").time()),
            alert.get("ip"),
            alert.get("name"),
            alert.get("severity"),
            json.dumps(alert.get("mitre_ttps", [])),
            alert.get("event_count", 0),
            json.dumps(alert),
        ))
        await db.commit()
        return cursor.lastrowid


async def get_live_attacks(limit: int = 50) -> list[dict]:
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute(
            "SELECT * FROM events ORDER BY timestamp DESC LIMIT ?", (limit,)
        )
        rows = await cursor.fetchall()
        return [_row_to_dict(r) for r in rows]


async def get_events_by_session(session_id: str) -> list[dict]:
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute(
            "SELECT * FROM events WHERE session_id = ? ORDER BY timestamp ASC",
            (session_id,)
        )
        rows = await cursor.fetchall()
        return [_row_to_dict(r) for r in rows]


async def get_alerts(limit: int = 100) -> list[dict]:
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute(
            "SELECT * FROM alerts ORDER BY timestamp DESC LIMIT ?", (limit,)
        )
        rows = await cursor.fetchall()
        return [_row_to_dict(r) for r in rows]


async def block_ip(ip: str, reason: str = "manual"):
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "INSERT OR REPLACE INTO blocked_ips (ip, blocked_at, reason) VALUES (?,?,?)",
            (ip, __import__("time").time(), reason)
        )
        await db.commit()


async def get_blocked_ips() -> list[dict]:
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute("SELECT * FROM blocked_ips ORDER BY blocked_at DESC")
        rows = await cursor.fetchall()
        return [_row_to_dict(r) for r in rows]


def _row_to_dict(row) -> dict:
    d = dict(row)
    # Deserialize JSON fields
    for field in ("commands_executed", "mitre_ttps", "raw"):
        if field in d and d[field]:
            try:
                d[field] = json.loads(d[field])
            except (json.JSONDecodeError, TypeError):
                pass
    return d