"""
db.py — VigiNote database layer.

Tables
------
sent_log        One row per SENT alert (existing, extended with new columns)
clusters        Story clusters (cross-source threading)
cluster_members One row per article seen for a cluster
feed_health     Per-feed last-fetch tracking
kv              Key-value store (quotas, last timestamps)
"""

import os
import json
import sqlite3
import time
from datetime import datetime, timezone, timedelta
from contextlib import contextmanager

DB_PATH = os.getenv("DB_PATH", "/data/osint_alerts.db")


def _connect() -> sqlite3.Connection:
    parent = os.path.dirname(DB_PATH)
    if parent and not os.path.exists(parent):
        os.makedirs(parent, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db() -> sqlite3.Connection:
    """Create / migrate all tables and return an open connection."""
    conn = _connect()
    c = conn.cursor()

    # ── sent_log (extended) ──────────────────────────────────────────────────
    c.execute("""
        CREATE TABLE IF NOT EXISTS sent_log (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            url             TEXT    UNIQUE NOT NULL,
            ts              INTEGER NOT NULL,
            title           TEXT,
            title_hash      TEXT,
            is_critical     INTEGER DEFAULT 0,
            region          TEXT,
            source_domain   TEXT,
            source_tier     INTEGER DEFAULT 0,   -- 0=wire 1=regional 2=local
            score           INTEGER DEFAULT 0,
            precis          TEXT,
            article_text    TEXT,               -- first 2000 chars of body
            entities_json   TEXT,               -- JSON: {persons, orgs, locs}
            cluster_id      INTEGER,            -- FK -> clusters.id
            source_count    INTEGER DEFAULT 1,  -- corroboration count
            selection_reason TEXT               -- human-readable audit string
        )
    """)
    c.execute("CREATE INDEX IF NOT EXISTS idx_sent_ts         ON sent_log(ts)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_sent_hash       ON sent_log(title_hash)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_sent_region     ON sent_log(region)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_sent_cluster    ON sent_log(cluster_id)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_sent_critical   ON sent_log(is_critical)")

    # ── clusters ─────────────────────────────────────────────────────────────
    c.execute("""
        CREATE TABLE IF NOT EXISTS clusters (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            first_seen      INTEGER NOT NULL,
            last_seen       INTEGER NOT NULL,
            representative_title TEXT,
            region          TEXT,
            max_score       INTEGER DEFAULT 0,
            source_count    INTEGER DEFAULT 0,
            sent            INTEGER DEFAULT 0   -- 1 if at least one alert sent
        )
    """)

    # ── cluster_members ───────────────────────────────────────────────────────
    c.execute("""
        CREATE TABLE IF NOT EXISTS cluster_members (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            cluster_id      INTEGER NOT NULL REFERENCES clusters(id),
            url             TEXT NOT NULL,
            title           TEXT,
            source_domain   TEXT,
            source_tier     INTEGER DEFAULT 0,
            score           INTEGER DEFAULT 0,
            ts              INTEGER NOT NULL
        )
    """)
    c.execute("CREATE INDEX IF NOT EXISTS idx_cm_cluster ON cluster_members(cluster_id)")

    # ── feed_health ───────────────────────────────────────────────────────────
    c.execute("""
        CREATE TABLE IF NOT EXISTS feed_health (
            feed_url        TEXT PRIMARY KEY,
            region          TEXT,
            last_attempt    INTEGER,
            last_success    INTEGER,
            last_error      TEXT,
            consecutive_failures INTEGER DEFAULT 0,
            total_fetches   INTEGER DEFAULT 0,
            total_errors    INTEGER DEFAULT 0
        )
    """)

    # ── kv ───────────────────────────────────────────────────────────────────
    c.execute("""
        CREATE TABLE IF NOT EXISTS kv (
            k TEXT PRIMARY KEY,
            v TEXT
        )
    """)

    conn.commit()

    # ── Schema migrations — add new columns to existing DBs ──────────────────
    _migrate(conn)

    return conn


def _migrate(conn):
    """Add new columns to existing databases without losing data."""
    migrations = [
        ("sent_log", "country",  "TEXT"),
        ("sent_log", "stream",   "TEXT DEFAULT 'geographic'"),
    ]
    for table, column, col_def in migrations:
        try:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {col_def}")
            conn.commit()
        except Exception:
            pass  # Column already exists — fine

    # Add indexes for new columns
    try:
        conn.execute("CREATE INDEX IF NOT EXISTS idx_sent_country ON sent_log(country)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_sent_stream  ON sent_log(stream)")
        conn.commit()
    except Exception:
        pass


# ── helpers ──────────────────────────────────────────────────────────────────

def kv_get(conn, key, default=None):
    r = conn.execute("SELECT v FROM kv WHERE k=?", (key,)).fetchone()
    return r["v"] if r else default


def kv_set(conn, key, val):
    conn.execute("INSERT OR REPLACE INTO kv(k,v) VALUES(?,?)", (key, str(val)))
    conn.commit()


def today_bounds():
    now = datetime.now(timezone.utc)
    start = datetime(now.year, now.month, now.day, tzinfo=timezone.utc)
    return int(start.timestamp()), int((start + timedelta(days=1)).timestamp())


def daily_count(conn) -> int:
    s, e = today_bounds()
    r = conn.execute("SELECT COUNT(*) FROM sent_log WHERE ts>=? AND ts<?", (s, e)).fetchone()
    return int(r[0] or 0)


def recent_titles(conn, days=3) -> list[str]:
    cutoff = int((datetime.now(timezone.utc) - timedelta(days=days)).timestamp())
    rows = conn.execute(
        "SELECT title FROM sent_log WHERE ts>=? ORDER BY ts DESC LIMIT 500", (cutoff,)
    ).fetchall()
    return [r["title"] for r in rows]


def seen_title_hash(conn, title_hash: str, days=3) -> bool:
    cutoff = int((datetime.now(timezone.utc) - timedelta(days=days)).timestamp())
    r = conn.execute(
        "SELECT 1 FROM sent_log WHERE title_hash=? AND ts>=? LIMIT 1", (title_hash, cutoff)
    ).fetchone()
    return r is not None


def insert_sent(conn, *, url, title, title_hash, is_critical, region,
                source_domain, source_tier, score, precis,
                article_text, entities, cluster_id, source_count,
                selection_reason, country=None, stream="geographic"):
    """Insert a sent alert with all enriched fields including country and stream."""
    conn.execute("""
        INSERT OR IGNORE INTO sent_log
            (url, ts, title, title_hash, is_critical, region, source_domain,
             source_tier, score, precis, article_text, entities_json,
             cluster_id, source_count, selection_reason, country, stream)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
    """, (
        url, int(time.time()), title, title_hash, 1 if is_critical else 0,
        region, source_domain, source_tier, score, precis,
        (article_text or "")[:2000],
        json.dumps(entities or {}),
        cluster_id, source_count, selection_reason,
        country, stream or "geographic",
    ))
    conn.commit()


# ── cluster helpers ───────────────────────────────────────────────────────────

def find_or_create_cluster(conn, title: str, region: str, score: int,
                            url: str, domain: str, tier: int,
                            sim_fn) -> tuple[int, int]:
    """
    Find an existing open cluster whose representative title is similar
    to `title`, or create a new one.
    Returns (cluster_id, source_count).
    """
    now = int(time.time())
    cutoff = now - 86400 * 3  # look back 3 days

    rows = conn.execute(
        "SELECT id, representative_title, source_count FROM clusters WHERE last_seen>=? AND region=?",
        (cutoff, region),
    ).fetchall()

    cluster_id = None
    for row in rows:
        if sim_fn(title, row["representative_title"]) >= 80:
            cluster_id = row["id"]
            break

    if cluster_id is None:
        cur = conn.execute(
            "INSERT INTO clusters(first_seen, last_seen, representative_title, region, max_score, source_count, sent)"
            " VALUES(?,?,?,?,?,1,0)",
            (now, now, title, region, score),
        )
        cluster_id = cur.lastrowid
    else:
        conn.execute(
            "UPDATE clusters SET last_seen=?, max_score=MAX(max_score,?), source_count=source_count+1 WHERE id=?",
            (now, score, cluster_id),
        )

    conn.execute(
        "INSERT INTO cluster_members(cluster_id, url, title, source_domain, source_tier, score, ts)"
        " VALUES(?,?,?,?,?,?,?)",
        (cluster_id, url, title, domain, tier, score, now),
    )

    row = conn.execute("SELECT source_count FROM clusters WHERE id=?", (cluster_id,)).fetchone()
    source_count = row["source_count"] if row else 1
    conn.commit()
    return cluster_id, source_count


def mark_cluster_sent(conn, cluster_id: int):
    conn.execute("UPDATE clusters SET sent=1 WHERE id=?", (cluster_id,))
    conn.commit()


# ── feed health helpers ───────────────────────────────────────────────────────

def record_feed_attempt(conn, feed_url: str, region: str, success: bool, error: str = ""):
    now = int(time.time())
    existing = conn.execute(
        "SELECT consecutive_failures, total_fetches, total_errors FROM feed_health WHERE feed_url=?",
        (feed_url,),
    ).fetchone()

    if existing is None:
        conn.execute("""
            INSERT INTO feed_health(feed_url, region, last_attempt, last_success, last_error,
                                    consecutive_failures, total_fetches, total_errors)
            VALUES(?,?,?,?,?,?,1,?)
        """, (
            feed_url, region, now,
            now if success else None,
            "" if success else error,
            0 if success else 1,
            0 if success else 1,
        ))
    else:
        conn.execute("""
            UPDATE feed_health SET
                last_attempt = ?,
                last_success = CASE WHEN ? THEN ? ELSE last_success END,
                last_error   = CASE WHEN ? THEN '' ELSE ? END,
                consecutive_failures = CASE WHEN ? THEN 0 ELSE consecutive_failures+1 END,
                total_fetches = total_fetches + 1,
                total_errors  = total_errors + (CASE WHEN ? THEN 0 ELSE 1 END)
            WHERE feed_url = ?
        """, (
            now,
            success, now,
            success, error,
            success,
            success,
            feed_url,
        ))
    conn.commit()


def unhealthy_feeds(conn, min_failures: int = 5) -> list[dict]:
    """Return feeds with >= min_failures consecutive failures."""
    rows = conn.execute("""
        SELECT feed_url, region, consecutive_failures, last_success, last_error
        FROM feed_health
        WHERE consecutive_failures >= ?
        ORDER BY consecutive_failures DESC
    """, (min_failures,)).fetchall()
    return [dict(r) for r in rows]


# ── query helpers (used by API) ───────────────────────────────────────────────

def query_alerts(conn, *, region=None, is_critical=None, days=7,
                 min_score=None, limit=50) -> list[dict]:
    cutoff = int((datetime.now(timezone.utc) - timedelta(days=days)).timestamp())
    clauses = ["ts >= ?"]
    params  = [cutoff]
    if region:
        clauses.append("region = ?"); params.append(region.upper())
    if is_critical is not None:
        clauses.append("is_critical = ?"); params.append(1 if is_critical else 0)
    if min_score is not None:
        clauses.append("score >= ?"); params.append(min_score)
    where = " AND ".join(clauses)
    rows = conn.execute(
        f"SELECT * FROM sent_log WHERE {where} ORDER BY ts DESC LIMIT ?",
        params + [limit],
    ).fetchall()
    return [dict(r) for r in rows]


def query_clusters(conn, *, region=None, days=3, min_sources=2) -> list[dict]:
    cutoff = int((datetime.now(timezone.utc) - timedelta(days=days)).timestamp())
    clauses = ["last_seen >= ?", "source_count >= ?"]
    params  = [cutoff, min_sources]
    if region:
        clauses.append("region = ?"); params.append(region.upper())
    where = " AND ".join(clauses)
    rows = conn.execute(
        f"SELECT * FROM clusters WHERE {where} ORDER BY max_score DESC",
        params,
    ).fetchall()
    result = []
    for row in rows:
        d = dict(row)
        members = conn.execute(
            "SELECT * FROM cluster_members WHERE cluster_id=? ORDER BY ts ASC",
            (d["id"],),
        ).fetchall()
        d["members"] = [dict(m) for m in members]
        result.append(d)
    return result
