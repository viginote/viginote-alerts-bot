"""
sa_pipeline.py — South Africa edition: poll → dedupe → classify → score → store.

Storage model (table sa_articles) keeps ONLY: headline, a short machine summary
(<= 280 chars), the source name/link, topic, province/city, score and review
status. Article bodies are never stored or republished.

Review workflow:
  pending   -> waiting for a human (default)
  approved  -> visible on the public site
  rejected  -> hidden
SA_SITE_AUTOPUBLISH=1 auto-approves tier-3 (official) items for the SITE only.
Instagram posts always need explicit approval (see sa_site.py / sa_social.py).
"""
from __future__ import annotations

import asyncio
import hashlib
import os
import re
import sqlite3
import time
from html import unescape

import aiohttp
import feedparser
from rapidfuzz import fuzz

from viginote.sa_geo import detect_location
from viginote.sa_sources import rss_sources, source_by_domain
from viginote.sa_topics import classify_topic, importance, is_skippable, level

UA = os.getenv("USER_AGENT", "VigiNoteZA/1.0 (+https://viginote.com)")
POLL_LIMIT = int(os.getenv("SA_POLL_LIMIT", "30"))
MIN_SCORE = int(os.getenv("SA_MIN_SCORE", "2"))
SIM_THRESHOLD = int(os.getenv("SA_SIM_THRESHOLD", "82"))
AUTOPUBLISH = os.getenv("SA_SITE_AUTOPUBLISH", "0") == "1"
SUMMARY_MAX = 280
MAX_AGE_HOURS = int(os.getenv("SA_MAX_AGE_HOURS", "72"))
FETCH_TIMEOUT = aiohttp.ClientTimeout(total=25)

SCHEMA = """
CREATE TABLE IF NOT EXISTS sa_articles (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    url          TEXT UNIQUE NOT NULL,
    title        TEXT NOT NULL,
    title_hash   TEXT,
    summary      TEXT,
    source_name  TEXT,
    source_domain TEXT,
    source_tier  INTEGER DEFAULT 1,
    topic        TEXT,
    province     TEXT,
    city         TEXT,
    place        TEXT,
    score        INTEGER DEFAULT 0,
    level        TEXT,
    cluster_id   INTEGER,
    corroboration INTEGER DEFAULT 1,
    published_ts INTEGER,
    ts           INTEGER NOT NULL,
    status       TEXT DEFAULT 'pending',
    reviewed_ts  INTEGER,
    reviewer_note TEXT,
    instagram_ok INTEGER DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_saa_ts      ON sa_articles(ts);
CREATE INDEX IF NOT EXISTS idx_saa_status  ON sa_articles(status);
CREATE INDEX IF NOT EXISTS idx_saa_topic   ON sa_articles(topic);
CREATE INDEX IF NOT EXISTS idx_saa_prov    ON sa_articles(province);
CREATE TABLE IF NOT EXISTS sa_corrections (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    article_id INTEGER,
    ts         INTEGER NOT NULL,
    text       TEXT NOT NULL
);
"""


def init_sa(conn: sqlite3.Connection) -> None:
    conn.executescript(SCHEMA)
    conn.commit()


# ── helpers ───────────────────────────────────────────────────────────────
_TAG = re.compile(r"<[^>]+>")


def clean(text: str) -> str:
    return re.sub(r"\s+", " ", unescape(_TAG.sub(" ", text or ""))).strip()


def short_summary(text: str, title: str) -> str:
    """First sentence(s) of the feed's own summary, capped. Never full text."""
    t = clean(text)
    if not t or fuzz.ratio(t.lower(), title.lower()) > 90:
        return ""
    if len(t) <= SUMMARY_MAX:
        return t
    cut = t[:SUMMARY_MAX]
    end = max(cut.rfind(". "), cut.rfind("? "), cut.rfind("! "))
    return (cut[: end + 1] if end > 120 else cut.rsplit(" ", 1)[0] + "…")


def title_hash(title: str) -> str:
    t = re.sub(r"\s+", " ", title.split(" | ")[0].strip().lower())
    return hashlib.sha1(t.encode()).hexdigest()


def _entry_ts(entry) -> int | None:
    for k in ("published_parsed", "updated_parsed"):
        v = entry.get(k)
        if v:
            try:
                return int(time.mktime(v))
            except Exception:
                pass
    return None


async def _fetch(session: aiohttp.ClientSession, src: dict):
    try:
        async with session.get(src["url"], headers={"User-Agent": UA}, timeout=FETCH_TIMEOUT) as r:
            if r.status == 200:
                return src, await r.read(), ""
            return src, None, f"HTTP {r.status}"
    except Exception as e:  # noqa: BLE001
        return src, None, str(e)[:120]


async def _poll(sources: list[dict]):
    async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False, limit=30)) as s:
        return await asyncio.gather(*[_fetch(s, x) for x in sources])


def _record_health(conn, src, ok: bool, err: str):
    now = int(time.time())
    row = conn.execute("SELECT 1 FROM feed_health WHERE feed_url=?", (src["url"],)).fetchone()
    if not row:
        conn.execute("INSERT INTO feed_health(feed_url,region,total_fetches,total_errors,consecutive_failures)"
                     " VALUES(?,?,0,0,0)", (src["url"], "ZA"))
    if ok:
        conn.execute("UPDATE feed_health SET last_attempt=?,last_success=?,last_error='',consecutive_failures=0,"
                     "total_fetches=total_fetches+1 WHERE feed_url=?", (now, now, src["url"]))
    else:
        conn.execute("UPDATE feed_health SET last_attempt=?,last_error=?,consecutive_failures=consecutive_failures+1,"
                     "total_fetches=total_fetches+1,total_errors=total_errors+1 WHERE feed_url=?",
                     (now, err, src["url"]))


def _recent_titles(conn, hours=96) -> list[tuple[int, str]]:
    cutoff = int(time.time()) - hours * 3600
    return [(r[0], r[1]) for r in conn.execute(
        "SELECT id,title FROM sa_articles WHERE ts>=? ORDER BY ts DESC", (cutoff,))]


def run_once(conn: sqlite3.Connection, sources: list[dict] | None = None, fetched=None) -> dict:
    """Poll all SA feeds once. `fetched` lets tests inject [(src, bytes, err)]."""
    init_sa(conn)
    sources = sources or rss_sources()
    if fetched is None:
        fetched = asyncio.run(_poll(sources))

    recent = _recent_titles(conn)
    stats = {"feeds_ok": 0, "feeds_failed": 0, "seen": 0, "stored": 0, "dupes": 0, "skipped": 0, "stale": 0}
    now = int(time.time())
    cutoff = now - MAX_AGE_HOURS * 3600

    for src, body, err in fetched:
        _record_health(conn, src, body is not None, err)
        if body is None:
            stats["feeds_failed"] += 1
            continue
        stats["feeds_ok"] += 1
        for e in feedparser.parse(body).entries[:POLL_LIMIT]:
            title = clean(e.get("title", ""))
            link = (e.get("link") or "").strip()
            if not title or not link:
                continue
            stats["seen"] += 1
            if conn.execute("SELECT 1 FROM sa_articles WHERE url=?", (link,)).fetchone():
                continue
            pub = _entry_ts(e)
            if pub and pub < cutoff:
                stats["stale"] += 1
                continue
            summ_raw = e.get("summary") or ""
            if is_skippable(title, summ_raw):
                stats["skipped"] += 1
                continue

            # cluster: same story from other outlets bumps corroboration instead of a new row
            match = next((rid for rid, t in recent if fuzz.token_set_ratio(title, t) >= SIM_THRESHOLD), None)
            if match:
                conn.execute(
                    "UPDATE sa_articles SET corroboration=corroboration+1, "
                    "score=MIN(10, score + CASE WHEN corroboration+1 IN (2,4) THEN 1 ELSE 0 END) WHERE id=?",
                    (match,))
                conn.execute(
                    "UPDATE sa_articles SET level=CASE WHEN score>=8 THEN 'critical' WHEN score>=6 THEN 'high' "
                    "WHEN score>=4 THEN 'elevated' ELSE 'routine' END WHERE id=?", (match,))
                stats["dupes"] += 1
                continue

            topic = classify_topic(title, summ_raw, src["category"])
            loc = detect_location(title, clean(summ_raw))
            sc = importance(title, clean(summ_raw), src["tier"], 1, bool(loc["place"]) and loc["place"] != "National")
            if src["tier"] >= 3 and topic in ("government", "parliament", "courts", "economy"):
                sc = max(sc, MIN_SCORE)  # official statements are kept even if low-drama
            if sc < MIN_SCORE:
                stats["skipped"] += 1
                continue

            status = "approved" if (AUTOPUBLISH and src["tier"] >= 3) else "pending"
            cur = conn.execute(
                "INSERT INTO sa_articles(url,title,title_hash,summary,source_name,source_domain,source_tier,"
                "topic,province,city,place,score,level,published_ts,ts,status) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (link, title, title_hash(title), short_summary(summ_raw, title), src["name"], src["domain"],
                 src["tier"], topic, loc["province"], loc["city"], loc["place"], sc, level(sc),
                 pub or now, now, status))
            recent.insert(0, (cur.lastrowid, title))
            stats["stored"] += 1
    conn.commit()
    return stats
