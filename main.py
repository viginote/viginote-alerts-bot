"""
main.py — VigiNote OSINT Alerts Bot  v2.0
Orchestrator: wires together all modules in viginote/

Architecture
------------
viginote/db.py          Extended SQLite schema + query helpers
viginote/feeds.py       Feed registry + article fetching utilities
viginote/scoring.py     Severity scoring + source-tier bonus map
viginote/ner.py         Named entity extraction (spaCy)
viginote/collector.py   Async feed polling + candidate ranking
viginote/summary.py     AI / heuristic one-line summarisation
viginote/feed_monitor.py Feed health digest
viginote/api.py         FastAPI REST endpoint for briefing pipelines

Start API separately:
    uvicorn viginote.api:app --host 0.0.0.0 --port 8000
"""

import html
import os
import random
import time
import traceback
from collections import defaultdict
from datetime import datetime, timezone

import requests

from viginote.collector import collect_candidates, rank_candidates, make_title_hash
from viginote.db import (
    init_db, kv_get, kv_set, daily_count, recent_titles,
    insert_sent, find_or_create_cluster, mark_cluster_sent,
)
from viginote.feed_monitor import maybe_send_health_digest
from viginote.feeds import FEEDS, domain_of
from viginote.ner import extract_entities
from viginote.scoring import severity_icon, build_selection_reason, source_tier
from viginote.summary import concise_summary

# =======================
# ENV / CONFIG
# =======================
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID   = os.getenv("TELEGRAM_CHAT_ID", "")
if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
    raise SystemExit("ERROR: Set TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID env vars before starting.")

REGIONS            = [s.strip().upper() for s in os.getenv("REGIONS","GLOBAL,MIDDLE_EAST,EUROPE,ASIA,WEST_EAST_AFRICA,SOUTHERN_AFRICA,SOUTH_AMERICA").split(",") if s.strip()]
CUSTOM_FEEDS       = [u.strip() for u in os.getenv("CUSTOM_FEEDS","").split(",") if u.strip()]

MAX_ALERTS_PER_RUN = int(os.getenv("MAX_ALERTS_PER_RUN", "3"))
MAX_ALERTS_PER_DAY = int(os.getenv("MAX_ALERTS_PER_DAY", "18"))
MIN_GAP_SECONDS    = int(os.getenv("MIN_GAP_SECONDS", "90"))
QUIET_SPEC         = os.getenv("QUIET_HOURS_UTC", "")
MIN_PER_REGION     = int(os.getenv("MIN_PER_REGION", "1"))
CRITICAL_THRESHOLD = int(os.getenv("CRITICAL_THRESHOLD", "8"))
NONCRIT_COOLDOWN   = int(os.getenv("NONCRITICAL_COOLDOWN_SECONDS", "1500"))
FEED_SHUFFLE       = os.getenv("FEED_SHUFFLE", "1") == "1"
DEDUPE_DAYS        = int(os.getenv("DEDUPE_DAYS", "3"))
DEBUG              = os.getenv("DEBUG", "0") == "1"


# =======================
# UTILITIES
# =======================
def html_escape(s: str) -> str:
    return html.escape(s or "", quote=True)


def in_quiet_hours(spec: str) -> bool:
    if not spec or "-" not in spec:
        return False
    try:
        s, e = [int(x) for x in spec.split("-")]
        h = datetime.now(timezone.utc).hour
        return (s <= h < e) if s <= e else (h >= s or h < e)
    except Exception:
        return False


def send_tg(text: str) -> bool:
    try:
        r = requests.post(
            f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage",
            data={
                "chat_id": TELEGRAM_CHAT_ID,
                "text": text,
                "parse_mode": "HTML",
                "disable_web_page_preview": True,
            },
            timeout=20,
        )
        ok = r.json().get("ok", False)
        if not ok:
            print("[TG ERROR]", r.json())
        return ok
    except Exception as e:
        print("[TG EXC]", e)
        return False


def debug_tg(msg: str):
    if DEBUG:
        try:
            send_tg(f"🛠 {msg}")
        except Exception as e:
            print("[DEBUG_TG EXC]", e)


def build_feeds() -> list[tuple[str, list[str]]]:
    feeds = []
    for region in REGIONS:
        urls = FEEDS.get(region, [])
        if urls:
            feeds.append((region, urls))
    if CUSTOM_FEEDS:
        feeds.append(("CUSTOM", CUSTOM_FEEDS))
    if FEED_SHUFFLE:
        random.seed(int(time.time()) // 60)
        random.shuffle(feeds)
    return feeds


# =======================
# MAIN LOOP
# =======================
def run_once():
    if in_quiet_hours(QUIET_SPEC):
        print("⏸ quiet hours")
        debug_tg("Quiet hours—skipping.")
        return

    feeds = build_feeds()
    conn  = init_db()
    total_today = daily_count(conn)
    sent_run    = 0
    per_region_sent: dict[str, int] = defaultdict(int)
    seen_hash_this_run: set = set()

    last_nc = kv_get(conn, "last_noncritical_ts", "0")
    last_noncrit_ts = int(last_nc) if str(last_nc).isdigit() else 0

    total_feed_count = sum(len(u) for _, u in feeds)
    print(
        f"Polling {total_feed_count} feeds across {len(feeds)} regions "
        f"| caps: run={MAX_ALERTS_PER_RUN}/day={MAX_ALERTS_PER_DAY}"
    )

    recent = recent_titles(conn, days=DEDUPE_DAYS)

    # ── Phase 1: async-collect all candidates ────────────────────────────────
    candidates = collect_candidates(feeds, conn, recent, seen_hash_this_run)
    print(f"  → {len(candidates)} candidates above threshold")

    # ── Phase 2: rank (score + region diversity) ──────────────────────────────
    ranked = rank_candidates(candidates)

    # ── Phase 3: enrich + send top 1-3 ───────────────────────────────────────
    for c in ranked:
        if sent_run >= MAX_ALERTS_PER_RUN or total_today >= MAX_ALERTS_PER_DAY:
            break

        is_critical = c["is_critical"]
        now_ts = int(time.time())
        if not is_critical and (now_ts - last_noncrit_ts) < NONCRIT_COOLDOWN:
            continue

        # Best-effort regional diversity
        if MIN_PER_REGION > 0:
            need = {r for r, _ in feeds if per_region_sent[r] < MIN_PER_REGION}
            if need and c["region"] not in need and sent_run < len(need):
                continue

        # ── Enrichment ────────────────────────────────────────────────────────
        precis  = concise_summary(c["raw_title"], c["text"])
        entities = extract_entities(c["raw_title"], c["text"])

        # Cluster + corroboration
        from rapidfuzz import fuzz as _fuzz
        cluster_id, source_count = find_or_create_cluster(
            conn,
            title=c["raw_title"],
            region=c["region"],
            score=c["score"],
            url=c["link"],
            domain=c["dom"],
            tier=c["tier"],
            sim_fn=lambda a, b: _fuzz.token_set_ratio(a, b),
        )

        selection_reason = build_selection_reason(
            score=c["score"],
            tier=c["tier"],
            region=c["region"],
            source_count=source_count,
            is_critical=is_critical,
        )

        # ── Telegram message ──────────────────────────────────────────────────
        ico        = severity_icon(c["score"])
        region_tag = c["region"].replace("_", " ").title()

        if c["tier"] == 2:
            source_label = f"{html_escape(c['dom'])} 🔍"
        elif c["tier"] == 1:
            source_label = f"{html_escape(c['dom'])} 📡"
        else:
            source_label = html_escape(c["dom"])

        corroboration = ""
        if source_count >= 2:
            corroboration = f" | ✅ {source_count} sources"

        # Named entity snippet for Telegram
        locs = entities.get("locs", [])[:3]
        ents_snippet = f"\n📍 {', '.join(locs)}" if locs else ""

        msg = (
            f"{ico} <b>[{html_escape(region_tag)}] {html_escape(c['raw_title'])}</b>\n"
            f"<code>{html_escape(precis)}</code>"
            f"{ents_snippet}\n"
            f"• Source: {source_label}  |  Score: {c['score']}{corroboration}\n\n"
            f"🔗 <a href=\"{html_escape(c['link'])}\">Full report</a>"
        )

        if send_tg(msg):
            insert_sent(
                conn,
                url=c["link"],
                title=c["raw_title"],
                title_hash=c["h"],
                is_critical=is_critical,
                region=c["region"],
                source_domain=c["dom"],
                source_tier=c["tier"],
                score=c["score"],
                precis=precis,
                article_text=c["text"],
                entities=entities,
                cluster_id=cluster_id,
                source_count=source_count,
                selection_reason=selection_reason,
            )
            mark_cluster_sent(conn, cluster_id)
            recent.insert(0, c["raw_title"])
            seen_hash_this_run.add(c["h"])
            per_region_sent[c["region"]] += 1
            sent_run += 1
            total_today += 1
            print(
                f"+ sent [{c['region']}] {c['raw_title'][:75]} "
                f"(score={c['score']} tier={c['tier']} sources={source_count} src={c['dom']})"
            )

            if not is_critical:
                last_noncrit_ts = now_ts
                kv_set(conn, "last_noncritical_ts", last_noncrit_ts)

            if MIN_GAP_SECONDS and not is_critical:
                time.sleep(MIN_GAP_SECONDS)
        else:
            print("- send failed:", c["raw_title"][:90])

    # ── Phase 4: feed health digest ───────────────────────────────────────────
    maybe_send_health_digest(conn, send_tg)

    print(
        f"Run done. Sent {sent_run} this run; {total_today}/{MAX_ALERTS_PER_DAY} today "
        f"@ {datetime.now(timezone.utc).isoformat()}"
    )
    if DEBUG:
        debug_tg(f"Heartbeat: sent={sent_run} today={total_today}/{MAX_ALERTS_PER_DAY}")


# =======================
# ENTRYPOINT
# =======================
if __name__ == "__main__":
    interval = int(os.getenv("POLL_INTERVAL", "900"))
    if interval > 0:
        while True:
            try:
                run_once()
            except Exception as e:
                print("FATAL RUN ERROR:", e)
                traceback.print_exc()
            time.sleep(interval)
    else:
        run_once()
