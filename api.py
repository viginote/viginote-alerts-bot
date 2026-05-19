"""
VigiNote Briefing API — FastAPI webhook receiver + query interface.

Start:  uvicorn api:app --host 0.0.0.0 --port 8000 --reload
Or set: WEBHOOK_URL=http://localhost:8000/ingest in your bot env.

Endpoints:
  POST /ingest          — receive alerts from the bot (called automatically)
  GET  /alerts          — query stored alerts with filters
  GET  /alerts/{id}     — single alert with full article text + entities
  GET  /briefing        — markdown briefing digest for a time window
  GET  /entities        — top entities across a time window
  GET  /health          — uptime check
"""

import os, json, sqlite3
from datetime import datetime, timezone, timedelta
from typing import Optional
from fastapi import FastAPI, Query, HTTPException
from fastapi.responses import PlainTextResponse

DB_PATH = os.getenv("DB_PATH", "/data/osint_alerts.db")

app = FastAPI(
    title="VigiNote Briefing API",
    description="Query and ingest OSINT alerts for professional briefing generation.",
    version="1.0.0",
)

# =======================
# DB HELPER
# =======================
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def row_to_dict(row) -> dict:
    d = dict(row)
    if d.get("entities") and isinstance(d["entities"], str):
        try:
            d["entities"] = json.loads(d["entities"])
        except Exception:
            d["entities"] = {}
    return d

# =======================
# INGEST (called by bot)
# =======================
@app.post("/ingest", status_code=201)
def ingest(alert: dict):
    """
    Receive a structured alert from the bot and write it to the DB.
    The bot calls this automatically if WEBHOOK_URL is set.
    """
    conn = get_db()
    cur  = conn.cursor()
    try:
        cur.execute("""INSERT OR IGNORE INTO sent_log
            (url, ts, ts_iso, title, title_hash, region, source_dom, source_tier,
             score, is_critical, precis, entities, article_text, selection_reason, feed_url)
            VALUES (:url,:ts,:ts_iso,:title,:title_hash,:region,:source_dom,:source_tier,
                    :score,:is_critical,:precis,:entities,:article_text,:selection_reason,:feed_url)""",
            {**alert,
             "entities": json.dumps(alert.get("entities",{})),
             "is_critical": 1 if alert.get("is_critical") else 0,
             "article_text": (alert.get("article_text","") or "")[:2000],
            }
        )
        conn.commit()
        return {"status": "ok", "inserted": cur.rowcount}
    finally:
        conn.close()

# =======================
# QUERY ALERTS
# =======================
@app.get("/alerts")
def list_alerts(
    region:      Optional[str] = Query(None, description="Filter by region, e.g. MIDDLE_EAST"),
    tier:        Optional[int] = Query(None, description="Source tier: 0=wire, 1=regional, 2=local"),
    critical:    Optional[bool]= Query(None, description="True = critical only"),
    min_score:   int           = Query(0,    description="Minimum severity score"),
    hours:       int           = Query(24,   description="Look-back window in hours"),
    limit:       int           = Query(50,   description="Max results"),
    entity:      Optional[str] = Query(None, description="Filter by entity name (partial match)"),
):
    """
    List alerts with optional filters. Default: last 24 h, all regions.
    Use for feeding briefing templates.
    """
    cutoff = int((datetime.now(timezone.utc) - timedelta(hours=hours)).timestamp())
    conn = get_db()
    cur  = conn.cursor()

    sql = "SELECT * FROM sent_log WHERE ts >= ? AND score >= ?"
    params: list = [cutoff, min_score]

    if region:
        sql += " AND region = ?"
        params.append(region.upper())
    if tier is not None:
        sql += " AND source_tier = ?"
        params.append(tier)
    if critical is not None:
        sql += " AND is_critical = ?"
        params.append(1 if critical else 0)
    if entity:
        sql += " AND entities LIKE ?"
        params.append(f"%{entity}%")

    sql += " ORDER BY score DESC, ts DESC LIMIT ?"
    params.append(limit)

    rows = [row_to_dict(r) for r in cur.execute(sql, params).fetchall()]
    conn.close()
    return {"count": len(rows), "alerts": rows}

# =======================
# SINGLE ALERT
# =======================
@app.get("/alerts/{alert_id}")
def get_alert(alert_id: int):
    """Full alert record including article text and parsed entities."""
    conn = get_db()
    cur  = conn.cursor()
    row  = cur.execute("SELECT * FROM sent_log WHERE id=?", (alert_id,)).fetchone()
    conn.close()
    if not row:
        raise HTTPException(status_code=404, detail="Alert not found")
    return row_to_dict(row)

# =======================
# BRIEFING DIGEST
# =======================
@app.get("/briefing", response_class=PlainTextResponse)
def briefing_digest(
    hours:     int           = Query(24,  description="Time window in hours"),
    region:    Optional[str] = Query(None),
    min_score: int           = Query(5),
):
    """
    Returns a plain-text markdown briefing digest.
    Paste directly into a report template or pipe to a document generator.
    """
    cutoff = int((datetime.now(timezone.utc) - timedelta(hours=hours)).timestamp())
    conn = get_db()
    cur  = conn.cursor()

    sql = "SELECT * FROM sent_log WHERE ts>=? AND score>=?"
    params: list = [cutoff, min_score]
    if region:
        sql += " AND region=?"
        params.append(region.upper())
    sql += " ORDER BY score DESC, ts DESC"

    rows = [row_to_dict(r) for r in cur.execute(sql, params).fetchall()]
    conn.close()

    if not rows:
        return f"# VigiNote Briefing\n_No alerts matching criteria in the last {hours}h._\n"

    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    window  = f"Last {hours}h" if hours < 48 else f"Last {hours//24}d"
    lines   = [
        f"# VigiNote Intelligence Briefing",
        f"_Generated: {now_str} | Window: {window} | Alerts: {len(rows)}_",
        "",
    ]

    # Group by region
    by_region: dict = {}
    for r in rows:
        by_region.setdefault(r["region"], []).append(r)

    for reg, alerts in by_region.items():
        lines.append(f"## {reg.replace('_',' ').title()}")
        for a in alerts:
            crit_flag = " 🛑 **CRITICAL**" if a["is_critical"] else ""
            lines.append(f"### {a['title']}{crit_flag}")
            lines.append(f"- **Score:** {a['score']}  |  **Source:** {a['source_dom']} (tier {a['source_tier']})  |  **Time:** {a['ts_iso'][:16]}")
            lines.append(f"- **Summary:** {a['precis']}")

            ents = a.get("entities") or {}
            if ents.get("locations"):
                lines.append(f"- **Locations:** {', '.join(ents['locations'][:6])}")
            if ents.get("organizations"):
                lines.append(f"- **Actors/Orgs:** {', '.join(ents['organizations'][:5])}")
            if ents.get("persons"):
                lines.append(f"- **Persons:** {', '.join(ents['persons'][:4])}")

            lines.append(f"- **Selection:** _{a.get('selection_reason','')}_")
            lines.append(f"- **Link:** {a['url']}")
            lines.append("")
        lines.append("")

    return "\n".join(lines)

# =======================
# ENTITY FREQUENCY
# =======================
@app.get("/entities")
def top_entities(
    hours:  int           = Query(48),
    region: Optional[str] = Query(None),
    etype:  str           = Query("locations", description="locations | organizations | persons"),
    limit:  int           = Query(20),
):
    """
    Returns the most-mentioned entities across recent alerts.
    Useful for spotting hotspots and key actors for a briefing.
    """
    cutoff = int((datetime.now(timezone.utc) - timedelta(hours=hours)).timestamp())
    conn = get_db()
    cur  = conn.cursor()

    sql = "SELECT entities FROM sent_log WHERE ts>=? AND entities IS NOT NULL AND entities!='{}'"
    params: list = [cutoff]
    if region:
        sql += " AND region=?"
        params.append(region.upper())

    counts: dict = {}
    for (raw,) in cur.execute(sql, params).fetchall():
        try:
            ents = json.loads(raw)
            for name in ents.get(etype, []):
                counts[name] = counts.get(name, 0) + 1
        except Exception:
            continue
    conn.close()

    ranked = sorted(counts.items(), key=lambda x: x[1], reverse=True)[:limit]
    return {
        "entity_type": etype,
        "hours": hours,
        "region": region,
        "results": [{"name": n, "count": c} for n, c in ranked],
    }

# =======================
# HEALTH
# =======================
@app.get("/health")
def health():
    try:
        conn = get_db()
        count = conn.execute("SELECT COUNT(*) FROM sent_log").fetchone()[0]
        conn.close()
        return {"status": "ok", "total_alerts_stored": count}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
