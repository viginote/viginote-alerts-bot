"""
api.py — VigiNote Master API v2.0
Serves all frontend pages and provides all AI generation endpoints.

Pages served:
  GET /dashboard     — Briefing Studio
  GET /assessment    — Location Assessment Studio
  GET /digest        — Weekly Digest Studio
  GET /portal        — Client Portal

AI endpoints:
  POST /ai/generate        — Briefing generation (dashboard)
  POST /ai/assessment      — Location security assessment
  POST /ai/digest          — Weekly digest generation
  POST /ai/image           — Image selection for thumbnail

Data endpoints:
  GET  /alerts             — Query alerts (all filters)
  GET  /alerts/{id}        — Single alert
  GET  /clusters           — Corroborated story clusters
  GET  /entities           — Aggregated named entities
  GET  /briefing           — Structured briefing payload
  GET  /feed-health        — Feed failure report
  GET  /analytics/trajectory — Regional risk trajectory
  GET  /analytics/diversity  — Source diversity score
  GET  /watchlist/check    — Watchlist keyword monitoring

System:
  POST /ingest             — Receive alerts from bot (webhook)
  GET  /health             — Heartbeat
"""

import json
import os
import pathlib
import time
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from typing import List, Optional

import httpx
from fastapi import FastAPI, Query, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, PlainTextResponse
from pydantic import BaseModel

from viginote.db import (
    init_db, query_alerts, query_clusters, unhealthy_feeds,
    kv_get, kv_set,
)

# =======================
# CONFIG
# =======================
ANTHROPIC_KEY   = os.getenv("ANTHROPIC_API_KEY", "")
ANTHROPIC_MODEL = os.getenv("ANTHROPIC_MODEL", "claude-sonnet-4-6")
OPENAI_KEY      = os.getenv("OPENAI_API_KEY", "")

# Client portal watchlist — comma-separated terms to monitor
WATCHLIST = [w.strip() for w in os.getenv("WATCHLIST", "").split(",") if w.strip()]

BASE_DIR = pathlib.Path(__file__).parent

# =======================
# APP
# =======================
app = FastAPI(
    title="VigiNote Intelligence API",
    description="Full intelligence platform API — alerts, AI generation, analytics, and portal.",
    version="2.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

_conn = None

def get_conn():
    global _conn
    if _conn is None:
        _conn = init_db()
    return _conn

def row_to_dict(row) -> dict:
    d = dict(row) if not isinstance(row, dict) else row
    raw = d.get("entities_json") or d.get("entities") or "{}"
    if isinstance(raw, str):
        try:
            d["entities"] = json.loads(raw)
        except Exception:
            d["entities"] = {}
    d.pop("entities_json", None)
    return d

# =======================
# PAGE ROUTES
# =======================
def _serve(filename: str) -> HTMLResponse:
    p = BASE_DIR / filename
    if not p.exists():
        raise HTTPException(status_code=404, detail=f"{filename} not found in project root")
    return HTMLResponse(content=p.read_text())

@app.get("/dashboard", response_class=HTMLResponse)
async def page_dashboard(): return _serve("dashboard.html")

@app.get("/assessment", response_class=HTMLResponse)
async def page_assessment(): return _serve("assessment.html")

@app.get("/digest", response_class=HTMLResponse)
async def page_digest(): return _serve("digest.html")

@app.get("/portal", response_class=HTMLResponse)
async def page_portal():
    """Serve client portal with config injected."""
    p = BASE_DIR / "portal.html"
    if not p.exists():
        raise HTTPException(status_code=404, detail="portal.html not found")
    cfg = {
        "client": os.getenv("PORTAL_CLIENT_NAME", "VigiNote Client"),
        "region": os.getenv("PORTAL_REGION", ""),
        "location": os.getenv("PORTAL_LOCATION", ""),
        "watchlist": WATCHLIST,
    }
    html = p.read_text().replace("__CLIENT_CONFIG__", json.dumps(cfg))
    return HTMLResponse(content=html)

# =======================
# INGEST (from bot)
# =======================
@app.post("/ingest", status_code=201)
def ingest(alert: dict):
    conn = get_conn()
    cur  = conn.cursor()
    try:
        cur.execute("""INSERT OR IGNORE INTO sent_log
            (url, ts, title, title_hash, is_critical, region, source_domain, source_tier,
             score, precis, article_text, entities_json, selection_reason)
            VALUES (:url,:ts,:title,:title_hash,:is_critical,:region,:source_domain,
                    :source_tier,:score,:precis,:article_text,:entities_json,:selection_reason)""",
            {
                "url":              alert.get("url",""),
                "ts":               alert.get("ts", int(time.time())),
                "title":            alert.get("title",""),
                "title_hash":       alert.get("title_hash",""),
                "is_critical":      1 if alert.get("is_critical") else 0,
                "region":           alert.get("region",""),
                "source_domain":    alert.get("source_dom", alert.get("source_domain","")),
                "source_tier":      alert.get("source_tier", alert.get("tier", 0)),
                "score":            alert.get("score", 0),
                "precis":           alert.get("precis",""),
                "article_text":     (alert.get("article_text","") or "")[:2000],
                "entities_json":    json.dumps(alert.get("entities",{})),
                "selection_reason": alert.get("selection_reason",""),
            }
        )
        conn.commit()
        return {"status": "ok", "inserted": cur.rowcount}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        pass

# =======================
# ALERTS
# =======================
@app.get("/alerts")
def list_alerts(
    region:    Optional[str] = Query(None),
    tier:      Optional[str] = Query(None),
    critical:  Optional[str] = Query(None),
    min_score: Optional[str] = Query(None),
    hours:     Optional[str] = Query(None),
    limit:     Optional[str] = Query(None),
    keyword:   Optional[str] = Query(None),
    entity:    Optional[str] = Query(None),
):
    try: hours_i  = max(1, min(8760, int(hours))) if hours else 24
    except: hours_i = 24
    try: score_i  = max(0, int(min_score)) if min_score else 0
    except: score_i = 0
    try: limit_i  = max(1, min(500, int(limit))) if limit else 100
    except: limit_i = 100
    try: tier_i   = int(tier) if tier and tier not in ("ALL","") else None
    except: tier_i = None
    crit_i = None
    if critical and critical.lower() == "true":  crit_i = True
    if critical and critical.lower() == "false": crit_i = False
    region_s = region.upper() if region and region not in ("ALL","") else None

    days = max(1, hours_i // 24) if hours_i < 24 else hours_i // 24
    # Use hours directly via cutoff
    from datetime import datetime, timezone, timedelta
    cutoff = int((datetime.now(timezone.utc) - timedelta(hours=hours_i)).timestamp())

    conn = get_conn()
    cur  = conn.cursor()

    try:
        col_rows = cur.execute("PRAGMA table_info(sent_log)").fetchall()
        cols = [c[1] for c in col_rows]
    except Exception as e:
        return {"count": 0, "alerts": [], "error": str(e)}

    safe_cols = ", ".join(cols)
    sql = f"SELECT {safe_cols} FROM sent_log WHERE ts >= ? AND score >= ?"
    params: list = [cutoff, score_i]

    if region_s and "region" in cols:
        sql += " AND region = ?"; params.append(region_s)
    if tier_i is not None and "source_tier" in cols:
        sql += " AND source_tier = ?"; params.append(tier_i)
    if crit_i is not None:
        sql += " AND is_critical = ?"; params.append(1 if crit_i else 0)
    if keyword:
        sql += " AND (title LIKE ?"
        params.append(f"%{keyword}%")
        if "precis" in cols:
            sql += " OR precis LIKE ?"
            params.append(f"%{keyword}%")
        if "entities_json" in cols:
            sql += " OR entities_json LIKE ?"
            params.append(f"%{keyword}%")
        sql += ")"
    if entity and "entities_json" in cols:
        sql += " AND entities_json LIKE ?"; params.append(f"%{entity}%")

    sql += " ORDER BY score DESC, ts DESC LIMIT ?"
    params.append(limit_i)

    try:
        rows = [row_to_dict(dict(zip(cols, r))) for r in cur.execute(sql, params).fetchall()]
        return {"count": len(rows), "alerts": rows}
    except Exception as e:
        return {"count": 0, "alerts": [], "error": str(e)}

@app.get("/alerts/{alert_id}")
def get_alert(alert_id: int):
    conn = get_conn()
    row  = conn.execute("SELECT * FROM sent_log WHERE id=?", (alert_id,)).fetchone()
    if not row: raise HTTPException(status_code=404, detail="Alert not found")
    return row_to_dict(dict(row))

@app.get("/clusters")
def get_clusters(
    region:      Optional[str] = Query(None),
    days:        int            = Query(3),
    min_sources: int            = Query(2),
):
    conn = get_conn()
    try:
        clusters = query_clusters(conn, region=region, days=days, min_sources=min_sources)
        return {"count": len(clusters), "clusters": clusters}
    except Exception:
        return {"count": 0, "clusters": []}

@app.get("/entities")
def get_entities(
    region: Optional[str] = Query(None),
    hours:  int            = Query(168),
    etype:  str            = Query("locs"),
    limit:  int            = Query(20),
):
    days = max(1, hours // 24)
    conn = get_conn()
    rows = query_alerts(conn, region=region, days=days, limit=500)
    counts: dict = {}
    for r in rows:
        try:
            ents = json.loads(r.get("entities_json") or "{}")
        except Exception:
            ents = {}
        for name in ents.get(etype, []):
            counts[name] = counts.get(name, 0) + 1
    ranked = sorted(counts.items(), key=lambda x: x[1], reverse=True)[:limit]
    return {"entity_type": etype, "hours": hours, "region": region,
            "results": [{"name": n, "count": c} for n, c in ranked]}

@app.get("/feed-health")
def get_feed_health(min_failures: int = Query(3)):
    conn = get_conn()
    bad  = unhealthy_feeds(conn, min_failures=min_failures)
    try:
        all_feeds = conn.execute(
            "SELECT feed_url, region, last_success, consecutive_failures, total_fetches, total_errors "
            "FROM feed_health ORDER BY region, feed_url"
        ).fetchall()
        return {"unhealthy_feeds": bad, "unhealthy_count": len(bad),
                "all_feeds": [dict(r) for r in all_feeds]}
    except Exception:
        return {"unhealthy_feeds": bad, "unhealthy_count": len(bad), "all_feeds": []}

@app.get("/briefing", response_class=PlainTextResponse)
def get_briefing_md(
    hours:     int           = Query(24),
    region:    Optional[str] = Query(None),
    min_score: int           = Query(5),
):
    days = max(1, hours // 24)
    conn = get_conn()
    rows = [row_to_dict(r) for r in query_alerts(conn, region=region, days=days,
                                                   min_score=min_score, limit=200)]
    if not rows:
        return f"# VigiNote Briefing\n_No alerts in the last {hours}h._\n"
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines = [f"# VigiNote Intelligence Briefing", f"_{now_str} | {len(rows)} alerts_", ""]
    by_region: dict = {}
    for r in rows:
        by_region.setdefault(r.get("region","UNKNOWN"), []).append(r)
    for reg, alerts in by_region.items():
        lines.append(f"## {reg.replace('_',' ').title()}")
        for a in alerts:
            lines.extend([
                f"### {a['title']}",
                f"- **Source:** {a.get('source_domain','')} | **Score:** {a.get('score','')}",
                f"- {a.get('precis','')}",
                f"- {a.get('url','')}",
                "",
            ])
    return "\n".join(lines)

# =======================
# ANALYTICS
# =======================
@app.get("/analytics/trajectory")
def analytics_trajectory(
    days:   int            = Query(7),
    region: Optional[str]  = Query(None),
):
    """Compare this period vs prior period per region — for portal trajectory cards."""
    conn = get_conn()
    now  = datetime.now(timezone.utc)

    def _period_stats(start_ts, end_ts, region_filter=None):
        sql = "SELECT region, score, is_critical FROM sent_log WHERE ts>=? AND ts<?"
        params = [int(start_ts), int(end_ts)]
        if region_filter:
            sql += " AND region=?"; params.append(region_filter.upper())
        rows = conn.execute(sql, params).fetchall()
        out: dict = defaultdict(lambda: {"alerts":0,"score_sum":0,"critical":0})
        for r in rows:
            reg = r[0] or "UNKNOWN"
            out[reg]["alerts"] += 1
            out[reg]["score_sum"] += (r[1] or 0)
            out[reg]["critical"] += (1 if r[2] else 0)
        return out

    this_end   = now
    this_start = now - timedelta(days=days)
    prev_end   = this_start
    prev_start = this_start - timedelta(days=days)

    this_data = _period_stats(this_start.timestamp(), this_end.timestamp(), region)
    prev_data = _period_stats(prev_start.timestamp(), prev_end.timestamp(), region)

    all_regions = set(list(this_data.keys()) + list(prev_data.keys()))
    results = []
    for reg in sorted(all_regions):
        tp = this_data.get(reg, {"alerts":0,"score_sum":0,"critical":0})
        pp = prev_data.get(reg, {"alerts":0,"score_sum":0,"critical":0})
        ta = tp["alerts"]
        pa = pp["alerts"]
        avg_score = round(tp["score_sum"] / ta, 1) if ta else 0
        change = ta - pa
        if change > 1 or (ta > 0 and pa == 0):
            traj = "DETERIORATING"
        elif change < -1 or (ta == 0 and pa > 0):
            traj = "IMPROVING"
        else:
            traj = "STABLE"
        results.append({
            "region": reg,
            "trajectory": traj,
            "alert_change": change,
            "this_period": {"alerts": ta, "avg_score": avg_score, "critical": tp["critical"]},
            "prior_period": {"alerts": pa},
        })

    return {"period_days": days, "regions": results}

@app.get("/analytics/diversity")
def analytics_diversity(
    hours:  int            = Query(168),
    region: Optional[str]  = Query(None),
):
    """Source diversity breakdown — for portal diversity card."""
    days = max(1, hours // 24)
    conn = get_conn()
    rows = query_alerts(conn, region=region, days=days, limit=500)
    if not rows:
        return {"error": "No alerts in period", "diversity_score": 0}

    tier_counts = {0: 0, 1: 0, 2: 0}
    domain_counts: dict = {}
    for r in rows:
        t = r.get("source_tier", 0) or 0
        tier_counts[t] = tier_counts.get(t, 0) + 1
        dom = r.get("source_domain","")
        if dom: domain_counts[dom] = domain_counts.get(dom, 0) + 1

    total = len(rows)
    lp = round(tier_counts[2] / total * 100) if total else 0
    rp = round(tier_counts[1] / total * 100) if total else 0
    wp = round(tier_counts[0] / total * 100) if total else 0
    score = min(100, lp * 2 + rp)

    if lp >= 50: summary = f"Excellent source diversity — {lp}% from local/specialist outlets."
    elif lp >= 30: summary = f"Good diversity — {lp}% local/specialist, {rp}% regional sources."
    elif lp >= 15: summary = f"Moderate diversity — consider adding more local outlets."
    else: summary = f"Low diversity — {wp}% wire sources. Local coverage is limited."

    top_sources = sorted(domain_counts.items(), key=lambda x: x[1], reverse=True)[:8]

    return {
        "diversity_score": score,
        "summary": summary,
        "total_alerts": total,
        "breakdown": {
            "local_specialist": {"count": tier_counts[2], "pct": lp},
            "regional":         {"count": tier_counts[1], "pct": rp},
            "wire":             {"count": tier_counts[0], "pct": wp},
        },
        "top_sources": [{"domain": d, "count": c} for d, c in top_sources],
    }

@app.get("/watchlist/check")
def watchlist_check(hours: int = Query(168)):
    """Check all watchlist terms against recent alerts — for portal watchlist card."""
    if not WATCHLIST:
        return {"note": "No watchlist configured. Set WATCHLIST env var (comma-separated terms).",
                "total_hits": 0}
    days = max(1, hours // 24)
    conn = get_conn()
    rows = query_alerts(conn, days=days, limit=500)
    matches: dict = {}
    total_hits = 0
    for term in WATCHLIST:
        hits = []
        for r in rows:
            text = f"{r.get('title','')} {r.get('precis','')} {r.get('entities_json','')}".lower()
            if term.lower() in text:
                hits.append({"title": r.get("title",""), "region": r.get("region",""),
                             "score": r.get("score",0), "ts_iso": r.get("ts","")})
        matches[term] = hits
        total_hits += len(hits)
    return {"watchlist": WATCHLIST, "matches": matches, "total_hits": total_hits, "hours": hours}

# =======================
# AI — BRIEFING GENERATION
# =======================
class BriefingRequest(BaseModel):
    alerts: List[dict]
    briefing_type: str = "morning"
    custom_title: Optional[str] = None

@app.post("/ai/generate")
async def ai_generate(req: BriefingRequest):
    if not ANTHROPIC_KEY:
        raise HTTPException(status_code=503, detail="ANTHROPIC_API_KEY not configured")
    if not req.alerts:
        raise HTTPException(status_code=400, detail="No alerts provided")

    now_str  = datetime.now(timezone.utc).strftime("%d %B %Y, %H:%M UTC")
    regions  = list({a.get("region","").replace("_"," ").title() for a in req.alerts})
    critical = sum(1 for a in req.alerts if a.get("is_critical"))

    alerts_text = ""
    for i, a in enumerate(req.alerts, 1):
        ents = a.get("entities") or {}
        alerts_text += (
            f"\nALERT {i}:\n"
            f"Title: {a.get('title','')}\n"
            f"Region: {a.get('region','').replace('_',' ')}\n"
            f"Source: {a.get('source_dom', a.get('source_domain',''))} (tier {a.get('source_tier',0)})\n"
            f"Score: {a.get('score',0)} | Critical: {'Yes' if a.get('is_critical') else 'No'}\n"
            f"Summary: {a.get('precis','')}\n"
            f"Locations: {', '.join((ents.get('locs') or ents.get('locations') or [])[:3])}\n"
            f"Orgs: {', '.join((ents.get('orgs') or ents.get('organizations') or [])[:3])}\n"
            f"Text: {(a.get('article_text','') or '')[:500]}\n---"
        )

    prompt = f"""You are a senior intelligence analyst writing the VigiNote {req.briefing_type.title()} Briefing for {now_str}.

Selected alerts ({len(req.alerts)} items, {critical} critical, regions: {', '.join(regions)}):
{alerts_text}

Respond ONLY with a JSON object with these exact keys:
{{
  "briefing_title": "Sharp professional title for this briefing",
  "executive_summary": "2-3 paragraph professional intelligence executive summary (~200 words). Authoritative, factual, no speculation.",
  "alert_summaries": [{{"id": 1, "enhanced_summary": "2-3 sentence enhanced summary, more context than the original."}}],
  "linkedin_caption": "Compelling 120-150 word LinkedIn post. Start with a hook. Professional but engaging. 3-4 relevant hashtags at the end. Written as VigiNote.",
  "thumbnail_headline": "Maximum 10 words. Punchy news-style hook for the thumbnail image card."
}}

Return ONLY the JSON. No preamble, no markdown fences."""

    try:
        async with httpx.AsyncClient(timeout=60.0) as client:
            resp = await client.post(
                "https://api.anthropic.com/v1/messages",
                headers={"x-api-key": ANTHROPIC_KEY, "anthropic-version": "2023-06-01",
                         "content-type": "application/json"},
                json={"model": ANTHROPIC_MODEL, "max_tokens": 2000,
                      "messages": [{"role": "user", "content": prompt}]},
            )
        resp.raise_for_status()
        raw = resp.json()["content"][0]["text"].strip()
        if raw.startswith("```"):
            raw = raw.split("```")[1]
            if raw.startswith("json"): raw = raw[4:]
        return {"status": "ok", "generated": json.loads(raw.strip())}
    except json.JSONDecodeError as e:
        raise HTTPException(status_code=500, detail=f"AI response parse error: {e}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"AI generation error: {str(e)}")

# =======================
# AI — LOCATION ASSESSMENT
# =======================
class AssessmentRequest(BaseModel):
    location: str
    event: Optional[str] = None
    mode: str = "combined"   # ai | alerts | combined
    hours: int = 168

@app.post("/ai/assessment")
async def ai_assessment(req: AssessmentRequest):
    if not ANTHROPIC_KEY:
        raise HTTPException(status_code=503, detail="ANTHROPIC_API_KEY not configured")

    now_str = datetime.now(timezone.utc).strftime("%d %B %Y")
    alert_context = ""

    if req.mode in ("alerts", "combined"):
        try:
            conn   = get_conn()
            days   = max(1, req.hours // 24)
            rows   = [row_to_dict(r) for r in query_alerts(conn, days=days, limit=200)]
            loc_lc = req.location.lower()
            loc_words = [w.strip() for w in loc_lc.replace(",","").split() if len(w.strip()) > 3]
            matched = []
            for r in rows:
                text = f"{r.get('title','')} {r.get('precis','')} {json.dumps(r.get('entities',{}))}".lower()
                if loc_lc in text or any(w in text for w in loc_words):
                    matched.append(r)
            if matched:
                alert_context = f"\n\nLIVE VIGINOTE ALERTS for {req.location} (last {req.hours}h):\n"
                for a in matched[:10]:
                    alert_context += (
                        f"- [{a.get('region','')}] Score {a.get('score',0)}: "
                        f"{a.get('title','')} — {a.get('precis','')}\n"
                    )
            elif req.mode == "alerts":
                return {"message": f"No alerts found for {req.location}. Try Combined or AI mode.",
                        "generated": None}
        except Exception as db_err:
            import traceback; traceback.print_exc()
            print(f"[ASSESSMENT DB ERROR] {db_err}")
            # Continue with AI-only mode if DB fails

    event_context = f"\nEvent context: {req.event}" if req.event else ""

    prompt = f"""You are a senior security analyst. Produce a security assessment for {req.location} on {now_str}.{event_context}{alert_context}

Return ONLY valid JSON with these exact keys. Be concise but specific — max 2 sentences per field unless stated:

{{"report_title":"Security Assessment: {req.location}","location":"{req.location}","assessment_date":"{now_str}","classification":"CLIENT CONFIDENTIAL","event_context":"{req.event or ''}","overall_risk_level":"HIGH","overall_risk_score":7,"risk_trajectory":"STABLE","risk_trajectory_note":"One sentence.","intelligence_note":"","executive_summary":"Write 2 focused paragraphs on the security environment, key threats, and visitor risk for {req.location}.","location_profile":{{"country":"","region":"","population":"","strategic_significance":"One sentence.","key_infrastructure":["item1","item2"],"upcoming_events":[]}},"threat_matrix":[{{"category":"Political Violence","assessment":"2 sentences.","risk_level":"HIGH","risk_score":7,"visitor_impact":"1 sentence.","key_indicators":["indicator1","indicator2"]}},{{"category":"Terrorism & Extremism","assessment":"2 sentences.","risk_level":"MEDIUM","risk_score":5,"visitor_impact":"1 sentence.","key_indicators":["ind1"]}},{{"category":"Organised Crime","assessment":"2 sentences.","risk_level":"MEDIUM","risk_score":5,"visitor_impact":"1 sentence.","key_indicators":["ind1"]}},{{"category":"Civil Unrest","assessment":"2 sentences.","risk_level":"MEDIUM","risk_score":4,"visitor_impact":"1 sentence.","key_indicators":["ind1"]}},{{"category":"Natural Hazards","assessment":"1 sentence.","risk_level":"LOW","risk_score":3,"visitor_impact":"1 sentence.","key_indicators":[]}},{{"category":"Health & Medical","assessment":"1 sentence.","risk_level":"LOW","risk_score":3,"visitor_impact":"1 sentence.","key_indicators":[]}}],"hotspots":[{{"name":"Area name","description":"1 sentence.","risk_level":"HIGH","recommendation":"1 sentence."}},{{"name":"Area name","description":"1 sentence.","risk_level":"MEDIUM","recommendation":"1 sentence."}}],"visitor_advisory":{{"before_travel":["Action 1","Action 2","Action 3"],"areas_to_avoid":["Area — reason","Area — reason"],"safe_zones":["Safe area 1","Safe area 2"],"transport":"1 sentence on transport safety.","accommodation":"1 sentence on accommodation security.","communication":"1 sentence on comms security.","emergency_contacts":["Police: xxx","Embassy: xxx","Medical: xxx"]}},"organised_crime_profile":{{"active_groups":["Group — activity"],"primary_methods":["Method 1","Method 2"],"visitor_targeting":"1 sentence.","trend":"1 sentence."}},"recommended_measures":[{{"category":"Pre-Deployment","measures":["Action 1","Action 2","Action 3"]}},{{"category":"In-Country","measures":["Action 1","Action 2","Action 3"]}},{{"category":"Digital Security","measures":["Action 1","Action 2"]}},{{"category":"Emergency Response","measures":["Action 1","Action 2"]}}],"linkedin_teaser":"100-word LinkedIn post on security in {req.location}. End with 3 hashtags."}}

Fill every field accurately for {req.location}. Return ONLY the JSON object."""

    try:
        async with httpx.AsyncClient(timeout=120.0) as client:
            resp = await client.post(
                "https://api.anthropic.com/v1/messages",
                headers={"x-api-key": ANTHROPIC_KEY, "anthropic-version": "2023-06-01",
                         "content-type": "application/json"},
                json={"model": "claude-haiku-4-5-20251001", "max_tokens": 6000,
                      "messages": [{"role": "user", "content": prompt}]},
            )
        resp.raise_for_status()
        raw = resp.json()["content"][0]["text"].strip()
        if raw.startswith("```"):
            raw = raw.split("```")[1]
            if raw.startswith("json"): raw = raw[4:]
        raw = raw.strip()
        # Handle truncated JSON by finding the last complete top-level key
        try:
            result = json.loads(raw)
        except json.JSONDecodeError:
            # Try to recover by finding the last valid closing brace
            for i in range(len(raw), 0, -1):
                if raw[i-1] == '}':
                    try:
                        result = json.loads(raw[:i])
                        break
                    except json.JSONDecodeError:
                        continue
            else:
                raise HTTPException(status_code=500, detail="Assessment parse error: response was truncated. Try a shorter location or use AI mode.")
        return {"status": "ok", "generated": result}
    except HTTPException:
        raise
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Assessment error: {type(e).__name__}: {str(e)}")

# =======================
# AI — WEEKLY DIGEST
# =======================
class DigestRequest(BaseModel):
    hours: int = 168
    region: Optional[str] = None
    min_score: int = 5

@app.post("/ai/digest")
async def ai_digest(req: DigestRequest):
    if not ANTHROPIC_KEY:
        raise HTTPException(status_code=503, detail="ANTHROPIC_API_KEY not configured")

    days = max(1, req.hours // 24)
    conn = get_conn()
    region_filter = req.region.upper() if req.region and req.region not in ("","ALL") else None
    rows = query_alerts(conn, region=region_filter, days=days,
                        min_score=req.min_score, limit=200)

    if not rows:
        return {"message": f"No alerts found in the last {req.hours}h. Try a longer window.",
                "digest": None, "alert_count": 0}

    rows = [row_to_dict(r) for r in rows]
    now  = datetime.now(timezone.utc)
    period_start = (now - timedelta(hours=req.hours)).strftime("%d %b")
    period_end   = now.strftime("%d %b %Y")
    period_str   = f"{period_start} – {period_end}"

    alerts_text = ""
    for i, a in enumerate(rows[:40], 1):
        ents = a.get("entities") or {}
        alerts_text += (
            f"\n{i}. [{a.get('region','').replace('_',' ')}] Score {a.get('score',0)}"
            f"{'🛑' if a.get('is_critical') else ''}: {a.get('title','')}\n"
            f"   {a.get('precis','')}\n"
            f"   Source: {a.get('source_domain','')} (tier {a.get('source_tier',0)})\n"
        )

    regions_covered = list({a.get("region","") for a in rows})
    critical_count  = sum(1 for a in rows if a.get("is_critical"))

    prompt = f"""You are a senior intelligence analyst writing the VigiNote Weekly Intelligence Digest.

Period: {period_str}
Total alerts analysed: {len(rows)}
Critical alerts: {critical_count}
Regions covered: {', '.join(r.replace('_',' ') for r in regions_covered)}

Intelligence collected this period:
{alerts_text}

Write the weekly digest. Respond ONLY with this JSON:

{{
  "digest_title": "VigiNote Weekly Intelligence Digest — {period_end}",
  "period": "{period_str}",
  "week_in_review": "3-4 paragraph comprehensive overview of the week's most significant developments. Analytical, connecting events across regions where relevant. ~300 words.",
  "top_stories": [
    {{
      "headline": "Sharp headline for the story",
      "region": "Region name",
      "significance": "2-3 sentences on why this matters and what to watch"
    }}
  ],
  "regional_roundup": [
    {{
      "region": "Region name",
      "summary": "2-3 sentence summary of the week in this region",
      "trend": "IMPROVING|STABLE|DETERIORATING",
      "alert_count": 5
    }}
  ],
  "watch_next_week": [
    "Specific situation or development to monitor in the coming week",
    "Another situation worth watching"
  ],
  "stat_headline": "One compelling data point or statistic from this week's intelligence",
  "source_note": "Brief note on source diversity and intelligence coverage this period",
  "linkedin_post": "A compelling LinkedIn post introducing this week's digest. 150 words max. Hook opening line. Professional but engaging. 4 relevant hashtags at the end. Written as VigiNote."
}}

Return ONLY the JSON. Base everything on the actual alerts provided."""

    try:
        async with httpx.AsyncClient(timeout=120.0) as client:
            resp = await client.post(
                "https://api.anthropic.com/v1/messages",
                headers={"x-api-key": ANTHROPIC_KEY, "anthropic-version": "2023-06-01",
                         "content-type": "application/json"},
                json={"model": ANTHROPIC_MODEL, "max_tokens": 3000,
                      "messages": [{"role": "user", "content": prompt}]},
            )
        resp.raise_for_status()
        raw = resp.json()["content"][0]["text"].strip()
        if raw.startswith("```"):
            raw = raw.split("```")[1]
            if raw.startswith("json"): raw = raw[4:]
        return {"status": "ok", "digest": json.loads(raw.strip()), "alert_count": len(rows)}
    except json.JSONDecodeError as e:
        raise HTTPException(status_code=500, detail=f"Digest parse error: {e}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Digest error: {str(e)}")

# =======================
# AI — IMAGE
# =======================
class ImageRequest(BaseModel):
    headline: str
    regions: List[str]
    organizations: List[str] = []
    locations: List[str] = []
    briefing_type: str = "morning"

@app.post("/ai/image")
async def ai_image(req: ImageRequest):
    region_str = ", ".join(req.regions[:3]) if req.regions else "global"
    combined   = (req.headline + " " + " ".join(req.organizations) + " " + " ".join(req.locations)).lower()

    if any(w in combined for w in ["ebola","cholera","disease","outbreak","epidemic","pandemic","health","medical"]):
        scene = "healthcare workers wearing full protective white suits at an outdoor field medical station, golden hour light"
    elif any(w in combined for w in ["flood","cyclone","hurricane","earthquake","tsunami","disaster","wildfire"]):
        scene = "aerial view of flooded landscape at dawn, dramatic storm clouds, blue and grey tones"
    elif any(w in combined for w in ["coup","protest","unrest","demonstration"]):
        scene = "empty city square at dusk with dramatic street lighting, wide angle urban photography"
    elif any(w in combined for w in ["famine","drought","hunger","refugee","displacement"]):
        scene = "vast arid landscape at golden hour, dramatic sky, dust in the air"
    elif any(w in combined for w in ["navy","maritime","ship","vessel","sea","coast"]):
        scene = "dramatic ocean seascape during stormy weather, dark waves, deep blue tones"
    elif "africa" in region_str.lower() or any(w in combined for w in ["sudan","somalia","congo","mali","nigeria","ethiopia"]):
        scene = "African savanna landscape at sunset, golden hour light, acacia trees silhouetted"
    elif "middle east" in region_str.lower() or any(w in combined for w in ["gaza","israel","syria","yemen","iraq","iran"]):
        scene = "ancient desert city skyline at dusk, warm amber sky, architecture silhouetted"
    elif "europe" in region_str.lower() or any(w in combined for w in ["ukraine","russia","nato","balkan"]):
        scene = "winter European landscape, snow covered plain, bare trees, overcast grey sky"
    elif "asia" in region_str.lower() or any(w in combined for w in ["china","taiwan","korea","myanmar","afghanistan"]):
        scene = "Asian city skyline at night, reflections on wet streets, neon lights"
    elif "south america" in region_str.lower() or any(w in combined for w in ["venezuela","colombia","brazil","mexico","haiti"]):
        scene = "South American cityscape at dusk, dramatic sky, warm tones"
    else:
        scene = "planet Earth from space, continents and clouds visible, dark background, deep blue tones"

    # Try DALL-E 3
    if OPENAI_KEY:
        full_prompt = (
            f"Professional landscape or cityscape photograph. {scene}. "
            f"Dark navy and deep blue colour palette. Cinematic composition. "
            f"No people, no text, no logos, no watermarks. High quality photography."
        )
        try:
            async with httpx.AsyncClient(timeout=60.0) as client:
                resp = await client.post(
                    "https://api.openai.com/v1/images/generations",
                    headers={"Authorization": f"Bearer {OPENAI_KEY}", "Content-Type":"application/json"},
                    json={"model":"dall-e-3","prompt":full_prompt,"n":1,
                          "size":"1792x1024","quality":"standard","style":"natural"},
                )
            if resp.status_code == 200:
                data = resp.json()
                item = data["data"][0]
                image_url = item.get("url") or ("data:image/png;base64," + item.get("b64_json",""))
                return {"status":"ok","image_url":image_url,"source":"dalle"}
            else:
                print(f"[IMAGE] DALL-E {resp.status_code}: {resp.text[:200]}")
        except Exception as e:
            print(f"[IMAGE] DALL-E error: {e}")

    # Unsplash fallback
    kw_map = {
        "medical":"healthcare,field,documentary","disease":"medical,emergency,field",
        "flood":"flood,aerial,dramatic","protest":"crowd,city,dusk","famine":"humanitarian,landscape",
        "maritime":"ocean,storm,sea","africa":"africa,landscape,sunset",
        "middle east":"desert,city,dusk","europe":"europe,winter,landscape",
        "asia":"asia,city,night","south america":"latin,america,landscape",
    }
    kw = "world,globe,dramatic,sky"
    for k, v in kw_map.items():
        if k in combined or k in region_str.lower():
            kw = v; break
    return {"status":"ok","image_url":f"https://source.unsplash.com/1792x1024/?{kw},dark","source":"unsplash"}

# =======================
# SYSTEM
# =======================
@app.get("/health")
def health():
    conn = get_conn()
    try:
        count = conn.execute("SELECT COUNT(*) FROM sent_log").fetchone()[0]
        return {"status":"ok","total_alerts_stored":count,"ai_enabled":bool(ANTHROPIC_KEY)}
    except Exception as e:
        return {"status":"degraded","error":str(e)}

@app.post("/webhook/test")
def webhook_test():
    import requests as req
    token   = os.getenv("TELEGRAM_BOT_TOKEN","")
    chat_id = os.getenv("TELEGRAM_CHAT_ID","")
    if not token or not chat_id:
        raise HTTPException(status_code=500, detail="Telegram env vars not set")
    r = req.post(f"https://api.telegram.org/bot{token}/sendMessage",
                 data={"chat_id":chat_id,"text":"✅ VigiNote API v2 webhook test OK","parse_mode":"HTML"},
                 timeout=10)
    return r.json()
