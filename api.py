"""
VigiNote Briefing API — FastAPI webhook receiver + query interface + AI briefing studio.

Endpoints:
  POST /ingest              — receive alerts from the bot
  GET  /alerts              — query stored alerts with filters
  GET  /alerts/{id}         — single alert
  GET  /briefing            — markdown briefing digest
  GET  /entities            — top entities
  POST /ai/generate         — AI-powered briefing generation (Claude)
  GET  /dashboard           — serve the briefing studio UI
  GET  /health              — uptime check
"""

import os, json, sqlite3, httpx
from datetime import datetime, timezone, timedelta
from typing import Optional, List
from fastapi import FastAPI, Query, HTTPException
from fastapi.responses import PlainTextResponse, HTMLResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

DB_PATH          = os.getenv("DB_PATH", "/data/osint_alerts.db")
ANTHROPIC_KEY    = os.getenv("ANTHROPIC_API_KEY", "")
ANTHROPIC_MODEL  = os.getenv("ANTHROPIC_MODEL", "claude-sonnet-4-6")
OPENAI_KEY       = os.getenv("OPENAI_API_KEY", "")

app = FastAPI(
    title="VigiNote Briefing API",
    description="Query and ingest OSINT alerts for professional briefing generation.",
    version="2.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
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
# INGEST
# =======================
@app.post("/ingest", status_code=201)
def ingest(alert: dict):
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
    region:    Optional[str] = Query(None),
    tier:      Optional[str] = Query(None),
    critical:  Optional[str] = Query(None),
    min_score: Optional[str] = Query(None),
    hours:     Optional[str] = Query(None),
    limit:     Optional[str] = Query(None),
    entity:    Optional[str] = Query(None),
    keyword:   Optional[str] = Query(None),
):
    # Parse with safe defaults
    try: hours_i = max(1, min(8760, int(hours))) if hours else 24
    except: hours_i = 24
    try: score_i = max(0, int(min_score)) if min_score else 0
    except: score_i = 0
    try: limit_i = max(1, min(500, int(limit))) if limit else 100
    except: limit_i = 100
    try: tier_i = int(tier) if tier and tier not in ("ALL","") else None
    except: tier_i = None
    crit_i = None
    if critical and critical.lower() == "true":  crit_i = 1
    if critical and critical.lower() == "false": crit_i = 0
    region_s = region.upper() if region and region not in ("ALL","") else None

    cutoff = int((datetime.now(timezone.utc) - timedelta(hours=hours_i)).timestamp())
    conn = get_db()
    cur  = conn.cursor()

    # Discover actual columns to avoid crashing on schema mismatch
    try:
        col_rows = cur.execute("PRAGMA table_info(sent_log)").fetchall()
        cols = [c[1] for c in col_rows]
    except Exception as e:
        conn.close()
        return {"count": 0, "alerts": [], "error": f"DB schema error: {str(e)}"}

    safe_cols = ", ".join(cols) if cols else "*"
    sql = f"SELECT {safe_cols} FROM sent_log WHERE ts >= ? AND score >= ?"
    params: list = [cutoff, score_i]

    if region_s and "region" in cols:
        sql += " AND region = ?"
        params.append(region_s)
    if tier_i is not None and "source_tier" in cols:
        sql += " AND source_tier = ?"
        params.append(tier_i)
    if crit_i is not None:
        sql += " AND is_critical = ?"
        params.append(crit_i)
    if entity and "entities" in cols:
        sql += " AND entities LIKE ?"
        params.append(f"%{entity}%")
    if keyword:
        if "precis" in cols:
            sql += " AND (title LIKE ? OR precis LIKE ?)"
            params.extend([f"%{keyword}%", f"%{keyword}%"])
        else:
            sql += " AND title LIKE ?"
            params.append(f"%{keyword}%")

    sql += " ORDER BY score DESC, ts DESC LIMIT ?"
    params.append(limit_i)

    try:
        rows = [row_to_dict(r) for r in cur.execute(sql, params).fetchall()]
        conn.close()
        return {"count": len(rows), "alerts": rows}
    except Exception as e:
        conn.close()
        return {"count": 0, "alerts": [], "error": str(e)}

# =======================
# SINGLE ALERT
# =======================
@app.get("/alerts/{alert_id}")
def get_alert(alert_id: int):
    conn = get_db()
    cur  = conn.cursor()
    row  = cur.execute("SELECT * FROM sent_log WHERE id=?", (alert_id,)).fetchone()
    conn.close()
    if not row:
        raise HTTPException(status_code=404, detail="Alert not found")
    return row_to_dict(row)

# =======================
# BRIEFING DIGEST (markdown)
# =======================
@app.get("/briefing", response_class=PlainTextResponse)
def briefing_digest(
    hours:     int           = Query(24),
    region:    Optional[str] = Query(None),
    min_score: int           = Query(5),
):
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
        return f"# VigiNote Briefing\n_No alerts in the last {hours}h._\n"
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines = [f"# VigiNote Intelligence Briefing", f"_{now_str} | {len(rows)} alerts_", ""]
    by_region: dict = {}
    for r in rows:
        by_region.setdefault(r["region"], []).append(r)
    for reg, alerts in by_region.items():
        lines.append(f"## {reg.replace('_',' ').title()}")
        for a in alerts:
            lines.append(f"### {a['title']}")
            lines.append(f"- **Source:** {a['source_dom']} | **Score:** {a['score']} | **Time:** {a['ts_iso'][:16]}")
            lines.append(f"- {a['precis']}")
            lines.append(f"- {a['url']}")
            lines.append("")
    return "\n".join(lines)

# =======================
# ENTITY FREQUENCY
# =======================
@app.get("/entities")
def top_entities(
    hours:  int           = Query(48),
    region: Optional[str] = Query(None),
    etype:  str           = Query("locations"),
    limit:  int           = Query(20),
):
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
    return {"entity_type": etype, "hours": hours, "region": region,
            "results": [{"name": n, "count": c} for n, c in ranked]}

# =======================
# AI BRIEFING GENERATION
# =======================
class BriefingRequest(BaseModel):
    alerts: List[dict]
    briefing_type: str = "morning"   # morning | rapid | daily | custom
    custom_title: Optional[str] = None

@app.post("/ai/generate")
async def ai_generate(req: BriefingRequest):
    """
    Takes a list of selected alert dicts, calls Claude to write:
    - executive_summary (2-3 paragraphs)
    - per-alert enhanced summaries (2-3 sentences each)
    - linkedin_caption (punchy 150-word post)
    - thumbnail_headline (max 12 words, hook for the image card)
    """
    if not ANTHROPIC_KEY:
        raise HTTPException(status_code=503, detail="ANTHROPIC_API_KEY not configured")
    if not req.alerts:
        raise HTTPException(status_code=400, detail="No alerts provided")

    now_str = datetime.now(timezone.utc).strftime("%d %B %Y, %H:%M UTC")
    regions = list({a.get("region","").replace("_"," ").title() for a in req.alerts})
    critical_count = sum(1 for a in req.alerts if a.get("is_critical"))

    alerts_text = ""
    for i, a in enumerate(req.alerts, 1):
        ents = a.get("entities") or {}
        locs = ", ".join((ents.get("locations") or [])[:3])
        orgs = ", ".join((ents.get("organizations") or [])[:3])
        alerts_text += f"""
ALERT {i}:
Title: {a.get('title','')}
Region: {a.get('region','').replace('_',' ')}
Source: {a.get('source_dom','')} (tier {a.get('source_tier',0)})
Score: {a.get('score',0)} | Critical: {'Yes' if a.get('is_critical') else 'No'}
Current summary: {a.get('precis','')}
Locations: {locs}
Organizations: {orgs}
Article text: {(a.get('article_text') or '')[:600]}
---"""

    prompt = f"""You are a senior intelligence analyst writing the VigiNote {req.briefing_type.title()} Intelligence Briefing for {now_str}.

Selected alerts ({len(req.alerts)} items, {critical_count} critical, regions: {', '.join(regions)}):
{alerts_text}

Write the following in strict JSON format with these exact keys:

{{
  "executive_summary": "2-3 paragraph professional intelligence executive summary covering the overall threat picture, key developments, and regional dynamics. Authoritative, factual, no speculation. ~200 words.",
  "alert_summaries": [
    {{
      "id": 1,
      "enhanced_summary": "2-3 sentence enhanced summary for this alert. More context than the original. Professional intelligence tone."
    }}
  ],
  "linkedin_caption": "A compelling 120-150 word LinkedIn post introducing this briefing. Professional but engaging. Start with a hook line. Include 3-4 relevant hashtags at the end. Written as VigiNote, not as an individual.",
  "thumbnail_headline": "Maximum 10 words. A punchy news-style headline for the thumbnail image card. The single most important story or theme from this briefing.",
  "briefing_title": "A sharp professional title for this briefing, e.g. 'VigiNote Morning Brief — Gaza Escalation & Sudan Crisis'"
}}

Return ONLY the JSON object. No preamble, no markdown fences."""

    try:
        async with httpx.AsyncClient(timeout=45.0) as client:
            resp = await client.post(
                "https://api.anthropic.com/v1/messages",
                headers={
                    "x-api-key": ANTHROPIC_KEY,
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json",
                },
                json={
                    "model": ANTHROPIC_MODEL,
                    "max_tokens": 2000,
                    "messages": [{"role": "user", "content": prompt}],
                },
            )
        resp.raise_for_status()
        raw = resp.json()["content"][0]["text"].strip()
        # Strip markdown fences if Claude wrapped them anyway
        if raw.startswith("```"):
            raw = raw.split("```")[1]
            if raw.startswith("json"):
                raw = raw[4:]
        result = json.loads(raw.strip())
        return {"status": "ok", "generated": result}
    except json.JSONDecodeError as e:
        raise HTTPException(status_code=500, detail=f"AI response parse error: {e}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"AI generation error: {str(e)}")


# =======================
# AI IMAGE GENERATION
# =======================
class ImageRequest(BaseModel):
    headline: str
    regions: List[str]
    organizations: List[str] = []
    locations: List[str] = []
    briefing_type: str = "morning"

@app.post("/ai/image")
async def ai_image(req: ImageRequest):
    """Generates a conflict-appropriate image via DALL-E 3. Falls back to Unsplash if unavailable."""

    region_str = ", ".join(req.regions[:3]) if req.regions else "global"
    combined   = (req.headline + " " + " ".join(req.organizations) + " " + " ".join(req.locations)).lower()

    # Ultra-minimal prompts — no conflict language at all
    if any(w in combined for w in ["ebola","cholera","disease","outbreak","epidemic","pandemic","health","medical"]):
        scene = "scientists in white lab coats working outdoors, golden hour light, blue sky, landscape photography"
    elif any(w in combined for w in ["flood","cyclone","hurricane","earthquake","tsunami","disaster","wildfire"]):
        scene = "dramatic storm clouds over a wide river landscape at dawn, blue and grey tones, landscape photography"
    elif any(w in combined for w in ["coup","protest","unrest","demonstration","riot"]):
        scene = "empty city square at dusk with dramatic street lighting, wide angle urban photography, deep blue tones"
    elif any(w in combined for w in ["famine","drought","hunger","refugee","displacement","camp"]):
        scene = "vast arid landscape at golden hour, dramatic sky, dust in the air, landscape photography"
    elif any(w in combined for w in ["navy","maritime","ship","vessel","sea","coast","port"]):
        scene = "dramatic ocean seascape during stormy weather, dark waves, cinematic wide angle, deep blue tones"
    elif any(w in combined for w in ["nuclear","chemical","biological","wmd","sanctions"]):
        scene = "glowing world map with network data connections, dark blue background, abstract digital art"
    elif any(w in combined for w in ["airstrike","bombing","missile","drone","explosion","shelling"]):
        scene = "dramatic urban skyline at dusk, storm clouds, city lights, wide angle architecture photography"
    elif "africa" in region_str.lower() or any(w in combined for w in ["sudan","somalia","congo","mali","nigeria","ethiopia"]):
        scene = "African savanna landscape at sunset, golden hour light, acacia trees silhouetted, landscape photography"
    elif "middle east" in region_str.lower() or any(w in combined for w in ["gaza","israel","syria","yemen","iraq","iran","lebanon"]):
        scene = "ancient desert city skyline at dusk, warm amber sky, architecture silhouetted, landscape photography"
    elif "europe" in region_str.lower() or any(w in combined for w in ["ukraine","russia","nato","balkan","caucasus"]):
        scene = "winter European landscape, snow covered plain, bare trees, overcast grey sky, landscape photography"
    elif "asia" in region_str.lower() or any(w in combined for w in ["china","taiwan","korea","myanmar","afghanistan","pakistan"]):
        scene = "Asian city skyline at night, reflections on wet streets, neon lights, urban photography"
    elif "south america" in region_str.lower() or any(w in combined for w in ["venezuela","colombia","brazil","mexico","haiti"]):
        scene = "South American cityscape at dusk, dramatic sky, warm tones, landscape photography"
    else:
        scene = "planet Earth from space, continents and clouds visible, dark background, deep blue tones"

    full_prompt = (
        f"Professional landscape or cityscape photograph. {scene}. "
        f"Dark navy and deep blue colour palette. Cinematic composition. "
        f"No people, no text, no logos, no watermarks. High quality photography."
    )

    # Try DALL-E 3 first
    if OPENAI_KEY:
        try:
            async with httpx.AsyncClient(timeout=60.0) as client:
                resp = await client.post(
                    "https://api.openai.com/v1/images/generations",
                    headers={
                        "Authorization": f"Bearer {OPENAI_KEY}",
                        "Content-Type": "application/json",
                    },
                    json={
                        "model": "dall-e-3",
                        "prompt": full_prompt,
                        "n": 1,
                        "size": "1792x1024",
                        "quality": "standard",
                        "style": "natural",
                    },
                )
            if resp.status_code == 200:
                data = resp.json()
                item = data["data"][0]
                # gpt-image-1 returns b64_json, dall-e-3 returns url
                if item.get("url"):
                    image_url = item["url"]
                elif item.get("b64_json"):
                    image_url = "data:image/png;base64," + item["b64_json"]
                else:
                    raise ValueError("No image data in response")
                return {"status": "ok", "image_url": image_url, "scene_type": scene[:80], "source": "gpt-image-1"}
            else:
                # Log the actual error for debugging
                error_detail = resp.text[:200]
                print(f"[DALL-E ERROR] {resp.status_code}: {error_detail}")
        except Exception as e:
            print(f"[DALL-E EXCEPTION] {str(e)}")

    # Unsplash fallback — keyed by topic
    unsplash_map = {
        "medical": "healthcare,field,documentary",
        "disease": "medical,emergency,field",
        "flood":   "flood,aerial,dramatic",
        "protest": "crowd,city,dusk",
        "famine":  "humanitarian,landscape,people",
        "maritime":"ocean,storm,sea",
        "nuclear": "global,network,dark",
        "africa":  "africa,landscape,sunset",
        "middle east": "desert,city,dusk",
        "europe":  "europe,winter,landscape",
        "asia":    "asia,city,night",
        "south america": "latin,america,landscape",
    }
    kw = "world,globe,dramatic,sky"
    for k, v in unsplash_map.items():
        if k in combined or k in region_str.lower():
            kw = v
            break

    image_url = f"https://source.unsplash.com/1792x1024/?{kw},dark"
    return {"status": "ok", "image_url": image_url, "scene_type": scene[:80], "source": "unsplash"}

# =======================
# DASHBOARD
# =======================
@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard():
    """Serve the briefing studio UI."""
    import pathlib
    html_path = pathlib.Path(__file__).parent / "dashboard.html"
    if html_path.exists():
        return HTMLResponse(content=html_path.read_text())
    raise HTTPException(status_code=404, detail="dashboard.html not found in project root")

# =======================
# HEALTH
# =======================
@app.get("/health")
def health():
    try:
        conn = get_db()
        count = conn.execute("SELECT COUNT(*) FROM sent_log").fetchone()[0]
        conn.close()
        return {"status": "ok", "total_alerts_stored": count, "ai_enabled": bool(ANTHROPIC_KEY)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
