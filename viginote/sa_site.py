"""
sa_site.py — FastAPI router for the South Africa edition.

Public:
  GET /za                      daily briefing website (single page)
  GET /za/api/articles         approved articles (filters: topic, province, q, days, min_score, limit)
  GET /za/api/briefing         today's top stories + counts by topic/province
  GET /za/api/sources          source list with tier + verification flag
  GET /za/api/corrections      published corrections
  GET /za/report/{id}.pdf      one-page PDF report for an approved article
Admin (header X-Admin-Secret = $ADMIN_SECRET; disabled if the env var is unset):
  GET  /za/admin               approval queue UI
  GET  /za/admin/queue         pending items
  POST /za/admin/review        {id, action: approve|reject|instagram}
  POST /za/admin/correction    {id, text}
  GET  /za/admin/social/{id}.zip   Instagram slides + caption (only if instagram-approved)
"""
from __future__ import annotations

import hmac
import os
import pathlib
import time
from typing import Optional

from fastapi import APIRouter, Header, HTTPException, Query
from fastapi.responses import FileResponse, HTMLResponse, Response
from pydantic import BaseModel

from viginote.sa_pipeline import init_sa
from viginote.sa_sources import SA_SOURCES
from viginote.sa_topics import TOPICS

router = APIRouter(prefix="/za", tags=["south-africa"])
WEB = pathlib.Path(__file__).resolve().parent.parent / "sa_web"
_get_conn = None  # injected by api.py


def configure(get_conn):
    global _get_conn
    _get_conn = get_conn


def _conn():
    c = _get_conn()
    init_sa(c)
    return c


def _rows(cur):
    cols = [c[0] for c in cur.description]
    return [dict(zip(cols, r)) for r in cur.fetchall()]


PUBLIC_COLS = ("id,url,title,summary,source_name,source_domain,source_tier,topic,province,city,place,score,level,"
               "corroboration,published_ts,ts")


def _admin(secret: Optional[str]):
    expected = os.getenv("ADMIN_SECRET", "")
    if not expected or not secret or not hmac.compare_digest(secret, expected):
        raise HTTPException(status_code=401, detail="Admin secret required")


# ── public ────────────────────────────────────────────────────────────────
@router.get("", response_class=HTMLResponse)
@router.get("/", response_class=HTMLResponse, include_in_schema=False)
def home():
    return HTMLResponse((WEB / "index.html").read_text(encoding="utf-8"))


@router.get("/api/articles")
def articles(topic: Optional[str] = None, province: Optional[str] = None, q: Optional[str] = None,
             days: int = Query(3, ge=1, le=90), min_score: int = Query(0, ge=0, le=10),
             limit: int = Query(60, ge=1, le=200)):
    sql = f"SELECT {PUBLIC_COLS} FROM sa_articles WHERE status='approved' AND ts>=? AND score>=?"
    p: list = [int(time.time()) - days * 86400, min_score]
    if topic and topic in TOPICS:
        sql += " AND topic=?"; p.append(topic)
    if province:
        sql += " AND province=?"; p.append(province)
    if q:
        sql += " AND (title LIKE ? OR summary LIKE ?)"; p += [f"%{q}%", f"%{q}%"]
    sql += " ORDER BY ts DESC, score DESC LIMIT ?"; p.append(limit)
    rows = _rows(_conn().execute(sql, p))
    return {"count": len(rows), "articles": rows}


@router.get("/api/briefing")
def briefing(hours: int = Query(36, ge=6, le=168)):
    c = _conn()
    since = int(time.time()) - hours * 3600
    top = _rows(c.execute(f"SELECT {PUBLIC_COLS} FROM sa_articles WHERE status='approved' AND ts>=? "
                          "ORDER BY score DESC, corroboration DESC, ts DESC LIMIT 8", (since,)))
    by_topic = _rows(c.execute("SELECT topic, COUNT(*) n FROM sa_articles WHERE status='approved' AND ts>=? "
                               "GROUP BY topic ORDER BY n DESC", (since,)))
    by_prov = _rows(c.execute("SELECT province, COUNT(*) n FROM sa_articles WHERE status='approved' AND ts>=? "
                              "AND province!='' GROUP BY province ORDER BY n DESC", (since,)))
    last = c.execute("SELECT MAX(ts) FROM sa_articles WHERE status='approved'").fetchone()[0]
    return {"hours": hours, "top": top, "by_topic": by_topic, "by_province": by_prov,
            "topics": TOPICS, "last_update": last}


@router.get("/api/sources")
def sources():
    return {"sources": [{k: s[k] for k in ("name", "domain", "category", "tier", "kind", "verified")}
                        for s in SA_SOURCES],
            "policy": "We publish headlines, short summaries and links only, and always link to the original "
                      "publisher. Tier 3 = official/primary body, 2 = established newsroom, 1 = general news."}


@router.get("/api/corrections")
def corrections():
    return {"corrections": _rows(_conn().execute(
        "SELECT c.id,c.ts,c.text,c.article_id,a.title FROM sa_corrections c "
        "LEFT JOIN sa_articles a ON a.id=c.article_id ORDER BY c.ts DESC LIMIT 50"))}


@router.get("/report/{article_id}.pdf")
def report_pdf(article_id: int):
    from viginote.sa_social import build_pdf
    row = _rows(_conn().execute("SELECT * FROM sa_articles WHERE id=? AND status='approved'", (article_id,)))
    if not row:
        raise HTTPException(404, "Not found")
    return Response(build_pdf(row[0]), media_type="application/pdf",
                    headers={"Content-Disposition": f'inline; filename="viginote-za-{article_id}.pdf"'})


# ── admin ─────────────────────────────────────────────────────────────────
@router.get("/admin", response_class=HTMLResponse)
def admin_page():
    return HTMLResponse((WEB / "admin.html").read_text(encoding="utf-8"))


@router.get("/admin/queue")
def queue(status: str = "pending", x_admin_secret: Optional[str] = Header(None)):
    _admin(x_admin_secret)
    if status not in ("pending", "approved", "rejected"):
        raise HTTPException(400, "bad status")
    rows = _rows(_conn().execute(
        "SELECT * FROM sa_articles WHERE status=? ORDER BY score DESC, ts DESC LIMIT 150", (status,)))
    return {"count": len(rows), "articles": rows}


class Review(BaseModel):
    id: int
    action: str  # approve | reject | instagram | unpublish
    note: Optional[str] = None


@router.post("/admin/review")
def review(r: Review, x_admin_secret: Optional[str] = Header(None)):
    _admin(x_admin_secret)
    c = _conn()
    if not c.execute("SELECT 1 FROM sa_articles WHERE id=?", (r.id,)).fetchone():
        raise HTTPException(404, "Not found")
    now = int(time.time())
    if r.action == "approve":
        c.execute("UPDATE sa_articles SET status='approved',reviewed_ts=?,reviewer_note=? WHERE id=?", (now, r.note, r.id))
    elif r.action == "reject":
        c.execute("UPDATE sa_articles SET status='rejected',instagram_ok=0,reviewed_ts=?,reviewer_note=? WHERE id=?",
                  (now, r.note, r.id))
    elif r.action == "unpublish":
        c.execute("UPDATE sa_articles SET status='pending',instagram_ok=0,reviewed_ts=? WHERE id=?", (now, r.id))
    elif r.action == "instagram":
        c.execute("UPDATE sa_articles SET status='approved',instagram_ok=1,reviewed_ts=? WHERE id=?", (now, r.id))
    else:
        raise HTTPException(400, "bad action")
    c.commit()
    return {"ok": True}


class Correction(BaseModel):
    id: Optional[int] = None
    text: str


@router.post("/admin/correction")
def add_correction(body: Correction, x_admin_secret: Optional[str] = Header(None)):
    _admin(x_admin_secret)
    if not body.text.strip():
        raise HTTPException(400, "text required")
    c = _conn()
    c.execute("INSERT INTO sa_corrections(article_id,ts,text) VALUES(?,?,?)",
              (body.id, int(time.time()), body.text.strip()[:1000]))
    c.commit()
    return {"ok": True}


@router.get("/admin/social/{article_id}.zip")
def social_zip(article_id: int, x_admin_secret: Optional[str] = Header(None)):
    _admin(x_admin_secret)
    from viginote.sa_social import build_zip
    row = _rows(_conn().execute("SELECT * FROM sa_articles WHERE id=? AND instagram_ok=1 AND status='approved'",
                                (article_id,)))
    if not row:
        raise HTTPException(404, "Not approved for Instagram")
    return Response(build_zip(row[0]), media_type="application/zip",
                    headers={"Content-Disposition": f'attachment; filename="viginote-za-{article_id}.zip"'})
