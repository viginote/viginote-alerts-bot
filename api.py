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

import hashlib
import json
import os
import pathlib
import secrets
import time
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from typing import List, Optional

import httpx
from fastapi import FastAPI, Query, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse, Response
from pydantic import BaseModel

from viginote.deliverables import (
    save_deliverable, get_deliverable, get_by_token,
    list_deliverables, publish_to_clients, remove_client,
    mark_viewed, delete_deliverable, is_expired, time_remaining,
)
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

# ── CLIENT PROFILE SYSTEM ────────────────────────────────────────────────────
BASE_DIR      = pathlib.Path(__file__).parent
_CLIENTS_PATH = pathlib.Path(os.getenv("DB_PATH", "/data/viginote_v6.db")).parent / "clients.json"
_ALL_REGIONS  = ["GLOBAL","MIDDLE_EAST","EUROPE","ASIA","WEST_EAST_AFRICA","SOUTHERN_AFRICA","SOUTH_AMERICA"]
_TIER_LIMITS  = {
    "monitor":    {"regions": 1, "watchlist": 3,  "briefs": 0},
    "analyst":    {"regions": 2, "watchlist": 5,  "briefs": 2},
    "operator":   {"regions": 4, "watchlist": 10, "briefs": 5},
    "enterprise": {"regions": 7, "watchlist": -1, "briefs": -1},
    "admin":      {"regions": 7, "watchlist": -1, "briefs": -1},
}

def _load_clients() -> dict:
    """Load client profiles from /data/clients.json. Falls back to src dir then FEED_USERS."""
    # Try /data disk first
    if _CLIENTS_PATH.exists():
        try:
            data = json.loads(_CLIENTS_PATH.read_text())
            if data:
                return data
        except Exception:
            pass
    # Try project source directory (same folder as api.py)
    src_path = BASE_DIR / "clients.json"
    if src_path.exists():
        try:
            data = json.loads(src_path.read_text())
            if data:
                # Copy to /data for next time
                try:
                    _CLIENTS_PATH.parent.mkdir(parents=True, exist_ok=True)
                    _CLIENTS_PATH.write_text(json.dumps(data, indent=2))
                    print(f"[CLIENTS] Bootstrapped clients.json to {_CLIENTS_PATH}")
                except Exception:
                    pass
                return data
        except Exception:
            pass
    # Fallback: parse legacy FEED_USERS env var
    raw = os.getenv("FEED_USERS", "")
    clients = {}
    for pair in raw.split(","):
        pair = pair.strip()
        if ":" not in pair:
            continue
        parts = pair.split(":")
        u = parts[0].strip().lower()
        p = parts[1].strip() if len(parts) > 1 else ""
        tier = parts[2].strip() if len(parts) > 2 else "analyst"
        regions = parts[3].strip().split("|") if len(parts) > 3 else _ALL_REGIONS
        watchlist = parts[4].strip().split("|") if len(parts) > 4 else []
        clients[u] = {
            "password": p, "tier": tier, "regions": regions,
            "watchlist": watchlist, "brief_allowance": _TIER_LIMITS.get(tier,{}).get("briefs",2),
            "briefs_used": 0, "label": u.replace("_"," ").title()
        }
    return clients

def _save_clients(clients: dict):
    _CLIENTS_PATH.parent.mkdir(parents=True, exist_ok=True)
    _CLIENTS_PATH.write_text(json.dumps(clients, indent=2))

def _get_client(username: str) -> dict | None:
    return _load_clients().get(username.lower())

def _client_regions(username: str) -> list[str]:
    c = _get_client(username)
    if not c: return _ALL_REGIONS
    if c.get("tier") in ("admin","enterprise"): return _ALL_REGIONS
    return c.get("regions", _ALL_REGIONS)

def _client_watchlist(username: str) -> list[str]:
    c = _get_client(username)
    if not c: return []
    return c.get("watchlist", [])

def _client_streams(username: str) -> list[str]:
    c = _get_client(username)
    if not c: return ["geographic"]
    if c.get("tier") in ("admin","enterprise"): return ["geographic","maritime","cyber","economic","political","executive"]
    streams = c.get("streams", ["geographic"])
    if "geographic" not in streams:
        streams = ["geographic"] + streams
    return streams

def _client_countries(username: str) -> list[str]:
    c = _get_client(username)
    if not c: return []
    if c.get("tier") in ("admin","enterprise"): return []  # empty = all
    return c.get("countries", [])

def _streams_for_request(request: Request) -> list[str]:
    tok = _token_from_request(request)
    if not tok: return ["geographic","maritime","cyber","economic","political","executive"]
    uname = _verify_token(tok)
    if not uname: return ["geographic","maritime","cyber","economic","political","executive"]
    return _client_streams(uname)

def _countries_for_request(request: Request) -> list[str]:
    tok = _token_from_request(request)
    if not tok: return []
    uname = _verify_token(tok)
    if not uname: return []
    return _client_countries(uname)

# Active sessions: token -> {username, created}
_feed_sessions: dict = {}

# Admin sessions: token -> created
_admin_sessions: dict = {}

def _admin_password() -> str:
    return os.getenv("ADMIN_PASSWORD", "")

def _make_admin_token() -> str:
    return hashlib.sha256(f"admin{secrets.token_hex(20)}".encode()).hexdigest()

_ADMIN_SESSIONS_PATH = pathlib.Path(os.getenv("DB_PATH", "/data/viginote_v6.db")).parent / "admin_sessions.json"

def _load_admin_sessions() -> dict:
    """Load persisted admin sessions from disk."""
    try:
        if _ADMIN_SESSIONS_PATH.exists():
            return json.loads(_ADMIN_SESSIONS_PATH.read_text())
    except Exception:
        pass
    return {}

def _save_admin_sessions(sessions: dict):
    try:
        _ADMIN_SESSIONS_PATH.write_text(json.dumps(sessions))
    except Exception:
        pass

def _verify_admin(request: Request) -> bool:
    """Return True if request carries a valid admin session token."""
    token = request.cookies.get("vgn_admin")
    if not token:
        return False
    # Check memory first (fast path)
    created = _admin_sessions.get(token)
    if not created:
        # Check disk (survives restarts)
        disk = _load_admin_sessions()
        created = disk.get(token)
        if created:
            _admin_sessions[token] = created  # restore to memory
    if not created:
        return False
    if time.time() - created > 43200:  # 12 hours
        _admin_sessions.pop(token, None)
        return False
    return True

def _make_token(username: str) -> str:
    return hashlib.sha256(f"{username}{secrets.token_hex(16)}".encode()).hexdigest()

def _verify_token(token: str) -> str | None:
    """Return username if token is valid, None otherwise."""
    sess = _feed_sessions.get(token)
    if not sess:
        return None
    if time.time() - sess["created"] > 43200:
        del _feed_sessions[token]
        return None
    return sess["username"]

def _token_from_request(request: Request) -> str | None:
    return (request.headers.get("X-Feed-Token") or
            request.query_params.get("token") or
            request.cookies.get("vgn_feed"))

def _regions_for_request(request: Request) -> list[str]:
    """Return the allowed regions for the requesting client."""
    tok = _token_from_request(request)
    if not tok: return _ALL_REGIONS
    uname = _verify_token(tok)
    if not uname: return _ALL_REGIONS
    return _client_regions(uname)

def _watchlist_for_request(request: Request) -> list[str]:
    tok = _token_from_request(request)
    if not tok: return []
    uname = _verify_token(tok)
    if not uname: return []
    return _client_watchlist(uname)

# Client portal watchlist — comma-separated terms to monitor
WATCHLIST = [w.strip() for w in os.getenv("WATCHLIST", "").split(",") if w.strip()]

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

def _admin_redirect():
    return RedirectResponse(url="/admin/login", status_code=302)

@app.get("/", response_class=HTMLResponse)
async def page_root(request: Request):
    if not _verify_admin(request): return _admin_redirect()
    return RedirectResponse(url="/hub", status_code=302)

@app.get("/hub", response_class=HTMLResponse)
async def page_hub(request: Request):
    if not _verify_admin(request): return _admin_redirect()
    return _serve("hub.html")

@app.get("/dashboard", response_class=HTMLResponse)
async def page_dashboard(request: Request):
    if not _verify_admin(request): return _admin_redirect()
    return _serve("dashboard.html")

@app.get("/assessment", response_class=HTMLResponse)
async def page_assessment(request: Request):
    if not _verify_admin(request): return _admin_redirect()
    return _serve("assessment.html")

@app.get("/digest", response_class=HTMLResponse)
async def page_digest(request: Request):
    if not _verify_admin(request): return _admin_redirect()
    return _serve("digest.html")

@app.get("/brief", response_class=HTMLResponse)
async def page_brief(request: Request):
    if not _verify_admin(request): return _admin_redirect()
    return _serve("brief.html")

@app.get("/client", response_class=HTMLResponse)
async def page_client(): return _serve("client.html")

@app.get("/intelligence", response_class=HTMLResponse)
async def page_intelligence(): return RedirectResponse(url="/client", status_code=302)

# ── AUTH ENDPOINTS ────────────────────────────────────────────────────────────

class LoginRequest(BaseModel):
    username: str
    password: str

class SaveDeliverableRequest(BaseModel):
    type:     str
    title:    str
    content:  dict
    clients:  list[str] = []
    one_off:  bool = False

class PublishRequest(BaseModel):
    clients: list[str]

# ── DELIVERABLES ENDPOINTS ───────────────────────────────────────────────────

@app.post("/deliverables/save")
async def deliverable_save(req: SaveDeliverableRequest, request: Request):
    """Admin — save a generated deliverable and optionally publish to clients."""
    if not _verify_admin(request):
        raise HTTPException(status_code=403, detail="Admin only.")
    if req.type not in ("brief", "assessment", "digest"):
        raise HTTPException(status_code=400, detail="Invalid type.")
    rec = save_deliverable(
        dtype=req.type,
        title=req.title,
        content=req.content,
        clients=req.clients,
        one_off=req.one_off,
    )
    return {
        "id":      rec["id"],
        "token":   rec["token"],
        "view_url": f"/view/{rec['token']}",
        "expires": time_remaining(rec),
    }

@app.get("/deliverables")
async def deliverables_list(
    request: Request,
    dtype:  Optional[str] = Query(None),
    limit:  int           = Query(50),
):
    """Admin — list all deliverables."""
    if not _verify_admin(request):
        raise HTTPException(status_code=403, detail="Admin only.")
    items = list_deliverables(dtype=dtype, limit=limit)
    for item in items:
        item["time_remaining"] = time_remaining(item)
        item["expired"] = is_expired(item)
    return {"deliverables": items, "count": len(items)}

@app.get("/deliverables/client")
async def deliverables_for_client(request: Request):
    """Client — list deliverables published to them."""
    tok = _token_from_request(request)
    uname = _verify_token(tok) if tok else None
    if not uname:
        raise HTTPException(status_code=401, detail="Not authenticated.")
    items = list_deliverables(client=uname)
    for item in items:
        item["time_remaining"] = time_remaining(item)
        item["expired"] = is_expired(item)
        item["viewed"] = uname in item.get("viewed_by", {})
    return {"deliverables": items, "count": len(items)}

@app.get("/deliverables/{del_id}")
async def deliverable_get(del_id: str, request: Request):
    """Get a single deliverable with full content — requires admin or client auth."""
    rec = get_deliverable(del_id)
    if not rec:
        raise HTTPException(status_code=404, detail="Deliverable not found.")
    if is_expired(rec):
        raise HTTPException(status_code=410, detail="Deliverable has expired.")
    # Check access
    if _verify_admin(request):
        mark_viewed(del_id)
        return rec
    tok = _token_from_request(request)
    uname = _verify_token(tok) if tok else None
    if uname and uname in rec.get("clients", []):
        mark_viewed(del_id, uname)
        return rec
    raise HTTPException(status_code=403, detail="Access denied.")

@app.post("/deliverables/{del_id}/publish")
async def deliverable_publish(del_id: str, req: PublishRequest, request: Request):
    """Admin — publish a deliverable to one or more clients."""
    if not _verify_admin(request):
        raise HTTPException(status_code=403, detail="Admin only.")
    rec = publish_to_clients(del_id, req.clients)
    if not rec:
        raise HTTPException(status_code=404, detail="Deliverable not found.")
    return {"id": del_id, "clients": rec["clients"], "view_url": f"/view/{rec['token']}"}

@app.delete("/deliverables/{del_id}")
async def deliverable_delete(del_id: str, request: Request):
    """Admin — delete a deliverable."""
    if not _verify_admin(request):
        raise HTTPException(status_code=403, detail="Admin only.")
    if delete_deliverable(del_id):
        return {"status": "deleted"}
    raise HTTPException(status_code=404, detail="Deliverable not found.")

@app.get("/view/{token}", response_class=HTMLResponse)
async def view_deliverable(token: str, request: Request):
    """Public view — render a deliverable by its unguessable token."""
    rec = get_by_token(token)
    if not rec:
        return HTMLResponse("<html><body style='background:#080c14;color:#ef4444;font-family:monospace;display:flex;align-items:center;justify-content:center;height:100vh;font-size:16px'>Deliverable not found or link has expired.</body></html>", status_code=404)
    if is_expired(rec):
        return HTMLResponse("<html><body style='background:#080c14;color:#ef4444;font-family:monospace;display:flex;align-items:center;justify-content:center;height:100vh;font-size:16px'>This link has expired.</body></html>", status_code=410)
    # For subscriber deliverables, require login (check cookie)
    if not rec.get("one_off"):
        tok = _token_from_request(request)
        uname = _verify_token(tok) if tok else None
        if not uname and not _verify_admin(request):
            # Redirect to client login with return URL
            return RedirectResponse(url=f"/client?view={token}", status_code=302)
        if uname:
            mark_viewed(rec["id"], uname)
        else:
            mark_viewed(rec["id"])
    else:
        mark_viewed(rec["id"])
    # Serve the view page with data embedded
    view_html = _serve("view.html")
    # Inject the deliverable data
    injected = view_html.body.decode().replace(
        "__DELIVERABLE_DATA__",
        json.dumps(rec).replace("</", "<\\/")
    )
    return HTMLResponse(content=injected)

@app.get("/view/{token}/data")
async def view_deliverable_data(token: str, request: Request):
    """JSON data endpoint for the view page."""
    rec = get_by_token(token)
    if not rec or is_expired(rec):
        raise HTTPException(status_code=404, detail="Not found or expired.")
    mark_viewed(rec["id"])
    return rec

@app.post("/auth/login")
async def auth_login(req: LoginRequest):
    clients = _load_clients()
    uname   = req.username.strip().lower()
    if not clients:
        raise HTTPException(status_code=503, detail="No clients configured. Create /data/clients.json.")
    client  = clients.get(uname)
    if not client or client.get("password") != req.password:
        print(f"[AUTH] Failed login: user={req.username} ts={int(time.time())}")
        raise HTTPException(status_code=401, detail="Invalid credentials.")
    token   = _make_token(uname)
    _feed_sessions[token] = {"username": uname, "created": time.time()}
    regions = client.get("regions", _ALL_REGIONS)
    if client.get("tier") in ("admin", "enterprise"):
        regions = _ALL_REGIONS
    print(f"[AUTH] Login: user={uname} tier={client.get('tier')} ts={int(time.time())}")
    all_streams = ["geographic","maritime","cyber","economic","political","executive"]
    client_streams = client.get("streams", ["geographic"])
    if client.get("tier") in ("admin","enterprise"):
        client_streams = all_streams
    if "geographic" not in client_streams:
        client_streams = ["geographic"] + client_streams

    return {
        "token":            token,
        "username":         uname,
        "tier":             client.get("tier", "analyst"),
        "label":            client.get("label", uname),
        "regions":          regions,
        "all_regions":      _ALL_REGIONS,
        "countries":        client.get("countries", []),
        "streams":          client_streams,
        "all_streams":      all_streams,
        "watchlist":        client.get("watchlist", []),
        "brief_allowance":  client.get("brief_allowance", 0),
        "briefs_used":      client.get("briefs_used", 0),
    }

@app.post("/auth/logout")
async def auth_logout(token: str):
    if token in _feed_sessions:
        del _feed_sessions[token]
    return {"status": "ok"}

@app.get("/auth/debug")
async def auth_debug():
    """Debug endpoint — check clients config status without exposing passwords."""
    clients_on_disk = _CLIENTS_PATH.exists()
    clients = _load_clients()
    feed_users_env = os.getenv("FEED_USERS", "")
    return {
        "clients_json_path": str(_CLIENTS_PATH),
        "clients_json_exists": clients_on_disk,
        "client_count": len(clients),
        "usernames": list(clients.keys()),
        "feed_users_env_set": bool(feed_users_env),
        "feed_users_count": len([p for p in feed_users_env.split(",") if ":" in p]),
        "admin_password_set": bool(os.getenv("ADMIN_PASSWORD","")),
    }

@app.get("/auth/sessions")
async def auth_sessions():
    """Admin endpoint — shows active sessions."""
    return {
        "active_sessions": len(_feed_sessions),
        "sessions": [
            {"username": v["username"], "created": int(v["created"]),
             "age_minutes": round((time.time()-v["created"])/60)}
            for v in _feed_sessions.values()
        ]
    }

@app.get("/admin/clients")
async def list_clients(request: Request):
    """Admin — list all client profiles (passwords redacted)."""
    if not _verify_admin(request):
        raise HTTPException(status_code=403, detail="Admin only.")
    clients = _load_clients()
    result = []
    for u, prof in clients.items():
        entry = {k: v for k, v in prof.items()}
        entry["username"] = u
        result.append(entry)
    return {"clients": result}

class ClientProfile(BaseModel):
    username:        str
    password:        str
    tier:            str = "analyst"
    regions:         list[str] = []
    watchlist:       list[str] = []
    brief_allowance: int = 2
    label:           str = ""

@app.post("/admin/clients")
async def upsert_client(req: ClientProfile, request: Request):
    """Admin — create or update a client profile."""
    if not _verify_admin(request):
        raise HTTPException(status_code=403, detail="Admin only.")
    clients = _load_clients()
    ukey = req.username.lower()
    # Enforce tier region limits
    limits = _TIER_LIMITS.get(req.tier, _TIER_LIMITS["analyst"])
    regions = req.regions if req.tier in ("admin","enterprise") else req.regions[:limits["regions"]]
    watchlist = req.watchlist if limits["watchlist"] == -1 else req.watchlist[:limits["watchlist"]]
    clients[ukey] = {
        "password":        req.password,
        "tier":            req.tier,
        "regions":         regions,
        "watchlist":       watchlist,
        "brief_allowance": req.brief_allowance if limits["briefs"] == -1 else min(req.brief_allowance, limits["briefs"]),
        "briefs_used":     clients.get(ukey, {}).get("briefs_used", 0),
        "label":           req.label or req.username.replace("_"," ").title(),
    }
    _save_clients(clients)
    return {"status": "ok", "username": ukey, "profile": clients[ukey]}

@app.delete("/admin/clients/{username}")
async def delete_client(username: str, request: Request):
    """Admin — remove a client."""
    if not _verify_admin(request):
        raise HTTPException(status_code=403, detail="Admin only.")
    clients = _load_clients()
    if username not in clients:
        raise HTTPException(status_code=404, detail="Client not found.")
    del clients[username]
    _save_clients(clients)
    return {"status": "deleted", "username": username}

@app.get("/auth/profile")
async def get_profile(request: Request):
    """Return the calling client\'s own profile."""
    tok = _token_from_request(request)
    uname = _verify_token(tok) if tok else None
    if not uname:
        raise HTTPException(status_code=401, detail="Not authenticated.")
    c = _get_client(uname)
    if not c:
        raise HTTPException(status_code=404, detail="Profile not found.")
    regions = c.get("regions", _ALL_REGIONS)
    if c.get("tier") in ("admin","enterprise"):
        regions = _ALL_REGIONS
    all_streams = ["geographic","maritime","cyber","economic","political","executive"]
    client_streams = c.get("streams", ["geographic"])
    if c.get("tier") in ("admin","enterprise"):
        client_streams = all_streams
    if "geographic" not in client_streams:
        client_streams = ["geographic"] + client_streams

    return {
        "username":         uname,
        "tier":             c.get("tier","analyst"),
        "label":            c.get("label", uname),
        "regions":          regions,
        "all_regions":      _ALL_REGIONS,
        "countries":        c.get("countries", []),
        "streams":          client_streams,
        "all_streams":      all_streams,
        "watchlist":        c.get("watchlist",[]),
        "brief_allowance":  c.get("brief_allowance",0),
        "briefs_used":      c.get("briefs_used",0),
    }

@app.get("/admin/login", response_class=HTMLResponse)
async def admin_login_page():
    html = """<!DOCTYPE html>
<html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>VigiNote Admin</title>
<link href="https://fonts.googleapis.com/css2?family=Syne:wght@700;800&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{background:#080c14;display:flex;align-items:center;justify-content:center;min-height:100vh;font-family:'JetBrains Mono',monospace}
.card{background:#0e1420;border:1px solid #1e2d4a;border-radius:12px;padding:44px 48px;width:100%;max-width:400px;position:relative;overflow:hidden}
.card::before{content:'';position:absolute;top:0;left:0;right:0;height:3px;background:linear-gradient(90deg,#1d4ed8,#3b82f6,#1d4ed8)}
.logo{display:flex;align-items:center;gap:12px;justify-content:center;margin-bottom:32px}
.brand{font-family:'Syne',sans-serif;font-size:20px;font-weight:800;letter-spacing:3px;color:#e2e8f0}
.sub{font-size:9px;letter-spacing:2px;color:#64748b;display:block;margin-top:2px;text-align:center}
label{font-size:8px;font-weight:700;letter-spacing:2px;text-transform:uppercase;color:#64748b;display:block;margin-bottom:6px}
input{width:100%;padding:12px 14px;background:#111827;border:1px solid #243558;border-radius:6px;font-family:'JetBrains Mono',monospace;font-size:13px;color:#e2e8f0;outline:none;margin-bottom:16px;transition:border-color .15s}
input:focus{border-color:#3b82f6}
input::placeholder{color:#334155}
button{width:100%;padding:13px;background:#1d4ed8;color:#fff;border:none;border-radius:6px;font-family:'Syne',sans-serif;font-size:13px;font-weight:700;letter-spacing:1.5px;cursor:pointer;transition:background .15s}
button:hover{background:#3b82f6}
.err{color:#ef4444;font-size:10px;text-align:center;margin-top:12px;padding:8px;background:rgba(239,68,68,.1);border-radius:4px;border:1px solid rgba(239,68,68,.2);display:none}
.foot{font-size:9px;color:#334155;text-align:center;margin-top:20px;line-height:1.8}
</style></head>
<body><div class="card">
<div class="logo">
<svg width="26" height="30" viewBox="0 0 72 84" fill="none">
<path d="M36 3 L66 14 L66 40 C66 58 36 72 36 72 C36 72 6 58 6 40 L6 14 Z" fill="#151d2e" stroke="#3b82f6" stroke-width="2" stroke-linejoin="round"/>
<circle cx="36" cy="32" r="7" fill="none" stroke="#3b82f6" stroke-width="2.5"/>
<circle cx="36" cy="32" r="3" fill="#3b82f6"/>
</svg>
<div><div class="brand">VIGINOTE</div><div class="sub">Admin Access · Authorised Only</div></div>
</div>
<label>Password</label>
<input type="password" id="pw" placeholder="••••••••" autocomplete="current-password">
<button onclick="doLogin()">Enter Platform</button>
<div class="err" id="err">Incorrect password.</div>
<div class="foot">All access is logged · info@viginote.com<br>Unauthorised access is prohibited</div>
</div>
<script>
async function doLogin(){
  const pw=document.getElementById('pw').value;
  if(!pw)return;
  const r=await fetch('/admin/auth',{
    method:'POST',
    headers:{'Content-Type':'application/json'},
    credentials:'include',
    body:JSON.stringify({password:pw})
  });
  if(r.ok){
    const d=await r.json();
    if(d.redirect) window.location.href=d.redirect;
  } else {
    document.getElementById('err').style.display='block';
    document.getElementById('err').textContent = r.status===503
      ? 'ADMIN_PASSWORD not set on server.'
      : 'Incorrect password.';
  }
}
document.addEventListener('keydown',e=>{if(e.key==='Enter')doLogin();});
</script></body></html>"""
    return HTMLResponse(content=html)

class AdminLoginRequest(BaseModel):
    password: str

@app.post("/admin/auth")
async def admin_auth(req: AdminLoginRequest, response: Response):
    pw = _admin_password()
    if not pw:
        raise HTTPException(status_code=503, detail="ADMIN_PASSWORD not configured.")
    if req.password != pw:
        print(f"[ADMIN] Failed login attempt ts={int(time.time())}")
        raise HTTPException(status_code=401, detail="Incorrect password.")
    token = _make_admin_token()
    created = time.time()
    _admin_sessions[token] = created
    # Persist to disk so sessions survive Render restarts
    disk = _load_admin_sessions()
    disk[token] = created
    # Prune expired entries
    disk = {t: c for t, c in disk.items() if time.time() - c < 43200}
    _save_admin_sessions(disk)
    response.set_cookie(
        "vgn_admin", token,
        max_age=43200,
        httponly=True,
        samesite="lax",
        secure=False,   # works on both HTTP and HTTPS
    )
    print(f"[ADMIN] Login ts={int(time.time())} sessions={len(_admin_sessions)}")
    return {"redirect": "/hub"}

@app.post("/admin/logout")
async def admin_logout(response: Response):
    response.delete_cookie("vgn_admin")
    return RedirectResponse(url="/admin/login", status_code=302)

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
    request:   Request,
    region:    Optional[str] = Query(None),
    country:   Optional[str] = Query(None),
    stream:    Optional[str] = Query(None),
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
        # Server-side region enforcement
        allowed = _regions_for_request(request)
        if not region_s:
            rows = [r for r in rows if r.get("region") in allowed]
        elif region_s not in allowed:
            return {"count": 0, "alerts": [], "allowed_regions": allowed, "access_denied": True}

        # Server-side country enforcement
        allowed_countries = _countries_for_request(request)
        if allowed_countries and country:
            rows = [r for r in rows if r.get("country") == country]
        elif allowed_countries:
            pass  # Don't filter by country when browsing all — region filter is enough

        # Server-side stream enforcement
        allowed_streams = _streams_for_request(request)
        if stream:
            if stream not in allowed_streams:
                return {"count": 0, "alerts": [], "access_denied": True}
            rows = [r for r in rows if (r.get("stream") or "geographic") == stream]
        else:
            rows = [r for r in rows if (r.get("stream") or "geographic") in allowed_streams]

        return {"count": len(rows), "alerts": rows,
                "allowed_regions": allowed,
                "allowed_streams": allowed_streams,
                "allowed_countries": allowed_countries}
    except Exception as e:
        return {"count": 0, "alerts": [], "error": str(e)}

@app.get("/alerts/{alert_id}")
def get_alert(alert_id: int):
    conn = get_conn()
    row  = conn.execute("SELECT * FROM sent_log WHERE id=?", (alert_id,)).fetchone()
    if not row: raise HTTPException(status_code=404, detail="Alert not found")
    d = row_to_dict(dict(row))
    # Return full article text for the article preview panel (no truncation)
    return d

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
    request: Request,
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

    allowed = _regions_for_request(request)
    results = [r for r in results if r.get("region") in allowed]
    return {"period_days": days, "regions": results, "allowed_regions": allowed}

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
def watchlist_check(request: Request, hours: int = Query(168)):
    """Check client watchlist terms against recent alerts — filtered by client profile."""
    client_wl = _watchlist_for_request(request)
    effective_watchlist = client_wl if client_wl else WATCHLIST
    if not effective_watchlist:
        return {"note": "No watchlist configured.",
                "total_hits": 0}
    days = max(1, hours // 24)
    conn = get_conn()
    allowed = _regions_for_request(request)
    rows = query_alerts(conn, days=days, limit=500)
    rows = [r for r in rows if r.get("region") in allowed]
    matches: dict = {}
    total_hits = 0
    for term in effective_watchlist:
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

CRITICAL COORDINATE REQUIREMENT: Every hotspot MUST have real accurate decimal lat/lng for the named location. Replace REAL_LATITUDE_HERE/REAL_LONGITUDE_HERE with actual values. Never return 0.0. Example: Gaza=31.5017/34.4668, Khartoum=15.5007/32.5599, Beirut=33.8938/35.5018.

Return ONLY valid JSON with these exact keys. Be concise but specific — max 2 sentences per field unless stated:

{{"report_title":"Security Assessment: {req.location}","location":"{req.location}","assessment_date":"{now_str}","classification":"CLIENT CONFIDENTIAL","event_context":"{req.event or ''}","overall_risk_level":"HIGH","overall_risk_score":7,"risk_trajectory":"STABLE","risk_trajectory_note":"One sentence.","intelligence_note":"","executive_summary":"Write 2 focused paragraphs on the security environment, key threats, and visitor risk for {req.location}.","location_profile":{{"country":"","region":"","population":"","strategic_significance":"One sentence.","key_infrastructure":["item1","item2"],"upcoming_events":[]}},"threat_matrix":[{{"category":"Political Violence","assessment":"2 sentences.","risk_level":"HIGH","risk_score":7,"visitor_impact":"1 sentence.","key_indicators":["indicator1","indicator2"]}},{{"category":"Terrorism & Extremism","assessment":"2 sentences.","risk_level":"MEDIUM","risk_score":5,"visitor_impact":"1 sentence.","key_indicators":["ind1"]}},{{"category":"Organised Crime","assessment":"2 sentences.","risk_level":"MEDIUM","risk_score":5,"visitor_impact":"1 sentence.","key_indicators":["ind1"]}},{{"category":"Civil Unrest","assessment":"2 sentences.","risk_level":"MEDIUM","risk_score":4,"visitor_impact":"1 sentence.","key_indicators":["ind1"]}},{{"category":"Natural Hazards","assessment":"1 sentence.","risk_level":"LOW","risk_score":3,"visitor_impact":"1 sentence.","key_indicators":[]}},{{"category":"Health & Medical","assessment":"1 sentence.","risk_level":"LOW","risk_score":3,"visitor_impact":"1 sentence.","key_indicators":[]}}],"hotspots":[{{"name":"Specific district or area name","description":"1 sentence on why this area is high risk.","risk_level":"HIGH","recommendation":"1 sentence advisory.","lat":REAL_LATITUDE_HERE,"lng":REAL_LONGITUDE_HERE}},{{"name":"Specific district or area name","description":"1 sentence.","risk_level":"MEDIUM","recommendation":"1 sentence.","lat":REAL_LATITUDE_HERE,"lng":REAL_LONGITUDE_HERE}},{{"name":"Specific district or area name","description":"1 sentence.","risk_level":"HIGH","recommendation":"1 sentence.","lat":REAL_LATITUDE_HERE,"lng":REAL_LONGITUDE_HERE}},{{"name":"Specific district or area name","description":"1 sentence.","risk_level":"CRITICAL","recommendation":"1 sentence.","lat":REAL_LATITUDE_HERE,"lng":REAL_LONGITUDE_HERE}}],"visitor_advisory":{{"before_travel":["Action 1","Action 2","Action 3"],"areas_to_avoid":["Area — reason","Area — reason"],"safe_zones":["Safe area 1","Safe area 2"],"transport":"1 sentence on transport safety.","accommodation":"1 sentence on accommodation security.","communication":"1 sentence on comms security.","emergency_contacts":["Police: xxx","Embassy: xxx","Medical: xxx"]}},"organised_crime_profile":{{"active_groups":["Group — activity"],"primary_methods":["Method 1","Method 2"],"visitor_targeting":"1 sentence.","trend":"1 sentence."}},"recommended_measures":[{{"category":"Pre-Deployment","measures":["Action 1","Action 2","Action 3"]}},{{"category":"In-Country","measures":["Action 1","Action 2","Action 3"]}},{{"category":"Digital Security","measures":["Action 1","Action 2"]}},{{"category":"Emergency Response","measures":["Action 1","Action 2"]}}],"linkedin_teaser":"100-word LinkedIn post on security in {req.location}. End with 3 hashtags."}}

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
