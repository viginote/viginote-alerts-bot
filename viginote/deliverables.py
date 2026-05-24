"""
deliverables.py — VigiNote deliverables storage system
Handles saving, retrieving and publishing briefs, assessments and digests.
"""
from __future__ import annotations
import json
import os
import pathlib
import secrets
import time
from typing import Optional

# Storage path — same disk as clients.json and DB
_BASE = pathlib.Path(os.getenv("DB_PATH", "/data/viginote_v6.db")).parent
_DELIVERABLES_DIR = _BASE / "deliverables"

TYPES = {"brief", "assessment", "digest"}

# View token expiry — subscribers: 30 days, one-off: 7 days
SUBSCRIBER_EXPIRY_DAYS = 30
ONE_OFF_EXPIRY_DAYS    = 7


def _ensure_dir():
    _DELIVERABLES_DIR.mkdir(parents=True, exist_ok=True)


def _make_id() -> str:
    return secrets.token_hex(8)  # 16-char hex — unique ID


def _make_token() -> str:
    return secrets.token_urlsafe(32)  # unguessable 43-char URL token


def _path(del_id: str) -> pathlib.Path:
    return _DELIVERABLES_DIR / f"{del_id}.json"


# ── SAVE ─────────────────────────────────────────────────────────────────────

def save_deliverable(
    dtype: str,
    title: str,
    content: dict,
    clients: list[str] | None = None,
    one_off: bool = False,
    expiry_days: int | None = None,
) -> dict:
    """
    Save a deliverable to disk. Returns the full deliverable record.
    dtype: 'brief' | 'assessment' | 'digest'
    content: the full generated JSON from Claude
    clients: list of usernames to publish to (can be empty — publish later)
    one_off: True = link-only access, no login required
    """
    _ensure_dir()

    del_id = _make_id()
    token  = _make_token()
    now    = int(time.time())

    if expiry_days is None:
        expiry_days = ONE_OFF_EXPIRY_DAYS if one_off else SUBSCRIBER_EXPIRY_DAYS

    record = {
        "id":         del_id,
        "type":       dtype,
        "title":      title,
        "token":      token,
        "created_at": now,
        "expires_at": now + (expiry_days * 86400),
        "content":    content,
        "clients":    clients or [],
        "one_off":    one_off,
        "viewed_by":  {},   # {username: timestamp}
        "view_count": 0,
    }

    _path(del_id).write_text(json.dumps(record, indent=2))
    return record


# ── RETRIEVE ─────────────────────────────────────────────────────────────────

def get_deliverable(del_id: str) -> dict | None:
    p = _path(del_id)
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text())
    except Exception:
        return None


def get_by_token(token: str) -> dict | None:
    """Find a deliverable by its public view token."""
    _ensure_dir()
    for p in _DELIVERABLES_DIR.glob("*.json"):
        try:
            rec = json.loads(p.read_text())
            if rec.get("token") == token:
                return rec
        except Exception:
            continue
    return None


def list_deliverables(
    dtype: str | None = None,
    client: str | None = None,
    limit: int = 50,
) -> list[dict]:
    """List deliverables. Optionally filter by type or client username."""
    _ensure_dir()
    records = []
    for p in sorted(_DELIVERABLES_DIR.glob("*.json"), reverse=True):
        try:
            rec = json.loads(p.read_text())
            if dtype and rec.get("type") != dtype:
                continue
            if client and client not in rec.get("clients", []):
                continue
            # Strip full content for listing — return summary only
            summary = {k: v for k, v in rec.items() if k != "content"}
            records.append(summary)
        except Exception:
            continue
        if len(records) >= limit:
            break
    return records


# ── PUBLISH ───────────────────────────────────────────────────────────────────

def publish_to_clients(del_id: str, usernames: list[str]) -> dict | None:
    """Add clients to a deliverable's recipient list."""
    rec = get_deliverable(del_id)
    if not rec:
        return None
    existing = set(rec.get("clients", []))
    for u in usernames:
        existing.add(u)
    rec["clients"] = list(existing)
    _path(del_id).write_text(json.dumps(rec, indent=2))
    return rec


def remove_client(del_id: str, username: str) -> dict | None:
    """Remove a client from a deliverable's recipient list."""
    rec = get_deliverable(del_id)
    if not rec:
        return None
    rec["clients"] = [c for c in rec.get("clients", []) if c != username]
    _path(del_id).write_text(json.dumps(rec, indent=2))
    return rec


# ── MARK VIEWED ───────────────────────────────────────────────────────────────

def mark_viewed(del_id: str, username: str | None = None) -> None:
    rec = get_deliverable(del_id)
    if not rec:
        return
    rec["view_count"] = rec.get("view_count", 0) + 1
    if username:
        rec.setdefault("viewed_by", {})[username] = int(time.time())
    _path(del_id).write_text(json.dumps(rec, indent=2))


# ── DELETE ────────────────────────────────────────────────────────────────────

def delete_deliverable(del_id: str) -> bool:
    p = _path(del_id)
    if p.exists():
        p.unlink()
        return True
    return False


# ── EXPIRY ────────────────────────────────────────────────────────────────────

def is_expired(rec: dict) -> bool:
    return int(time.time()) > rec.get("expires_at", 0)


def cleanup_expired() -> int:
    """Delete expired deliverables. Returns count deleted."""
    _ensure_dir()
    deleted = 0
    for p in _DELIVERABLES_DIR.glob("*.json"):
        try:
            rec = json.loads(p.read_text())
            if is_expired(rec):
                p.unlink()
                deleted += 1
        except Exception:
            pass
    return deleted


def time_remaining(rec: dict) -> str:
    """Human-readable time remaining before expiry."""
    secs = rec.get("expires_at", 0) - int(time.time())
    if secs <= 0:
        return "Expired"
    days = secs // 86400
    if days >= 1:
        return f"{days}d remaining"
    hours = secs // 3600
    return f"{hours}h remaining"
