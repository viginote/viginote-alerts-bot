# VigiNote ZA — South Africa edition

A South Africa–only version of the VigiNote pipeline: it polls ~50 official and newsroom sources, classifies each item by
topic and province/city, scores importance, de-duplicates the same story across outlets, and queues it for **human review**.
Approved items appear on a public daily-briefing site at `/za`. Approved items can also be exported as an Instagram carousel
(PNG slides + caption) and a one-page PDF report.

## Run it
Render web service, same as the original bot (`start.sh`), with these env vars:

| var | purpose |
|---|---|
| `EDITION=SA` | start `sa_main.py` instead of the Telegram bot |
| `ADMIN_SECRET` | required for `/za/admin` and the ops endpoints (fail-closed if unset) |
| `PUBLIC_BASE_URL` | your domain, used on slides/links |
| `DB_PATH=/data/viginote_v6.db` | on the persistent disk |
| `SA_SITE_AUTOPUBLISH=1` | optional: auto-publish official (tier-3) items to the **site only** |

Then open `https://<your-domain>/za` (public) and `/za/admin` (review queue; paste `ADMIN_SECRET`).

## First thing to do after deploy
`python check_sources.py` from the Render shell. Feed URLs in `viginote/sa_sources.py` were compiled without live access to
.za sites, so some will be wrong or dead. Fix or delete the failures; mark good ones `"verified": True`.
The runtime also writes every fetch result to `feed_health` (`GET /feed-health`).

## Pipeline
`sa_sources.py` registry → `sa_pipeline.py` poll/dedupe/store → `sa_topics.py` topic + importance (0–10) → `sa_geo.py`
province/city → status `pending` → reviewer approves in `/za/admin` → public `/za` and `/za/report/{id}.pdf`;
"Approve + Instagram" unlocks `/za/admin/social/{id}.zip`.

## Editorial safeguards (built in)
- Only headline, ≤280-char summary, source and link are stored/published. No article bodies.
- Every item shows source and confidence (official / multiple outlets / single source).
- Nothing is public until approved. Instagram needs a separate explicit approval.
- Corrections are published at `/za` → Corrections (`POST /za/admin/correction`).
- Review rule of thumb: don't approve items that name suspects/accused before conviction, or that rely on a single anonymous source.

## Tests
`python -m pytest tests -q` (uses synthetic feeds, no network).

## Not done yet
- SAPS quarterly precinct statistics (published as downloads, not RSS) — ingest as context, not as alerts.
- Scrapers for sources with no RSS (`kind: "page"` in `sa_sources.py`).
- Auto-posting to Instagram (needs a Meta Business account + Graph API); today the carousel is a download you post yourself.
