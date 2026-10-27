"""
sa_main.py — South Africa edition worker.

Polls the SA source list on an interval, stores classified articles for review.
No Telegram credentials are required. (Optional: set TELEGRAM_BOT_TOKEN and
SA_TELEGRAM_CHAT_ID to be pinged when new CRITICAL/HIGH items need review.)

Run:  python sa_main.py            # loop every SA_POLL_INTERVAL seconds (default 900)
      SA_POLL_INTERVAL=0 python sa_main.py   # run once (use with Render cron)
"""
import os
import time
import traceback

import requests

from viginote.db import init_db
from viginote.sa_pipeline import init_sa, run_once

INTERVAL = int(os.getenv("SA_POLL_INTERVAL", "900"))
TG_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
TG_CHAT = os.getenv("SA_TELEGRAM_CHAT_ID", "")


def notify_review(conn, since_ts: int):
    if not (TG_TOKEN and TG_CHAT):
        return
    rows = conn.execute(
        "SELECT id,title,level,place,province FROM sa_articles WHERE status='pending' AND ts>=? "
        "AND level IN ('critical','high') ORDER BY score DESC LIMIT 5", (since_ts,)).fetchall()
    if not rows:
        return
    base = os.getenv("PUBLIC_BASE_URL", "").rstrip("/")
    lines = ["VigiNote ZA — items waiting for review:"] + [
        f"• [{r[2].upper()}] {r[1]} ({r[3] or r[4] or 'SA'})" for r in rows]
    lines.append(f"{base}/za/admin")
    try:
        requests.post(f"https://api.telegram.org/bot{TG_TOKEN}/sendMessage",
                      data={"chat_id": TG_CHAT, "text": "\n".join(lines), "disable_web_page_preview": True}, timeout=15)
    except Exception as e:  # noqa: BLE001
        print("[TG]", e)


def cycle():
    conn = init_db()
    init_sa(conn)
    started = int(time.time())
    stats = run_once(conn)
    print(f"[ZA] {time.strftime('%H:%M:%S')} {stats}", flush=True)
    notify_review(conn, started)


if __name__ == "__main__":
    if INTERVAL <= 0:
        cycle()
    else:
        while True:
            try:
                cycle()
            except Exception:  # noqa: BLE001
                traceback.print_exc()
            time.sleep(INTERVAL)
