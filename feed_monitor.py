"""
feed_monitor.py — Periodic feed health digest.

Called from the main loop every N cycles. Posts a Telegram digest
if any feeds have been failing for more than MIN_FAIL_HOURS hours,
so blind spots don't accumulate silently.
"""

import os
import time
from datetime import datetime, timezone, timedelta

MIN_CONSECUTIVE_FAILURES = int(os.getenv("FEED_ALERT_MIN_FAILURES", "5"))
DIGEST_INTERVAL_HOURS    = int(os.getenv("FEED_DIGEST_HOURS", "24"))
_last_digest_ts: int = 0


def maybe_send_health_digest(conn, send_fn) -> None:
    """
    Send a feed-health Telegram digest if it's been >= DIGEST_INTERVAL_HOURS
    since the last one, and there are unhealthy feeds.
    """
    global _last_digest_ts

    now = int(time.time())
    if (now - _last_digest_ts) < (DIGEST_INTERVAL_HOURS * 3600):
        return

    from viginote.db import unhealthy_feeds
    bad = unhealthy_feeds(conn, min_failures=MIN_CONSECUTIVE_FAILURES)
    if not bad:
        _last_digest_ts = now
        return

    lines = ["⚠️ <b>VigiNote Feed Health Alert</b>\n"]
    for f in bad[:15]:
        since = ""
        if f.get("last_success"):
            dt = datetime.fromtimestamp(f["last_success"], tz=timezone.utc)
            since = f" (last OK: {dt.strftime('%Y-%m-%d %H:%M')} UTC)"
        lines.append(
            f"• <code>{f['feed_url'][:60]}</code>\n"
            f"  Region: {f['region']} | Fails: {f['consecutive_failures']}{since}\n"
        )

    if len(bad) > 15:
        lines.append(f"…and {len(bad) - 15} more. Check /feed-health API endpoint.")

    msg = "\n".join(lines)
    try:
        send_fn(msg)
    except Exception as e:
        print(f"[FEED MONITOR] Telegram error: {e}")

    _last_digest_ts = now
    print(f"[FEED MONITOR] Digest sent. {len(bad)} unhealthy feeds.")
