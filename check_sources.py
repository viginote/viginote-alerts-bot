#!/usr/bin/env python3
"""
check_sources.py — test every South African RSS source.

Usage:  python check_sources.py            # prints a table, exit 0
        python check_sources.py --json     # machine-readable output

Run this from Render shell or any machine with internet. Sources that return
items can be marked verified=True in viginote/sa_sources.py; sources that fail
should be fixed or removed. The runtime also records failures in feed_health.
"""
import asyncio
import json
import sys

import aiohttp
import feedparser

from viginote.sa_sources import rss_sources

UA = "Mozilla/5.0 (compatible; VigiNoteZA/1.0; +https://viginote.com)"


async def check(session, src):
    out = {"name": src["name"], "url": src["url"], "ok": False, "items": 0, "status": None, "error": ""}
    try:
        async with session.get(src["url"], headers={"User-Agent": UA},
                               timeout=aiohttp.ClientTimeout(total=25)) as r:
            out["status"] = r.status
            body = await r.read()
        parsed = feedparser.parse(body)
        out["items"] = len(parsed.entries)
        out["ok"] = out["status"] == 200 and out["items"] > 0
        if not out["ok"] and not out["error"]:
            out["error"] = "no items" if out["status"] == 200 else f"HTTP {out['status']}"
    except Exception as e:  # noqa: BLE001
        out["error"] = str(e)[:120]
    return out


async def main():
    srcs = rss_sources()
    async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False, limit=20)) as s:
        results = await asyncio.gather(*[check(s, x) for x in srcs])
    if "--json" in sys.argv:
        print(json.dumps(results, indent=2))
        return
    ok = [r for r in results if r["ok"]]
    print(f"{len(ok)}/{len(results)} feeds working\n")
    for r in sorted(results, key=lambda r: r["ok"]):
        mark = "OK  " if r["ok"] else "FAIL"
        print(f"{mark} {r['items']:>3} items  {r['name']:<42} {r['error']}")


if __name__ == "__main__":
    asyncio.run(main())
