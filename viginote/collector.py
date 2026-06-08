"""
collector.py — Async feed polling and candidate collection.

Polls all feeds concurrently using asyncio + aiohttp, dramatically
reducing cycle time compared to sequential requests.
"""

import asyncio
import hashlib
import os
import re
import time
from collections import defaultdict

import aiohttp
import feedparser
from rapidfuzz import fuzz

from viginote.feeds import FEEDS, STREAM_FEEDS, domain_of, fetch_article_text, first_sentence
from viginote.country_mapper import detect_country
from viginote.stream_classifier import classify_stream
from viginote.scoring import severity_score, source_tier

UA          = os.getenv("USER_AGENT", "VigiNoteAlertsBot/1.2 (+https://viginote.com)")
POLL_LIMIT  = int(os.getenv("POLL_LIMIT", "25"))
SIM_THRESHOLD      = int(os.getenv("SIM_THRESHOLD", "78"))  # catch same story, allow genuine new developmentsrom multiple sources
SEVERITY_THRESHOLD = int(os.getenv("SEVERITY_THRESHOLD", "5"))
CRITICAL_THRESHOLD = int(os.getenv("CRITICAL_THRESHOLD", "8"))
MAX_PER_SOURCE_RUN = int(os.getenv("MAX_PER_SOURCE_RUN", "1"))
MAX_PER_CLUSTER    = int(os.getenv("MAX_PER_CLUSTER", "1"))  # one alert per story cluster
DEDUPE_DAYS        = int(os.getenv("DEDUPE_DAYS", "4"))  # extended to 4 days

FEED_TIMEOUT = aiohttp.ClientTimeout(total=25)


def normalize_title(raw: str) -> str:
    t = raw.strip()
    if " | " in t:
        t = t.split(" | ")[0]
    return re.sub(r"\s+", " ", t).strip().lower()


def make_title_hash(raw: str) -> str:
    return hashlib.sha1(normalize_title(raw).encode()).hexdigest()


def looks_duplicate(title: str, pool: list[str], threshold: int) -> bool:
    """Check fuzzy title similarity."""
    return any(fuzz.token_set_ratio(title, t) >= threshold for t in pool)


def _key_words(title: str) -> set:
    """Extract meaningful words (4+ chars, not stopwords)."""
    STOP = {'with','that','this','from','have','been','will','were','they',
            'says','said','after','over','into','also','amid','amid','than',
            'more','less','some','news','report','latest','update'}
    words = re.findall(r"[A-Za-z]{4,}", title.lower())
    return {w for w in words if w not in STOP}


def keyword_overlap_duplicate(title: str, pool: list[str], min_overlap: int = 3) -> bool:
    """Block if article shares 3+ key words with a recent title — catches rephrased duplicates."""
    title_keys = _key_words(title)
    if len(title_keys) < 3:
        return False
    for existing in pool:
        overlap = title_keys & _key_words(existing)
        if len(overlap) >= min_overlap:
            return True
    return False


async def _fetch_feed_bytes(session: aiohttp.ClientSession, url: str) -> bytes | None:
    """Fetch RSS feed bytes asynchronously."""
    try:
        async with session.get(url, headers={"User-Agent": UA}, timeout=FEED_TIMEOUT) as resp:
            if resp.status == 200:
                return await resp.read()
    except Exception:
        pass
    return None


async def _poll_all_feeds_async(
    region_url_pairs: list[tuple[str, str]],
    db_conn,
    seen_hash_this_run: set,
    recent_titles: list[str],
) -> tuple[list[dict], dict[str, dict]]:
    """
    Fetch all feeds concurrently.
    Returns (raw_entries_list, feed_health_results).
    raw_entries_list: list of {region, feed_url, raw_title, link, summary}
    feed_health_results: {feed_url: {success, error}}
    """
    from viginote.db import seen_title_hash as _seen_hash, record_feed_attempt

    raw_entries: list[dict] = []
    health_results: dict[str, dict] = {}

    urls_list    = [url for _, url in region_url_pairs]
    regions_list = [r   for r, _ in region_url_pairs]

    connector = aiohttp.TCPConnector(ssl=False, limit=40)
    async with aiohttp.ClientSession(connector=connector) as session:
        fetch_tasks = [
            _fetch_feed_bytes(session, url) for url in urls_list
        ]
        results = await asyncio.gather(*fetch_tasks, return_exceptions=True)

    for i, (result, feed_url, region) in enumerate(zip(results, urls_list, regions_list)):
        if isinstance(result, Exception) or result is None:
            health_results[feed_url] = {"success": False, "error": str(result or "empty response")}
            record_feed_attempt(db_conn, feed_url, region, success=False,
                                error=str(result or "empty"))
            continue

        try:
            parsed = feedparser.parse(result)
            health_results[feed_url] = {"success": True, "error": ""}
            record_feed_attempt(db_conn, feed_url, region, success=True)

            for entry in parsed.entries[:POLL_LIMIT]:
                raw_title = (entry.get("title") or "").strip()
                link      = (entry.get("link")  or "").strip()
                summary   = (entry.get("summary") or "")
                if not raw_title or not link:
                    continue
                raw_entries.append({
                    "region":    region,
                    "feed_url":  feed_url,
                    "raw_title": raw_title,
                    "link":      link,
                    "summary":   summary,
                })
        except Exception as e:
            health_results[feed_url] = {"success": False, "error": str(e)}
            record_feed_attempt(db_conn, feed_url, region, success=False, error=str(e))

    return raw_entries, health_results


def collect_candidates(
    feeds: list[tuple[str, list[str]]],
    db_conn,
    recent: list[str],
    seen_hash_this_run: set,
) -> list[dict]:
    """
    1. Async-fetch all feeds concurrently (fast).
    2. For each entry that passes dedup, fetch article text (sync — trafilatura).
    3. Score and return candidates list.
    """
    from viginote.db import seen_title_hash as _seen_hash

    # Flatten to (region, url) pairs
    region_url_pairs = [
        (region, url)
        for region, urls in feeds
        for url in urls
    ]

    # Run async fetch
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        raw_entries, _ = loop.run_until_complete(
            _poll_all_feeds_async(region_url_pairs, db_conn, seen_hash_this_run, recent)
        )
    finally:
        loop.close()

    # Now process entries — dedup, score, fetch text (sync is fine here, we need text anyway)
    candidates: list[dict] = []
    per_source_collected: dict[str, int] = defaultdict(int)
    candidate_titles: list[str] = []

    for entry in raw_entries:
        raw_title = entry["raw_title"]
        link      = entry["link"]
        region    = entry["region"]
        feed_url  = entry["feed_url"]

        # URL-level dedupe — same link from different feeds
        link_h = hashlib.sha1((link or "").strip().lower().encode()).hexdigest()
        if link_h in seen_hash_this_run:
            continue

        h = make_title_hash(raw_title)
        if h in seen_hash_this_run:
            continue
        if _seen_hash(db_conn, h, days=DEDUPE_DAYS):
            continue

        # Cross-run cluster cap — fuzzy + keyword
        if looks_duplicate(raw_title, recent, SIM_THRESHOLD):
            dupes = sum(1 for t in recent if fuzz.token_set_ratio(raw_title, t) >= SIM_THRESHOLD)
            if dupes >= MAX_PER_CLUSTER:
                continue
        elif keyword_overlap_duplicate(raw_title, recent, min_overlap=5):
            # Same story rephrased — seen in recent DB titles
            continue

        # Within-run duplicate guard — fuzzy title match
        if looks_duplicate(raw_title, candidate_titles, SIM_THRESHOLD):
            continue

        # Within-run keyword overlap guard — catches rephrased same-story duplicates
        if keyword_overlap_duplicate(raw_title, candidate_titles, min_overlap=4):
            continue

        dom = domain_of(link)
        if per_source_collected[dom] >= MAX_PER_SOURCE_RUN:
            continue

        text = fetch_article_text(link) or entry["summary"]
        score = severity_score(raw_title, text, region, feed_url)
        if score < SEVERITY_THRESHOLD:
            continue

        tier = source_tier(dom)
        per_source_collected[dom] += 1
        candidate_titles.append(raw_title)
        candidates.append({
            "region":      region,
            "feed_url":    feed_url,
            "raw_title":   raw_title,
            "link":        link,
            "text":        text,
            "score":       score,
            "dom":         dom,
            "h":           h,
            "is_critical": score >= CRITICAL_THRESHOLD,
            "tier":        tier,
        })

    return candidates


def rank_candidates(candidates: list[dict]) -> list[dict]:
    """Score-descending with region-diversity pass."""
    candidates.sort(key=lambda c: c["score"], reverse=True)
    seen_regions: list[str] = []
    first_pass:   list[dict] = []
    second_pass:  list[dict] = []
    for c in candidates:
        if c["region"] not in seen_regions:
            first_pass.append(c)
            seen_regions.append(c["region"])
        else:
            second_pass.append(c)
    return first_pass + second_pass
