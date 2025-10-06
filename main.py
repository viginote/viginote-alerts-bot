# src/main.py  (you can keep it at repo root too; if you do, update Render start command accordingly)

import os, re, time, sqlite3, json, traceback
from datetime import datetime, timezone, timedelta
from urllib.parse import urlparse
import requests
import feedparser
from bs4 import BeautifulSoup
import trafilatura
import tldextract
from rapidfuzz import fuzz

# ------------- ENV / CONFIG -------------

UA = os.getenv("USER_AGENT", "VigiNoteAlertsBot/1.0 (+https://viginote.com)")

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID   = os.getenv("TELEGRAM_CHAT_ID", "")
assert TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID, "Set TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID"

REGIONS      = [s.strip().upper() for s in os.getenv("REGIONS", "GLOBAL,MIDDLE_EAST,EUROPE,ASIA,WEST_EAST_AFRICA,SOUTHERN_AFRICA,SOUTH_AMERICA").split(",") if s.strip()]
CUSTOM_FEEDS = [u.strip() for u in os.getenv("CUSTOM_FEEDS", "").split(",") if u.strip()]

POLL_LIMIT         = int(os.getenv("POLL_LIMIT", "25"))
MAX_ALERTS_PER_RUN = int(os.getenv("MAX_ALERTS_PER_RUN", "6"))
MAX_ALERTS_PER_DAY = int(os.getenv("MAX_ALERTS_PER_DAY", "18"))
MIN_GAP_SECONDS    = int(os.getenv("MIN_GAP_SECONDS", "90"))
QUIET_SPEC         = os.getenv("QUIET_HOURS_UTC", "")  # e.g. "22-06" -> mute between 22:00..06:59 UTC
MIN_PER_REGION     = int(os.getenv("MIN_PER_REGION", "1"))
MAX_PER_CLUSTER    = int(os.getenv("MAX_PER_CLUSTER", "2"))
SIM_THRESHOLD      = int(os.getenv("SIM_THRESHOLD", "86"))      # title similarity (RapidFuzz ratio)
SEVERITY_THRESHOLD = int(os.getenv("SEVERITY_THRESHOLD", "5"))  # how serious a story must be (3-8)
DB_PATH            = os.getenv("DB_PATH", "/data/osint.db")
DEBUG              = os.getenv("DEBUG", "0") == "1"

# ------------- TELEGRAM -------------

def send_tg(text: str) -> bool:
    try:
        r = requests.post(
            f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage",
            data={
                "chat_id": TELEGRAM_CHAT_ID,
                "text": text,
                "disable_web_page_preview": True,
                "parse_mode": "HTML",
            },
            timeout=20,
        )
        ok = r.json().get("ok", False)
        if not ok:
            print("[TG ERROR]", r.json())
        return ok
    except Exception as e:
        print("[TG EXC]", e)
        return False

def debug_tg(msg: str):
    if DEBUG:
        try:
            send_tg(f"🛠 {msg}")
        except Exception as e:
            print("[DEBUG_TG EXC]", e)

# ------------- DB / DEDUPE -------------

def db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True) if "/" in DB_PATH else None
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("CREATE TABLE IF NOT EXISTS sent_log (url TEXT PRIMARY KEY, ts INTEGER, title TEXT)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_sent_ts ON sent_log(ts)")
    conn.commit()
    return conn

def today_utc_bounds():
    now = datetime.now(timezone.utc)
    start = datetime(now.year, now.month, now.day, tzinfo=timezone.utc)
    end = start + timedelta(days=1)
    return int(start.timestamp()), int(end.timestamp())

def daily_count(conn) -> int:
    s, e = today_utc_bounds()
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM sent_log WHERE ts >= ? AND ts < ?", (s, e))
    return int(cur.fetchone()[0])

def insert_sent(conn, url, title):
    cur = conn.cursor()
    cur.execute("INSERT OR IGNORE INTO sent_log(url, ts, title) VALUES (?,?,?)", (url, int(time.time()), title))
    conn.commit()

def recent_titles(conn, days=3):
    cutoff = int((datetime.now(timezone.utc) - timedelta(days=days)).timestamp())
    cur = conn.cursor()
    cur.execute("SELECT title FROM sent_log WHERE ts >= ? ORDER BY ts DESC LIMIT 500", (cutoff,))
    return [r[0] for r in cur.fetchall()]

# ------------- QUIET HOURS -------------

def in_quiet_hours(spec: str) -> bool:
    """ spec like '22-06' (UTC). """
    if not spec or "-" not in spec:
        return False
    try:
        start_h, end_h = spec.split("-")
        start_h, end_h = int(start_h), int(end_h)
        now_h = datetime.now(timezone.utc).hour
        if start_h <= end_h:
            return start_h <= now_h < end_h
        else:
            return now_h >= start_h or now_h < end_h
    except:
        return False

# ------------- FEED SOURCES -------------

FEEDS = {
    "GLOBAL": [
        "https://feeds.reuters.com/reuters/worldNews",
        "https://www.aljazeera.com/xml/rss/all.xml",
        "https://rss.dw.com/rdf/rss-en-world",
        "https://www.bbc.co.uk/news/world/rss.xml",
        "https://apnews.com/hub/apf-topnews?utm_source=apnews.com&utm_medium=referral&utm_campaign=rss"
    ],
    "MIDDLE_EAST": [
        "https://english.alarabiya.net/.mrss",
        "https://www.jpost.com/Rss/RssFeedsHeadlines.aspx",
        "https://www.al-monitor.com/rss.xml",
        "https://www.arabnews.com/rss.xml"
    ],
    "EUROPE": [
        "https://www.euronews.com/rss?level=theme&name=news",
        "https://www.bbc.co.uk/news/world/europe/rss.xml",
        "https://www.reuters.com/world/europe/rss"
    ],
    "ASIA": [
        "https://www.reuters.com/world/asia-pacific/rss",
        "https://www.straitstimes.com/news/world/rss.xml",
        "https://www.thehindu.com/news/international/feeder/default.rss"
    ],
    "WEST_EAST_AFRICA": [
        "https://www.theeastafrican.co.ke/feeds/rss/2754392-2754392-ydbrdf/index.xml",
        "https://www.reuters.com/world/africa/rss",
        "https://www.aljazeera.com/xml/rss/all.xml?region=africa"
    ],
    "SOUTHERN_AFRICA": [
        "https://www.news24.com/news24/southafrica/rss",
        "https://ewn.co.za/RSS",
        "https://www.defenceweb.co.za/feed/"
    ],
    "SOUTH_AMERICA": [
        "https://www.reuters.com/world/americas/rss",
        "https://www.bbc.co.uk/news/world/latin_america/rss.xml",
        "https://www.aljazeera.com/xml/rss/all.xml?region=latin-america"
    ],
}

def build_feeds():
    feeds = []
    for region in REGIONS:
        urls = FEEDS.get(region, [])
        if urls:
            feeds.append((region, urls))
    if CUSTOM_FEEDS:
        feeds.append(("CUSTOM", CUSTOM_FEEDS))
    return feeds

# ------------- EXTRACTION / SCORING -------------

KEYWEIGHTS = {
    # conflict / kinetic
    r"\b(air ?strike|strike|shelling|artillery|missile|rocket|drone|uav|uav|explosion|blast|bomb|suicide attack)\b": 3,
    r"\b(assassination|ambush|clash|firefight|shooting|mass shooting|attack|raid)\b": 3,
    r"\b(ceasefire|truce|hostage|kidnap|abduction)\b": 2,
    r"\b(military|troops|brigade|battalion|militia|rebels|insurgents|terrorists?)\b": 1,
    # instability / political risk
    r"\b(coup|martial law|state of emergency|sanctions?|unrest|protests?|riots?)\b": 3,
    r"\b(blockade|border closure|evacuation|curfew)\b": 2,
    # disasters / HADR
    r"\b(earthquake|aftershock|tsunami|cyclone|hurricane|typhoon|tornado|floods?|wildfire|landslide|eruption|volcano)\b": 3,
    r"\b(famine|cholera|outbreak|epidemic|pandemic|disease)\b": 2,
    # severity cues
    r"\b(killed|dead|deaths|fatalities|casualties|wounded|injured)\b": 2,
    r"\b(massive|major|deadly|severe|devastating|worst)\b": 1,
}

def extract_text(link: str, user_agent: str) -> str:
    try:
        dl = trafilatura.fetch_url(link, no_ssl=True, timeout=20)
        if dl:
            txt = trafilatura.extract(dl, include_comments=False, include_tables=False)
            if txt and len(txt) > 200:
                return txt
    except Exception:
        pass
    try:
        r = requests.get(link, headers={"User-Agent": user_agent}, timeout=20)
        soup = BeautifulSoup(r.text, "html.parser")
        for s in soup(["script", "style", "noscript"]):
            s.extract()
        return " ".join(soup.get_text(separator=" ").split())[:4000]
    except Exception:
        return ""

def domain_of(link: str) -> str:
    try:
        t = tldextract.extract(link)
        return ".".join(p for p in [t.domain, t.suffix] if p)
    except Exception:
        return urlparse(link).netloc

def severity_score(title: str, text: str) -> int:
    s = 0
    blob = f"{title}\n{text}".lower()
    for pat, weight in KEYWEIGHTS.items():
        if re.search(pat, blob):
            s += weight
    # simple numeric cues
    if re.search(r"\b(\d{2,}|dozens|scores|hundreds|thousands)\b", blob):
        s += 1
    return s

def looks_duplicate(title: str, recent: list, threshold: int) -> bool:
    for t in recent:
        if fuzz.token_set_ratio(title, t) >= threshold:
            return True
    return False

# ------------- MAIN POLLER -------------

def run_once():
    if in_quiet_hours(QUIET_SPEC):
        print("⏸ quiet hours")
        debug_tg("Quiet hours—skipping this cycle.")
        return

    feeds = build_feeds()
    conn = db()
    total_today = daily_count(conn)
    sent_run = 0
    per_region_sent = {r: 0 for r, _ in feeds}

    feeds_polled = 0
    entries_seen = 0
    entries_scored = 0
    entries_passed = 0

    print(f"Polling {len(feeds)} feeds | caps: run={MAX_ALERTS_PER_RUN}/day={MAX_ALERTS_PER_DAY} | threshold={SEVERITY_THRESHOLD}")
    debug_tg(f"Polling {len(feeds)} feeds @ threshold {SEVERITY_THRESHOLD}")

    recent = recent_titles(conn, days=3)

    for region, urls in feeds:
        if sent_run >= MAX_ALERTS_PER_RUN:
            break
        for feed_url in urls:
            if sent_run >= MAX_ALERTS_PER_RUN:
                break
            try:
                parsed = feedparser.parse(feed_url, request_headers={"User-Agent": UA})
                feeds_polled += 1
            except Exception as e:
                print("[FEED ERR]", feed_url, "->", e)
                continue

            entries = parsed.entries[:POLL_LIMIT]
            entries_seen += len(entries)

            for e in entries:
                if sent_run >= MAX_ALERTS_PER_RUN:
                    break

                title = (e.get("title") or "").strip()
                link  = (e.get("link")  or "").strip()
                if not title or not link:
                    continue

                # region minimums: try to keep at least MIN_PER_REGION items per region
                if MIN_PER_REGION > 0 and per_region_sent.get(region, 0) < MIN_PER_REGION and total_today >= MAX_ALERTS_PER_DAY:
                    # if we've reached daily cap, skip region min enforcement
                    pass

                # extract text & score
                text = extract_text(link, UA) or (e.get("summary") or "")
                entries_scored += 1
                score = severity_score(title, text)
                if score < SEVERITY_THRESHOLD:
                    continue
                entries_passed += 1

                # dedupe / cluster control
                if looks_duplicate(title, recent, SIM_THRESHOLD):
                    # count near-duplicate cluster limit
                    dupes = sum(1 for t in recent if fuzz.token_set_ratio(title, t) >= SIM_THRESHOLD)
                    if dupes >= MAX_PER_CLUSTER:
                        # skip extra repeats of same story
                        continue

                # daily cap
                if total_today >= MAX_ALERTS_PER_DAY:
                    break

                # per-region sanity
                if MIN_PER_REGION > 0 and sum(per_region_sent.values()) < MIN_PER_REGION * len(per_region_sent):
                    # keep sending balanced
                    if per_region_sent.get(region, 0) >= MIN_PER_REGION:
                        # already satisfied region min—allow but no special logic
                        pass

                # Compose TG message
                dom = domain_of(link)
                msg = (
                    f"<b>{title}</b>\n"
                    f"<i>Region:</i> {region.replace('_', ' ').title()}  •  <i>Source:</i> {dom}\n\n"
                    f"{text[:450].rstrip()}…\n\n"
                    f"🔗 <a href=\"{link}\">Full report</a>"
                )

                if send_tg(msg):
                    insert_sent(conn, link, title)
                    sent_run += 1
                    total_today += 1
                    per_region_sent[region] = per_region_sent.get(region, 0) + 1
                    recent.insert(0, title)  # update dedupe memory
                    print(f"+ sent: {region} | {title[:80]}")
                    if MIN_GAP_SECONDS:
                        time.sleep(MIN_GAP_SECONDS)
                else:
                    print("- send failed:", title[:80])

    print(f"Run done. Sent {sent_run} this run; {total_today}/{MAX_ALERTS_PER_DAY} today @ {datetime.now(timezone.utc).isoformat()}")
    debug_tg(f"Heartbeat: polled {feeds_polled} feeds, saw {entries_seen} items, scored {entries_scored}, "
             f"passed {entries_passed}, sent {sent_run}.")

# ------------- ENTRYPOINT -------------

if __name__ == "__main__":
    try:
        if DEBUG:
            send_tg("🟢 VigiNoteAlerts connected. Starting poller…")
    except Exception as e:
        print("[STARTUP PING ERROR]", e)

    interval = int(os.getenv("POLL_INTERVAL", "0"))
    if interval > 0:
        while True:
            try:
                run_once()
            except Exception as e:
                print("FATAL RUN ERROR:", e)
                traceback.print_exc()
            time.sleep(interval)
    else:
        run_once()
