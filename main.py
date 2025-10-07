import os, re, time, sqlite3, traceback, random, html, json, hashlib
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from urllib.parse import urlparse

import requests
import feedparser
from bs4 import BeautifulSoup
import trafilatura
import tldextract
from rapidfuzz import fuzz

# =======================
# ENV / CONFIG
# =======================
UA = os.getenv("USER_AGENT", "VigiNoteAlertsBot/1.2 (+https://viginote.com)")

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID   = os.getenv("TELEGRAM_CHAT_ID", "")
assert TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID, "Set TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID"

REGIONS      = [s.strip().upper() for s in os.getenv("REGIONS","GLOBAL,MIDDLE_EAST,EUROPE,ASIA,WEST_EAST_AFRICA,SOUTHERN_AFRICA,SOUTH_AMERICA").split(",") if s.strip()]
CUSTOM_FEEDS = [u.strip() for u in os.getenv("CUSTOM_FEEDS","").split(",") if u.strip()]

POLL_LIMIT         = int(os.getenv("POLL_LIMIT","25"))
MAX_ALERTS_PER_RUN = int(os.getenv("MAX_ALERTS_PER_RUN","6"))
MAX_ALERTS_PER_DAY = int(os.getenv("MAX_ALERTS_PER_DAY","18"))
MIN_GAP_SECONDS    = int(os.getenv("MIN_GAP_SECONDS","90"))
QUIET_SPEC         = os.getenv("QUIET_HOURS_UTC","")        # e.g. "22-06"
MIN_PER_REGION     = int(os.getenv("MIN_PER_REGION","1"))
MAX_PER_CLUSTER    = int(os.getenv("MAX_PER_CLUSTER","2"))
SIM_THRESHOLD      = int(os.getenv("SIM_THRESHOLD","86"))   # dedupe similarity
SEVERITY_THRESHOLD = int(os.getenv("SEVERITY_THRESHOLD","6"))
CRITICAL_THRESHOLD = int(os.getenv("CRITICAL_THRESHOLD","8"))  # fast-track
NONCRIT_COOLDOWN   = int(os.getenv("NONCRITICAL_COOLDOWN_SECONDS","1500"))  # ~25 min
MAX_PER_SOURCE_RUN = int(os.getenv("MAX_PER_SOURCE_RUN","2"))
FEED_SHUFFLE       = os.getenv("FEED_SHUFFLE","1") == "1"

DB_PATH            = os.getenv("DB_PATH","/data/osint_alerts.db")
DEBUG              = os.getenv("DEBUG","0") == "1"

# AI (optional) – but always concise
AI_ENABLED       = os.getenv("AI_ENABLED","1") == "1"
OPENAI_API_KEY   = os.getenv("OPENAI_API_KEY","")
OPENAI_MODEL     = os.getenv("OPENAI_MODEL","gpt-4o-mini")
AI_TIMEOUT       = int(os.getenv("AI_TIMEOUT","12"))
AI_MAX_TOKENS    = int(os.getenv("AI_MAX_TOKENS","60"))    # small & cheap
PRECIS_MAX_CHARS = int(os.getenv("PRÉCIS_MAX_CHARS","120"))

# Stronger cross-run dedupe via normalized title hash
DEDUPE_DAYS = int(os.getenv("DEDUPE_DAYS","3"))

# =======================
# FEEDS (diversified)
# =======================
FEEDS = {
    "GLOBAL": [
        "https://feeds.reuters.com/reuters/worldNews",
        "https://www.bbc.co.uk/news/world/rss.xml",
        "https://apnews.com/hub/world-news?output=rss",
        "https://reliefweb.int/updates/rss.xml",
        "https://rss.dw.com/rdf/rss-en-world",
    ],
    "MIDDLE_EAST": [
        "https://www.timesofisrael.com/feed/",
        "https://www.jpost.com/Rss/RssFeedsHeadlines.aspx",
        "https://www.israelnationalnews.com/Rss/",
        "https://www.reuters.com/world/middle-east/rss",
        "https://english.alarabiya.net/.mrss",
        # "https://www.aljazeera.com/xml/rss/middleeast.xml",
    ],
    "EUROPE": [
        "https://www.reuters.com/world/europe/rss",
        "https://www.bbc.co.uk/news/world/europe/rss.xml",
        "https://www.dw.com/feeds/rss",
        "https://euobserver.com/feed",
        "https://apnews.com/hub/europe?output=rss",
    ],
    "ASIA": [
        "https://www.reuters.com/world/asia-pacific/rss",
        "https://www.scmp.com/rss/91/feed",
        "https://www.japantimes.co.jp/feed/",
        "https://www.straitstimes.com/news/asia/rss.xml",
        "https://timesofindia.indiatimes.com/rssfeeds/-2128936835.cms",
    ],
    "WEST_EAST_AFRICA": [
        "https://www.bbc.co.uk/news/world/africa/rss.xml",
        "https://www.theeastafrican.co.ke/feeds/rss",
        "https://www.nation.africa/kenya/rssfeed",
        "https://www.reuters.com/world/africa/rss",
        "https://reliefweb.int/updates/rss.xml?search=class_type%3A12%20OR%20class_type%3A13%20AND%20PC-107",
        "https://punchng.com/feed/",
        "https://www.vanguardngr.com/feed/",
        "https://dailytrust.com/feed/",
        "https://addisstandard.com/feed/",
        "https://www.garoweonline.com/en/rss",
    ],
    "SOUTHERN_AFRICA": [
        "https://www.news24.com/rss?sectionId=1032",
        "https://ewn.co.za/RSS",
        "https://www.dailymaverick.co.za/section/news/feed/",
        "https://www.timeslive.co.za/rss/",
        "https://www.reuters.com/world/africa/rss",
    ],
    "SOUTH_AMERICA": [
        "https://www.reuters.com/world/americas/rss",
        "https://www.bbc.co.uk/news/world/latin_america/rss.xml",
        "https://www.infobae.com/america/rss/",
        "https://en.mercopress.com/rss",
        "https://reliefweb.int/updates/rss.xml?search=class_type%3A12%20OR%20class_type%3A13%20AND%20PC-13",
    ],
}

# =======================
# DB & QUOTAS
# =======================
def db():
    try:
        parent = os.path.dirname(DB_PATH)
        if parent and not os.path.exists(parent):
            os.makedirs(parent, exist_ok=True)
    except Exception:
        pass
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("CREATE TABLE IF NOT EXISTS sent_log (url TEXT PRIMARY KEY, ts INTEGER, title TEXT, title_hash TEXT, is_critical INTEGER)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_sent_ts ON sent_log(ts)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_title_hash ON sent_log(title_hash)")
    cur.execute("CREATE TABLE IF NOT EXISTS kv (k TEXT PRIMARY KEY, v TEXT)")
    conn.commit()
    return conn

def kv_get(conn, key, default=None):
    cur = conn.cursor()
    cur.execute("SELECT v FROM kv WHERE k=?", (key,))
    r = cur.fetchone()
    return r[0] if r else default

def kv_set(conn, key, val):
    cur = conn.cursor()
    cur.execute("INSERT OR REPLACE INTO kv (k,v) VALUES (?,?)", (key, str(val)))
    conn.commit()

def today_bounds():
    now = datetime.now(timezone.utc)
    start = datetime(now.year, now.month, now.day, tzinfo=timezone.utc)
    end   = start + timedelta(days=1)
    return int(start.timestamp()), int(end.timestamp())

def daily_count(conn):
    s, e = today_bounds()
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM sent_log WHERE ts>=? AND ts<?", (s,e))
    return int(cur.fetchone()[0] or 0)

def insert_sent(conn, url, title, title_hash, is_critical):
    cur = conn.cursor()
    cur.execute("INSERT OR IGNORE INTO sent_log(url, ts, title, title_hash, is_critical) VALUES (?,?,?,?,?)",
                (url, int(time.time()), title, title_hash, 1 if is_critical else 0))
    conn.commit()

def recent_titles(conn, days=3):
    cutoff = int((datetime.now(timezone.utc) - timedelta(days=days)).timestamp())
    cur = conn.cursor()
    cur.execute("SELECT title FROM sent_log WHERE ts>=? ORDER BY ts DESC LIMIT 500", (cutoff,))
    return [r[0] for r in cur.fetchall()]

def seen_title_hash(conn, title_hash, days=3):
    cutoff = int((datetime.now(timezone.utc) - timedelta(days=days)).timestamp())
    cur = conn.cursor()
    cur.execute("SELECT 1 FROM sent_log WHERE title_hash=? AND ts>=? LIMIT 1", (title_hash, cutoff))
    return cur.fetchone() is not None

# =======================
# UTILITIES
# =======================
def html_escape(s: str) -> str:
    return html.escape(s or "", quote=True)

def in_quiet_hours(spec: str) -> bool:
    if not spec or "-" not in spec: return False
    try:
        s,e = [int(x) for x in spec.split("-")]
        h = datetime.now(timezone.utc).hour
        return (s <= h < e) if s<=e else (h>=s or h<e)
    except Exception:
        return False

def domain_of(url: str) -> str:
    try:
        t = tldextract.extract(url)
        return ".".join(p for p in [t.domain, t.suffix] if p)
    except Exception:
        return urlparse(url).netloc

def fetch_article_text(link: str) -> str:
    try:
        dl = trafilatura.fetch_url(link, no_ssl=True, timeout=20)
        if dl:
            txt = trafilatura.extract(dl, include_comments=False, include_tables=False)
            if txt and len(txt) > 200:
                return txt
    except Exception:
        pass
    try:
        r = requests.get(link, headers={"User-Agent": UA}, timeout=20)
        soup = BeautifulSoup(r.text, "html.parser")
        for s in soup(["script","style","noscript"]): s.extract()
        return " ".join(soup.get_text(separator=" ").split())[:4000]
    except Exception:
        return ""

def first_sentence(text: str, max_chars=120) -> str:
    if not text: return ""
    parts = re.split(r"(?<=[\.\!\?])\s+", text.strip())
    lead = parts[0] if parts else text
    lead = re.sub(r"^\s*(REUTERS|AP|AFP)\s*[-–—:]\s*", "", lead, flags=re.I)
    lead = re.sub(r"\s+", " ", lead).strip()
    return (lead[:max_chars] + "…") if len(lead) > max_chars else lead

def severity_icon(score: int) -> str:
    if score >= 9: return "🛑"
    if score >= 7: return "🔴"
    if score >= 5: return "🟠"
    return "🟡"

# --- Normalize title to avoid source tails like " | SCMP.com"
def normalize_title(raw: str) -> str:
    if not raw: return ""
    t = raw.strip()
    # Drop everything after a pipe (common source delimiter)
    if " | " in t:
        t = t.split(" | ")[0]
    # squeeze spaces & lowercase
    t = re.sub(r"\s+", " ", t).strip().lower()
    return t

def title_hash(raw: str) -> str:
    norm = normalize_title(raw)
    return hashlib.sha1(norm.encode("utf-8")).hexdigest()

# =======================
# SCORING (with Africa boosts)
# =======================
BASE_WEIGHTS = [
    (r"\b(air ?strike|strike|shelling|artillery|missile|rocket|drone|uav|explosion|blast|bomb)\b", 3),
    (r"\b(assassination|ambush|clash|firefight|shooting|mass shooting|attack|raid)\b", 3),
    (r"\b(ceasefire|truce|hostage|kidnap|abduction)\b", 2),
    (r"\b(military|troops|brigade|battalion|militia|rebels|insurgents|terrorists?)\b", 1),
    (r"\b(coup|martial law|state of emergency|sanctions?|unrest|protests?|riots?)\b", 3),
    (r"\b(blockade|border closure|evacuation|curfew)\b", 2),
    (r"\b(earthquake|aftershock|tsunami|cyclone|hurricane|typhoon|tornado|floods?|wildfire|landslide|eruption|volcano)\b", 3),
    (r"\b(famine|cholera|measles|outbreak|epidemic|pandemic|disease)\b", 2),
    (r"\b(killed|dead|deaths|fatalities|casualties|wounded|injured)\b", 2),
    (r"\b(massive|major|deadly|severe|devastating|worst)\b", 1),
]
BLACKLIST = re.compile(r"\b(football|soccer|cricket|tennis|celebrity|music|movie|gaming|esports|box office|fashion|gossip|opinion|review)\b", re.I)

AFRICA_BONUS_PATTERNS = [
    (r"\b(coup|junta|putsch|martial law|state of emergency)\b", 2),
    (r"\b(unrest|riots?|looting|clashes?|curfew)\b", 2),
    (r"\b(cholera|measles|ebola|famine|drought|water shortage|outbreak)\b", 2),
    (r"\b(cyclone|floods?|landslide|wildfire|earthquake)\b", 2),
    (r"\b(cartel|gang|bandit|kidnap|abduction|extortion)\b", 2),
    (r"\b(border closure|evacuation|IDPs?|refugees?)\b", 1),
]

def severity_score(title: str, text: str, region: str) -> int:
    T = f"{title}\n{text}".lower()
    if BLACKLIST.search(T): return 0
    score = 0
    for pat, w in BASE_WEIGHTS:
        if re.search(pat, T, flags=re.I):
            score += w
    if re.search(r"\b(\d{2,}|dozens|scores|hundreds|thousands)\b", T):
        score += 1
    if region in ("WEST_EAST_AFRICA", "SOUTHERN_AFRICA"):
        for pat, bonus in AFRICA_BONUS_PATTERNS:
            if re.search(pat, T, flags=re.I):
                score += bonus
    return score

# =======================
# AI SUMMARY (always concise)
# =======================
def concise_summary(title: str, text: str) -> str:
    """
    Returns a single concise line <= PRECIS_MAX_CHARS.
    Uses OpenAI if key provided; else heuristic fallback.
    """
    if not text:
        t = title.strip()
        return (t[:PRECIS_MAX_CHARS] + "…") if len(t) > PRECIS_MAX_CHARS else t

    # Fallback (no API / failure): first sentence clipped
    fallback = first_sentence(text, max_chars=PRECIS_MAX_CHARS)

    if not (AI_ENABLED and OPENAI_API_KEY):
        return fallback

    prompt = (
        f"Summarize the event in ONE line (<= {PRECIS_MAX_CHARS} characters). "
        f"Plain factual wording. No extra details, no emojis.\n\n"
        f"Title: {title}\n\nText: {text[:2400]}"
    )

    try:
        resp = requests.post(
            "https://api.openai.com/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {OPENAI_API_KEY}",
                "Content-Type": "application/json",
            },
            json={
                "model": OPENAI_MODEL,
                "messages": [{"role": "user", "content": prompt}],
                "max_tokens": AI_MAX_TOKENS,
                "temperature": 0.2,
            },
            timeout=AI_TIMEOUT,
        )
        j = resp.json()
        if not j.get("choices"):
            return fallback
        out = j["choices"][0]["message"]["content"].strip()
        # hard cap (belt & suspenders)
        out = re.sub(r"\s+", " ", out)
        return (out[:PRECIS_MAX_CHARS] + "…") if len(out) > PRECIS_MAX_CHARS else out
    except Exception as e:
        print("[AI SUMMARY ERROR]", e)
        return fallback

# =======================
# TELEGRAM
# =======================
def send_tg(text: str) -> bool:
    try:
        r = requests.post(
            f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage",
            data={"chat_id": TELEGRAM_CHAT_ID, "text": text, "parse_mode":"HTML", "disable_web_page_preview": True},
            timeout=20
        )
        ok = r.json().get("ok", False)
        if not ok: print("[TG ERROR]", r.json())
        return ok
    except Exception as e:
        print("[TG EXC]", e)
        return False

def debug_tg(msg: str):
    if DEBUG:
        try: send_tg(f"🛠 {msg}")
        except Exception as e: print("[DEBUG_TG EXC]", e)

# =======================
# CORE
# =======================
def build_feeds():
    feeds = []
    for region in REGIONS:
        urls = FEEDS.get(region, [])
        if urls: feeds.append((region, urls))
    if CUSTOM_FEEDS:
        feeds.append(("CUSTOM", CUSTOM_FEEDS))
    if FEED_SHUFFLE:
        random.seed(int(time.time()) // 60)
        random.shuffle(feeds)
    return feeds

def looks_duplicate(title: str, recent: list, threshold: int) -> bool:
    for t in recent:
        if fuzz.token_set_ratio(title, t) >= threshold:
            return True
    return False

def run_once():
    if in_quiet_hours(QUIET_SPEC):
        print("⏸ quiet hours"); debug_tg("Quiet hours—skipping."); return

    feeds = build_feeds()
    conn = db()
    total_today = daily_count(conn)
    sent_run = 0
    per_region_sent = defaultdict(int)
    per_source_sent = defaultdict(int)
    seen_hash_this_run = set()

    last_nc = kv_get(conn, "last_noncritical_ts", "0")
    last_noncrit_ts = int(last_nc) if str(last_nc).isdigit() else 0

    print(f"Polling {len(feeds)} feeds | caps: run={MAX_ALERTS_PER_RUN}/day={MAX_ALERTS_PER_DAY} | thr={SEVERITY_THRESHOLD} crit={CRITICAL_THRESHOLD} nc_cooldown={NONCRIT_COOLDOWN}s")
    recent = recent_titles(conn, days=DEDUPE_DAYS)

    for region, urls in feeds:
        if sent_run >= MAX_ALERTS_PER_RUN or total_today >= MAX_ALERTS_PER_DAY:
            break
        for feed_url in urls:
            if sent_run >= MAX_ALERTS_PER_RUN or total_today >= MAX_ALERTS_PER_DAY:
                break
            try:
                parsed = feedparser.parse(feed_url, request_headers={"User-Agent": UA})
            except Exception as e:
                print("[FEED ERR]", feed_url, "->", e)
                continue

            entries = parsed.entries[:POLL_LIMIT]

            for e in entries:
                if sent_run >= MAX_ALERTS_PER_RUN or total_today >= MAX_ALERTS_PER_DAY:
                    break

                raw_title = (e.get("title") or "").strip()
                link      = (e.get("link")  or "").strip()
                if not raw_title or not link:
                    continue

                # 1) exact link dedupe via DB primary key (insert later)
                # 2) normalized title hash dedupe across DEDUPE_DAYS
                h = title_hash(raw_title)
                if h in seen_hash_this_run:
                    continue
                if seen_title_hash(conn, h, days=DEDUPE_DAYS):
                    continue

                # Similarity-based cluster dedupe
                if looks_duplicate(raw_title, recent, SIM_THRESHOLD):
                    dupes = sum(1 for t in recent if fuzz.token_set_ratio(raw_title, t) >= SIM_THRESHOLD)
                    if dupes >= MAX_PER_CLUSTER:
                        continue

                text = fetch_article_text(link) or (e.get("summary") or "")
                score = severity_score(raw_title, text, region)
                if score < SEVERITY_THRESHOLD:
                    continue

                dom = domain_of(link)
                if per_source_sent[dom] >= MAX_PER_SOURCE_RUN:
                    continue

                is_critical = score >= CRITICAL_THRESHOLD
                now_ts = int(time.time())
                if not is_critical and (now_ts - last_noncrit_ts) < NONCRIT_COOLDOWN:
                    continue

                if MIN_PER_REGION > 0:
                    need = {r for r,_ in feeds if per_region_sent[r] < MIN_PER_REGION}
                    if need and region not in need and sent_run < len(need):
                        continue

                ico = severity_icon(score)
                region_tag = region.replace("_"," ").title()

                precis = concise_summary(raw_title, text)

                msg = (
                    f"{ico} <b>[{html_escape(region_tag)}] {html_escape(raw_title)}</b>\n"
                    f"<code>{html_escape(precis)}</code>\n"
                    f"• Source: {html_escape(dom)}\n\n"
                    f"🔗 <a href=\"{html_escape(link)}\">Full report</a>"
                )

                if send_tg(msg):
                    insert_sent(conn, link, raw_title, h, is_critical)
                    recent.insert(0, raw_title)
                    seen_hash_this_run.add(h)
                    per_source_sent[dom] += 1
                    per_region_sent[region] += 1
                    sent_run += 1
                    total_today += 1
                    print(f"+ sent [{region}] {raw_title[:80]} (score={score}, src={dom})")

                    if not is_critical:
                        last_noncrit_ts = now_ts
                        kv_set(conn, "last_noncritical_ts", last_noncrit_ts)

                    if MIN_GAP_SECONDS and not is_critical:
                        time.sleep(MIN_GAP_SECONDS)
                else:
                    print("- send failed:", raw_title[:90])

    print(f"Run done. Sent {sent_run} this run; {total_today}/{MAX_ALERTS_PER_DAY} today @ {datetime.now(timezone.utc).isoformat()}")
    if DEBUG:
        debug_tg(f"Heartbeat: sent {sent_run}, today {total_today}/{MAX_ALERTS_PER_DAY}.")

# =======================
# ENTRYPOINT LOOP
# =======================
if __name__ == "__main__":
    interval = int(os.getenv("POLL_INTERVAL","120"))  # 2 min for quick critical
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
