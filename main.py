import os, time, json, sqlite3, requests, feedparser, trafilatura, re, html
from bs4 import BeautifulSoup
from datetime import datetime, timezone, timedelta
from dotenv import load_dotenv
from rapidfuzz import fuzz
import tldextract

# ---------- Load env ----------
load_dotenv()
UA = os.getenv("USER_AGENT", "VigiNoteAlertsBot/1.0 (+https://viginote.com)")

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN","")
TELEGRAM_CHAT_ID   = os.getenv("TELEGRAM_CHAT_ID","")
assert TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID, "Set TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID"

REGIONS = [s.strip().upper() for s in os.getenv("REGIONS","GLOBAL").split(",") if s.strip()]
CUSTOM_FEEDS = [u.strip() for u in os.getenv("CUSTOM_FEEDS","").split(",") if u.strip()]

POLL_LIMIT         = int(os.getenv("POLL_LIMIT","25"))
MAX_ALERTS_PER_RUN = int(os.getenv("MAX_ALERTS_PER_RUN","6"))
MAX_ALERTS_PER_DAY = int(os.getenv("MAX_ALERTS_PER_DAY","18"))
MIN_GAP_SECONDS    = int(os.getenv("MIN_GAP_SECONDS","90"))
QUIET_SPEC         = os.getenv("QUIET_HOURS_UTC","")
MIN_PER_REGION     = int(os.getenv("MIN_PER_REGION","1"))
MAX_PER_CLUSTER    = int(os.getenv("MAX_PER_CLUSTER","2"))
SIM_THRESHOLD      = int(os.getenv("SIM_THRESHOLD","86"))

OPENAI_API_KEY     = os.getenv("OPENAI_API_KEY","")
OPENAI_MODEL       = os.getenv("OPENAI_MODEL","gpt-4o-mini")

DB_PATH = os.getenv("DB_PATH","./osint.db")

# ---------- Feeds ----------
REGIONAL_FEEDS = {
    "GLOBAL": [
        "https://feeds.bbci.co.uk/news/world/rss.xml",
        "https://www.reutersagency.com/feed/?best-topics=world",
        "https://reliefweb.int/updates/rss.xml",
        "https://www.aljazeera.com/xml/rss/all.xml",
        "https://apnews.com/hub/world-news?output=rss",
    ],
    "MIDDLE_EAST": [
        "https://english.alarabiya.net/.mrss/en/section/middle-east.xml",
        "https://www.aljazeera.com/xml/rss/middleeast.xml",
        "https://www.reutersagency.com/feed/?best-topics=middle-east",
        "https://www.timesofisrael.com/feed/",
        "https://www.jpost.com/Rss/RssFeedsHeadlines.aspx",
    ],
    "EUROPE": [
        "https://www.dw.com/feeds/rss",
        "https://www.reutersagency.com/feed/?best-topics=europe",
        "https://www.theguardian.com/world/europe/rss",
        "https://apnews.com/hub/europe?output=rss",
        "https://euobserver.com/feed",
    ],
    "ASIA": [
        "https://www.reutersagency.com/feed/?best-topics=asia",
        "https://www.scmp.com/rss/91/feed",
        "https://www.japantimes.co.jp/feed/",
        "https://www.straitstimes.com/news/asia/rss.xml",
        "https://timesofindia.indiatimes.com/rssfeeds/296589292.cms",
    ],
    "WEST_EAST_AFRICA": [
        "https://www.bbc.co.uk/news/world/africa/rss.xml",
        "https://allafrica.com/tools/headlines/rdf/africa/headlines.rdf",
        "https://www.theeastafrican.co.ke/feeds/rss",
        "https://www.nation.africa/kenya/rssfeed",
        "https://www.reutersagency.com/feed/?best-topics=africa",
        "https://reliefweb.int/updates/rss.xml?search=class_type%3A12%20OR%20class_type%3A13%20AND%20PC-107",
    ],
    "SOUTHERN_AFRICA": [
        "https://www.news24.com/rss?sectionId=1032",
        "https://www.dailymaverick.co.za/section/news/feed/",
        "https://allafrica.com/tools/headlines/rdf/southafrica/headlines.rdf",
        "https://www.reutersagency.com/feed/?best-topics=africa",
    ],
    "SOUTH_AMERICA": [
        "https://www.reutersagency.com/feed/?best-topics=latam",
        "https://www.bbc.co.uk/news/world/latin_america/rss.xml",
        "https://www.infobae.com/america/rss/",
        "https://www.aporrea.org/rss/rss.php",
        "https://reliefweb.int/updates/rss.xml?search=class_type%3A12%20OR%20class_type%3A13%20AND%20PC-13",
    ],
}

# ---------- Severity (weighted keywords) ----------
WEIGHTS = {
    "airstrike":3, "air strike":3, "missile":3, "rocket":3, "drone":3, "shelling":3, "bomb":3, "explosion":3,
    "suicide bombing":4, "vbied":4, "car bomb":4, "ied":4, "ambush":3, "firefight":3, "clashes":2,
    "militant":2, "insurgent":2, "terror":3, "hostage":4, "kidnapped":4, "assassination":4,
    "mass shooting":4, "casualties":3, "killed":3, "dead":3, "wounded":3,
    "coup":5, "martial law":4, "state of emergency":3, "protest":2, "riots":3, "unrest":3, "crackdown":3, "curfew":2,
    "sanctions":2, "evacuation":3, "border closed":3, "blockade":3,
    "earthquake":4, "flood":3, "landslide":3, "cyclone":4, "hurricane":4, "typhoon":4, "tsunami":5, "wildfire":3,
    "eruption":4, "drought":3, "famine":4,
    "cholera":4, "ebola":5, "measles":3, "outbreak":3, "epidemic":4, "pandemic":4,
    "refugees":3, "displacement":3, "humanitarian crisis":4
}
EXCLUDES = {"football","soccer","cricket","tennis","golf","basketball","match","tournament","entertainment",
            "movie","music","fashion","award","gaming","esports","press release","sponsored"}
SEVERITY_THRESHOLD = 5  # raise to 7 for stricter

# ---------- DB ----------
def db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""CREATE TABLE IF NOT EXISTS seen (url TEXT PRIMARY KEY, ts INTEGER)""")
    conn.execute("""CREATE TABLE IF NOT EXISTS clusters (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title_norm TEXT, first_ts INTEGER
    )""")
    conn.execute("""CREATE TABLE IF NOT EXISTS cluster_hits (
        cluster_id INTEGER, source_domain TEXT, ts INTEGER,
        UNIQUE(cluster_id, source_domain)
    )""")
    conn.execute("""CREATE TABLE IF NOT EXISTS quota (d TEXT PRIMARY KEY, sent INTEGER, last_ts INTEGER)""")
    conn.commit()
    return conn

def today_key(): return datetime.now(timezone.utc).strftime("%Y-%m-%d")
def daily_count(conn):
    row = conn.execute("SELECT sent,last_ts FROM quota WHERE d=?", (today_key(),)).fetchone()
    return (row[0] or 0) if row else 0
def inc_daily(conn, n=1):
    d = today_key(); s = daily_count(conn) + n
    conn.execute("INSERT OR REPLACE INTO quota (d,sent,last_ts) VALUES (?,?,?)", (d, s, int(time.time())))
    conn.commit(); return s

# ---------- Helpers ----------
def severity_score(text: str) -> int:
    t = text.lower()
    if any(x in t for x in EXCLUDES): return 0
    score = 0
    for k,w in WEIGHTS.items():
        if k in t: score += w
    if re.search(r"\b(\d{2,})\s+(killed|dead|wounded|injured|evacuated)\b", t):
        score += 2
    return score

def domain(url):
    ex = tldextract.extract(url)
    return ".".join(p for p in [ex.domain, ex.suffix] if p) or "source"

STOP = set("a an the for of in on at to from with by and or as into after before over under about amid during".split())
def normalize_title(t):
    t = re.sub(r"[\(\)\[\]\-–—:;|,!?\"'`]", " ", t.lower())
    words = [w for w in t.split() if w not in STOP and len(w)>2]
    return " ".join(words)[:200]

def match_cluster(conn, title_norm):
    rows = conn.execute("SELECT id, title_norm, first_ts FROM clusters ORDER BY id DESC LIMIT 500").fetchall()
    best = None; best_score = 0
    for cid, tnorm, _ in rows:
        sc = fuzz.token_set_ratio(title_norm, tnorm)
        if sc > best_score: best_score, best = sc, cid
    return best if best_score >= SIM_THRESHOLD else None

def upsert_cluster(conn, title_norm):
    cid = match_cluster(conn, title_norm)
    if cid: return cid
    cur = conn.cursor()
    cur.execute("INSERT INTO clusters (title_norm, first_ts) VALUES (?,?)", (title_norm, int(time.time())))
    conn.commit()
    return cur.lastrowid

def cluster_can_post(conn, cid, src_domain):
    day_ago = int((datetime.now(timezone.utc) - timedelta(hours=24)).timestamp())
    hits = conn.execute("SELECT source_domain, ts FROM cluster_hits WHERE cluster_id=? AND ts>=?",
                        (cid, day_ago)).fetchall()
    sources = {d for d,_ in hits}
    if len(sources) >= MAX_PER_CLUSTER and src_domain not in sources:
        return False
    return True

def record_cluster_hit(conn, cid, src_domain):
    conn.execute("INSERT OR IGNORE INTO cluster_hits (cluster_id, source_domain, ts) VALUES (?,?,?)",
                 (cid, src_domain, int(time.time())))
    conn.commit()

def in_quiet_hours(spec):
    if not spec: return False
    try:
        s,e = [int(x) for x in spec.split("-")]
        h = datetime.now(timezone.utc).hour
        return (s <= h < e) if s<=e else (h>=s or h<e)
    except Exception: return False

def extract_text(url, timeout=20):
    try:
        dl = trafilatura.fetch_url(url, timeout=timeout, no_ssl=True)
        if dl:
            txt = trafilatura.extract(dl, include_comments=False, include_tables=False)
            if txt and len(txt)>300: return txt
    except Exception: pass
    try:
        html_ = requests.get(url, headers={"User-Agent": UA}, timeout=timeout).text
        soup = BeautifulSoup(html_, "html.parser")
        for s in soup(["script","style","noscript"]): s.extract()
        return " ".join(soup.get_text(separator=" ").split())[:8000]
    except Exception: return ""

# -------- Telegram & formatting --------
def html_escape(s: str) -> str:
    return html.escape(s or "", quote=True)

def make_dek(text: str, max_sent=2, min_len=40) -> str:
    if not text: return "Developing: open link for details."
    parts = [p.strip() for p in re.split(r"(?<=[\.\!\?])\s+", text) if len(p.strip()) >= min_len]
    return " ".join(parts[:max_sent]) if parts else text[:200] + "…"

def bullets_to_html(bullets_text: str) -> str:
    lines = [ln.strip(" •") for ln in (bullets_text or "").split("\n") if ln.strip()]
    if not lines: return "<i>Monitoring: details emerging.</i>"
    return "<br>".join(f"&bull; {html_escape(ln)}" for ln in lines)

def send_tg(text):
    r = requests.post(
        f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage",
        data={
            "chat_id": TELEGRAM_CHAT_ID,
            "text": text,
            "parse_mode": "HTML",
            "disable_web_page_preview": True
        },
        timeout=20
    )
    ok = False
    try:
        ok = r.json().get("ok", False)
        if not ok:
            print("[TG ERROR]", r.json().get("description"))
    except Exception:
        print("[TG HTTP]", r.status_code, r.text[:200])
    return ok

# -------- AI bullets (optional) --------
def extractive_bullets(text, n=3):
    parts = [p.strip() for p in re.split(r"(?<=[\.\!\?])\s+", text) if len(p.strip())>40][:n]
    if not parts: parts = [text[:180]+"..."] if text else ["Update available at source."]
    return "\n".join("• "+p for p in parts)

def ai_bullets(title, link, text):
    if not OPENAI_API_KEY:
        return extractive_bullets(text)
    try:
        payload = {
            "model": OPENAI_MODEL,
            "messages": [{"role":"user","content": f"Summarize for an OSINT alert in 3 crisp bullets. Neutral, specific; include location & impact.\nTITLE: {title}\nLINK: {link}\nTEXT:\n{text[:6000]}"}],
            "temperature": 0.2,
            "max_tokens": 180
        }
        r = requests.post("https://api.openai.com/v1/chat/completions",
                          headers={"Authorization": f"Bearer {OPENAI_API_KEY}", "Content-Type":"application/json"},
                          json=payload, timeout=45)
        if r.status_code != 200: raise RuntimeError(f"OPENAI_{r.status_code}")
        return r.json()["choices"][0]["message"]["content"].strip()
    except Exception as e:
        print("[AI OFF/FALLBACK]", e)
        return extractive_bullets(text)

# -------- Feed builder --------
def build_feeds():
    seen=set(); out=[]
    for r in REGIONS:
        for f in REGIONAL_FEEDS.get(r, []):
            if f not in seen: seen.add(f); out.append((r,f))
    for f in CUSTOM_FEEDS:
        if f not in seen: seen.add(f); out.append(("CUSTOM", f))
    return out

# -------- Main poll --------
def run_once():
    if in_quiet_hours(QUIET_SPEC):
        print("⏸ quiet hours"); return
    feeds = build_feeds()
    conn = db()

    total_sent = daily_count(conn)
    sent_run = 0
    per_region_sent = {r:0 for r,_ in feeds}
    print(f"Polling {len(feeds)} feeds | caps: run={MAX_ALERTS_PER_RUN}/day={MAX_ALERTS_PER_DAY}")

    for region, feed_url in feeds:
        if sent_run >= MAX_ALERTS_PER_RUN or total_sent >= MAX_ALERTS_PER_DAY:
            break
        try:
            parsed = feedparser.parse(feed_url, request_headers={"User-Agent": UA})
            entries = parsed.entries[:POLL_LIMIT]
        except Exception as e:
            print("[FEED ERR]", feed_url, "->", e); continue

        for e in entries:
            if sent_run >= MAX_ALERTS_PER_RUN or total_sent >= MAX_ALERTS_PER_DAY:
                break

            title = (e.get("title") or "").strip()
            link  = e.get("link") or ""
            if not title or not link: continue

            if conn.execute("SELECT 1 FROM seen WHERE url=?", (link,)).fetchone():
                continue

            text = extract_text(link) or (e.get("summary") or "")
            score = severity_score(title + " " + text)
            if score < SEVERITY_THRESHOLD:
                continue

            src = domain(link)
            tnorm = normalize_title(title)
            cid   = upsert_cluster(conn, tnorm)
            if not cluster_can_post(conn, cid, src):
                continue

            if MIN_PER_REGION > 0:
                needed = [r for r in set(r for r,_ in feeds) if per_region_sent.get(r,0) < MIN_PER_REGION]
                if region not in needed and needed and sent_run < len(needed):
                    continue

            dek = make_dek(text, max_sent=2)
            bullets_txt = ai_bullets(title, link, text)
            bullets_html = bullets_to_html(bullets_txt)
            msg = (
                f"🛰️ <b>VigiNote Alert — {html_escape(region.title())}</b><br><br>"
                f"<b>{html_escape(title)}</b><br>"
                f"{html_escape(dek)}<br><br>"
                f"{bullets_html}<br><br>"
                f"🔗 <a href=\"{html_escape(link)}\">Full report</a> — {html_escape(src)}"
            )

            if send_tg(msg):
                conn.execute("INSERT OR IGNORE INTO seen (url, ts) VALUES (?,?)", (link, int(time.time())))
                conn.execute("INSERT OR IGNORE INTO cluster_hits (cluster_id, source_domain, ts) VALUES (?,?,?)",
                             (cid, src, int(time.time())))
                conn.commit()
                sent_run += 1
                total_sent = inc_daily(conn, 1)
                per_region_sent[region] = per_region_sent.get(region,0)+1
                print(f" + sent: {region} | {title[:80]}")
                if MIN_GAP_SECONDS: time.sleep(MIN_GAP_SECONDS)

    print(f"Run done. Sent {sent_run} this run; {total_sent}/{MAX_ALERTS_PER_DAY} today @ {datetime.now(timezone.utc).isoformat()}")
if __name__ == "__main__":
    # If POLL_INTERVAL > 0 (seconds), run forever with a sleep between cycles.
    # If POLL_INTERVAL = 0 or unset, run once and exit (use cron instead).
    interval = int(os.getenv("POLL_INTERVAL", "0"))
    if interval > 0:
        while True:
            try:
                run_once()
            except Exception as e:
                print("FATAL RUN ERROR:", e)
            time.sleep(interval)
    else:
        run_once()

