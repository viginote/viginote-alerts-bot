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
from geotext import GeoText

# =======================
# ENV / CONFIG
# =======================
UA = os.getenv("USER_AGENT", "VigiNoteAlertsBot/1.2 (+https://viginote.com)")

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID   = os.getenv("TELEGRAM_CHAT_ID", "")
if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
    raise SystemExit("ERROR: Set TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID env vars before starting.")

REGIONS      = [s.strip().upper() for s in os.getenv("REGIONS","GLOBAL,MIDDLE_EAST,EUROPE,ASIA,WEST_EAST_AFRICA,SOUTHERN_AFRICA,SOUTH_AMERICA").split(",") if s.strip()]
CUSTOM_FEEDS = [u.strip() for u in os.getenv("CUSTOM_FEEDS","").split(",") if u.strip()]

POLL_LIMIT         = int(os.getenv("POLL_LIMIT","25"))
MAX_ALERTS_PER_RUN = int(os.getenv("MAX_ALERTS_PER_RUN","3"))
MAX_ALERTS_PER_DAY = int(os.getenv("MAX_ALERTS_PER_DAY","18"))
MIN_GAP_SECONDS    = int(os.getenv("MIN_GAP_SECONDS","90"))
QUIET_SPEC         = os.getenv("QUIET_HOURS_UTC","")
MIN_PER_REGION     = int(os.getenv("MIN_PER_REGION","1"))
MAX_PER_CLUSTER    = int(os.getenv("MAX_PER_CLUSTER","2"))
SIM_THRESHOLD      = int(os.getenv("SIM_THRESHOLD","86"))
SEVERITY_THRESHOLD = int(os.getenv("SEVERITY_THRESHOLD","5"))
CRITICAL_THRESHOLD = int(os.getenv("CRITICAL_THRESHOLD","8"))
NONCRIT_COOLDOWN   = int(os.getenv("NONCRITICAL_COOLDOWN_SECONDS","1500"))
MAX_PER_SOURCE_RUN = int(os.getenv("MAX_PER_SOURCE_RUN","1"))
FEED_SHUFFLE       = os.getenv("FEED_SHUFFLE","1") == "1"

DB_PATH  = os.getenv("DB_PATH","/data/osint_alerts.db")
DEBUG    = os.getenv("DEBUG","0") == "1"

AI_ENABLED       = os.getenv("AI_ENABLED","1") == "1"
OPENAI_API_KEY   = os.getenv("OPENAI_API_KEY","")
OPENAI_MODEL     = os.getenv("OPENAI_MODEL","gpt-4o-mini")
AI_TIMEOUT       = int(os.getenv("AI_TIMEOUT","12"))
AI_MAX_TOKENS    = int(os.getenv("AI_MAX_TOKENS","60"))
PRECIS_MAX_CHARS = int(os.getenv("PRECIS_MAX_CHARS","120"))

DEDUPE_DAYS = int(os.getenv("DEDUPE_DAYS","3"))

# Webhook endpoint — if set, each sent alert is POSTed as JSON
WEBHOOK_URL = os.getenv("WEBHOOK_URL","")   # e.g. http://localhost:8000/ingest

# =======================
# SOURCE TIERS
# Tier 1 = wire / major international  -> no bonus
# Tier 2 = regional / national outlet  -> +1
# Tier 3 = local / specialist / indie  -> +2
# =======================
SOURCE_TIER_BONUS = {
    "acleddata.com":2,"addisstandard.com":2,"africareport.com":2,
    "alertnet.org":2,"armenpress.am":2,"azatutyun.am":2,
    "balkaninsight.com":2,"bellingcat.com":2,"birn.eu.com":2,
    "colombiareports.com":2,"crisisgroup.org":2,"dailytrust.com":2,
    "defensenews.com":2,"duvarenglish.com":2,"ekathimerini.com":2,
    "garoweonline.com":2,"globalvoices.org":2,"hurriyetdailynews.com":2,
    "insightcrime.org":2,"irrawaddy.com":2,"iswresearch.org":2,
    "kavkaz-uzel.eu":2,"kyivindependent.com":2,"kurdistan24.net":2,
    "lorientlejour.com":2,"lestimesline.co.ls":2,"lusakatimes.com":2,
    "madamasr.com":2,"malawi24.com":2,"mediazimbabwe.com":2,
    "mercopress.com":2,"militarytimes.com":2,"monitor.co.ug":2,
    "nacla.org":2,"newframe.com":2,"newsday.co.zw":2,
    "newzimbabwe.com":2,"occrp.org":2,"oilprice.com":2,
    "palestinechronicle.com":2,"punchng.com":2,"rudaw.net":2,
    "shabelle.net":2,"standardmedia.co.ke":2,"sudantribune.com":2,
    "syriahr.com":2,"thecitizen.co.tz":2,"theeastafrican.co.ke":2,
    "theinsider.ua":2,"thenewhumanitarian.org":2,"thenewsminute.com":2,
    "thesomalipost.com":2,"tolonews.com":2,"ukraineworld.org":2,
    "vanguardngr.com":2,"venezuelanalysis.com":2,"haitiantimes.com":2,
    "washingtonpost.com":2,"yemenmonitor.com":2,"zimeye.net":2,
    "clubofmozambique.com":2,"mmegi.bw":2,
    "alarabiya.net":1,"aljazeera.com":1,"dhakatribune.com":1,
    "dawn.com":1,"euobserver.com":1,"ewn.co.za":1,"geo.tv":1,
    "haaretz.com":1,"infobae.com":1,"jpost.com":1,"japantimes.co.jp":1,
    "middleeasteye.net":1,"nation.africa":1,"news24.com":1,
    "rferl.org":1,"rfa.org":1,"rnz.co.nz":1,"scmp.com":1,
    "straitstimes.com":1,"dailymaverick.co.za":1,"timesofisrael.com":1,
    "timesofindia.indiatimes.com":1,"timeslive.co.za":1,"bangkokpost.com":1,
}

# =======================
# FEEDS
# =======================
FEEDS = {
    "GLOBAL": [
        "https://feeds.reuters.com/reuters/worldNews",
        "https://apnews.com/hub/world-news?output=rss",
        "https://reliefweb.int/updates/rss.xml",
        "https://www.thenewhumanitarian.org/rss.xml",
        "https://crisisgroup.org/rss",
        "https://www.bellingcat.com/feed/",
        "https://www.occrp.org/en/rss",
        "https://rss.dw.com/rdf/rss-en-world",
        "https://foreignpolicy.com/feed/",
        "https://acleddata.com/feed/",
        "https://www.iswresearch.org/feeds/posts/default",
        "https://oilprice.com/rss/main",
        "https://globalvoices.org/feed/",
    ],
    "MIDDLE_EAST": [
        "https://www.reuters.com/world/middle-east/rss",
        "https://www.timesofisrael.com/feed/",
        "https://www.jpost.com/Rss/RssFeedsHeadlines.aspx",
        "https://www.haaretz.com/rss",
        "https://english.alarabiya.net/.mrss",
        "https://www.aljazeera.com/xml/rss/all.xml",
        "https://www.middleeasteye.net/rss",
        "https://www.rudaw.net/rss/middleeast",
        "https://www.kurdistan24.net/en/rss",
        "https://www.lorientlejour.com/rss/news.rss",
        "https://www.syriahr.com/en/feed/",
        "https://www.yemenmonitor.com/feed",
        "https://palestinechronicle.com/feed/",
        "https://www.hurriyetdailynews.com/rss",
        "https://www.duvarenglish.com/feed",
    ],
    "EUROPE": [
        "https://www.reuters.com/world/europe/rss",
        "https://kyivindependent.com/feed/",
        "https://ukraineworld.org/feed",
        "https://theinsider.com.ua/rss",
        "https://balkaninsight.com/feed/",
        "https://birn.eu.com/feed/",
        "https://www.azatutyun.am/api/z-pqiyet",
        "https://kavkaz-uzel.eu/rss",
        "https://armenpress.am/eng/rss/news/",
        "https://www.ekathimerini.com/rss",
        "https://euobserver.com/feed",
        "https://www.defensenews.com/rss/",
        "https://www.militarytimes.com/rss/",
        "https://www.rferl.org/api/zpiqmeoivi",
    ],
    "ASIA": [
        "https://www.reuters.com/world/asia-pacific/rss",
        "https://www.scmp.com/rss/91/feed",
        "https://www.japantimes.co.jp/feed/",
        "https://www.straitstimes.com/news/asia/rss.xml",
        "https://www.bangkokpost.com/rss/data/topstories.xml",
        "https://timesofindia.indiatimes.com/rssfeeds/-2128936835.cms",
        "https://www.dawn.com/feeds/home",
        "https://www.geo.tv/rss",
        "https://www.dhakatribune.com/feed",
        "https://www.thenewsminute.com/feed",
        "https://www.irrawaddy.com/feed",
        "https://www.rnz.co.nz/rss/pacific.xml",
        "https://www.rfa.org/english/rss2.xml",
        "https://tolonews.com/rss",
    ],
    "WEST_EAST_AFRICA": [
        "https://www.reuters.com/world/africa/rss",
        "https://www.theeastafrican.co.ke/feeds/rss",
        "https://www.nation.africa/kenya/rssfeed",
        "https://www.standardmedia.co.ke/rss/all",
        "https://www.monitor.co.ug/rss",
        "https://www.thecitizen.co.tz/feed/",
        "https://addisstandard.com/feed/",
        "https://www.garoweonline.com/en/rss",
        "https://www.shabelle.net/feed/",
        "https://www.thesomalipost.com/feed/",
        "https://punchng.com/feed/",
        "https://www.vanguardngr.com/feed/",
        "https://dailytrust.com/feed/",
        "https://sudantribune.com/spip.php?page=backend",
        "https://reliefweb.int/updates/rss.xml?search=class_type%3A12%20OR%20class_type%3A13%20AND%20PC-107",
        "https://www.theafricareport.com/feed/",
    ],
    "SOUTHERN_AFRICA": [
        "https://www.reuters.com/world/africa/rss",
        "https://www.news24.com/rss?sectionId=1032",
        "https://ewn.co.za/RSS",
        "https://www.timeslive.co.za/rss/",
        "https://www.dailymaverick.co.za/section/news/feed/",
        "https://newframe.com/feed/",
        "https://www.newzimbabwe.com/feed/",
        "https://www.mediazimbabwe.com/feed/",
        "https://zimeye.net/feed/",
        "https://www.newsday.co.zw/feed/",
        "https://www.lusakatimes.com/feed/",
        "https://malawi24.com/feed/",
        "https://www.clubofmozambique.com/feed/",
        "https://www.mmegi.bw/rss.php",
    ],
    "SOUTH_AMERICA": [
        "https://www.reuters.com/world/americas/rss",
        "https://en.mercopress.com/rss",
        "https://nacla.org/rss.xml",
        "https://www.infobae.com/america/rss/",
        "https://www.batimes.com.ar/feed",
        "https://venezuelanalysis.com/feed",
        "https://www.colombiareports.com/feed/",
        "https://insightcrime.org/feed/",
        "https://agenciabrasil.ebc.com.br/rss/ultimasnoticias/feed.xml",
        "https://www.elsalvadortimes.com/feed/",
        "https://insightcrime.org/tag/mexico/feed/",
        "https://haitiantimes.com/feed/",
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
    cur.execute("""CREATE TABLE IF NOT EXISTS sent_log (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        url         TEXT UNIQUE,
        ts          INTEGER,
        ts_iso      TEXT,
        title       TEXT,
        title_hash  TEXT,
        region      TEXT,
        source_dom  TEXT,
        source_tier INTEGER,
        score       INTEGER,
        is_critical INTEGER,
        precis      TEXT,
        entities    TEXT,
        article_text TEXT,
        selection_reason TEXT,
        feed_url    TEXT
    )""")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_sent_ts   ON sent_log(ts)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_title_hash ON sent_log(title_hash)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_region    ON sent_log(region)")
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
    return int(start.timestamp()), int((start + timedelta(days=1)).timestamp())

def daily_count(conn):
    s, e = today_bounds()
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM sent_log WHERE ts>=? AND ts<?", (s,e))
    return int(cur.fetchone()[0] or 0)

def insert_sent(conn, alert: dict):
    cur = conn.cursor()
    cur.execute("""INSERT OR IGNORE INTO sent_log
        (url, ts, ts_iso, title, title_hash, region, source_dom, source_tier,
         score, is_critical, precis, entities, article_text, selection_reason, feed_url)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""", (
        alert["url"],
        alert["ts"],
        alert["ts_iso"],
        alert["title"],
        alert["title_hash"],
        alert["region"],
        alert["source_dom"],
        alert["source_tier"],
        alert["score"],
        1 if alert["is_critical"] else 0,
        alert["precis"],
        json.dumps(alert["entities"]),
        alert.get("article_text","")[:2000],
        alert["selection_reason"],
        alert["feed_url"],
    ))
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

def source_tier_bonus(url: str) -> int:
    dom = domain_of(url)
    for fragment, bonus in SOURCE_TIER_BONUS.items():
        if fragment in dom:
            return bonus
    return 0

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

def normalize_title(raw: str) -> str:
    if not raw: return ""
    t = raw.strip()
    if " | " in t: t = t.split(" | ")[0]
    return re.sub(r"\s+", " ", t).strip().lower()

def title_hash(raw: str) -> str:
    return hashlib.sha1(normalize_title(raw).encode("utf-8")).hexdigest()

# =======================
# NAMED ENTITY RECOGNITION
# Gazetteer-augmented regex NER — no model download required.
# Extracts: locations (geo + regex), organizations, and persons.
# =======================

# Org-type suffixes that hint a capitalised phrase is an organisation
_ORG_SUFFIXES = re.compile(
    r"\b(Forces|Ministry|Command|Brigade|Battalion|Regiment|Army|Navy|Air Force|"
    r"Police|Agency|Committee|Council|Union|Party|Group|Front|Movement|Coalition|"
    r"Alliance|Government|Parliament|Senate|Congress|Court|Bank|Fund|Commission|"
    r"Authority|Office|Bureau|Department|Directorate|Service|Corps|Guard|"
    r"Militia|Rebels|Insurgents|Junta|Administration|Cabinet|Presidency|"
    r"Intelligence|Security|Task Force|Headquarters|HQ)\b", re.I
)

# Person-name patterns: "Firstname Lastname" where both words are capitalised
# and neither is a known org/location word
_KNOWN_NON_PERSON = re.compile(
    r"^(The|A|An|This|That|These|Those|Its|Their|His|Her|Our|Your|"
    r"Monday|Tuesday|Wednesday|Thursday|Friday|Saturday|Sunday|"
    r"January|February|March|April|May|June|July|August|September|"
    r"October|November|December|North|South|East|West|Central|"
    r"New|Old|Greater|Upper|Lower|Port|Lake|Mount|Al|Abu|Um)$", re.I
)

def extract_entities(title: str, text: str) -> dict:
    """
    Returns dict with keys: locations, organizations, persons.
    Each value is a sorted deduplicated list of strings.
    """
    combined = f"{title}. {text[:3000]}"

    entities = {"locations": set(), "organizations": set(), "persons": set()}

    # 1) Geographic entities via GeoText (bundled gazetteer)
    try:
        geo = GeoText(combined)
        entities["locations"].update(geo.cities)
        entities["locations"].update(geo.countries)
    except Exception:
        pass

    # 2) Capitalised multi-word phrases
    caps_phrases = re.findall(r'\b([A-Z][a-z]{1,20}(?:\s+[A-Z][a-z]{1,20}){0,3})\b', combined)

    for phrase in caps_phrases:
        words = phrase.split()

        # Skip single common words that aren't proper nouns
        if len(words) == 1 and _KNOWN_NON_PERSON.match(words[0]):
            continue

        if _ORG_SUFFIXES.search(phrase):
            entities["organizations"].add(phrase)
            continue

        # Two-word phrases where neither word is a stop: likely person
        if len(words) == 2:
            if not any(_KNOWN_NON_PERSON.match(w) for w in words):
                # Avoid adding pure location phrases already caught by geo
                if phrase not in entities["locations"]:
                    entities["persons"].add(phrase)
            continue

        # 3+ word caps phrases not caught above: treat as org or location
        if len(words) >= 3:
            entities["organizations"].add(phrase)

    # 3) Explicit actor patterns from text
    actor_patterns = [
        (r'\b(ISIS|ISIL|IS|Al[- ]Qaeda|Al[- ]Shabaab|Boko Haram|Hamas|Hezbollah|'
         r'Houthis?|Taliban|Wagner|PMC Wagner|IDF|SAF|RSF|IRGC|PKK|YPG|SDF|'
         r'FARC|ELN|MS-13|Zetas|Sinaloa Cartel|JNIM|ISWAP|ADF|LRA)\b', "organizations"),
        (r'\b(UN|NATO|EU|ECOWAS|SADC|AU|IGAD|OSCE|ICC|ICJ|IMF|World Bank|'
         r'WHO|UNICEF|WFP|UNHCR|MSF|ICRC|Human Rights Watch|Amnesty International)\b', "organizations"),
    ]
    for pat, etype in actor_patterns:
        for m in re.finditer(pat, combined, re.I):
            entities[etype].add(m.group(0))

    return {k: sorted(v) for k, v in entities.items() if v}

# =======================
# SCORING
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
BLACKLIST = re.compile(
    r"\b(football|soccer|cricket|tennis|celebrity|music|movie|gaming|esports|"
    r"box office|fashion|gossip|opinion|review|lifestyle|travel|food|recipes?)\b", re.I
)
AFRICA_BONUS_PATTERNS = [
    (r"\b(coup|junta|putsch|martial law|state of emergency)\b", 2),
    (r"\b(unrest|riots?|looting|clashes?|curfew)\b", 2),
    (r"\b(cholera|measles|ebola|famine|drought|water shortage|outbreak)\b", 2),
    (r"\b(cyclone|floods?|landslide|wildfire|earthquake)\b", 2),
    (r"\b(cartel|gang|bandit|kidnap|abduction|extortion)\b", 2),
    (r"\b(border closure|evacuation|IDPs?|refugees?)\b", 1),
]

def severity_score(title: str, text: str, region: str, feed_url: str = "") -> int:
    T = f"{title}\n{text}".lower()
    if BLACKLIST.search(T): return 0
    score = 0
    for pat, w in BASE_WEIGHTS:
        if re.search(pat, T, flags=re.I): score += w
    if re.search(r"\b(\d{2,}|dozens|scores|hundreds|thousands)\b", T): score += 1
    if region in ("WEST_EAST_AFRICA","SOUTHERN_AFRICA"):
        for pat, bonus in AFRICA_BONUS_PATTERNS:
            if re.search(pat, T, flags=re.I): score += bonus
    score += source_tier_bonus(feed_url)
    return score

def build_selection_reason(score: int, tier: int, region: str, is_critical: bool, ranked_position: int) -> str:
    tier_labels = {0: "wire/international", 1: "regional outlet", 2: "local/specialist"}
    parts = [
        f"score={score}",
        f"tier={tier_labels.get(tier,'unknown')}",
        f"region={region}",
        f"rank=#{ranked_position+1}",
    ]
    if is_critical:
        parts.append("CRITICAL")
    return ", ".join(parts)

# =======================
# AI SUMMARY
# =======================
def concise_summary(title: str, text: str) -> str:
    if not text:
        t = title.strip()
        return (t[:PRECIS_MAX_CHARS] + "…") if len(t) > PRECIS_MAX_CHARS else t
    fallback = first_sentence(text, max_chars=PRECIS_MAX_CHARS)
    if not (AI_ENABLED and OPENAI_API_KEY): return fallback
    prompt = (
        f"Summarize the event in ONE line (<= {PRECIS_MAX_CHARS} characters). "
        f"Plain factual wording. No extra details, no emojis.\n\n"
        f"Title: {title}\n\nText: {text[:2400]}"
    )
    try:
        resp = requests.post(
            "https://api.openai.com/v1/chat/completions",
            headers={"Authorization": f"Bearer {OPENAI_API_KEY}", "Content-Type":"application/json"},
            json={"model":OPENAI_MODEL,"messages":[{"role":"user","content":prompt}],
                  "max_tokens":AI_MAX_TOKENS,"temperature":0.2},
            timeout=AI_TIMEOUT,
        )
        j = resp.json()
        if not j.get("choices"): return fallback
        out = re.sub(r"\s+"," ",j["choices"][0]["message"]["content"].strip())
        return (out[:PRECIS_MAX_CHARS]+"…") if len(out)>PRECIS_MAX_CHARS else out
    except Exception as e:
        print("[AI SUMMARY ERROR]",e); return fallback

# =======================
# TELEGRAM
# =======================
def send_tg(text: str) -> bool:
    try:
        r = requests.post(
            f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage",
            data={"chat_id":TELEGRAM_CHAT_ID,"text":text,"parse_mode":"HTML","disable_web_page_preview":True},
            timeout=20
        )
        ok = r.json().get("ok",False)
        if not ok: print("[TG ERROR]", r.json())
        return ok
    except Exception as e:
        print("[TG EXC]",e); return False

def debug_tg(msg: str):
    if DEBUG:
        try: send_tg(f"🛠 {msg}")
        except Exception as e: print("[DEBUG_TG EXC]",e)

# =======================
# WEBHOOK
# =======================
def push_webhook(alert: dict):
    """POST the alert JSON to WEBHOOK_URL if configured. Non-blocking on failure."""
    if not WEBHOOK_URL:
        return
    try:
        payload = {k:v for k,v in alert.items() if k != "article_text"}  # keep payload lean
        requests.post(WEBHOOK_URL, json=payload, timeout=8)
    except Exception as e:
        print("[WEBHOOK ERR]", e)

# =======================
# CORE
# =======================
def build_feeds():
    feeds = []
    for region in REGIONS:
        urls = FEEDS.get(region,[])
        if urls: feeds.append((region,urls))
    if CUSTOM_FEEDS:
        feeds.append(("CUSTOM",CUSTOM_FEEDS))
    if FEED_SHUFFLE:
        random.seed(int(time.time())//60)
        random.shuffle(feeds)
    return feeds

def looks_duplicate(title: str, recent: list, threshold: int) -> bool:
    return any(fuzz.token_set_ratio(title,t) >= threshold for t in recent)

def collect_candidates(feeds, conn, recent, seen_hash_this_run):
    candidates = []
    per_source_collected = defaultdict(int)
    candidate_titles = []

    for region, urls in feeds:
        for feed_url in urls:
            try:
                parsed = feedparser.parse(feed_url, request_headers={"User-Agent":UA})
            except Exception as e:
                print("[FEED ERR]", feed_url, "->", e); continue

            for e in parsed.entries[:POLL_LIMIT]:
                raw_title = (e.get("title") or "").strip()
                link      = (e.get("link")  or "").strip()
                if not raw_title or not link: continue

                h = title_hash(raw_title)
                if h in seen_hash_this_run: continue
                if seen_title_hash(conn, h, days=DEDUPE_DAYS): continue

                if looks_duplicate(raw_title, recent, SIM_THRESHOLD):
                    if sum(1 for t in recent if fuzz.token_set_ratio(raw_title,t)>=SIM_THRESHOLD) >= MAX_PER_CLUSTER:
                        continue

                if looks_duplicate(raw_title, candidate_titles, SIM_THRESHOLD): continue

                dom = domain_of(link)
                if per_source_collected[dom] >= MAX_PER_SOURCE_RUN: continue

                text  = fetch_article_text(link) or (e.get("summary") or "")
                score = severity_score(raw_title, text, region, feed_url)
                if score < SEVERITY_THRESHOLD: continue

                tier = source_tier_bonus(feed_url)
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

def rank_candidates(candidates):
    candidates.sort(key=lambda c: c["score"], reverse=True)
    seen_regions, first_pass, second_pass = [], [], []
    for c in candidates:
        if c["region"] not in seen_regions:
            first_pass.append(c); seen_regions.append(c["region"])
        else:
            second_pass.append(c)
    return first_pass + second_pass

def run_once():
    if in_quiet_hours(QUIET_SPEC):
        print("⏸ quiet hours"); debug_tg("Quiet hours—skipping."); return

    feeds = build_feeds()
    conn  = db()
    total_today = daily_count(conn)
    sent_run = 0
    per_region_sent = defaultdict(int)
    seen_hash_this_run = set()

    last_nc = kv_get(conn, "last_noncritical_ts","0")
    last_noncrit_ts = int(last_nc) if str(last_nc).isdigit() else 0

    total_feeds = sum(len(u) for _,u in feeds)
    print(f"Polling {total_feeds} feeds across {len(feeds)} regions "
          f"| caps: run={MAX_ALERTS_PER_RUN}/day={MAX_ALERTS_PER_DAY} "
          f"| thr={SEVERITY_THRESHOLD} crit={CRITICAL_THRESHOLD}")

    recent = recent_titles(conn, days=DEDUPE_DAYS)

    # Phase 1: collect
    candidates = collect_candidates(feeds, conn, recent, seen_hash_this_run)
    print(f"  -> {len(candidates)} candidates above threshold")

    # Phase 2: rank
    ranked = rank_candidates(candidates)

    # Phase 3: send top 1-3
    for position, c in enumerate(ranked):
        if sent_run >= MAX_ALERTS_PER_RUN or total_today >= MAX_ALERTS_PER_DAY:
            break

        is_critical = c["is_critical"]
        now_ts = int(time.time())
        if not is_critical and (now_ts - last_noncrit_ts) < NONCRIT_COOLDOWN:
            continue

        if MIN_PER_REGION > 0:
            need = {r for r,_ in feeds if per_region_sent[r] < MIN_PER_REGION}
            if need and c["region"] not in need and sent_run < len(need):
                continue

        # --- Enrich ---
        precis   = concise_summary(c["raw_title"], c["text"])
        entities = extract_entities(c["raw_title"], c["text"])
        sel_reason = build_selection_reason(c["score"], c["tier"], c["region"], is_critical, position)

        ts_now  = int(time.time())
        ts_iso  = datetime.now(timezone.utc).isoformat()

        # --- Build full alert record ---
        alert = {
            "url":              c["link"],
            "ts":               ts_now,
            "ts_iso":           ts_iso,
            "title":            c["raw_title"],
            "title_hash":       c["h"],
            "region":           c["region"],
            "source_dom":       c["dom"],
            "source_tier":      c["tier"],
            "score":            c["score"],
            "is_critical":      is_critical,
            "precis":           precis,
            "entities":         entities,
            "article_text":     c["text"],
            "selection_reason": sel_reason,
            "feed_url":         c["feed_url"],
        }

        # --- Telegram message ---
        ico        = severity_icon(c["score"])
        region_tag = c["region"].replace("_"," ").title()
        if c["tier"] == 2:
            src_label = f"{html_escape(c['dom'])} 🔍"
        elif c["tier"] == 1:
            src_label = f"{html_escape(c['dom'])} 📡"
        else:
            src_label = html_escape(c["dom"])

        # Entity summary line for Telegram
        entity_parts = []
        if entities.get("locations"):
            entity_parts.append("📍 " + ", ".join(entities["locations"][:4]))
        if entities.get("organizations"):
            entity_parts.append("🏛 " + ", ".join(entities["organizations"][:3]))
        if entities.get("persons"):
            entity_parts.append("👤 " + ", ".join(entities["persons"][:3]))
        entity_line = "\n" + "  ".join(entity_parts) if entity_parts else ""

        msg = (
            f"{ico} <b>[{html_escape(region_tag)}] {html_escape(c['raw_title'])}</b>\n"
            f"<code>{html_escape(precis)}</code>{entity_line}\n"
            f"• Source: {src_label}  |  Score: {c['score']}\n"
            f"• <i>{html_escape(sel_reason)}</i>\n\n"
            f"🔗 <a href=\"{html_escape(c['link'])}\">Full report</a>"
        )

        if send_tg(msg):
            insert_sent(conn, alert)
            push_webhook(alert)
            recent.insert(0, c["raw_title"])
            seen_hash_this_run.add(c["h"])
            per_region_sent[c["region"]] += 1
            sent_run += 1
            total_today += 1
            print(f"+ sent [{c['region']}] {c['raw_title'][:80]} (score={c['score']}, src={c['dom']})")
            print(f"  entities: {entities}")

            if not is_critical:
                last_noncrit_ts = now_ts
                kv_set(conn, "last_noncritical_ts", last_noncrit_ts)
            if MIN_GAP_SECONDS and not is_critical:
                time.sleep(MIN_GAP_SECONDS)
        else:
            print("- send failed:", c["raw_title"][:90])

    print(f"Run done. Sent {sent_run} this run; {total_today}/{MAX_ALERTS_PER_DAY} today "
          f"@ {datetime.now(timezone.utc).isoformat()}")
    if DEBUG:
        debug_tg(f"Heartbeat: sent {sent_run}, today {total_today}/{MAX_ALERTS_PER_DAY}.")

# =======================
# ENTRYPOINT
# =======================
if __name__ == "__main__":
    interval = int(os.getenv("POLL_INTERVAL","900"))
    if interval > 0:
        while True:
            try: run_once()
            except Exception as e:
                print("FATAL RUN ERROR:", e); traceback.print_exc()
            time.sleep(interval)
    else:
        run_once()
