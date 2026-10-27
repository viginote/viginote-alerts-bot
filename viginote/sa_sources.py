"""
sa_sources.py — VigiNote South Africa edition: source registry.

Each source: name, feed URL, category hint, trust tier, and kind.
  tier 3 = official / primary (government, Parliament, SAPS, regulators)
  tier 2 = established newsroom / specialist
  tier 1 = general or aggregated news
  kind   = "rss"  -> polled directly
           "page" -> no RSS known; needs a scraper or manual monitoring (not polled)

IMPORTANT: feed URLs were compiled from public knowledge and have NOT been
verified from the build sandbox (no outbound access to .za sites). Run
`python check_sources.py` from Render (or any machine with internet) to test
every feed; failures are also recorded in the feed_health table at runtime.
Set `verified` to True only after a feed has returned items.

Terms of use: the pipeline stores headline + short summary + link only and
always links back to the original. Do not republish article bodies. Check each
publisher's terms before adding a feed that is commercial or paywalled.
"""
from __future__ import annotations

from urllib.parse import urlparse

# category hints map to topics in sa_topics.py
SA_SOURCES: list[dict] = [
    # ── Official / primary ───────────────────────────────────────────────
    {"name": "SA Government – news", "url": "https://www.gov.za/news/rss.xml", "category": "government", "tier": 3, "kind": "rss"},
    {"name": "SA Government – media statements", "url": "https://www.gov.za/news/media-statements/rss.xml", "category": "government", "tier": 3, "kind": "rss"},
    {"name": "SAnews (govt news agency)", "url": "https://www.sanews.gov.za/rss.xml", "category": "government", "tier": 3, "kind": "rss"},
    {"name": "Parliamentary Monitoring Group", "url": "https://pmg.org.za/rss/", "category": "parliament", "tier": 3, "kind": "rss"},
    {"name": "SAPS media statements", "url": "https://www.saps.gov.za/newsroom/rss.php", "category": "crime", "tier": 3, "kind": "rss"},
    {"name": "SA Reserve Bank", "url": "https://www.resbank.co.za/en/home/rss", "category": "economy", "tier": 3, "kind": "rss"},
    {"name": "Stats SA", "url": "https://www.statssa.gov.za/?feed=rss", "category": "economy", "tier": 3, "kind": "rss"},
    {"name": "National Treasury", "url": "https://www.treasury.gov.za/rss.aspx", "category": "economy", "tier": 3, "kind": "rss"},
    {"name": "SARS media", "url": "https://www.sars.gov.za/feed/", "category": "economy", "tier": 3, "kind": "rss"},
    {"name": "Judiciary of SA – media", "url": "https://www.judiciary.org.za/index.php/media-releases?format=feed&type=rss", "category": "courts", "tier": 3, "kind": "rss"},
    {"name": "NPA media", "url": "https://www.npa.gov.za/media/rss", "category": "courts", "tier": 3, "kind": "rss"},
    {"name": "IPID", "url": "https://www.ipid.gov.za/feed/", "category": "crime", "tier": 3, "kind": "rss"},
    {"name": "Public Protector SA", "url": "https://www.pprotect.org/feed", "category": "corruption", "tier": 3, "kind": "rss"},
    {"name": "Auditor-General SA", "url": "https://www.agsa.co.za/feed/", "category": "corruption", "tier": 3, "kind": "rss"},
    {"name": "NICD (health alerts)", "url": "https://www.nicd.ac.za/feed/", "category": "health", "tier": 3, "kind": "rss"},
    {"name": "SA Weather Service", "url": "https://www.weathersa.co.za/rss", "category": "weather", "tier": 3, "kind": "rss"},
    {"name": "Eskom media", "url": "https://www.eskom.co.za/feed/", "category": "services", "tier": 3, "kind": "rss"},
    {"name": "Transnet", "url": "https://www.transnet.net/feed/", "category": "trade", "tier": 3, "kind": "rss"},
    {"name": "Johannesburg Water", "url": "https://www.johannesburgwater.co.za/feed/", "category": "services", "tier": 3, "kind": "rss"},
    {"name": "City of Cape Town – news", "url": "https://www.capetown.gov.za/feeds/news", "category": "services", "tier": 3, "kind": "rss"},
    {"name": "City of Johannesburg", "url": "https://www.joburg.org.za/feed/", "category": "services", "tier": 3, "kind": "rss"},
    {"name": "City of Tshwane", "url": "https://www.tshwane.gov.za/?feed=rss2", "category": "services", "tier": 3, "kind": "rss"},
    {"name": "eThekwini Municipality", "url": "https://www.durban.gov.za/feed/", "category": "services", "tier": 3, "kind": "rss"},
    {"name": "Gauteng Provincial Govt", "url": "https://www.gauteng.gov.za/rss", "category": "government", "tier": 3, "kind": "rss"},
    {"name": "Western Cape Government", "url": "https://www.westerncape.gov.za/rss/news", "category": "government", "tier": 3, "kind": "rss"},
    # ── Newsrooms ────────────────────────────────────────────────────────
    {"name": "Daily Maverick", "url": "https://www.dailymaverick.co.za/feed/", "category": "general", "tier": 2, "kind": "rss"},
    {"name": "GroundUp", "url": "https://groundup.org.za/feed/", "category": "general", "tier": 2, "kind": "rss"},
    {"name": "amaBhungane", "url": "https://amabhungane.org/feed/", "category": "corruption", "tier": 2, "kind": "rss"},
    {"name": "News24", "url": "https://feeds.news24.com/articles/news24/TopStories/rss", "category": "general", "tier": 2, "kind": "rss"},
    {"name": "News24 – South Africa", "url": "https://feeds.news24.com/articles/news24/SouthAfrica/rss", "category": "general", "tier": 2, "kind": "rss"},
    {"name": "EWN", "url": "https://ewn.co.za/RSS%20Feeds/Latest%20News", "category": "general", "tier": 2, "kind": "rss"},
    {"name": "SABC News", "url": "https://www.sabcnews.com/sabcnews/feed/", "category": "general", "tier": 2, "kind": "rss"},
    {"name": "TimesLIVE", "url": "https://www.timeslive.co.za/rss/", "category": "general", "tier": 2, "kind": "rss"},
    {"name": "Sowetan LIVE", "url": "https://www.sowetanlive.co.za/rss/", "category": "general", "tier": 2, "kind": "rss"},
    {"name": "IOL", "url": "https://www.iol.co.za/rss", "category": "general", "tier": 1, "kind": "rss"},
    {"name": "The Citizen", "url": "https://www.citizen.co.za/feed/", "category": "general", "tier": 1, "kind": "rss"},
    {"name": "Mail & Guardian", "url": "https://mg.co.za/feed/", "category": "general", "tier": 2, "kind": "rss"},
    {"name": "City Press", "url": "https://www.news24.com/citypress/rss", "category": "general", "tier": 1, "kind": "rss"},
    {"name": "Scrolla / Newsroom Afrika", "url": "https://www.newsroom.co.za/feed/", "category": "general", "tier": 1, "kind": "rss"},
    {"name": "Cape Argus / Cape Times (IOL)", "url": "https://www.iol.co.za/capetimes/rss", "category": "general", "tier": 1, "kind": "rss"},
    {"name": "GroundUp – courts", "url": "https://groundup.org.za/rss/courts/", "category": "courts", "tier": 2, "kind": "rss"},
    # ── Business / trade ─────────────────────────────────────────────────
    {"name": "BusinessTech", "url": "https://businesstech.co.za/news/feed/", "category": "economy", "tier": 2, "kind": "rss"},
    {"name": "Moneyweb", "url": "https://www.moneyweb.co.za/feed/", "category": "economy", "tier": 2, "kind": "rss"},
    {"name": "BusinessLIVE", "url": "https://www.businesslive.co.za/rss/", "category": "economy", "tier": 2, "kind": "rss"},
    {"name": "Engineering News", "url": "https://www.engineeringnews.co.za/page/rss", "category": "trade", "tier": 2, "kind": "rss"},
    {"name": "Mining Weekly", "url": "https://www.miningweekly.com/page/rss", "category": "trade", "tier": 2, "kind": "rss"},
    {"name": "Freight News", "url": "https://www.freightnews.co.za/feed", "category": "trade", "tier": 2, "kind": "rss"},
    {"name": "Fin24", "url": "https://feeds.news24.com/articles/fin24/tech/rss", "category": "economy", "tier": 2, "kind": "rss"},
    # ── Services / infrastructure / safety ───────────────────────────────
    {"name": "MyBroadband", "url": "https://mybroadband.co.za/news/feed", "category": "services", "tier": 1, "kind": "rss"},
    {"name": "Arrive Alive (road safety)", "url": "https://www.arrivealive.co.za/rss.aspx", "category": "crime", "tier": 1, "kind": "rss"},
    {"name": "Corruption Watch", "url": "https://www.corruptionwatch.org.za/feed/", "category": "corruption", "tier": 2, "kind": "rss"},
    {"name": "ISS Africa (security analysis)", "url": "https://issafrica.org/rss", "category": "crime", "tier": 2, "kind": "rss"},
    {"name": "Global Initiative – organised crime", "url": "https://globalinitiative.net/feed/", "category": "crime", "tier": 2, "kind": "rss"},
    # ── No known RSS: monitor/scrape later ───────────────────────────────
    {"name": "SAPS crime statistics (quarterly)", "url": "https://www.saps.gov.za/services/crimestats.php", "category": "crime", "tier": 3, "kind": "page"},
    {"name": "Gauteng Water Security dashboard", "url": "https://www.gauteng.gov.za/", "category": "services", "tier": 3, "kind": "page"},
    {"name": "Eskom load-shedding status", "url": "https://loadshedding.eskom.co.za/", "category": "services", "tier": 3, "kind": "page"},
]

for _s in SA_SOURCES:
    _s.setdefault("verified", False)
    _s["domain"] = urlparse(_s["url"]).netloc.lower().removeprefix("www.")


def rss_sources() -> list[dict]:
    return [s for s in SA_SOURCES if s["kind"] == "rss"]


def source_by_url(url: str) -> dict | None:
    for s in SA_SOURCES:
        if s["url"] == url:
            return s
    return None


def source_by_domain(domain: str) -> dict | None:
    domain = (domain or "").lower().removeprefix("www.")
    best = None
    for s in SA_SOURCES:
        d = s["domain"]
        if domain == d or domain.endswith("." + d) or d.endswith("." + domain):
            if best is None or s["tier"] > best["tier"]:
                best = s
    return best
