"""
feeds.py — Feed registry, URL utilities, and article fetching.
"""

import os
import re
from urllib.parse import urlparse

import requests
import tldextract
from bs4 import BeautifulSoup
import trafilatura

UA = os.getenv("USER_AGENT", "VigiNoteAlertsBot/1.2 (+https://viginote.com)")

# ── Feed registry ─────────────────────────────────────────────────────────────
# 10-15 sources per region. Wire services (Reuters/AP/BBC) capped at 1 slot each.
# Rest are regional, local, specialist, and investigative outlets.

FEEDS: dict[str, list[str]] = {
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


def domain_of(url: str) -> str:
    try:
        t = tldextract.extract(url)
        return ".".join(p for p in [t.domain, t.suffix] if p)
    except Exception:
        return urlparse(url).netloc


def fetch_article_text(link: str) -> str:
    """Two-stage extraction: trafilatura first, BeautifulSoup fallback."""
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
        for s in soup(["script", "style", "noscript"]):
            s.extract()
        return " ".join(soup.get_text(separator=" ").split())[:4000]
    except Exception:
        return ""


def first_sentence(text: str, max_chars: int = 120) -> str:
    if not text:
        return ""
    parts = re.split(r"(?<=[\.\!\?])\s+", text.strip())
    lead = parts[0] if parts else text
    lead = re.sub(r"^\s*(REUTERS|AP|AFP)\s*[-–—:]\s*", "", lead, flags=re.I)
    lead = re.sub(r"\s+", " ", lead).strip()
    return (lead[:max_chars] + "…") if len(lead) > max_chars else lead
