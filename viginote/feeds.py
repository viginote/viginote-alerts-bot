"""
feeds.py — VigiNote RSS source library
Diverse mix: wire services, regional specialists, independent outlets,
investigative journalists, NGO monitors, local press.
Researched and verified May 2026.
"""
from __future__ import annotations

UA = (
    "Mozilla/5.0 (X11; Linux x86_64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)

# ──────────────────────────────────────────────────────────────────────────────
# FEED LIBRARY
# Mix per region:
#   - International wire backbone (Reuters/BBC/AP/AFP)
#   - Regional specialists and local press
#   - Independent / investigative outlets
#   - NGO monitors (ACLED, ICG, HRW, UN)
#   - Conflict/security focused
# ──────────────────────────────────────────────────────────────────────────────

FEEDS: dict[str, list[str]] = {

    # ── GLOBAL ────────────────────────────────────────────────────────────────
    # Wire + investigative + multilateral institutions
    "GLOBAL": [
        # Wire backbone
        "https://feeds.bbci.co.uk/news/world/rss.xml",
        "https://rss.dw.com/rdf/rss-en-world",
        "https://feeds.skynews.com/feeds/rss/world.xml",
        # Investigative / OSINT
        "https://www.bellingcat.com/feed/",
        "https://www.occrp.org/en/rss",
        "https://theintercept.com/feed/?rss",
        "https://foreignpolicy.com/feed/",
        # Security / conflict monitors
        "https://www.iswresearch.org/feeds/posts/default",
        "https://acleddata.com/feed/",
        "https://www.crisisgroup.org/rss",
        # Humanitarian / UN
        "https://www.thenewhumanitarian.org/rss.xml",
        "https://reliefweb.int/updates/rss.xml",
        "https://news.un.org/feed/subscribe/en/news/region/all/feed.rss",
        # Analysis
        "https://globalvoices.org/feed/",
        "https://www.chathamhouse.org/rss.xml",
        "https://geopoliticalmonitor.com/feed/",
        "https://encyclopediageopolitica.com/feed/",
        "https://polgeonow.com/feeds/posts/default",
        "https://oilprice.com/rss/main",
    ],

    # ── MIDDLE EAST ──────────────────────────────────────────────────────────
    # Israel-Palestine, Syria, Yemen, Iraq, Iran, Turkey, Gulf
    "MIDDLE_EAST": [
        # International backbone
        "https://feeds.bbci.co.uk/news/world/middle_east/rss.xml",
        "https://rss.dw.com/rdf/rss-en-middle-east",
        # Pan-Arab / regional
        "https://www.aljazeera.com/xml/rss/all.xml",
        "https://www.middleeasteye.net/rss",
        "https://english.alarabiya.net/rss.xml",
        "https://www.al-monitor.com/rss",
        # Israel / Palestine
        "https://www.timesofisrael.com/feed/",
        "https://www.haaretz.com/cmlink/1.628765",
        "https://www.jpost.com/Rss/RssFeedsHeadlines.aspx",
        "https://www.i24news.com/i24feed/en/recent",
        "https://palestinechronicle.com/feed/",
        "https://www.middleeastmonitor.com/feed/",
        # Syria
        "https://www.syriahr.com/en/feed/",
        "https://syriastories.net/feed/",
        # Yemen
        "https://www.yemenmonitor.com/feed",
        "https://www.yemeniportal.net/feed",
        # Iraq
        "https://www.iraq-businessnews.com/feed",
        # Iran
        "https://www.iranintl.com/en/rss",
        # Turkey
        "https://www.duvarenglish.com/feed",
        "https://www.hurriyetdailynews.com/rss",
        # Kurdish
        "https://www.rudaw.net/rss/middleeast",
        "https://www.kurdistan24.net/en/rss",
        # Security / conflict
        "https://www.crisisgroup.org/rss",
        "https://english.enabbaladi.net/feed",
    ],

    # ── EUROPE ───────────────────────────────────────────────────────────────
    # Ukraine/Russia, Balkans, Caucasus, EU security, far-right, organised crime
    "EUROPE": [
        # International backbone
        "https://feeds.bbci.co.uk/news/world/europe/rss.xml",
        "https://rss.dw.com/rdf/rss-en-eu",
        "https://www.politico.eu/feed/",
        # Ukraine / Russia — specialist
        "https://kyivindependent.com/feed/",
        "https://www.rferl.org/api/zpiqmeoivi",
        "https://theinsider.com.ua/rss",
        "https://meduza.io/en/rss/all",
        "https://www.euromaidan.press/feed/",
        # Balkans
        "https://balkaninsight.com/feed/",
        "https://birn.eu.com/feed/",
        "https://www.slobodnaevropa.org/api/zprqospuyp",
        # Caucasus
        "https://www.azatutyun.am/api/z-pqiyet",
        "https://armenpress.am/eng/rss/news/",
        "https://jam-news.net/feed/",
        # EU / policy
        "https://euobserver.com/feed",
        "https://www.euractiv.com/feed/",
        "https://www.europarl.europa.eu/rss/doc/press-releases-en.xml",
        # Organised crime / security
        "https://www.occrp.org/en/rss",
        "https://www.investigate-europe.eu/en/feed/",
        # Defence
        "https://www.defensenews.com/arc/outboundfeeds/rss/?outputType=xml",
        "https://www.janes.com/feeds/news",
        # Human rights
        "https://www.hrw.org/rss/news",
    ],

    # ── ASIA ─────────────────────────────────────────────────────────────────
    # China/Taiwan, South/SE Asia, Pacific, Afghanistan, Myanmar, Koreas
    "ASIA": [
        # International backbone
        "https://feeds.bbci.co.uk/news/world/asia/rss.xml",
        "https://rss.dw.com/rdf/rss-en-asia",
        "https://www.channelnewsasia.com/api/v1/rss-outbound-feed?_format=xml",
        # China / Taiwan / HK
        "https://www.scmp.com/rss/91/feed",
        "https://focustaiwan.tw/rss",
        "https://hongkongfp.com/feed/",
        # SE Asia
        "https://www.irrawaddy.com/feed",
        "https://www.bangkokpost.com/rss/data/topstories.xml",
        "https://www.rfa.org/english/rss2.xml",
        "https://www.straitstimes.com/news/asia/rss.xml",
        # South Asia — Pakistan/India/Kashmir
        "https://www.dawn.com/feeds/home",
        "https://www.geo.tv/rss",
        "https://timesofindia.indiatimes.com/rssfeeds/-2128936835.cms",
        "https://thediplomat.com/feed/",
        # Afghanistan
        "https://tolonews.com/rss",
        "https://www.khaama.com/feed/",
        # Myanmar
        "https://www.bnionline.net/feed",
        # Korea
        "https://www.38north.org/feed/",
        "https://en.yna.co.kr/RSS/news.xml",
        # Pacific
        "https://www.rnz.co.nz/rss/pacific.xml",
        "https://www.pacificislandtimes.com/feed",
        # Japan
        "https://www.japantimes.co.jp/feed/",
        # Security / analysis
        "https://amti.csis.org/feed/",
        "https://www.lowyinstitute.org/the-interpreter/rss",
    ],

    # ── WEST / EAST AFRICA ───────────────────────────────────────────────────
    # Sudan, Somalia, Ethiopia, Nigeria, Sahel, DRC, Great Lakes, Horn
    "WEST_EAST_AFRICA": [
        # International backbone
        "https://feeds.bbci.co.uk/news/world/africa/rss.xml",
        "https://rss.dw.com/rdf/rss-en-africa",
        "https://allafrica.com/tools/rss/generate.php?pubid=pub00010510",
        # Sudan
        "https://sudantribune.com/spip.php?page=backend",
        "https://www.sudanwarmonitor.com/feed",
        "https://radiotamazuj.org/en/rss.xml",
        # Somalia / Horn
        "https://www.garoweonline.com/en/rss",
        "https://www.shabelle.net/feed/",
        "https://hiiraan.com/rss/news_en.xml",
        "https://www.somalicurrent.com/feed/",
        # Ethiopia
        "https://addisstandard.com/feed/",
        "https://www.ethpress.gov.et/feed",
        # Nigeria / West Africa
        "https://punchng.com/feed/",
        "https://www.premiumtimesng.com/feed",
        "https://dailytrust.com/feed/",
        "https://www.vanguardngr.com/feed/",
        # Sahel — specialist
        "https://www.theafricareport.com/feed/",
        "https://www.africaintelligence.com/feed",
        # DRC / Great Lakes
        "https://www.radiookapi.net/feed",
        "https://www.kinshasatimes.cd/feed",
        # East Africa regional
        "https://www.theeastafrican.co.ke/feeds/rss",
        "https://nation.africa/rss",
        "https://www.monitor.co.ug/rss",
        "https://www.thecitizen.co.tz/feed/",
        # Security monitors
        "https://acleddata.com/feed/",
        "https://reliefweb.int/updates/rss.xml",
        "https://insightcrime.org/tag/west-africa/feed/",
        "https://www.crisisgroup.org/rss",
    ],

    # ── SOUTHERN AFRICA ──────────────────────────────────────────────────────
    # South Africa, Zimbabwe, Mozambique, SADC, crime, political instability
    "SOUTHERN_AFRICA": [
        # International backbone
        "https://feeds.bbci.co.uk/news/world/africa/rss.xml",
        # South Africa — diverse outlets
        "https://www.dailymaverick.co.za/section/news/feed/",
        "https://www.groundup.org.za/feed/",
        "https://ewn.co.za/RSS",
        "https://www.news24.com/rss",
        "https://www.timeslive.co.za/rss/",
        "https://newframe.com/feed/",
        "https://www.amabhungane.org/feed/",
        # Zimbabwe
        "https://www.newzimbabwe.com/feed/",
        "https://www.newsday.co.zw/feed/",
        "https://zimbabwesituation.com/feed/",
        "https://www.zimlive.com/feed/",
        # Mozambique
        "https://www.clubofmozambique.com/feed/",
        "https://pinnaclenews.net/feed/",
        # Zambia / Malawi / Botswana
        "https://www.lusakatimes.com/feed/",
        "https://malawi24.com/feed/",
        "https://www.mmegi.bw/rss.php",
        # Namibia / Angola
        "https://www.namibian.com.na/feed/",
        "https://club-k.net/feed",
        # Regional / security
        "https://www.issafrica.org/iss-today/rss",
        "https://globalinitiative.net/feed/",
        "https://insightcrime.org/tag/southern-africa/feed/",
    ],

    # ── SOUTH AMERICA ────────────────────────────────────────────────────────
    # Venezuela, Colombia, Brazil, organised crime, narcotics, political crisis
    "SOUTH_AMERICA": [
        # International backbone
        "https://feeds.bbci.co.uk/news/world/latin_america/rss.xml",
        "https://rss.dw.com/rdf/rss-en-latin-america",
        # Organised crime / security — specialist
        "https://insightcrime.org/feed/",
        "https://insightcrime.org/tag/mexico/feed/",
        "https://insightcrime.org/tag/colombia/feed/",
        "https://insightcrime.org/tag/venezuela/feed/",
        "https://insightcrime.org/tag/brazil/feed/",
        # Venezuela
        "https://venezuelanalysis.com/feed",
        "https://www.el-nacional.com/feed",
        "https://efectococuyo.com/feed/",
        # Colombia
        "https://www.colombiareports.com/feed/",
        "https://www.lasillavacia.com/feed",
        # Brazil
        "https://agenciabrasil.ebc.com.br/rss/ultimasnoticias/feed.xml",
        "https://brazilreports.com/feed/",
        "https://thebrazilinstitute.com/feed/",
        # Regional
        "https://en.mercopress.com/rss",
        "https://nacla.org/rss.xml",
        "https://www.batimes.com.ar/feed",
        "https://haitiantimes.com/feed/",
        "https://www.lapresse.ca/international/amerique-latine/rss",
        # Human rights / monitors
        "https://www.hrw.org/rss/news",
        "https://reliefweb.int/updates/rss.xml",
        "https://www.telesurtv.net/rss/news",
    ],
}


def get_region_feeds(region: str) -> list[str]:
    return FEEDS.get(region.upper(), [])


def all_region_feeds() -> list[tuple[str, str]]:
    """Return [(region, url), ...] for all configured feeds."""
    pairs = []
    for region, urls in FEEDS.items():
        for url in urls:
            pairs.append((region, url))
    return pairs


def total_feed_count() -> int:
    return sum(len(v) for v in FEEDS.values())



# ── STREAM-SPECIFIC FEEDS ─────────────────────────────────────────────────────
# These feeds are tagged by stream type and processed separately from
# geographic feeds. Each URL is associated with a stream tag.

STREAM_FEEDS: dict[str, list[str]] = {

    "maritime": [
        # Incident reporting
        "https://www.maritime-executive.com/rss",
        "https://gcaptain.com/feed/",
        "https://www.navyrecognition.com/index.php?option=com_ninjarsssyndicator&feed_id=1&format=raw",
        "https://navaltoday.com/feed/",
        "https://www.marinelink.com/rss/all",
        "https://www.seatrade-maritime.com/rss.xml",
        "https://www.hellenicshippingnews.com/feed/",
        "https://offshore-energy.biz/feed/",
        # Intelligence / advisories
        "https://www.icc-ccs.org/index.php/rss-feeds/send/3-piracy-news",
        "https://reliefweb.int/updates/rss.xml?search=maritime",
        # Trade / chokepoints
        "https://oilprice.com/rss/main",
        "https://www.tradewindsnews.com/rss",
    ],

    "cyber": [
        # Threat intelligence
        "https://www.bleepingcomputer.com/feed/",
        "https://feeds.feedburner.com/TheHackersNews",
        "https://krebsonsecurity.com/feed/",
        "https://www.darkreading.com/rss.xml",
        "https://cyberscoop.com/feed/",
        "https://www.securityweek.com/feed/",
        "https://www.infosecurity-magazine.com/rss/news/",
        # Government advisories
        "https://www.cisa.gov/uscert/ncas/alerts.xml",
        "https://www.ncsc.gov.uk/api/1/services/v1/all-rss-feed.xml",
        "https://www.enisa.europa.eu/news/rss",
        # Research
        "https://blog.mandiant.com/feed",
        "https://www.recordedfuture.com/feed",
    ],

    "economic": [
        # Sanctions
        "https://home.treasury.gov/system/files/126/ofac.rss",
        "https://eur-lex.europa.eu/oj/daily-view/L-series/rss.xml",
        # IMF / World Bank
        "https://www.imf.org/en/News/rss?language=eng",
        "https://feeds.worldbank.org/worldbank/financialnewsrss",
        # Trade / economic risk
        "https://www.globaltradealert.org/feed",
        "https://tradingeconomics.com/rss",
        "https://www.ft.com/rss/home/uk",
        # Commodity / energy
        "https://oilprice.com/rss/main",
        "https://www.mining.com/feed/",
        # Rating agencies (public)
        "https://www.fitchratings.com/rss",
    ],

    "political": [
        # Democracy / elections
        "https://freedomhouse.org/rss.xml",
        "https://www.idea.int/news-media/rss.xml",
        "https://carnegieendowment.org/rss/solr.rss?query=political+risk",
        "https://www.chathamhouse.org/rss.xml",
        # Political violence
        "https://acleddata.com/feed/",
        "https://www.crisisgroup.org/rss",
        # Regional political
        "https://www.al-monitor.com/rss",
        "https://foreignpolicy.com/feed/",
        "https://theintercept.com/feed/?rss",
        "https://www.opendemocracy.net/en/rss.xml",
        "https://www.lowyinstitute.org/the-interpreter/rss",
        "https://geopoliticalmonitor.com/feed/",
    ],

    "executive": [
        # Government travel advisories
        "https://travel.state.gov/content/travel/en/traveladvisories/traveladvisories.html.rss",
        "https://www.gov.uk/foreign-travel-advice.atom",
        "https://www.smartraveller.gov.au/destinations/rss.xml",
        # Security / KFR
        "https://www.osac.gov/Content/RssXml",
        "https://www.controlrisks.com/rss",
        # Health / medical intelligence
        "https://www.who.int/feeds/entity/csr/don/en/rss.xml",
        "https://www.promedmail.org/feed/",
        # Crime / personal security
        "https://insightcrime.org/feed/",
        "https://globalinitiative.net/feed/",
        "https://www.issafrica.org/iss-today/rss",
    ],
}


def get_stream_feeds(stream: str) -> list[str]:
    """Return feed URLs for a specific stream."""
    return STREAM_FEEDS.get(stream, [])


def all_stream_feed_pairs() -> list[tuple[str, str, str]]:
    """Return [(stream, region, url), ...] for all stream feeds."""
    pairs = []
    for stream, urls in STREAM_FEEDS.items():
        for url in urls:
            pairs.append((stream, "GLOBAL", url))
    return pairs


def total_stream_feed_count() -> int:
    return sum(len(v) for v in STREAM_FEEDS.values())

# ── Article extraction helpers ────────────────────────────────────────────────

import requests
import trafilatura

def fetch_article_text(link: str) -> str:
    """Try trafilatura first, fall back to requests."""
    try:
        dl = trafilatura.fetch_url(link, no_ssl=True, timeout=20)
        if dl:
            text = trafilatura.extract(dl, include_comments=False,
                                       include_tables=False, no_fallback=False)
            if text and len(text) > 100:
                return text.strip()
    except Exception:
        pass
    try:
        r = requests.get(link, headers={"User-Agent": UA}, timeout=20)
        text = trafilatura.extract(r.text, include_comments=False,
                                   include_tables=False, no_fallback=False)
        if text and len(text) > 100:
            return text.strip()
    except Exception:
        pass
    return ""


# ── Legacy helpers expected by collector.py ──────────────────────────────────

from urllib.parse import urlparse

def domain_of(url: str) -> str:
    """Extract bare domain from a URL."""
    try:
        h = urlparse(url).netloc
        return h.replace("www.", "")
    except Exception:
        return url

def first_sentence(text: str, max_chars: int = 280) -> str:
    """Return the first sentence of text, capped at max_chars."""
    if not text:
        return ""
    for sep in (". ", "! ", "? ", "\n"):
        idx = text.find(sep)
        if 0 < idx < max_chars:
            return text[:idx + 1].strip()
    return text[:max_chars].strip()
