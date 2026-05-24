"""
stream_classifier.py — VigiNote intelligence stream tagger
Tags each alert with one of 6 stream types based on source domain,
title keywords, and article content.

Streams:
  geographic      — conflict, security, military, protests (default)
  maritime        — piracy, shipping, chokepoints, naval
  cyber           — hacking, malware, ransomware, breaches, infrastructure
  economic        — sanctions, currency, trade, IMF, supply chain
  political       — elections, coups, regime change, political violence
  executive       — kidnap, travel security, targeted attacks, civil unrest
"""
from __future__ import annotations
import re

# ── Stream definitions ────────────────────────────────────────────────────────

STREAM_GEOGRAPHIC   = "geographic"
STREAM_MARITIME     = "maritime"
STREAM_CYBER        = "cyber"
STREAM_ECONOMIC     = "economic"
STREAM_POLITICAL    = "political"
STREAM_EXECUTIVE    = "executive"

ALL_STREAMS = [
    STREAM_GEOGRAPHIC,
    STREAM_MARITIME,
    STREAM_CYBER,
    STREAM_ECONOMIC,
    STREAM_POLITICAL,
    STREAM_EXECUTIVE,
]

STREAM_LABELS = {
    STREAM_GEOGRAPHIC: "Geographic Intelligence",
    STREAM_MARITIME:   "Maritime Security",
    STREAM_CYBER:      "Cyber & Infrastructure",
    STREAM_ECONOMIC:   "Economic & Financial Risk",
    STREAM_POLITICAL:  "Political Risk",
    STREAM_EXECUTIVE:  "Executive Protection",
}

STREAM_ICONS = {
    STREAM_GEOGRAPHIC: "🌍",
    STREAM_MARITIME:   "⚓",
    STREAM_CYBER:      "💻",
    STREAM_ECONOMIC:   "📊",
    STREAM_POLITICAL:  "🗳",
    STREAM_EXECUTIVE:  "🛡",
}

# ── Source domain → stream ────────────────────────────────────────────────────
# High-confidence domain-based classification
DOMAIN_STREAM_MAP: dict[str, str] = {
    # Maritime
    "gcaptain.com":            STREAM_MARITIME,
    "maritimeexecutive.com":   STREAM_MARITIME,
    "lloydslist.com":          STREAM_MARITIME,
    "navyrecognition.com":     STREAM_MARITIME,
    "navaltoday.com":          STREAM_MARITIME,
    "marinelink.com":          STREAM_MARITIME,
    "maritime-executive.com":  STREAM_MARITIME,
    "porttechnology.org":      STREAM_MARITIME,
    "tradewindsnews.com":      STREAM_MARITIME,
    "seatrade-maritime.com":   STREAM_MARITIME,
    "hellenicshippingnews.com":STREAM_MARITIME,
    "offshore-energy.biz":     STREAM_MARITIME,
    # Cyber
    "bleepingcomputer.com":    STREAM_CYBER,
    "thehackernews.com":       STREAM_CYBER,
    "krebsonsecurity.com":     STREAM_CYBER,
    "recordedfuture.com":      STREAM_CYBER,
    "mandiant.com":            STREAM_CYBER,
    "darkreading.com":         STREAM_CYBER,
    "cyberscoop.com":          STREAM_CYBER,
    "securityweek.com":        STREAM_CYBER,
    "infosecurity-magazine.com":STREAM_CYBER,
    "threatpost.com":          STREAM_CYBER,
    "cisa.gov":                STREAM_CYBER,
    "ncsc.gov.uk":             STREAM_CYBER,
    "enisa.europa.eu":         STREAM_CYBER,
    "shadowserver.org":        STREAM_CYBER,
    # Economic
    "imf.org":                 STREAM_ECONOMIC,
    "worldbank.org":           STREAM_ECONOMIC,
    "treasury.gov":            STREAM_ECONOMIC,
    "globaltradealert.org":    STREAM_ECONOMIC,
    "tradingeconomics.com":    STREAM_ECONOMIC,
    "fitchratings.com":        STREAM_ECONOMIC,
    "moodys.com":              STREAM_ECONOMIC,
    "spglobal.com":            STREAM_ECONOMIC,
    "reuters.com":             STREAM_GEOGRAPHIC,  # mixed — keyword decides
    # Political
    "freedomhouse.org":        STREAM_POLITICAL,
    "idea.int":                STREAM_POLITICAL,
    "aceproject.org":          STREAM_POLITICAL,
    "carnegieendowment.org":   STREAM_POLITICAL,
    "vdem.net":                STREAM_POLITICAL,
    "ndi.org":                 STREAM_POLITICAL,
    "ifes.org":                STREAM_POLITICAL,
    # Executive protection
    "osac.gov":                STREAM_EXECUTIVE,
    "travel.state.gov":        STREAM_EXECUTIVE,
    "gov.uk":                  STREAM_EXECUTIVE,
    "smartraveller.gov.au":    STREAM_EXECUTIVE,
    "crisis24.com":            STREAM_EXECUTIVE,
    "controlrisks.com":        STREAM_EXECUTIVE,
}

# ── Keyword patterns per stream ───────────────────────────────────────────────
# Each entry: (pattern, stream, weight)
# Higher weight = stronger signal

_KEYWORD_RULES: list[tuple[re.Pattern, str, int]] = []

def _rule(pattern: str, stream: str, weight: int = 1) -> tuple[re.Pattern, str, int]:
    return (re.compile(pattern, re.IGNORECASE), stream, weight)

_RAW_RULES: list[tuple[str, str, int]] = [
    # Maritime — strong signals (weight 3)
    (r'\bpiracy\b|\bpirates?\b',                    STREAM_MARITIME, 3),
    (r'\bhijack(ed|ing)?\b.{0,30}\bship\b|vessel',  STREAM_MARITIME, 3),
    (r'\bcoast guard\b',                             STREAM_MARITIME, 2),
    (r'\bnaval\b.{0,20}\battack|strike|vessel',      STREAM_MARITIME, 3),
    (r'\bshipping\s+lane|sea\s+lane',                STREAM_MARITIME, 3),
    (r'\bchokep?oint\b',                             STREAM_MARITIME, 3),
    (r'\bsuez\s+canal\b',                            STREAM_MARITIME, 3),
    (r'\bstrait\s+of\b',                             STREAM_MARITIME, 3),
    (r'\bred\s+sea\b',                               STREAM_MARITIME, 2),
    (r'\bgulf\s+of\s+aden\b',                        STREAM_MARITIME, 3),
    (r'\bhouthi.{0,30}ship|vessel.{0,30}attack',     STREAM_MARITIME, 3),
    (r'\bmissile.{0,30}ship|vessel.{0,30}missile',   STREAM_MARITIME, 3),
    (r'\bdrone.{0,30}\bship\b|\bvessel\b',           STREAM_MARITIME, 2),
    (r'\bport\s+clos|port\s+block',                  STREAM_MARITIME, 2),
    (r'\bcontainer\s+ship|cargo\s+ship|tanker\b',    STREAM_MARITIME, 2),
    (r'\bimo\b|\bukmto\b|\bimb\b',                   STREAM_MARITIME, 3),
    (r'\bnautical|seafar|seaborne',                  STREAM_MARITIME, 2),

    # Cyber — strong signals
    (r'\bransom\s*ware\b',                           STREAM_CYBER, 3),
    (r'\bcyber\s*attack\b',                          STREAM_CYBER, 3),
    (r'\bdata\s+breach\b',                           STREAM_CYBER, 3),
    (r'\bmalware\b|\bspyware\b|\bradware\b',         STREAM_CYBER, 3),
    (r'\bhack(ed|ing|ers?)\b',                       STREAM_CYBER, 2),
    (r'\bphishing\b|\bspear.phishing\b',             STREAM_CYBER, 3),
    (r'\bcve-\d{4}',                                 STREAM_CYBER, 3),
    (r'\bzero.day\b',                                STREAM_CYBER, 3),
    (r'\bddos\b|\bdenial.of.service\b',              STREAM_CYBER, 3),
    (r'\bstate.sponsored\b.{0,30}\bcyber|hack',      STREAM_CYBER, 3),
    (r'\bcritical\s+infrastructure.{0,30}\battack',  STREAM_CYBER, 3),
    (r'\bscada\b|\bics\b.{0,10}\battack',            STREAM_CYBER, 3),
    (r'\bncsc\b|\bcisa\b|\bcert\b',                  STREAM_CYBER, 2),
    (r'\bthreat\s+actor\b|\bapt\d+',                 STREAM_CYBER, 3),
    (r'\bdisinformation\b|\bcognitive\s+warfare\b',  STREAM_CYBER, 2),
    (r'\bpower\s+grid.{0,20}\battack|attack.{0,20}\bpower grid', STREAM_CYBER, 3),

    # Economic — strong signals
    (r'\bsanctions?\b.{0,30}\bimposed|announced|expanded', STREAM_ECONOMIC, 3),
    (r'\bofac\b',                                    STREAM_ECONOMIC, 3),
    (r'\bcurrency\s+crisis\b|\bcurrency\s+collapse', STREAM_ECONOMIC, 3),
    (r'\bimf\s+bailout|imf\s+loan|imf\s+deal',      STREAM_ECONOMIC, 3),
    (r'\bsovereign\s+debt\b|\bdebt\s+default\b',    STREAM_ECONOMIC, 3),
    (r'\bcapital\s+controls?\b',                     STREAM_ECONOMIC, 3),
    (r'\bhyperinflation\b',                          STREAM_ECONOMIC, 3),
    (r'\bsupply\s+chain.{0,20}\bdisrupt',            STREAM_ECONOMIC, 2),
    (r'\btrade\s+war\b|\btrade\s+sanction',          STREAM_ECONOMIC, 3),
    (r'\bbank\s+run\b|\bbank\s+coll',                STREAM_ECONOMIC, 3),
    (r'\bcredit\s+rating.{0,20}\bdowngrad',          STREAM_ECONOMIC, 3),
    (r'\bcommodity.{0,20}\bshock|price\s+spike',     STREAM_ECONOMIC, 2),
    (r'\bblockade.{0,20}\bport|trade\s+blockade',    STREAM_ECONOMIC, 2),
    (r'\bembargo\b',                                 STREAM_ECONOMIC, 3),

    # Political — strong signals
    (r'\belection\b.{0,30}\bfraud|violenc|crisis|disputed', STREAM_POLITICAL, 3),
    (r'\bcoup\b|\bcoup\s+attempt\b|\bcoup\s+d.état', STREAM_POLITICAL, 3),
    (r'\bregime\s+change\b',                         STREAM_POLITICAL, 3),
    (r'\bpolitical\s+crisis\b',                      STREAM_POLITICAL, 2),
    (r'\bopposition\s+leader.{0,20}\barrest|detain', STREAM_POLITICAL, 3),
    (r'\bparliament\s+dissolv|parliament\s+suspend', STREAM_POLITICAL, 3),
    (r'\bstate\s+of\s+emergency\b',                 STREAM_POLITICAL, 2),
    (r'\bpresident.{0,20}\barrest|imprison|assassin', STREAM_POLITICAL, 3),
    (r'\bjunta\b',                                   STREAM_POLITICAL, 3),
    (r'\bmartial\s+law\b',                           STREAM_POLITICAL, 3),
    (r'\bconstitutional\s+crisis\b',                 STREAM_POLITICAL, 3),
    (r'\bmass\s+protest\b.{0,30}\bgovernment',       STREAM_POLITICAL, 2),
    (r'\bpolitical\s+assassination\b',               STREAM_POLITICAL, 3),
    (r'\belectoral\s+violenc',                       STREAM_POLITICAL, 3),
    (r'\bsuccession\s+crisis\b',                     STREAM_POLITICAL, 3),

    # Executive protection — strong signals
    (r'\bkidnap|kidnapping\b',                       STREAM_EXECUTIVE, 3),
    (r'\bhostage\b',                                 STREAM_EXECUTIVE, 3),
    (r'\bransom\b.{0,30}\bforeign|expat|executive',  STREAM_EXECUTIVE, 3),
    (r'\bforeigners?.{0,30}\battack|target|kill',    STREAM_EXECUTIVE, 3),
    (r'\bexpats?.{0,30}\battack|target|warn',        STREAM_EXECUTIVE, 3),
    (r'\bhotel.{0,20}\battack|bomb|target',          STREAM_EXECUTIVE, 3),
    (r'\bairport.{0,20}\bclos|attack|threat',        STREAM_EXECUTIVE, 2),
    (r'\btravel\s+warning\b|\btravel\s+advisory\b',  STREAM_EXECUTIVE, 3),
    (r'\bevacuation.{0,20}\bforeign|civilian|expat', STREAM_EXECUTIVE, 3),
    (r'\bassassination\s+attempt\b',                 STREAM_EXECUTIVE, 2),
    (r'\bsecurity\s+detail\b|\bbodyguard\b',         STREAM_EXECUTIVE, 2),
    (r'\bcivil\s+unrest.{0,30}\bforeign|business',  STREAM_EXECUTIVE, 2),
    (r'\bdo\s+not\s+travel\b',                       STREAM_EXECUTIVE, 3),
    (r'\bcarjack\b',                                 STREAM_EXECUTIVE, 2),
]

# Compile all rules
for pattern_str, stream, weight in _RAW_RULES:
    try:
        _KEYWORD_RULES.append((re.compile(pattern_str, re.IGNORECASE), stream, weight))
    except re.error:
        pass  # Skip bad patterns


def classify_stream(
    title: str = "",
    text: str = "",
    source_domain: str = "",
    existing_stream: str | None = None,
) -> str:
    """
    Classify an alert into one of 6 intelligence streams.
    Returns stream name string.
    Priority: existing tag > domain match > keyword scoring > geographic default.
    """
    # Don't reclassify if already tagged with a non-default stream
    if existing_stream and existing_stream != STREAM_GEOGRAPHIC:
        return existing_stream

    # Domain-based classification (high confidence)
    domain_clean = source_domain.lower().replace("www.", "")
    for domain, stream in DOMAIN_STREAM_MAP.items():
        if domain in domain_clean:
            if stream != STREAM_GEOGRAPHIC:
                return stream
            break  # Reuters etc — fall through to keyword scoring

    # Keyword scoring
    search_text = f"{title} {text[:800]}".lower()
    scores: dict[str, int] = {s: 0 for s in ALL_STREAMS}

    for pattern, stream, weight in _KEYWORD_RULES:
        if pattern.search(search_text):
            scores[stream] += weight

    # Get highest scoring non-geographic stream
    best_stream = STREAM_GEOGRAPHIC
    best_score = 2  # Minimum threshold to override geographic default

    for stream, score in scores.items():
        if stream != STREAM_GEOGRAPHIC and score > best_score:
            best_score = score
            best_stream = stream

    return best_stream


def get_stream_label(stream: str) -> str:
    return STREAM_LABELS.get(stream, stream.title())


def get_stream_icon(stream: str) -> str:
    return STREAM_ICONS.get(stream, "📡")
