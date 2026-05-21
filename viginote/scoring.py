"""
scoring.py — Severity scoring and source-tier logic for VigiNote.
"""

import re

# ── Source tier bonus map ─────────────────────────────────────────────────────
# 0 = wire / major international (Reuters, AP, BBC) — no bonus
# 1 = regional / national outlet                    — +1
# 2 = local / specialist / independent              — +2
SOURCE_TIER_BONUS: dict[str, int] = {
    # Tier 3 — local, specialist, independent
    "acleddata.com":               2,
    "addisstandard.com":           2,
    "africareport.com":            2,
    "alertnet.org":                2,
    "ansamed.info":                2,
    "armenpress.am":               2,
    "azatutyun.am":                2,
    "balkaninsight.com":           2,
    "bellingcat.com":              2,
    "bhrtv.ba":                    2,
    "birn.eu.com":                 2,
    "colombiareports.com":         2,
    "crisisgroup.org":             2,
    "dailytrust.com":              2,
    "defensenews.com":             2,
    "duvarenglish.com":            2,
    "ekathimerini.com":            2,
    "garoweonline.com":            2,
    "globalvoices.org":            2,
    "hurriyetdailynews.com":       2,
    "insightcrime.org":            2,
    "irrawaddy.com":               2,
    "iswresearch.org":             2,
    "kavkaz-uzel.eu":              2,
    "kyivindependent.com":         2,
    "kurdistan24.net":             2,
    "lorientlejour.com":           2,
    "lestimesline.co.ls":          2,
    "lusakatimes.com":             2,
    "madamasr.com":                2,
    "malawi24.com":                2,
    "mediazimbabwe.com":           2,
    "mercopress.com":              2,
    "militarytimes.com":           2,
    "monitor.co.ug":               2,
    "nacla.org":                   2,
    "newframe.com":                2,
    "newsday.co.zw":               2,
    "newzimbabwe.com":             2,
    "occrp.org":                   2,
    "oilprice.com":                2,
    "palestinechronicle.com":      2,
    "punchng.com":                 2,
    "rudaw.net":                   2,
    "shabelle.net":                2,
    "standardmedia.co.ke":         2,
    "sudantribune.com":            2,
    "syriahr.com":                 2,
    "thecitizen.co.tz":            2,
    "theeastafrican.co.ke":        2,
    "theinsider.ua":               2,
    "thenewhumanitarian.org":      2,
    "thenewsminute.com":           2,
    "thesomalipost.com":           2,
    "tolonews.com":                2,
    "ukraineworld.org":            2,
    "vanguardngr.com":             2,
    "venezuelanalysis.com":        2,
    "haitiantimes.com":            2,
    "washingtonpost.com":          2,
    "yemenmonitor.com":            2,
    "zimeye.net":                  2,
    "clubofmozambique.com":        2,
    "mmegi.bw":                    2,
    # Tier 2 — strong regional / national outlets
    "alarabiya.net":               1,
    "aljazeera.com":               1,
    "dhakatribune.com":            1,
    "dawn.com":                    1,
    "euobserver.com":              1,
    "ewn.co.za":                   1,
    "geo.tv":                      1,
    "haaretz.com":                 1,
    "infobae.com":                 1,
    "jpost.com":                   1,
    "japantimes.co.jp":            1,
    "middleeasteye.net":           1,
    "nation.africa":               1,
    "news24.com":                  1,
    "rferl.org":                   1,
    "rfa.org":                     1,
    "rnz.co.nz":                   1,
    "scmp.com":                    1,
    "straitstimes.com":            1,
    "dailymaverick.co.za":         1,
    "timesofisrael.com":           1,
    "timesofindia.indiatimes.com": 1,
    "timeslive.co.za":             1,
    "bangkokpost.com":             1,
}

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
    r"box office|fashion|gossip|opinion|review|lifestyle|travel|food|recipes?)\b",
    re.I,
)

AFRICA_BONUS = [
    (r"\b(coup|junta|putsch|martial law|state of emergency)\b", 2),
    (r"\b(unrest|riots?|looting|clashes?|curfew)\b", 2),
    (r"\b(cholera|measles|ebola|famine|drought|water shortage|outbreak)\b", 2),
    (r"\b(cyclone|floods?|landslide|wildfire|earthquake)\b", 2),
    (r"\b(cartel|gang|bandit|kidnap|abduction|extortion)\b", 2),
    (r"\b(border closure|evacuation|IDPs?|refugees?)\b", 1),
]


def source_tier(domain: str) -> int:
    """Return 0/1/2 tier for a domain string."""
    for fragment, bonus in SOURCE_TIER_BONUS.items():
        if fragment in domain:
            return bonus
    return 0


def severity_score(title: str, text: str, region: str, feed_url: str = "") -> int:
    """
    Keyword-weighted score with Africa bonus and source-tier bonus.
    Returns 0 for blacklisted content.
    """
    from viginote.feeds import domain_of
    T = f"{title}\n{text}".lower()
    if BLACKLIST.search(T):
        return 0
    score = 0
    for pat, w in BASE_WEIGHTS:
        if re.search(pat, T, flags=re.I):
            score += w
    if re.search(r"\b(\d{2,}|dozens|scores|hundreds|thousands)\b", T):
        score += 1
    if region in ("WEST_EAST_AFRICA", "SOUTHERN_AFRICA"):
        for pat, bonus in AFRICA_BONUS:
            if re.search(pat, T, flags=re.I):
                score += bonus
    score += source_tier(domain_of(feed_url))
    return score


def severity_icon(score: int) -> str:
    if score >= 9: return "🛑"
    if score >= 7: return "🔴"
    if score >= 5: return "🟠"
    return "🟡"


def build_selection_reason(score: int, tier: int, region: str,
                           source_count: int, is_critical: bool) -> str:
    """Human-readable audit string stored with every sent alert."""
    tier_label = {0: "wire", 1: "regional", 2: "local/specialist"}.get(tier, "unknown")
    parts = [
        f"score={score}",
        f"tier={tier_label}",
        f"region={region}",
        f"sources={source_count}",
    ]
    if is_critical:
        parts.append("CRITICAL")
    return "; ".join(parts)
