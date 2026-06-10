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
    # New local African sources — tier 2 (local)
    "sabcnews.com":                2,
    "groundup.org.za":            2,
    "amabhungane.org":            2,
    "nehandaradio.com":           2,
    "263chat.com":                2,
    "zimlive.com":                2,
    "zimbabwesituation.com":      2,
    "citizen.co.za":              2,
    "iol.co.za":                  2,
    "thecable.ng":                2,
    "channelstv.com":             2,
    "premiumtimesng.com":         2,
    "the-star.co.ke":             2,
    "dabangasudan.org":           2,
    "sudanwarmonitor.com":        2,
    "radiookapi.net":             2,
    "kinshasatimes.cd":           2,
    "actualite.cd":               2,
    "horseedmedia.net":           2,
    "hiiraan.com":                2,
    "somalicurrent.com":          2,
    "thereporterethiopia.com":    2,
    "borkena.com":                2,
    "maliweb.net":                2,
    "studio-tamani.org":          2,
    "pinnaclenews.net":           2,
    "namibian.com.na":            2,
    "club-k.net":                 2,
}

BASE_WEIGHTS = [
    # CRITICAL events — confirmed violence, mass casualties, major attacks (score 3-4)
    (r"\b(mass shooting|suicide.?bomb|car.?bomb|assassination|massacre|genocide|ethnic.?cleansing)\b", 4),
    (r"\b(air ?strike|shelling|artillery|missile.?strike|rocket.?attack|drone.?strike|blast|explosion)\b", 4),
    (r"\b(coup|putsch|martial law|state of emergency|nuclear)\b", 3),
    (r"\b(earthquake|tsunami|cyclone|hurricane|typhoon|eruption|volcano)\b", 3),
    # HIGH events — significant security incidents (score 2)
    (r"\b(ambush|firefight|raid|hostage|kidnap|abduction|attack|hijack|hijacking)\b", 2),
    (r"\b(tanker.?attack|vessel.?attack|ship.?attack|maritime.?incident|seized.?vessel)\b", 3),
    (r"\b(shooting|killed|dead|deaths|fatalities|casualties)\b", 2),
    (r"\b(sanctions?|blockade|border closure|evacuation|curfew)\b", 2),
    (r"\b(famine|cholera|ebola|outbreak|epidemic|pandemic)\b", 2),
    (r"\b(ceasefire|truce|peace.?talks|collapse)\b", 2),
    # MEDIUM events — elevated concern (score 1)
    (r"\b(clash|clashes|unrest|protests?|riots?|demonstration)\b", 1),
    (r"\b(military|troops|militia|rebels|insurgents|terrorists?)\b", 1),
    (r"\b(wounded|injured|arrested|detained|missing)\b", 1),
    (r"\b(floods?|wildfire|landslide|drought|famine)\b", 1),
    (r"\b(deadly|devastating|severe|major|significant)\b", 1),
]

BLACKLIST = re.compile(
    r"\b(football|soccer|cricket|tennis|celebrity|music|movie|gaming|esports|"
    r"box office|fashion|gossip|opinion|review|lifestyle|travel|food|recipes?)\b",
    re.I,
)

AFRICA_BONUS = [
    # Africa-specific high priority — genuine escalation signals
    (r"\b(coup|junta|putsch|martial law|state of emergency)\b", 2),
    (r"\b(ebola|cholera|famine|severe.?drought)\b", 2),
    (r"\b(mass.?shooting|mass.?killing|massacre)\b", 2),
    # Moderate Africa signals
    (r"\b(cartel|gang|bandit|kidnap|abduction)\b", 1),
    (r"\b(border closure|evacuation|IDPs?|refugees?)\b", 1),
    # Removed: unrest/riots/clashes/floods (too common, over-triggers)
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
