"""
sa_topics.py — topic classification and importance scoring for the South
Africa edition.

Topics (what members browse by):
  crime        Crime & Safety
  government   Government & Policy
  parliament   Parliament & Committees
  courts       Courts & Justice
  corruption   Corruption & Accountability
  economy      Economy & Money
  trade        Trade, Mining & Freight
  services     Services & Infrastructure (power, water, roads, municipalities)
  health       Health
  weather      Weather & Disasters
  general      Current Affairs
"""
from __future__ import annotations

import re

TOPICS = {
    "crime":      "Crime & Safety",
    "government": "Government & Policy",
    "parliament": "Parliament & Committees",
    "courts":     "Courts & Justice",
    "corruption": "Corruption & Accountability",
    "economy":    "Economy & Money",
    "trade":      "Trade, Mining & Freight",
    "services":   "Services & Infrastructure",
    "health":     "Health",
    "weather":    "Weather & Disasters",
    "general":    "Current Affairs",
}

# (pattern, topic, weight) — highest summed weight wins; feed category hint adds 2
_RULES = [
    (r"\b(murder|shooting|shot dead|robbery|hijack\w*|kidnap\w*|gang\w*|extortion|police|saps|arrested|"
     r"crime|rape|assault|armed|cash.in.transit|cit heist|taxi violence|stabbing|mob justice)\b", "crime", 2),
    (r"\b(parliament|portfolio committee|national assembly|ncop|select committee|bill|hearing|mps?)\b", "parliament", 2),
    (r"\b(court|judge|high court|constitutional court|bail|sentenced|trial|acquit\w*|magistrate|npa|prosecut\w*)\b", "courts", 2),
    (r"\b(corruption|state capture|zondo|tender|fraud|irregular expenditure|auditor.general|public protector|"
     r"forensic|looting|siu)\b", "corruption", 2),
    (r"\b(minister|cabinet|president|ramaphosa|department of|policy|legislation|gnu|municipal(ity)?|mayor|"
     r"premier|anc|eff|mk party|ifp|election)\b", "government", 1),
    (r"\b(rand|inflation|interest rate|repo|reserve bank|sarb|budget|gdp|unemployment|jobs?|treasury|"
     r"tax|sars|economy|rating|moody|fitch|s&p|jse|fuel price|petrol|diesel)\b", "economy", 2),
    (r"\b(mining|mines|port|transnet|rail|freight|export|import|tariff|agoa|trade deal|harbour|container|"
     r"platinum|coal|gold|manganese)\b", "trade", 2),
    (r"\b(load.?shedding|eskom|electricity|power cut|outage|water|sewage|pothole|road|bridge|municipal|"
     r"infrastructure|telkom|fibre|vodacom|mtn|cable theft|substation|burst pipe)\b", "services", 2),
    (r"\b(hospital|clinic|health|disease|outbreak|cholera|measles|tb|hiv|vaccine|nicd|medicine|nurses?)\b", "health", 2),
    (r"\b(flood|storm|cold front|weather warning|snow|veld fire|wildfire|drought|disaster|tornado|sinkhole)\b", "weather", 2),
]
_RULES = [(re.compile(p, re.I), t, w) for p, t, w in _RULES]

# Impact weights. Scores are 0–10; ≥7 = "high", ≥5 = "elevated".
_IMPACT = [
    (r"\b(state of disaster|national disaster|mass shooting|massacre|killed \d{2,}|dozens killed|"
     r"stage ?[5-8]|blackout|grid collapse|cholera outbreak|national shutdown|unrest|looting)\b", 4),
    (r"\b(murder|killed|shot dead|hijack\w*|kidnap\w*|cash.in.transit|extortion|bomb|explosion|"
     r"fire|floods?|water outage|no water|sinkhole|collapse\w*)\b", 2),
    (r"\b(arrested|sentenced|convicted|raid|charged|fraud|corruption|irregular|billion|r\d+\s?(bn|billion))\b", 2),
    (r"\b(strike|protest|march|shutdown|taxi|blockade|load.?shedding|tariff|price hike|fuel price|"
     r"interest rate|downgrade|upgrade|budget|bill passed|parliament|committee)\b", 1),
    (r"\b(warning|alert|evacuat\w*|curfew|lockdown|emergency|urgent|outbreak)\b", 2),
]
_IMPACT = [(re.compile(p, re.I), w) for p, w in _IMPACT]

# Low-value / non-news — dropped
_SKIP = re.compile(
    r"\b(horoscope|celebrity|gossip|recipe|lifestyle|fashion|soapie|big brother|idols|"
    r"sponsored|advertorial|competition|win a|giveaway|sport|rugby|springbok|bafana|psl|kaizer chiefs|"
    r"orlando pirates|cricket|proteas|golf|tennis)\b", re.I)


def classify_topic(title: str, text: str, category_hint: str = "general") -> str:
    blob = f"{title}\n{title}\n{(text or '')[:1200]}"
    scores: dict[str, int] = {}
    for rx, topic, w in _RULES:
        hits = len(rx.findall(blob))
        if hits:
            scores[topic] = scores.get(topic, 0) + w * min(hits, 3)
    if category_hint and category_hint != "general":
        scores[category_hint] = scores.get(category_hint, 0) + 2
    if not scores:
        return category_hint if category_hint in TOPICS else "general"
    return max(scores, key=scores.get)


def is_skippable(title: str, text: str = "") -> bool:
    return bool(_SKIP.search(f"{title} {(text or '')[:300]}"))


def importance(title: str, text: str, source_tier: int, corroboration: int = 1, has_place: bool = False) -> int:
    """0–10 score: impact keywords + official source + corroboration + local specificity."""
    blob = f"{title}\n{(text or '')[:1500]}"
    s = 0
    for rx, w in _IMPACT:
        if rx.search(blob):
            s += w
    if re.search(r"\b(\d{2,}|dozens|hundreds|thousands)\b", title):
        s += 1
    if source_tier >= 3:
        s += 1
    if corroboration >= 2:
        s += 1
    if corroboration >= 4:
        s += 1
    if has_place:
        s += 1
    return max(0, min(10, s))


def level(score: int) -> str:
    if score >= 8:
        return "critical"
    if score >= 6:
        return "high"
    if score >= 4:
        return "elevated"
    return "routine"
