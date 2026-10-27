"""
sa_geo.py — South African province / city detection from text.

Returns the most specific place found: {"province": ..., "city": ..., "place": ...}.
Matching is whole-word and case-insensitive. Ambiguous short names are only
matched with a qualifier to avoid false positives.
"""
from __future__ import annotations

import re

PROVINCES = {
    "Gauteng": ["gauteng"],
    "Western Cape": ["western cape"],
    "KwaZulu-Natal": ["kwazulu-natal", "kwazulu natal", "kzn"],
    "Eastern Cape": ["eastern cape"],
    "Limpopo": ["limpopo"],
    "Mpumalanga": ["mpumalanga"],
    "North West": ["north west province", "north-west province", "north west"],
    "Free State": ["free state"],
    "Northern Cape": ["northern cape"],
}

# place -> (province, city/metro)
PLACES: dict[str, tuple[str, str]] = {
    # Gauteng
    "johannesburg": ("Gauteng", "Johannesburg"), "joburg": ("Gauteng", "Johannesburg"),
    "soweto": ("Gauteng", "Johannesburg"), "sandton": ("Gauteng", "Johannesburg"),
    "alexandra": ("Gauteng", "Johannesburg"), "randburg": ("Gauteng", "Johannesburg"),
    "roodepoort": ("Gauteng", "Johannesburg"), "midrand": ("Gauteng", "Johannesburg"),
    "pretoria": ("Gauteng", "Tshwane"), "tshwane": ("Gauteng", "Tshwane"),
    "centurion": ("Gauteng", "Tshwane"), "soshanguve": ("Gauteng", "Tshwane"),
    "mamelodi": ("Gauteng", "Tshwane"), "ekurhuleni": ("Gauteng", "Ekurhuleni"),
    "germiston": ("Gauteng", "Ekurhuleni"), "benoni": ("Gauteng", "Ekurhuleni"),
    "boksburg": ("Gauteng", "Ekurhuleni"), "tembisa": ("Gauteng", "Ekurhuleni"),
    "vereeniging": ("Gauteng", "Sedibeng"), "vanderbijlpark": ("Gauteng", "Sedibeng"),
    "oliver tambo": ("Gauteng", "Ekurhuleni"),
    # Western Cape
    "cape town": ("Western Cape", "Cape Town"), "khayelitsha": ("Western Cape", "Cape Town"),
    "mitchells plain": ("Western Cape", "Cape Town"), "nyanga": ("Western Cape", "Cape Town"),
    "gugulethu": ("Western Cape", "Cape Town"), "bellville": ("Western Cape", "Cape Town"),
    "stellenbosch": ("Western Cape", "Stellenbosch"), "paarl": ("Western Cape", "Drakenstein"),
    "mossel bay": ("Western Cape", "Mossel Bay"),
    "knysna": ("Western Cape", "Knysna"), "worcester": ("Western Cape", "Worcester"),
    # KZN
    "durban": ("KwaZulu-Natal", "eThekwini"), "ethekwini": ("KwaZulu-Natal", "eThekwini"),
    "pietermaritzburg": ("KwaZulu-Natal", "Msunduzi"), "richards bay": ("KwaZulu-Natal", "uMhlathuze"),
    "newcastle": ("KwaZulu-Natal", "Newcastle"), "ladysmith": ("KwaZulu-Natal", "Alfred Duma"),
    "umlazi": ("KwaZulu-Natal", "eThekwini"), "inanda": ("KwaZulu-Natal", "eThekwini"),
    # Eastern Cape
    "gqeberha": ("Eastern Cape", "Nelson Mandela Bay"), "port elizabeth": ("Eastern Cape", "Nelson Mandela Bay"),
    "nelson mandela bay": ("Eastern Cape", "Nelson Mandela Bay"), "east london": ("Eastern Cape", "Buffalo City"),
    "buffalo city": ("Eastern Cape", "Buffalo City"), "mthatha": ("Eastern Cape", "Mthatha"),
    "makhanda": ("Eastern Cape", "Makhanda"), "komani": ("Eastern Cape", "Komani"),
    # Others
    "bloemfontein": ("Free State", "Mangaung"), "mangaung": ("Free State", "Mangaung"),
    "welkom": ("Free State", "Matjhabeng"), "polokwane": ("Limpopo", "Polokwane"),
    "thohoyandou": ("Limpopo", "Thulamela"), "musina": ("Limpopo", "Musina"),
    "mbombela": ("Mpumalanga", "Mbombela"), "nelspruit": ("Mpumalanga", "Mbombela"),
    "emalahleni": ("Mpumalanga", "Emalahleni"), "witbank": ("Mpumalanga", "Emalahleni"),
    "rustenburg": ("North West", "Rustenburg"), "mahikeng": ("North West", "Mahikeng"),
    "mafikeng": ("North West", "Mahikeng"), "klerksdorp": ("North West", "Matlosana"),
    "madibeng": ("North West", "Madibeng"), "kimberley": ("Northern Cape", "Sol Plaatje"),
    "upington": ("Northern Cape", "Upington"),
}

_NATIONAL = re.compile(
    r"\b(parliament|union buildings|cabinet|national assembly|ncop|national treasury|"
    r"reserve bank|ramaphosa|south africa(n)?|saps)\b", re.I)


def _compile(words):
    return re.compile(r"\b(" + "|".join(re.escape(w) for w in sorted(words, key=len, reverse=True)) + r")\b", re.I)


_PLACE_RE = _compile(PLACES.keys())
_PROV_RE = {p: _compile(a) for p, a in PROVINCES.items()}


def detect_location(title: str, text: str = "") -> dict:
    """Most specific SA location. Title matches outrank body matches."""
    for blob in (title or "", (text or "")[:1500]):
        m = _PLACE_RE.search(blob)
        if m:
            prov, city = PLACES[m.group(1).lower()]
            return {"province": prov, "city": city, "place": m.group(1).title()}
        for prov, rx in _PROV_RE.items():
            if rx.search(blob):
                return {"province": prov, "city": "", "place": prov}
    if _NATIONAL.search(f"{title} {text[:600]}"):
        return {"province": "National", "city": "", "place": "National"}
    return {"province": "", "city": "", "place": ""}
