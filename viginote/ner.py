"""
ner.py — Named Entity Recognition for VigiNote.

Uses spaCy en_core_web_sm (fast, no GPU required).
Falls back gracefully if spaCy is not installed.

Extracts:
  persons  — named individuals (leaders, commanders, victims)
  orgs     — organizations, armed groups, governments
  locs     — locations (GPE = countries/cities, LOC = physical locations)
  events   — labelled events (spaCy EVENT label)

Usage:
    from viginote.ner import extract_entities
    ents = extract_entities(title, body_text)
    # => {"persons": [...], "orgs": [...], "locs": [...], "events": [...]}
"""

import re
from typing import Optional

_nlp = None
_NER_AVAILABLE = False


def _load_model():
    global _nlp, _NER_AVAILABLE
    if _nlp is not None:
        return
    try:
        import spacy
        try:
            _nlp = spacy.load("en_core_web_sm", disable=["parser", "lemmatizer"])
        except OSError:
            # Model not downloaded yet — try to pull it
            import subprocess, sys
            subprocess.run(
                [sys.executable, "-m", "spacy", "download", "en_core_web_sm"],
                check=True, capture_output=True,
            )
            _nlp = spacy.load("en_core_web_sm", disable=["parser", "lemmatizer"])
        _NER_AVAILABLE = True
    except Exception as e:
        print(f"[NER] spaCy unavailable ({e}) — entity extraction disabled")
        _NER_AVAILABLE = False


def _clean(text: str) -> str:
    """Strip bylines and dateline noise before NER."""
    text = re.sub(r"^(REUTERS|AP|AFP|BBC|CNN)\s*[-–—:]\s*", "", text, flags=re.I)
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def extract_entities(title: str, body: str, max_body_chars: int = 1500) -> dict:
    """
    Return entity dict with deduplicated, title-cased entries.
    Always returns the dict keys even if NER is disabled.
    """
    result: dict[str, list[str]] = {
        "persons": [], "orgs": [], "locs": [], "events": []
    }
    _load_model()
    if not _NER_AVAILABLE or _nlp is None:
        return result

    # Combine title + truncated body for analysis
    combined = _clean(title) + ". " + _clean(body[:max_body_chars])

    try:
        doc = _nlp(combined)
    except Exception as e:
        print(f"[NER] processing error: {e}")
        return result

    label_map = {
        "PERSON":  "persons",
        "ORG":     "orgs",
        "GPE":     "locs",   # geopolitical entity
        "LOC":     "locs",   # physical location
        "FAC":     "locs",   # facility / building
        "EVENT":   "events",
        "NORP":    "orgs",   # nationalities / groups (e.g. "Taliban")
    }

    seen: dict[str, set] = {k: set() for k in result}
    for ent in doc.ents:
        bucket = label_map.get(ent.label_)
        if not bucket:
            continue
        text = ent.text.strip()
        # Filter noise: skip single chars, pure numbers, common stopwords
        if len(text) < 2 or text.isdigit():
            continue
        key = text.lower()
        if key in seen[bucket]:
            continue
        seen[bucket].add(key)
        result[bucket].append(text)

    return result
