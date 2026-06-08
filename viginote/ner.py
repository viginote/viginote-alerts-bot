"""
ner.py — Named Entity Recognition for VigiNote.

Uses spaCy en_core_web_sm if available.
Falls back gracefully to empty entities if spaCy or model not installed.
spaCy is optional — removing it from requirements.txt disables NER silently.
"""

import re

_nlp = None
_NER_AVAILABLE = False
_load_attempted = False


def _load_model():
    global _nlp, _NER_AVAILABLE, _load_attempted
    if _load_attempted:
        return
    _load_attempted = True
    try:
        import spacy
        _nlp = spacy.load("en_core_web_sm", disable=["parser", "lemmatizer"])
        _NER_AVAILABLE = True
        print("[NER] spaCy en_core_web_sm loaded OK")
    except ImportError:
        print("[NER] spaCy not installed — entity extraction disabled")
    except OSError:
        print("[NER] en_core_web_sm model not found — entity extraction disabled")
    except Exception as e:
        print(f"[NER] unavailable ({e}) — entity extraction disabled")


def _clean(text: str) -> str:
    text = re.sub(r"^(REUTERS|AP|AFP|BBC|CNN)\s*[-–—:]\s*", "", text, flags=re.I)
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def extract_entities(title: str, body: str, max_body_chars: int = 1500) -> dict:
    """
    Return entity dict. Always returns all keys even if NER is disabled.
    """
    result = {"persons": [], "orgs": [], "locs": [], "events": []}
    _load_model()
    if not _NER_AVAILABLE or _nlp is None:
        return result

    combined = _clean(title) + ". " + _clean(body[:max_body_chars])
    try:
        doc = _nlp(combined)
    except Exception as e:
        print(f"[NER] processing error: {e}")
        return result

    label_map = {
        "PERSON": "persons",
        "ORG":    "orgs",
        "GPE":    "locs",
        "LOC":    "locs",
        "FAC":    "locs",
        "EVENT":  "events",
        "NORP":   "orgs",
    }

    seen = {k: set() for k in result}
    for ent in doc.ents:
        bucket = label_map.get(ent.label_)
        if not bucket:
            continue
        text = ent.text.strip()
        if len(text) < 2 or text.isdigit():
            continue
        key = text.lower()
        if key in seen[bucket]:
            continue
        seen[bucket].add(key)
        result[bucket].append(text)

    return result
