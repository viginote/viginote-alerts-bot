"""
summary.py — AI-powered (or heuristic) one-line summarisation.
"""

import os
import re

import requests

from viginote.feeds import first_sentence

OPENAI_API_KEY   = os.getenv("OPENAI_API_KEY", "")
OPENAI_MODEL     = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
AI_ENABLED       = os.getenv("AI_ENABLED", "1") == "1"
AI_TIMEOUT       = int(os.getenv("AI_TIMEOUT", "12"))
AI_MAX_TOKENS    = int(os.getenv("AI_MAX_TOKENS", "60"))
PRECIS_MAX_CHARS = int(os.getenv("PRECIS_MAX_CHARS", "120"))


def concise_summary(title: str, text: str) -> str:
    """
    Return a single factual line <= PRECIS_MAX_CHARS.
    Uses OpenAI gpt-4o-mini if key is set, else heuristic first-sentence.
    """
    if not text:
        t = title.strip()
        return (t[:PRECIS_MAX_CHARS] + "…") if len(t) > PRECIS_MAX_CHARS else t

    fallback = first_sentence(text, max_chars=PRECIS_MAX_CHARS)

    if not (AI_ENABLED and OPENAI_API_KEY):
        return fallback

    prompt = (
        f"Summarize the event in ONE line (<= {PRECIS_MAX_CHARS} characters). "
        f"Plain factual wording. No extra details, no emojis.\n\n"
        f"Title: {title}\n\nText: {text[:2400]}"
    )

    try:
        resp = requests.post(
            "https://api.openai.com/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {OPENAI_API_KEY}",
                "Content-Type": "application/json",
            },
            json={
                "model":       OPENAI_MODEL,
                "messages":    [{"role": "user", "content": prompt}],
                "max_tokens":  AI_MAX_TOKENS,
                "temperature": 0.2,
            },
            timeout=AI_TIMEOUT,
        )
        j = resp.json()
        if not j.get("choices"):
            return fallback
        out = j["choices"][0]["message"]["content"].strip()
        out = re.sub(r"\s+", " ", out)
        return (out[:PRECIS_MAX_CHARS] + "…") if len(out) > PRECIS_MAX_CHARS else out
    except Exception as e:
        print("[AI SUMMARY ERROR]", e)
        return fallback
