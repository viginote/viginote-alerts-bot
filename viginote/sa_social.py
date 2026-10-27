"""
sa_social.py — Instagram carousel (PNG slides + caption) and one-page report PDF
for an approved South Africa article.

Slides (1080x1350):
  1 headline + level badge + topic
  2 what / where
  3 why it matters (source summary)
  4 sources, confidence and link-in-bio call to action
Only headline, short summary, source name and link are used — never full text.
"""
from __future__ import annotations

import io
import os
import textwrap
import time
import zipfile

from PIL import Image, ImageDraw, ImageFont

from viginote.sa_topics import TOPICS

W, H = 1080, 1350
BG, FG, MUTED = (11, 18, 32), (240, 244, 250), (150, 162, 184)
LEVEL_COL = {"critical": (220, 53, 69), "high": (245, 124, 0), "elevated": (240, 180, 41), "routine": (76, 175, 125)}
BRAND = os.getenv("SA_BRAND", "VigiNote ZA")
HANDLE = os.getenv("SA_INSTAGRAM_HANDLE", "@viginote.za")
SITE = os.getenv("PUBLIC_BASE_URL", "viginote.com").replace("https://", "").replace("http://", "").rstrip("/")

_FONT_DIRS = ["/usr/share/fonts/truetype/dejavu/", "/usr/share/fonts/dejavu/", "/Library/Fonts/", "C:/Windows/Fonts/"]


def _font(size: int, bold=False):
    names = ["DejaVuSans-Bold.ttf" if bold else "DejaVuSans.ttf", "Arial Bold.ttf" if bold else "Arial.ttf",
             "arialbd.ttf" if bold else "arial.ttf"]
    for d in _FONT_DIRS:
        for n in names:
            try:
                return ImageFont.truetype(os.path.join(d, n), size)
            except OSError:
                continue
    try:
        return ImageFont.load_default(size=size)
    except TypeError:
        return ImageFont.load_default()


def confidence(a: dict) -> tuple[str, str]:
    n = a.get("corroboration") or 1
    if a.get("source_tier", 1) >= 3:
        return "Official source", "Published by the responsible body. Not independently verified by us."
    if n >= 3:
        return "Reported by multiple outlets", f"{n} outlets reported this story."
    if n == 2:
        return "Two outlets", "Two outlets reported this story."
    return "Single source", "One outlet so far. Treat as unconfirmed."


def _wrap(draw, text, font, width):
    lines, cur = [], ""
    for word in text.split():
        t = f"{cur} {word}".strip()
        if draw.textlength(t, font=font) <= width:
            cur = t
        else:
            if cur:
                lines.append(cur)
            cur = word
    if cur:
        lines.append(cur)
    return lines


def _block(draw, xy, text, font, fill, width, spacing=12, max_lines=None):
    x, y = xy
    lines = _wrap(draw, text, font, width)
    if max_lines and len(lines) > max_lines:
        lines = lines[:max_lines]
        lines[-1] = lines[-1].rstrip(" .,;") + "…"
    for ln in lines:
        draw.text((x, y), ln, font=font, fill=fill)
        y += font.size + spacing
    return y


def _frame(n, total, a):
    im = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(im)
    col = LEVEL_COL.get(a.get("level", "routine"), LEVEL_COL["routine"])
    d.rectangle([0, 0, W, 14], fill=col)
    d.text((70, 60), BRAND.upper(), font=_font(34, True), fill=FG)
    d.text((W - 70, 64), f"{n}/{total}", font=_font(30), fill=MUTED, anchor="ra")
    d.text((70, H - 80), f"{HANDLE}  ·  {time.strftime('%d %b %Y', time.localtime(a.get('ts', time.time())))}",
           font=_font(28), fill=MUTED)
    return im, d, col


def build_slides(a: dict) -> list[bytes]:
    topic = TOPICS.get(a.get("topic", "general"), "Current Affairs")
    place = ", ".join(x for x in [a.get("city") or a.get("place"), a.get("province")] if x and x != a.get("place")) \
        or a.get("place") or "South Africa"
    conf, conf_note = confidence(a)
    slides = []

    im, d, col = _frame(1, 4, a)
    d.rounded_rectangle([70, 190, 70 + 330, 190 + 70], 14, fill=col)
    d.text((70 + 165, 225), a.get("level", "routine").upper(), font=_font(34, True), fill=(255, 255, 255), anchor="mm")
    d.text((70, 300), topic.upper(), font=_font(32, True), fill=MUTED)
    _block(d, (70, 370), a["title"], _font(64, True), FG, W - 140, 16, 9)
    d.text((70, H - 160), "Swipe for details  →", font=_font(34), fill=col)
    slides.append(im)

    im, d, col = _frame(2, 4, a)
    d.text((70, 200), "WHAT", font=_font(30, True), fill=col)
    y = _block(d, (70, 250), a["title"], _font(44, True), FG, W - 140, 12, 5)
    d.text((70, y + 60), "WHERE", font=_font(30, True), fill=col)
    _block(d, (70, y + 110), place, _font(52, True), FG, W - 140)
    d.text((70, y + 260), "TOPIC", font=_font(30, True), fill=col)
    _block(d, (70, y + 310), topic, _font(44), FG, W - 140)
    slides.append(im)

    im, d, col = _frame(3, 4, a)
    d.text((70, 200), "WHY IT MATTERS", font=_font(30, True), fill=col)
    body = a.get("summary") or "Read the original report for full details."
    _block(d, (70, 260), body, _font(46), FG, W - 140, 16, 14)
    slides.append(im)

    im, d, col = _frame(4, 4, a)
    d.text((70, 200), "SOURCE", font=_font(30, True), fill=col)
    y = _block(d, (70, 250), a.get("source_name", ""), _font(50, True), FG, W - 140)
    d.text((70, y + 50), "CONFIDENCE", font=_font(30, True), fill=col)
    y = _block(d, (70, y + 100), conf, _font(44, True), FG, W - 140)
    y = _block(d, (70, y + 10), conf_note, _font(34), MUTED, W - 140)
    d.text((70, H - 330), "Full report as PDF + original link:", font=_font(34), fill=MUTED)
    d.text((70, H - 270), "Link in bio  →  " + SITE, font=_font(44, True), fill=FG)
    slides.append(im)

    out = []
    for s in slides:
        b = io.BytesIO()
        s.save(b, "PNG", optimize=True)
        out.append(b.getvalue())
    return out


def build_caption(a: dict) -> str:
    topic = TOPICS.get(a.get("topic", "general"), "Current Affairs")
    conf, _ = confidence(a)
    place = a.get("city") or a.get("place") or ""
    tags = ["#SouthAfrica", "#SANews", f"#{topic.split(' ')[0].replace(',', '').replace('&', '')}"]
    if a.get("province") and a["province"] != "National":
        tags.append("#" + a["province"].replace(" ", "").replace("-", ""))
    lines = [f"{a['level'].upper()} · {a['title']}", ""]
    if a.get("summary"):
        lines += [a["summary"], ""]
    lines += [f"📍 {place}" if place else "", f"Source: {a.get('source_name', '')} ({conf.lower()})",
              "Full report + original link: link in bio.", "",
              "Reported from public sources. Spot an error? Message us and we'll correct it.", "", " ".join(tags)]
    return "\n".join(x for x in lines if x is not None).strip()


def build_zip(a: dict) -> bytes:
    b = io.BytesIO()
    with zipfile.ZipFile(b, "w", zipfile.ZIP_DEFLATED) as z:
        for i, png in enumerate(build_slides(a), 1):
            z.writestr(f"slide{i}.png", png)
        z.writestr("caption.txt", build_caption(a))
    return b.getvalue()


def build_pdf(a: dict) -> bytes:
    """One-page report. Headline, short summary, source and link only."""
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.platypus import HRFlowable, Paragraph, SimpleDocTemplate, Spacer
    from xml.sax.saxutils import escape as esc

    topic = TOPICS.get(a.get("topic", "general"), "Current Affairs")
    conf, conf_note = confidence(a)
    place = ", ".join(x for x in [a.get("city"), a.get("province")] if x) or a.get("place") or "South Africa"
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=22 * mm, rightMargin=22 * mm, topMargin=20 * mm,
                            bottomMargin=20 * mm, title=a["title"], author=BRAND)
    h0 = ParagraphStyle("h0", fontName="Helvetica-Bold", fontSize=10, textColor="#6b7a90", spaceAfter=6)
    h1 = ParagraphStyle("h1", fontName="Helvetica-Bold", fontSize=22, leading=27, spaceAfter=10)
    meta = ParagraphStyle("meta", fontName="Helvetica", fontSize=10.5, leading=15, textColor="#33415c")
    body = ParagraphStyle("body", fontName="Helvetica", fontSize=12.5, leading=19, spaceAfter=10)
    small = ParagraphStyle("small", fontName="Helvetica", fontSize=9, leading=13, textColor="#6b7a90")
    date = time.strftime("%d %B %Y", time.localtime(a.get("ts", time.time())))
    story = [
        Paragraph(f"{esc(BRAND.upper())} · {esc(topic.upper())} · {a.get('level', '').upper()}", h0),
        Paragraph(esc(a["title"]), h1),
        Paragraph(f"<b>Where:</b> {esc(place)} &nbsp;&nbsp; <b>Date:</b> {date}", meta),
        Spacer(1, 6), HRFlowable(width="100%", color="#c8d0dc"), Spacer(1, 10),
        Paragraph(esc(a.get("summary") or "See the original report for details."), body),
        Spacer(1, 6),
        Paragraph(f"<b>Source:</b> {esc(a.get('source_name', ''))}", meta),
        Paragraph(f"<b>Original report:</b> <link href='{esc(a['url'])}' color='blue'>{esc(a['url'])}</link>", meta),
        Paragraph(f"<b>Confidence:</b> {esc(conf)} — {esc(conf_note)}", meta),
        Spacer(1, 18), HRFlowable(width="100%", color="#c8d0dc"), Spacer(1, 6),
        Paragraph("This is a short summary compiled from public sources. It links to the original publisher and "
                  "does not reproduce their article. If you spot an error, tell us and we will publish a correction. "
                  "Not legal, safety or financial advice.", small),
    ]
    doc.build(story)
    return buf.getvalue()
