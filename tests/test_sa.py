"""End-to-end tests for the SA edition using synthetic feeds (no network)."""
import os, sys, time, tempfile
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
os.environ["DB_PATH"] = os.path.join(tempfile.mkdtemp(), "t.db")
os.environ["ADMIN_SECRET"] = "s3cret"
os.environ["SA_SITE_AUTOPUBLISH"] = "0"

from viginote.db import init_db
from viginote import sa_pipeline as P
from viginote.sa_geo import detect_location
from viginote.sa_topics import classify_topic, importance
from viginote.sa_sources import rss_sources, SA_SOURCES

def rss(items):
    now = time.strftime("%a, %d %b %Y %H:%M:%S +0000", time.gmtime())
    body = "".join(f"<item><title>{t}</title><link>{l}</link><description>{d}</description><pubDate>{now}</pubDate></item>" for t, l, d in items)
    return f'<?xml version="1.0"?><rss version="2.0"><channel><title>x</title>{body}</channel></rss>'.encode()

def test_geo():
    assert detect_location("Gunmen kill two in Soweto")["province"] == "Gauteng"
    assert detect_location("Floods hit Khayelitsha")["city"] == "Cape Town"
    assert detect_location("Water crisis in KZN")["province"] == "KwaZulu-Natal"
    assert detect_location("Parliament debates budget")["province"] == "National"
    assert detect_location("Mr George said hello")["place"] == ""

def test_topics():
    assert classify_topic("Portfolio committee hears SAPS crime stats", "", "general") in ("parliament", "crime")
    assert classify_topic("Eskom announces stage 4 load-shedding", "", "general") == "services"
    assert classify_topic("Reserve Bank holds repo rate", "", "general") == "economy"
    assert importance("Mass shooting leaves 12 dead in Soweto", "", 2, 1, True) >= 6
    assert importance("Minister opens new library", "", 2, 1, False) <= 2

def test_sources():
    assert len(rss_sources()) >= 40
    urls = [s["url"] for s in SA_SOURCES]
    assert len(urls) == len(set(urls))

def test_pipeline_and_dedupe():
    conn = init_db()
    src = {"name": "Test News", "url": "http://t/1", "category": "general", "tier": 2, "kind": "rss", "domain": "t"}
    src2 = {"name": "Other News", "url": "http://t/2", "category": "general", "tier": 2, "kind": "rss", "domain": "o"}
    off = {"name": "SAPS", "url": "http://t/3", "category": "crime", "tier": 3, "kind": "rss", "domain": "saps.gov.za"}
    a = rss([("Mass shooting in Soweto leaves 12 dead", "http://t/a1", "<p>Police say gunmen opened fire at a tavern.</p>"),
             ("Springboks win rugby test", "http://t/a2", "sport"),
             ("Minister opens library", "http://t/a3", "ribbon")])
    b = rss([("Mass shooting in Soweto leaves twelve dead", "http://o/b1", "Tavern attack")])
    c = rss([("SAPS arrests suspects after Gauteng cash-in-transit heist", "http://t/c1", "Three arrested.")])
    st = P.run_once(conn, [src, src2, off], fetched=[(src, a, ""), (src2, b, ""), (off, c, ""), ({"name":"bad","url":"http://bad","category":"general","tier":1,"kind":"rss","domain":"bad"}, None, "HTTP 404")])
    assert st["feeds_failed"] == 1 and st["feeds_ok"] == 3
    assert st["dupes"] == 1, st
    rows = conn.execute("SELECT title,status,province,topic,corroboration,level FROM sa_articles ORDER BY id").fetchall()
    titles = [r[0] for r in rows]
    assert not any("Springboks" in t for t in titles), titles
    top = next(r for r in rows if "Soweto" in r[0])
    assert top[1] == "pending" and top[2] == "Gauteng" and top[4] == 2
    # second run is idempotent
    st2 = P.run_once(conn, [src], fetched=[(src, a, "")])
    assert st2["stored"] == 0

def test_site_and_social():
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from viginote import sa_site
    conn = init_db(); P.init_sa(conn)
    sa_site.configure(lambda: conn)
    app = FastAPI(); app.include_router(sa_site.router)
    cl = TestClient(app)
    ids = [r[0] for r in conn.execute("SELECT id FROM sa_articles").fetchall()]
    assert ids
    # public sees nothing until approved
    assert cl.get("/za/api/articles").json()["count"] == 0
    assert cl.get("/za/admin/queue").status_code == 401
    assert cl.get("/za/admin/queue", headers={"X-Admin-Secret": "wrong"}).status_code == 401
    H = {"X-Admin-Secret": "s3cret"}
    q = cl.get("/za/admin/queue", headers=H).json()
    assert q["count"] >= 2
    aid = q["articles"][0]["id"]
    assert cl.get(f"/za/report/{aid}.pdf").status_code == 404
    assert cl.get(f"/za/admin/social/{aid}.zip", headers=H).status_code == 404
    assert cl.post("/za/admin/review", json={"id": aid, "action": "approve"}, headers=H).status_code == 200
    pub = cl.get("/za/api/articles").json()
    assert pub["count"] == 1 and "article_text" not in pub["articles"][0]
    pdf = cl.get(f"/za/report/{aid}.pdf")
    assert pdf.status_code == 200 and pdf.content[:4] == b"%PDF"
    # instagram needs explicit approval
    assert cl.get(f"/za/admin/social/{aid}.zip", headers=H).status_code == 404
    cl.post("/za/admin/review", json={"id": aid, "action": "instagram"}, headers=H)
    z = cl.get(f"/za/admin/social/{aid}.zip", headers=H)
    assert z.status_code == 200
    import zipfile, io
    names = zipfile.ZipFile(io.BytesIO(z.content)).namelist()
    assert sorted(names) == ["caption.txt", "slide1.png", "slide2.png", "slide3.png", "slide4.png"], names
    cl.post("/za/admin/correction", json={"id": aid, "text": "Updated death toll."}, headers=H)
    assert cl.get("/za/api/corrections").json()["corrections"][0]["text"] == "Updated death toll."
    b = cl.get("/za/api/briefing").json()
    assert b["top"] and b["by_topic"]
    assert cl.get("/za").status_code == 200 and "VigiNote" in cl.get("/za").text
    assert cl.get("/za/admin").status_code == 200
    assert cl.get("/za/api/sources").json()["sources"]

def test_admin_disabled_without_secret():
    from viginote import sa_site
    os.environ["ADMIN_SECRET"] = ""
    try:
        try:
            sa_site._admin("anything"); assert False
        except Exception as e:
            assert getattr(e, "status_code", 0) == 401
    finally:
        os.environ["ADMIN_SECRET"] = "s3cret"

if __name__ == "__main__":
    for n, f in list(globals().items()):
        if n.startswith("test_"):
            f(); print("ok", n)
