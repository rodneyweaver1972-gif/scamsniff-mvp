# app.py — FULL FILE (env var + fallback to your Stripe TEST link)

import os, re, sqlite3
from datetime import datetime
from flask import Flask, render_template, request, jsonify, g

# ---------- App setup ----------
app = Flask(__name__, template_folder="templates", static_folder="static")

# SQLite DB (instance/scans.db by default)
DB_PATH = os.getenv("SCAM_SNIFF_DB", os.path.join("instance", "scans.db"))
os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)

# ---------- DB helpers ----------
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()

def init_db():
    db = get_db()
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS scans (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          text TEXT NOT NULL,
          score REAL NOT NULL,
          reasons TEXT NOT NULL,
          created_at TEXT NOT NULL
        );
        """
    )
    db.commit()

# ---------- Scoring ----------
PATTERNS = {
    "gift cards / codes": r"\bgift\s*card|\bsteam\s*card|\bitunes|\bgoogle\s*play\s*card|\bscratch\s*off",
    "crypto ask": r"\bbitcoin|\beth(?:ereum)?|\bcrypto|\bUSDT\b|\bwallet (?:address|id)",
    "urgent pressure": r"\burgent|\bimmediately|\bright now|\bwithin\s+\d+\s*(?:min|hour|day)s?",
    "sob story hook": r"\bwidow|\borphan|\bdeployment|\bmilitary\b|\bcancer|\bhospital\b",
    "alt payments": r"\bzelle\b|\bcash ?app\b|\bvenmo\b|\bwestern\s+union|\bmoney\s+gram",
    "shipping/agent": r"\bshipping\s+agent|\bprivate\s+courier|\barrange\s+pickup",
    "too good / advance": r"\badvance\s+payment|\bprepay\b|\boverpay\b|\bwiring\s+extra",
    "outside platform": r"\boff\s+platform|\bmessage\s+me\s+direct|\btelegram\b|\bwhatsapp\b",
}

def score_text(text: str):
    text_l = (text or "").lower()
    hits = []
    points = 0.0
    for label, rx in PATTERNS.items():
        if re.search(rx, text_l, re.I):
            hits.append(label); points += 1.0
    if len(text_l) > 400:
        hits.append("long message boost"); points += 0.5
    if re.search(r"https?://", text_l):
        hits.append("link present"); points += 0.5
    score = max(0.0, min(10.0, round(points, 2)))
    return score, hits

# ---------- Template global (reads env var, falls back to your test link) ----------
@app.context_processor
def inject_settings():
    return {
        "STRIPE_LINK": os.environ.get(
            "STRIPE_CHECKOUT_URL",
            "https://buy.stripe.com/test_14AfZg50W6Fh64g5dL5wI01"  # fallback
        )
    }

# ---------- Routes ----------
@app.route("/", methods=["GET"])
def home():
    return render_template("home.html")

@app.route("/result", methods=["POST"])
def result():
    text = request.form.get("message") or request.form.get("text")
    if not text and request.is_json:
        payload = request.get_json(silent=True) or {}
        text = payload.get("message") or payload.get("text") or ""
    score, reasons = score_text(text)
    db = get_db()
    db.execute(
        "INSERT INTO scans (text, score, reasons, created_at) VALUES (?, ?, ?, ?)",
        (text, score, "; ".join(reasons), datetime.utcnow().isoformat(timespec="seconds")),
    )
    db.commit()
    return render_template("result.html", original=text, text=text,
                           score=score, reasons=reasons, details=reasons)

@app.route("/history", methods=["GET"])
def history():
    rows = get_db().execute(
        "SELECT id, text, score, reasons, created_at FROM scans ORDER BY id DESC LIMIT 200"
    ).fetchall()
    return render_template("history.html", rows=rows)

@app.route("/pricing", methods=["GET"])
def pricing():
    return render_template("pricing.html")

@app.route("/api/score", methods=["POST"])
def api_score():
    data = request.get_json(force=True)
    text = data.get("text") or data.get("message") or ""
    score, reasons = score_text(text)
    return jsonify({"score": score, "reasons": reasons})

# ---------- Main ----------
if __name__ == "__main__":
    # open an application context before touching g/get_db()
    with app.app_context():
        init_db()
    print("Starting ScamSniff on http://127.0.0.1:5000", flush=True)
    app.run(host="127.0.0.1", port=5000, debug=True)
