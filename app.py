from __future__ import annotations
import os, sqlite3, re
from datetime import datetime, timezone
from typing import Dict, List
from flask import Flask, render_template, request, jsonify, g, send_from_directory, redirect, url_for

# =============== Flask + DB setup =================
app = Flask(__name__)
app.config.update(
    DATABASE=os.environ.get("SCAM_SNIFF_DB", os.path.join(os.path.dirname(__file__), "scans.db")),
)

def get_db() -> sqlite3.Connection:
    if "db" not in g:
        g.db = sqlite3.connect(app.config["DATABASE"])
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()

def init_db() -> None:
    db = get_db()
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            message TEXT NOT NULL,
            score REAL NOT NULL,
            summary TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
        """
    )
    db.commit()

# =============== Simple scoring logic ===============
KEYWORDS = {
    "bitcoin": 0.5,
    "gift card": 0.7,
    "gift cards": 0.7,
    "cash app": 0.4,
    "wire": 0.4,
    "zelle": 0.4,
    "check": 0.3,
    "urgent": 0.25,
    "code": 0.25,
}

def analyze_logic(message: str) -> Dict:
    msg = (message or "").lower()
    signals: List[str] = []

    score = 0.0
    for kw, w in KEYWORDS.items():
        if kw in msg:
            signals.append(f"Keyword: {kw}")
            score += w

    # common scam patterns
    patterns = [
        (r"pay\s+me\s+with\s+gift\s+cards", 0.7, "Pattern: asks to pay with gift cards"),
        (r"i'?m\s+stranded|mother'?s\s+sick|family\s+emergency", 0.4, "Pattern: urgent sob story"),
        (r"send\s+bitcoin|btc", 0.5, "Pattern: asks for crypto"),
        (r"can\s+you\s+cash\s+(a|my)\s+check", 0.4, "Pattern: check-cashing request"),
    ]
    for rx, w, label in patterns:
        if re.search(rx, msg, flags=re.I):
            signals.append(label)
            score += w

    score = max(0.0, min(1.0, round(score, 2)))

    if score >= 0.7:
        summary = "Scam likelihood: HIGH"
    elif score >= 0.4:
        summary = "Scam likelihood: MEDIUM"
    else:
        summary = "Scam likelihood: LOW"

    return {
        "ok": True,
        "score": score,
        "signals": signals[:20],
        "summary": summary,
    }

# =============== Routes (pages) ====================
@app.get("/")
def home():
    return render_template("home.html")

@app.get("/history")
def history():
    db = get_db()
    rows = db.execute(
        "SELECT created_at, score, summary, message FROM scans ORDER BY created_at DESC LIMIT 100"
    ).fetchall()
    return render_template("history.html", rows=rows)

@app.get("/pricing")
def pricing():
    return render_template("pricing.html")

# =============== API: analyze message ==============
@app.route("/api/analyze", methods=["POST", "OPTIONS"])
def api_analyze():
    if request.method == "OPTIONS":
        return ("", 204)
    try:
        data = request.get_json(silent=True) or {}
        # accept both "message" and "text"
        message = (data.get("message") or data.get("text") or "").strip()
        if not message:
            return jsonify({"ok": False, "error": "message is required"}), 400

        out = analyze_logic(message)

        # Save to DB (always)
        db = get_db()
        db.execute(
            "INSERT INTO scans (message, score, summary, created_at) VALUES (?, ?, ?, ?)",
            (message, out["score"], out["summary"], datetime.now(timezone.utc).isoformat()),
        )
        db.commit()

        return jsonify(out), 200
    except Exception as e:
        app.logger.exception("api_analyze failed")
        return jsonify({"ok": False, "error": f"Server error: {e}"}), 500

# (Optional) success page placeholder
@app.get("/success")
def success():
    return render_template("result.html")

# =============== Minimal social profile check (stub) ===============
# Keeps your front-end JS happy; returns a low-risk placeholder.
@app.post("/api/social_check")
def social_check():
    data = request.get_json(silent=True) or {}
    url = (data.get("url") or "").strip()
    if not url:
        return jsonify({"ok": False, "error": "url is required"}), 400
    # very light stubbed response
    return jsonify({
        "ok": True,
        "platform": "unknown",
        "status": "n/a",
        "signals": [],
        "summary": "Profile check is a preview feature.",
        "score": 0.1
    })

# =============== Entrypoint (local) ===============
if __name__ == "__main__":
    with app.app_context():
        init_db()
    print("Starting ScamSniff on http://127.0.0.1:5000", flush=True)
    app.run(host="127.0.0.1", port=5000, debug=True)
