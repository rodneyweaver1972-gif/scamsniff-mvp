from __future__ import annotations
import os, sqlite3
from datetime import datetime, timezone
from typing import Dict
from flask import Flask, render_template, request, jsonify, g, send_from_directory

# ---------------- Flask setup ----------------
app = Flask(__name__)
app.config.update(
    DATABASE=os.environ.get(
        "SCAM_SNIFF_DB",
        os.path.join(os.path.dirname(__file__), "scans.db"),
    )
)

# Allow browser JS to call our API
@app.after_request
def add_cors(resp):
    resp.headers["Access-Control-Allow-Origin"] = "*"
    resp.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    resp.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    return resp

# ---------------- DB helpers ----------------
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(app.config["DATABASE"])
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()

def init_db():
    db = get_db()
    db.executescript("""
    CREATE TABLE IF NOT EXISTS scans(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        message    TEXT NOT NULL,
        score      REAL NOT NULL,
        summary    TEXT NOT NULL,
        created_at TEXT NOT NULL
    );
    """)
    db.commit()

# Ensure DB exists when the app module is imported (works for Gunicorn/Render too)
with app.app_context():
    init_db()

# ---------------- Simple scoring ----------------
KEYWORDS = [
    ("gift card", 0.6),
    ("bitcoin", 0.5),
    ("western union", 0.5),
    ("zelle", 0.4),
    ("wire transfer", 0.4),
    ("urgent", 0.3),
    ("verify your account", 0.5),
    ("login now", 0.4),
    ("ssn", 0.6),
    ("bank details", 0.5),
]

def analyze_logic(message: str) -> Dict:
    text = (message or "").lower()
    hits = []
    total = 0.10  # baseline
    for kw, w in KEYWORDS:
        if kw in text:
            hits.append({"name": f"Keyword: {kw}", "score": w})
            total += w
    total = min(total, 0.99)
    label = "HIGH" if total >= 0.75 else "MEDIUM" if total >= 0.45 else "LOW"
    return {
        "ok": True,
        "summary": f"Scam likelihood: {label}",
        "score": round(total, 2),
        "signals": hits,
        "echo": message
    }

# ---------------- Pages ----------------
@app.route("/")
def home():
    return render_template("home.html")

@app.route("/history")
def history():
    db = get_db()
    rows = db.execute(
        "SELECT id, message, score, summary, created_at AS created "
        "FROM scans ORDER BY id DESC LIMIT 100"
    ).fetchall()
    return render_template("history.html", scans=rows)

# Optional: favicon route (silences 404 in logs if you add static/favicon.ico)
@app.route("/favicon.ico")
def favicon():
    static_dir = os.path.join(app.root_path, "static")
    icon_path = os.path.join(static_dir, "favicon.ico")
    if os.path.exists(icon_path):
        return send_from_directory(static_dir, "favicon.ico")
    return ("", 204)

# ---------------- JSON API for the Scan box ----------------
@app.route("/api/analyze", methods=["POST", "OPTIONS"])
def api_analyze():
    if request.method == "OPTIONS":
        return ("", 204)
    try:
        data = request.get_json(silent=True) or {}
        message = (data.get("message") or "").strip()
        if not message:
            return jsonify({"ok": False, "error": "message is required"}), 400

        out = analyze_logic(message)

        # Save to DB
        db = get_db()
        db.execute(
            "INSERT INTO scans (message, score, summary, created_at) VALUES (?, ?, ?, ?)",
            (message, out["score"], out["summary"], datetime.now(timezone.utc).isoformat())
        )
        db.commit()

        return jsonify(out), 200
    except Exception as e:
        app.logger.exception("api_analyze failed")
        return jsonify({"ok": False, "error": f"Server error: {e}"}), 500

# ---------------- Entrypoint (local run) ----------------
if __name__ == "__main__":
    # Also ensure DB when running locally
    with app.app_context():
        init_db()
    print("Starting ScamSniff on http://127.0.0.1:5000", flush=True)
    app.run(host="127.0.0.1", port=5000, debug=True)
