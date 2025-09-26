from __future__ import annotations
import os, sqlite3, re
from datetime import datetime, timezone
from typing import Dict
from flask import (
    Flask,
    render_template,
    request,
    jsonify,
    g,
    send_from_directory,
    redirect,
    url_for,
)

# ===================== Flask setup =====================
app = Flask(__name__)
app.config.update(
    DATABASE=os.environ.get(
        "SCAM_SNIFF_DB",
        os.path.join(os.path.dirname(__file__), "scans.db"),
    )
)

# Allow the page JS to call our API (simple CORS)
@app.after_request
def add_cors(resp):
    resp.headers["Access-Control-Allow-Origin"] = "*"
    resp.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    resp.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    return resp


# ===================== DB helpers ======================
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
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS scans(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            message    TEXT NOT NULL,
            score      REAL NOT NULL,
            summary    TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        """
    )
    db.commit()

# Ensure DB exists even under Gunicorn/Render
with app.app_context():
    init_db()


# ============== Scam scoring rules (tunable) ===========
PHRASES = {
    "payment_methods": [
        ("gift card", 0.60), ("gift cards", 0.60),
        ("bitcoin", 0.50), ("western union", 0.50), ("moneygram", 0.45),
        ("zelle", 0.40), ("cash app", 0.40),
        ("wire transfer", 0.40), ("prepaid card", 0.45),
        ("google play card", 0.55), ("apple gift card", 0.55),
    ],
    "check_overpayment": [
        ("cashier's check", 0.50), ("cash a check", 0.50), ("cash the check", 0.50),
        ("overpay", 0.40), ("over payment", 0.40),
        ("refund the extra", 0.40), ("send the rest", 0.40),
        ("shipping agent", 0.40), ("mover will pick up", 0.40),
        ("deposit the check", 0.40),
    ],
    "sob_story": [
        ("mother is sick", 0.30), ("my mother's sick", 0.30),
        ("family emergency", 0.30), ("stranded", 0.30),
        ("hospital", 0.30), ("surgery", 0.30), ("dying", 0.30),
    ],
    "urgency": [
        ("urgent", 0.30), ("immediately", 0.25),
        ("right now", 0.20), ("asap", 0.20),
    ],
}

def _score_bucket(text: str, bucket: str):
    score = 0.0
    hits = []
    any_hit = False
    for phrase, w in PHRASES[bucket]:
        if phrase in text:
            any_hit = True
            hits.append({"name": f"Keyword: {phrase}", "score": w})
            score += w
    return score, hits, any_hit

def analyze_logic(message: str) -> Dict:
    text = (message or "").lower()

    total = 0.10  # small baseline so nothing shows 0.00
    signals = []

    pm_score, pm_hits, pm_any = _score_bucket(text, "payment_methods")
    co_score, co_hits, co_any = _score_bucket(text, "check_overpayment")
    ss_score, ss_hits, ss_any = _score_bucket(text, "sob_story")
    ur_score, ur_hits, ur_any = _score_bucket(text, "urgency")

    total += pm_score + co_score + ss_score + ur_score
    signals.extend(pm_hits + co_hits + ss_hits + ur_hits)

    # ----- Combo bonuses (common scam patterns) -----
    # Sob story + unusual payment method
    if pm_any and ss_any:
        signals.append({"name": "Pattern: sob story + unusual payment method", "score": 0.25})
        total += 0.25

    # Check overpayment patterns (mentions check + action)
    if co_any and ("cash" in text or "deposit" in text or "send the rest" in text or "refund" in text):
        signals.append({"name": "Pattern: check overpayment", "score": 0.25})
        total += 0.25

    # Gift card + urgency
    if pm_any and ur_any and ("gift card" in text or "gift cards" in text):
        signals.append({"name": "Pattern: urgent gift-card payment", "score": 0.20})
        total += 0.20

    # Clamp and label
    total = max(0.0, min(total, 0.99))
    label = "HIGH" if total >= 0.75 else "MEDIUM" if total >= 0.45 else "LOW"

    return {
        "ok": True,
        "summary": f"Scam likelihood: {label}",
        "score": round(total, 2),
        "signals": signals,
        "echo": message,
    }


# ===================== Pages & routes ===================
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

# Visiting /result directly? Send them home.
@app.route("/result", methods=["GET"])
def result_get():
    return redirect(url_for("home"))

# Optional favicon (avoids 404s if you don't have one)
@app.route("/favicon.ico")
def favicon():
    static_dir = os.path.join(app.root_path, "static")
    icon_path = os.path.join(static_dir, "favicon.ico")
    if os.path.exists(icon_path):
        return send_from_directory(static_dir, "favicon.ico")
    return ("", 204)


# ===================== JSON API =========================
@app.route("/api/analyze", methods=["POST", "OPTIONS"])
def api_analyze():
    if request.method == "OPTIONS":
        return ("", 204)

    try:
        data = request.get_json(silent=True) or {}
        # ✅ Accept both "message" and "text"
        message = (data.get("message") or data.get("text") or "").strip()
        if not message:
            return jsonify({"ok": False, "error": "message is required"}), 400

        out = analyze_logic(message)

        # Save to DB
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



@app.get("/success")
def success():
    return _render("success")

# ---------- Social Profile Check (heuristics) ----------
import httpx
from bs4 import BeautifulSoup

PLATFORMS = {
    "facebook": re.compile(r"^https?://(www\.)?facebook\.com/[^/?#]+", re.I),
    "x": re.compile(r"^https?://(www\.)?(x\.com|twitter\.com)/[^/?#]+", re.I),
    "linkedin": re.compile(r"^https?://(www\.)?linkedin\.com/(in|company)/[^/?#]+", re.I),
    "instagram": re.compile(r"^https?://(www\.)?instagram\.com/[^/?#]+", re.I),
    "tiktok": re.compile(r"^https?://(www\.)?tiktok\.com/@[^/?#]+", re.I),
}

def _detect_platform(url: str):
    for name, pat in PLATFORMS.items():
        if pat.search(url.strip()):
            return nameS
    return None

def _fetch(url: str):
    headers = {"User-Agent": "Mozilla/5.0 (ScamSniff Profile Check)"}
    with httpx.Client(headers=headers, follow_redirects=True, timeout=6.0) as c:
        try:
            head = c.head(url)
        except Exception:
            head = None
        try:
            get = c.get(url)
        except Exception:
            get = None
    return head, get

NEG_STRINGS = [
    "page isn't available", "page not found", "doesn't exist", "not found",
    "this account doesn’t exist", "this account doesn't exist", "suspended",
    "removed", "deactivated", "blocked", "you must log in", "sign in to continue"
]

def _analyze_html(html: str):
    sigs = []
    soup = BeautifulSoup(html or "", "html.parser")
    if not soup.find("meta", property="og:title"):
        sigs.append("Missing og:title")
    if not soup.find("meta", property="og:description"):
        sigs.append("Missing og:description")
    meta_text = " ".join([
        soup.title.string if soup.title and soup.title.string else "",
        *[m.get("content", "") for m in soup.find_all("meta")]
    ]).lower()
    for bad in NEG_STRINGS:
        if bad in meta_text:
            sigs.append(f'Page indicates: "{bad}"')
    if len(html or "") < 2000:
        sigs.append("Very small page response (login wall or error)")
    return sigs

def _score(sigs, platform_detected, status_code):
    score = 0.5
    if not platform_detected:
        score += 0.25
    if status_code and status_code >= 400:
        score += 0.3
    for s in sigs:
        if s.startswith("Missing og:"):
            score += 0.05
        if s.startswith("Page indicates:"):
            score += 0.25
        if "Very small page" in s:
            score += 0.1
    return max(0.0, min(1.0, score))

@app.route("/api/social_check", methods=["POST"])
def social_check():
    data = request.get_json(silent=True) or {}
    url = (data.get("url") or "").strip()
    if not url:
        return jsonify({"error": "Missing 'url'"}), 400

    platform = _detect_platform(url)
    head, get = _fetch(url)
    status = get.status_code if get is not None else None
    html = get.text if get is not None else ""

    sigs = []
    if head is not None and head.status_code in (301, 302) and "login" in (head.headers.get("location", "").lower()):
        sigs.append("Redirected to login (profile may be private)")
    if html:
        sigs.extend(_analyze_html(html))
    else:
        sigs.append("No HTML fetched (network error or blocked)")

    score = round(_score(sigs, platform, status), 2)
    summary = f"Platform: {platform or 'unknown'}; HTTP: {status or 'n/a'}; Signals: {len(sigs)}; Risk: {score}"

    return jsonify({
        "score": score,
        "summary": summary,
        "platform": platform,
        "status": status,
        "signals": sigs[:20],
    })
# ---------- /Social Profile Check ----------

# ---------------- Entrypoint (local) ----------------
=======
# ===================== Entrypoint (local run) ===========
# -------- Entrypoint (local run) --------
if __name__ == "__main__":
    with app.app_context():
        init_db()
    print("Starting ScamSniff on http://127.0.0.1:5000", flush=True)
    app.run(host="127.0.0.1", port=5000, debug=True)
>