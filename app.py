# app.py — ScamSniff MVP (drop-in)
# Minimal Flask app with CORS, /health, and /api/analyze.

from __future__ import annotations
import os
from flask import Flask, request, jsonify, render_template, send_from_directory

app = Flask(__name__)

# ---------------- CORS (simple) ----------------
@app.after_request
def add_cors(resp):
    resp.headers["Access-Control-Allow-Origin"] = "*"
    resp.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    resp.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    return resp

# ---------------- Health check ----------------
@app.get("/health")
def health():
    return {"ok": True, "service": "scamsniff-mvp"}, 200

# ---------------- Demo Analyze API -------------
# Frontend should POST JSON: {"message": "..."} (also accepts "text" or "input")
@app.post("/api/analyze")
def api_analyze():
    data = request.get_json(silent=True) or {}
    message = (data.get("message") or data.get("text") or data.get("input") or "").strip()
    if not message:
        return jsonify({"ok": False, "error": "No message provided"}), 400

    # TODO: replace with real scoring logic
    score = 0.42
    summary = "Demo result only — replace with real analysis."

    return jsonify({"ok": True, "score": score, "summary": summary, "echo": message}), 200

# ---------------- Static helpers ---------------
@app.get("/favicon.ico")
def favicon():
    # Serve favicon if present; otherwise return 204
    static_dir = os.path.join(app.root_path, "static")
    ico_path = os.path.join(static_dir, "favicon.ico")
    if os.path.exists(ico_path):
        return send_from_directory(static_dir, "favicon.ico")
    return ("", 204)

# ---------------- Pages (optional) -------------
# These will render templates if they exist in /templates.
def _render_safely(name: str):
    try:
        return render_template(f"{name}.html")
    except Exception:
        return f"{name.title()} page (template not found). API is at /api/analyze", 200

@app.get("/")
def home():
    return _render_safely("home")

@app.get("/history")
def history():
    return _render_safely("history")

@app.get("/pricing")
def pricing():
    return _render_safely("pricing")

# ---------------- Local dev entrypoint ---------
if __name__ == "__main__":
    # Local run. On Render, use: gunicorn -w 2 -k gthread -b 0.0.0.0:$PORT app:app
    app.run(host="127.0.0.1", port=5000, debug=True)
