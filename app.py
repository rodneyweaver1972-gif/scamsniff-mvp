from flask import Flask, render_template, request
import re

app = Flask(__name__)

def score(url, friend_count, mutuals, active):
    points = 0
    reasons = []

    # URL pattern
    if re.search(r'facebook\.com/profile\.php\?id=\d+', url):
        reasons.append("Default ID link (more suspicious).")
    elif "facebook.com/" in url:
        points += 1
        reasons.append("Custom username (better).")
    else:
        reasons.append("Not a Facebook URL.")

    # Friend count
    if friend_count:
        try:
            fc = int(friend_count)
           if 25 <= fc <= 5000:
    points += 1
    reasons.append("Friend count looks normal.")
else:
    reasons.append("Friend count looks unusual.")
        except:
            reasons.append("Friend count not a number.")

    # Mutuals
    if mutuals:
        try:
            m = int(mutuals)
            if m >= 3:
                points += 1
                reasons.append("Has mutual friends.")
            else:
                reasons.append("Few or no mutual friends.")
        except:
            reasons.append("Mutuals not a number.")

    # Activity
    if active and active.lower().startswith('y'):
        points += 1
        reasons.append("Recently active.")
    else:
        reasons.append("Looks inactive.")

   label = "Likely legit" if points >= 2 else "Unclear — use caution"
    return label, reasons

@app.route("/", methods=["GET", "POST"])
def home():
    if request.method == "POST":
        url = request.form.get("url", "")
        friend_count = request.form.get("friend_count")
        mutuals = request.form.get("mutuals")
        active = 'y' if request.form.get('active') == 'y' else 'n'
        label, reasons = score(url, friend_count, mutuals, active)
        return render_template("result.html", label=label, reasons=reasons)
    return render_template("home.html")

if __name__ == "__main__":
    app.run()
