from flask import Flask, render_template, request
import re

app = Flask(__name__)

# --- helpers ---
def to_int(val):
    try:
        return int(val) if val not in (None, "") else None
    except:
        return None

def yn(val):
    return (val or "n").strip().lower() == "y"

# --- FACEBOOK ---
# Friends: 50–3000 => +1
# Mutuals: >=3 => +1
# Active (y) => +1
# Custom username URL => +1
def score_facebook(url, friend_count, mutuals, active_y):
    points, reasons = 0, []

    # URL check
    if "facebook.com/" not in url:
        reasons.append("This is not a Facebook URL. Paste a link from facebook.com.")
    elif re.search(r'facebook\.com/profile\.php\?id=\d+', url):
        reasons.append("Default ID link (a bit more suspicious).")
    else:
        points += 1
        reasons.append("Custom username in URL (good sign).")

    # Friend count
    fc = to_int(friend_count)
    if fc is not None:
        if 50 <= fc <= 3000:
            points += 1
            reasons.append("Friend count looks normal (50–3000).")
        else:
            reasons.append("Friend count looks unusual.")
    else:
        reasons.append("Friend count not provided.")

    # Mutual friends
    m = to_int(mutuals)
    if m is not None:
        if m >= 3:
            points += 1
            reasons.append("Has mutual friends (3+).")
        else:
            reasons.append("Few or no mutual friends.")
    else:
        reasons.append("Mutual friends not provided.")

    # Recent activity
    if active_y:
        points += 1
        reasons.append("Recently active.")
    else:
        reasons.append("Looks inactive.")

    label = "Likely legit" if points >= 2 else "Unclear — use caution"
    return label, reasons

# --- INSTAGRAM ---
# Followers: >=100 => +1
# Ratio followers/following: 0.3–3.0 => +1
# Posts: >=5 => +1
# Age: >=3 months => +1
# Active (y) => +1
# Verified (y) => +1
def score_instagram(followers, following, posts, age_months, active_y, verified_y, url):
    points, reasons = 0, []

    # URL check (soft)
    if "instagram.com/" not in (url or ""):
        reasons.append("Tip: This does not look like an Instagram URL.")

    # Followers
    fol = to_int(followers)
    if fol is not None:
        if fol >= 100:
            points += 1
            reasons.append("Followers look healthy (100+).")
        else:
            reasons.append("Very low followers.")
    else:
        reasons.append("Followers not provided.")

    # Following + ratio
    wing = to_int(following)
    if wing is not None and fol is not None and wing > 0:
        ratio = fol / wing
        if 0.3 <= ratio <= 3.0:
            points += 1
            reasons.append("Follower/following ratio looks typical (0.3–3.0).")
        else:
            reasons.append("Unusual follower/following ratio.")
    else:
        reasons.append("Following not provided or cannot compute ratio.")

    # Posts
    p = to_int(posts)
    if p is not None:
        if p >= 5:
            points += 1
            reasons.append("Has multiple posts (5+).")
        else:
            reasons.append("Very few or no posts.")
    else:
        reasons.append("Posts count not provided.")

    # Account age
    age = to_int(age_months)
    if age is not None:
        if age >= 3:
            points += 1
            reasons.append("Account has some history (3+ months).")
        else:
            reasons.append("Very new account.")
    else:
        reasons.append("Account age not provided.")

    # Activity & verified
    if active_y:
        points += 1
        reasons.append("Recently active.")
    if verified_y:
        points += 1
        reasons.append("Verified account (helpful signal).")

    label = "Likely legit" if points >= 2 else "Unclear — use caution"
    return label, reasons

# --- X (TWITTER) ---
# Same thresholds as Instagram
def score_x(followers, following, posts, age_months, active_y, verified_y, url):
    if ("x.com/" not in (url or "")) and ("twitter.com/" not in (url or "")):
        url_hint = "Tip: This does not look like an X/Twitter URL."
    else:
        url_hint = None

    label, reasons = score_instagram(followers, following, posts, age_months, active_y, verified_y, url)
    if url_hint:
        reasons.insert(0, url_hint)
    return label, reasons

# --- LINKEDIN ---
# Connections: >=50 => +1
# Age: >=6 months => +1
# Photo (y) => +1
# Active (y) => +1
def score_linkedin(connections, age_months, active_y, photo_y, url):
    points, reasons = 0, []

    # URL check (soft)
    if "linkedin.com/" not in (url or ""):
        reasons.append("Tip: This does not look like a LinkedIn URL.")

    # Connections
    conn = to_int(connections)
    if conn is not None:
        if conn >= 50:
            points += 1
            reasons.append("Has 50+ connections.")
        else:
            reasons.append("Very few connections.")
    else:
        reasons.append("Connections not provided.")

    # Account age
    age = to_int(age_months)
    if age is not None:
        if age >= 6:
            points += 1
            reasons.append("Account has history (6+ months).")
        else:
            reasons.append("Very new account.")
    else:
        reasons.append("Account age not provided.")

    # Activity & photo
    if active_y:
        points += 1
        reasons.append("Recently active.")
    if photo_y:
        points += 1
        reasons.append("Has a profile photo.")

    label = "Likely legit" if points >= 2 else "Unclear — use caution"
    return label, reasons

# --- web app ---
@app.route("/", methods=["GET", "POST"])
def home():
    if request.method == "POST":
        platform = (request.form.get("platform") or "facebook").lower().strip()
        url = request.form.get("url", "")

        # shared inputs
        active_y = yn(request.form.get("active"))
        age_months = request.form.get("age_months")

        if platform == "facebook":
            friend_count = request.form.get("friend_count")
            mutuals = request.form.get("mutuals")
            label, reasons = score_facebook(url, friend_count, mutuals, active_y)

        elif platform == "instagram":
            followers = request.form.get("followers")
            following = request.form.get("following")
            posts = request.form.get("posts")
            verified_y = yn(request.form.get("verified"))
            label, reasons = score_instagram(followers, following, posts, age_months, active_y, verified_y, url)

        elif platform == "x":
            followers = request.form.get("followers")
            following = request.form.get("following")
            posts = request.form.get("posts")
            verified_y = yn(request.form.get("verified"))
            label, reasons = score_x(followers, following, posts, age_months, active_y, verified_y, url)

        elif platform == "linkedin":
            connections = request.form.get("connections")
            li_photo = yn(request.form.get("li_photo"))
            label, reasons = score_linkedin(connections, age_months, active_y, li_photo, url)

        else:
            label, reasons = "Unclear — use caution", ["Unknown platform."]

        return render_template("result.html", label=label, reasons=reasons)

    return render_template("home.html")
@app.route("/pricing", methods=["GET"])
def pricing():
    return render_template("pricing.html")

if __name__ == "__main__":
    app.run()
