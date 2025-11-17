import os
from flask import Flask, redirect, url_for, session, request, render_template, flash
from authlib.integrations.flask_client import OAuth
from dotenv import load_dotenv
from urllib.parse import urljoin

# Load .env
load_dotenv()

FUSIONAUTH_DOMAIN = os.environ.get("FUSIONAUTH_DOMAIN")
CLIENT_ID = os.environ.get("CLIENT_ID")
CLIENT_SECRET = os.environ.get("CLIENT_SECRET")
REDIRECT_URI = os.environ.get("REDIRECT_URI")  # e.g. http://localhost:5000/auth/callback
SECRET_KEY = os.environ.get("SECRET_KEY") or "dev-secret"

if not FUSIONAUTH_DOMAIN or not CLIENT_ID or not CLIENT_SECRET:
    raise RuntimeError("Please set FUSIONAUTH_DOMAIN, CLIENT_ID, CLIENT_SECRET in .env")

app = Flask(__name__)
app.secret_key = SECRET_KEY

oauth = OAuth(app)

# Discover OIDC endpoints from the well-known URL
well_known = urljoin(FUSIONAUTH_DOMAIN, "/.well-known/openid-configuration")
import requests
resp = requests.get(well_known, timeout=5)
resp.raise_for_status()
conf = resp.json()

oauth.register(
    name="fusionauth",
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,
    server_metadata_url=well_known,
    client_kwargs={
        "scope": "openid profile email"
    },
    # redirect_uri is passed in authorize_redirect below (or can be set here)
)

# ---- Helpers ----
def is_logged_in():
    return "user" in session

# ---- Routes ----
@app.route("/")
def index():
    return render_template("index.html", user=session.get("user"))

@app.route("/login")
def login():
    redirect_uri = REDIRECT_URI or url_for("auth_callback", _external=True)
    return oauth.fusionauth.authorize_redirect(redirect_uri)

@app.route("/auth/callback")
def auth_callback():
    # Exchange code for tokens and fetch userinfo
    token = oauth.fusionauth.authorize_access_token()
    if token is None:
        flash("Authentication failed", "error")
        return redirect(url_for("index"))

    userinfo = oauth.fusionauth.parse_id_token(token) if token.get("id_token") else None

    # If userinfo missing, attempt userinfo endpoint
    if not userinfo:
        userinfo = oauth.fusionauth.userinfo(token=token)

    # Save minimal session info (don't store sensitive tokens in browser session without encryption)
    session["user"] = {
        "sub": userinfo.get("sub"),
        "email": userinfo.get("email"),
        "name": userinfo.get("name") or userinfo.get("preferred_username"),
        "raw": userinfo
    }
    # Optionally store tokens (access/refresh) if you plan to call FusionAuth APIs later:
    # session["token"] = token

    return redirect(url_for("profile"))

@app.route("/profile")
def profile():
    if not is_logged_in():
        return redirect(url_for("login"))
    return render_template("profile.html", user=session["user"])

@app.route("/logout")
def logout():
    # clear session
    session.clear()
    # Redirect to FusionAuth logout endpoint (optional) - to fully sign out from FusionAuth server
    logout_endpoint = conf.get("end_session_endpoint")
    if logout_endpoint:
        # Redirect back to home after logout
        post_logout = url_for("index", _external=True)
        # Some FusionAuth installations require 'client_id' and 'post_logout_redirect_uri'
        params = {"post_logout_redirect_uri": post_logout}
        return redirect(logout_endpoint + "?" + "&".join([f"{k}={requests.utils.quote(v, safe='')}" for k,v in params.items()]))
    return redirect(url_for("index"))

# ---- Simple protected API example ----
@app.route("/api/me")
def api_me():
    if not is_logged_in():
        return {"error": "Unauthorized"}, 401
    return {"user": session["user"]}

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
