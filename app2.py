import os
import time
import secrets
import json
from urllib.parse import urljoin, urlencode

import requests
from dotenv import load_dotenv
from flask import (
    Flask,
    redirect,
    url_for,
    session,
    request,
    render_template,
    flash,
    render_template_string,
    jsonify,
)
from authlib.integrations.flask_client import OAuth
from threading import Lock

# Load .env
load_dotenv()

# ---------- CONFIG (from env) ----------
FUSIONAUTH_DOMAIN = os.environ.get("FUSIONAUTH_DOMAIN")  # e.g. https://auth.example.com
CLIENT_ID = os.environ.get("CLIENT_ID")
CLIENT_SECRET = os.environ.get("CLIENT_SECRET")
REDIRECT_URI = os.environ.get("REDIRECT_URI")  # e.g. http://localhost:5000/auth/callback
SECRET_KEY = os.environ.get("SECRET_KEY") or "dev-secret"

DOMO_API_HOST = os.getenv("DOMO_API_HOST", "https://api.domo.com")
DOMO_EMBED_HOST = os.getenv("DOMO_EMBED_HOST", "https://public.domo.com")
DOMO_CLIENT_ID = os.getenv("DOMO_CLIENT_ID")
DOMO_CLIENT_SECRET = os.getenv("DOMO_CLIENT_SECRET")

# Optional: provide default embed page ids per user (or from env)
EMBED_PAGE_ID_1 = os.getenv("EMBED_PAGE_ID_1")  # used for specific user
EMBED_PAGE_ID_2 = os.getenv("EMBED_PAGE_ID_2")  # default

# Basic env validation (fail early)
required = {
    "FUSIONAUTH_DOMAIN": FUSIONAUTH_DOMAIN,
    "CLIENT_ID": CLIENT_ID,
    "CLIENT_SECRET": CLIENT_SECRET,
    "DOMO_CLIENT_ID": DOMO_CLIENT_ID,
    "DOMO_CLIENT_SECRET": DOMO_CLIENT_SECRET,
}
missing = [k for k, v in required.items() if not v]
if missing:
    raise RuntimeError(f"Missing required env vars: {', '.join(missing)}")

# ---------- APP SETUP ----------
app = Flask(__name__)
app.secret_key = SECRET_KEY

oauth = OAuth(app)

# fetch well-known safely:
well_known = urljoin(FUSIONAUTH_DOMAIN, "/.well-known/openid-configuration")
conf = {}
try:
    resp = requests.get(well_known, timeout=5)
    resp.raise_for_status()
    conf = resp.json()
except Exception as e:
    # If your app must run without the auth server available at import time,
    # consider delaying this call until first use.
    raise RuntimeError(f"Failed to fetch OpenID config from {well_known}: {e}")

oauth.register(
    name="fusionauth",
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,
    server_metadata_url=well_known,
    client_kwargs={"scope": "openid profile email"},
)

# ---------- Simple thread-safe in-memory cache for Domo OAuth token ----------
DOMO_TOKEN_CACHE = {"access_token": None, "expires_at": 0}
_DOMO_TOKEN_LOCK = Lock()

def get_domo_access_token(scopes: str = "data user dashboard"):
    """
    Request Domo OAuth token using client_credentials.
    Process-memory cache. Use Redis or similar in production.
    """
    now = time.time()
    with _DOMO_TOKEN_LOCK:
        if DOMO_TOKEN_CACHE["access_token"] and DOMO_TOKEN_CACHE["expires_at"] > now + 5:
            return DOMO_TOKEN_CACHE["access_token"]

        token_url = f"{DOMO_API_HOST}/oauth/token"
        auth = (DOMO_CLIENT_ID, DOMO_CLIENT_SECRET)
        headers = {"Accept": "application/json"}
        data = {"grant_type": "client_credentials", "scope": scopes}

        r = requests.post(token_url, auth=auth, data=data, headers=headers, timeout=10)
        r.raise_for_status()
        j = r.json()
        access_token = j.get("access_token")
        expires_in = int(j.get("expires_in", 300))

        DOMO_TOKEN_CACHE["access_token"] = access_token
        DOMO_TOKEN_CACHE["expires_at"] = time.time() + expires_in
        return access_token


def create_domo_embed_token(access_token: str, embed_id: str, session_length_minutes: int = 60):
    """
    Request an embed token from the Domo API.
    Make sure embed_id is valid and the Domo client has access.
    """
    if not embed_id:
        raise ValueError("embed_id is required")

    embed_token_url = f"{DOMO_API_HOST}/v1/stories/embed/auth"
    payload = {
        "sessionLength": session_length_minutes * 60,
        "authorizations": [
            {
                "token": embed_id,
                "permissions": ["READ", "FILTER", "EXPORT"],
                "filters": []
            }
        ]
    }
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/json",
        "Content-Type": "application/json",
    }
    r = requests.post(embed_token_url, headers=headers, json=payload, timeout=10)
    r.raise_for_status()
    return r.json().get("authentication")


# ---------- Auth helpers ----------
def is_logged_in():
    return "user" in session


@app.route("/")
def index():
    return render_template("index.html", user=session.get("user"))


@app.route("/login")
def login():
    redirect_uri = REDIRECT_URI or url_for("auth_callback", _external=True)
    nonce = secrets.token_urlsafe(16)
    session["oidc_nonce"] = nonce
    return oauth.fusionauth.authorize_redirect(redirect_uri, nonce=nonce)


@app.route("/auth/callback")
def auth_callback():
    token = oauth.fusionauth.authorize_access_token()
    if not token:
        flash("Authentication failed", "error")
        return redirect(url_for("index"))

    nonce = session.pop("oidc_nonce", None)
    userinfo = None
    if token.get("id_token"):
        try:
            userinfo = oauth.fusionauth.parse_id_token(token, nonce=nonce)
        except Exception:
            userinfo = None

    if not userinfo:
        userinfo = oauth.fusionauth.userinfo(token=token)

    session["user"] = {
        "sub": userinfo.get("sub"),
        "email": userinfo.get("email"),
        "name": userinfo.get("name") or userinfo.get("preferred_username"),
        "raw": userinfo,
    }
    return redirect(url_for("profile"))


@app.route("/profile")
def profile():
    if not is_logged_in():
        return redirect(url_for("login"))
    user = session["user"]
    print(user)
    return render_template("profile.html", user=user)


@app.route("/logout")
def logout():
    session.clear()
    logout_endpoint = conf.get("end_session_endpoint")
    if logout_endpoint:
        post_logout = url_for("index", _external=True)
        params = {"post_logout_redirect_uri": post_logout}
        return redirect(logout_endpoint + "?" + urlencode(params))
    return redirect(url_for("index"))


@app.route("/api/me")
def api_me():
    if not is_logged_in():
        return jsonify({"error": "Unauthorized"}), 401
    return jsonify({"user": session["user"]})


def choose_embed_page_for_user(user):
    """
    Return the embed page id to use for this user.
    Replace this logic with your real mapping (DB, roles, groups, etc).
    """
    if not user:
        return EMBED_PAGE_ID_2 or EMBED_PAGE_ID_1
    if user.get("name") == "Rohith":
        return EMBED_PAGE_ID_1 or EMBED_PAGE_ID_2
    return EMBED_PAGE_ID_2


@app.route("/embed-page")
def embed_page():
    if not is_logged_in():
        return redirect(url_for("login"))

    user = session.get("user")
    page_id = choose_embed_page_for_user(user)
    if not page_id:
        return render_template_string("<h3>No embed page configured for this user</h3>"), 500

    try:
        access_token = get_domo_access_token()
        embed_token = create_domo_embed_token(access_token, page_id, session_length_minutes=60)
        if not embed_token:
            raise RuntimeError("Domo did not return an embed token")
    except Exception as e:
        return render_template_string("<h3>Error creating Domo embed token</h3><pre>{{err}}</pre>", err=str(e)), 500

    html = f"""
    <!doctype html>
    <html>
      <head>
        <meta charset="utf-8" />
        <title>Domo Embed</title>
        <style>html,body,iframe{{height:100%;margin:0;padding:0;border:0}} iframe{{width:100%}}</style>
      </head>
      <body>
        <form id="domoForm" action="{DOMO_EMBED_HOST}/embed/pages/{page_id}" method="post" target="domoFrame">
          <input type="hidden" name="embedToken" value="{embed_token}" />
        </form>
        <iframe name="domoFrame" id="domoFrame" frameborder="0" allowfullscreen></iframe>
        <script>document.getElementById('domoForm').submit();</script>
      </body>
    </html>
    """
    return render_template_string(html)


@app.route("/domo/embed-token")
def domo_embed_token_api():
    if not is_logged_in():
        return jsonify({"error": "Unauthorized"}), 401
    try:
        access_token = get_domo_access_token()
        page_id = choose_embed_page_for_user(session.get("user"))
        embed_token = create_domo_embed_token(access_token, page_id, session_length_minutes=60)
        if not embed_token:
            raise RuntimeError("Domo did not return an embed token")
        return jsonify({"embedToken": embed_token})
    except Exception as e:
        return jsonify({"error": "failed to create embed token", "detail": str(e)}), 500


# ---- Optional: helper to ensure user exists in Domo (UI preferred) ----
def domo_create_user(access_token: str, email: str, first_name: str = "", last_name: str = "", role: str = "Participant"):
    """
    Example helper to create a user in Domo via API.
    NOTE: check Domo Admin API docs for exact payload and endpoint.
    This is a template showing how you'd call the users API.
    """
    # TODO: adjust endpoint/payload per Domo docs if different
    users_endpoint = f"{DOMO_API_HOST}/v1/users"  # verify from Domo docs
    payload = {
        "email": email,
        "firstName": first_name,
        "lastName": last_name,
        "role": role,  # role name or id depending on API
        # other fields (status, groups, etc) as needed
    }
    headers = {"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"}
    r = requests.post(users_endpoint, headers=headers, json=payload, timeout=10)
    r.raise_for_status()
    return r.json()


if __name__ == "__main__":
    app.run(debug=True, port=int(os.getenv("PORT", 5000)))

