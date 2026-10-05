import json
import os
import urllib.parse
import urllib.request
from flask import Flask, request, render_template

app = Flask(__name__)

TOKEN_URL = "https://auth.tiktok-shops.com/api/v2/token/get"


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/auth/callback", methods=["GET", "HEAD"])
def callback():
    # Some browsers/proxies may probe the callback URL with HEAD before the
    # real navigation. TikTok auth codes are one-time, so HEAD must NEVER
    # exchange/consume the code.
    if request.method == "HEAD":
        return "", 200

    auth_code = request.args.get("code")
    if not auth_code:
        return "Authorization failed: callback did not contain a code.", 400

    app_key = os.environ.get("TIKTOK_APP_KEY")
    app_secret = os.environ.get("TIKTOK_APP_SECRET")
    if not app_key or not app_secret:
        return (
            "Authorization code received, but the backend is missing "
            "TIKTOK_APP_KEY or TIKTOK_APP_SECRET in Render Environment Variables.",
            500,
        )

    params = urllib.parse.urlencode(
        {
            "app_key": app_key,
            "app_secret": app_secret,
            "auth_code": auth_code,
            "grant_type": "authorized_code",
        }
    )

    try:
        with urllib.request.urlopen(f"{TOKEN_URL}?{params}", timeout=20) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except Exception:
        app.logger.exception("TikTok token exchange failed")
        return "TikTok authorization reached the backend, but token exchange failed. Check Render logs.", 502

    if payload.get("code") != 0:
        # Do not expose credentials or the temporary auth code in the browser.
        message = payload.get("message", "Unknown TikTok authorization error")
        return f"TikTok token exchange was rejected: {message}", 400

    data = payload.get("data") or {}
    access_token = data.get("access_token")
    refresh_token = data.get("refresh_token")

    if not access_token or not refresh_token:
        return "TikTok responded successfully but no usable tokens were returned.", 502

    # Never print tokens to the browser or logs. Persistent token storage will
    # be added separately; this callback verifies and completes the exchange.
    return (
        "<h2>Authorization successful</h2>"
        "<p>The account has been connected successfully.</p>"
        "<p>You can close this page.</p>"
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "10000")))
