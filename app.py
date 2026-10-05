import json
import os
import urllib.parse
import urllib.request
import urllib.error
import time
import hmac
import hashlib
import psycopg
from flask import Flask, request, render_template, jsonify

app = Flask(__name__)

TOKEN_URL = "https://auth.tiktok-shops.com/api/v2/token/get"
OPEN_API = "https://open-api.tiktokglobalshop.com"


def sign_request(path, params, body=b""):
    secret = os.environ["TIKTOK_APP_SECRET"]
    clean = {k: str(v) for k, v in params.items() if k not in ("sign", "access_token")}
    base = path + "".join(k + clean[k] for k in sorted(clean)) + body.decode("utf-8")
    wrapped = secret + base + secret
    return hmac.new(secret.encode(), wrapped.encode(), hashlib.sha256).hexdigest()


def fingerprint(value):
    if not value:
        return None
    return hashlib.sha256(str(value).encode("utf-8")).hexdigest()[:10]


def latest_authorization():
    database_url = ensure_token_store()
    with psycopg.connect(database_url) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id, access_token, granted_scopes, metadata, created_at, app_key FROM tiktok_authorizations ORDER BY id DESC LIMIT 1")
            return cur.fetchone()


def get_authorized_shops(access_token):
    # Returns both TikTok JSON and safe HTTP diagnostics. Never returns/logs tokens.

    path = "/authorization/202309/shops"
    params = {"app_key": os.environ["TIKTOK_APP_KEY"], "timestamp": int(time.time())}
    params["sign"] = sign_request(path, params)
    url = OPEN_API + path + "?" + urllib.parse.urlencode(params)
    req = urllib.request.Request(url, headers={"x-tts-access-token": access_token, "content-type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=20) as response:
            parsed = json.loads(response.read().decode("utf-8"))
            return parsed, {"http_status": response.status, "request_id": response.headers.get("x-tts-logid") or response.headers.get("request-id")}
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        app.logger.error("TikTok shops API HTTP %s: %s", e.code, body)
        try:
            parsed = json.loads(body)
        except Exception:
            parsed = {"code": e.code, "message": body or str(e)}
        return parsed, {"http_status": e.code, "request_id": e.headers.get("x-tts-logid") or e.headers.get("request-id")}


def ensure_token_store():
    database_url = os.environ.get("DATABASE_URL")
    if not database_url:
        raise RuntimeError("DATABASE_URL is not configured")
    with psycopg.connect(database_url) as conn:
        with conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS tiktok_authorizations (
                    id BIGSERIAL PRIMARY KEY,
                    app_key TEXT NOT NULL,
                    access_token TEXT NOT NULL,
                    refresh_token TEXT NOT NULL,
                    access_token_expire_in BIGINT,
                    refresh_token_expire_in BIGINT,
                    granted_scopes JSONB,
                    metadata JSONB,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                )
            """)
        conn.commit()
    return database_url


def save_authorization(database_url, app_key, data):
    safe_metadata = {k: v for k, v in data.items() if k not in ("access_token", "refresh_token")}
    scopes = data.get("granted_scopes") or []
    with psycopg.connect(database_url) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO tiktok_authorizations
                    (app_key, access_token, refresh_token, access_token_expire_in,
                     refresh_token_expire_in, granted_scopes, metadata)
                VALUES (%s, %s, %s, %s, %s, %s::jsonb, %s::jsonb)
                """,
                (
                    app_key,
                    data["access_token"],
                    data["refresh_token"],
                    data.get("access_token_expire_in"),
                    data.get("refresh_token_expire_in"),
                    json.dumps(scopes),
                    json.dumps(safe_metadata),
                ),
            )
        conn.commit()


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

    # Verify durable storage BEFORE consuming TikTok's one-time auth code.
    try:
        database_url = ensure_token_store()
    except Exception:
        app.logger.exception("TikTok token store is unavailable")
        return "Authorization backend storage is not ready. The TikTok auth code was NOT consumed. Please try again after storage is configured.", 503

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

    try:
        app.logger.info("OAuth token received app_fp=%s access_fp=%s scopes=%s user_type=%s", fingerprint(app_key), fingerprint(access_token), data.get("granted_scopes") or [], data.get("user_type"))
        save_authorization(database_url, app_key, data)
    except Exception:
        app.logger.exception("TikTok authorization succeeded but durable token save failed")
        return "TikTok authorization succeeded, but saving the connection failed. Check Render logs.", 500

    # Never print tokens to the browser or logs.
    return (
        "<h2>Authorization successful</h2>"
        "<p>The account has been connected successfully.</p>"
        "<p>You can close this page.</p>"
    )


@app.get("/api/connection")
def connection_status():
    try:
        row = latest_authorization()
        if not row:
            return jsonify(connected=False, message="No TikTok Shop authorization saved yet.")
        granted = row[2] or []
        meta = row[3] or {}
        app.logger.info("Latest authorization id=%s user_type=%s granted_scopes=%s", row[0], meta.get("user_type"), granted)
        if "seller.authorization.info" not in granted:
            return jsonify(connected=False, saved=True, authorization_id=row[0], user_type=meta.get("user_type"), granted_scopes=granted, message="Latest token does not contain seller.authorization.info."), 409
        diagnostics = {
            "authorization_id": row[0],
            "created_at": row[4].isoformat() if row[4] else None,
            "granted_scopes": granted,
            "has_authorization_info": "seller.authorization.info" in granted,
            "user_type": meta.get("user_type"),
            "access_fp": fingerprint(row[1]),
            "stored_app_fp": fingerprint(row[5]),
            "runtime_app_fp": fingerprint(os.environ.get("TIKTOK_APP_KEY")),
            "same_app": row[5] == os.environ.get("TIKTOK_APP_KEY"),
        }
        app.logger.info("Connection diagnostic %s", diagnostics)
        payload, http_diag = get_authorized_shops(row[1])
        diagnostics.update(http_diag)
        if payload.get("code") != 0:
            return jsonify(connected=False, saved=True, diagnostic=diagnostics, tiktok={"code": payload.get("code"), "message": payload.get("message"), "request_id": payload.get("request_id") or diagnostics.get("request_id")}), 502
        shops = (payload.get("data") or {}).get("shops") or []
        safe_shops = []
        for shop in shops:
            safe_shops.append({"name": shop.get("shop_name") or shop.get("name") or "TikTok Shop", "region": shop.get("region"), "cipher": shop.get("cipher") or shop.get("shop_cipher"), "id": shop.get("id") or shop.get("shop_id")})
        return jsonify(connected=True, saved=True, shops=safe_shops, authorization_id=row[0], diagnostic=diagnostics)
    except Exception:
        app.logger.exception("Connection verification failed")
        return jsonify(connected=False, message="Connection verification failed. Check backend logs."), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "10000")))
