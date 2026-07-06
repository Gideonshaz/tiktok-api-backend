from flask import Flask, request

app = Flask(__name__)

@app.route("/")
def home():
    return "TikTok API Backend is running"

@app.route("/auth/callback")
def callback():
    code = request.args.get("code")
    return f"Received auth code: {code}"

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=10000)
