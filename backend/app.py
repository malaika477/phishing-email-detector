from flask import Flask, request, jsonify
from flask_cors import CORS

from analyzer import analyze_email

app = Flask(__name__)
CORS(app)  # allow the React dev server (different port) to call this API


@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})


@app.route("/api/analyze", methods=["POST"])
def analyze():
    data = request.get_json(silent=True) or {}
    email_text = data.get("email", "")

    if not email_text.strip():
        return jsonify({"error": "No email text provided."}), 400

    result = analyze_email(email_text)
    return jsonify(result)


if __name__ == "__main__":
    app.run(debug=True, port=5000)
