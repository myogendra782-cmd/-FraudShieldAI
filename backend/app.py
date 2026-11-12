from flask import Flask, request, jsonify
from flask_cors import CORS
import json

from fraud_detector import analyze_message, analyze_website
from database import (
    init_db,
    save_scan,
    get_history,
    save_website_scan,
    get_website_history
)

app = Flask(__name__)
CORS(app)

init_db()


@app.route("/")
def home():
    return "FraudShield AI Backend is Running!"


# SMS FRAUD SCANNER
@app.route("/analyze", methods=["POST"])
def analyze():

    data = request.get_json(silent=True) or {}
    message = data.get("message", "")

    if not message.strip():
        return jsonify({"error": "Please provide a message"}), 400

    result = analyze_message(message)

    save_scan(message, result)

    return jsonify(result)


# WEBSITE SAFETY CHECKER
@app.route("/analyze-website", methods=["POST"])
def analyze_website_route():

    data = request.get_json(silent=True) or {}
    url = data.get("url", "")

    if not url.strip():
        return jsonify({"error": "Please provide a website URL"}), 400

    result = analyze_website(url)

    save_website_scan(url, result)

    return jsonify(result)


# COMBINED SCAN HISTORY
@app.route("/history", methods=["GET"])
def history():

    sms_records = get_history()
    website_records = get_website_history()

    scans = []

    # SMS history
    for record in sms_records:

        scans.append({
            "id": record[0],
            "message": record[1],
            "risk_score": record[2],
            "status": record[3],
            "detected_words": json.loads(record[4]) if record[4] else [],
            "scan_time": record[5],
            "scan_type": "SMS"
        })

    # Website history
    for record in website_records:

        scans.append({
            "id": record[0],
            "message": record[1],
            "risk_score": record[2],
            "status": record[3],
            "detected_words": json.loads(record[4]) if record[4] else [],
            "scan_time": record[5],
            "scan_type": "WEBSITE"
        })

    # Latest scans first
    scans.sort(
        key=lambda x: x["scan_time"],
        reverse=True
    )

    return jsonify(scans)


if __name__ == "__main__":
    app.run(debug=True, port=5000)