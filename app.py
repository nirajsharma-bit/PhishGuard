"""
app.py — PhishGuard Flask Application
Phishing Detection + Vulnerability Scanner

Run with:
    python app.py

API endpoint:
    POST /analyze   { "url": "https://example.com" }
"""

import warnings
warnings.filterwarnings("ignore")  # Suppress SSL warnings for scanning unverified sites

from flask import Flask, request, jsonify, render_template
from flask_cors import CORS

from scanner.url_analyzer import analyze_url
from scanner.page_scanner import scan_page
from scanner.header_checker import check_headers
from scanner.ssl_checker import check_ssl
from scanner.scoring_engine import calculate_final_score

app = Flask(__name__)
CORS(app)


def normalize_url(url: str) -> str:
    """Ensure the URL has a scheme."""
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url


@app.route("/")
def index():
    """Serve the main frontend UI."""
    return render_template("index.html")


@app.route("/analyze", methods=["POST"])
def analyze():
    """
    Main analysis endpoint.
    Expects JSON: { "url": "https://example.com" }
    Returns full scan report with risk percentage.
    """
    data = request.get_json()
    if not data or "url" not in data:
        return jsonify({"error": "Please provide a 'url' field in the request body."}), 400

    raw_url = data["url"].strip()
    if not raw_url:
        return jsonify({"error": "URL cannot be empty."}), 400

    url = normalize_url(raw_url)

    # --- Run all scanner modules ---
    results = []

    print(f"[PhishGuard] Scanning: {url}")

    url_result = analyze_url(url)
    results.append(url_result)
    print(f"  [URL Analyzer]    score={url_result['score']}")

    ssl_result = check_ssl(url)
    results.append(ssl_result)
    print(f"  [SSL Checker]     score={ssl_result['score']}")

    header_result = check_headers(url)
    results.append(header_result)
    print(f"  [Header Checker]  score={header_result['score']}")

    page_result = scan_page(url)
    results.append(page_result)
    print(f"  [Page Scanner]    score={page_result['score']}")

    # --- Aggregate scores ---
    final = calculate_final_score(results)
    print(f"  [FINAL SCORE]     {final['final_score']}% — {final['risk_level']}")

    return jsonify({
        "url": url,
        "final_score": final["final_score"],
        "risk_level": final["risk_level"],
        "risk_icon": final["risk_icon"],
        "risk_description": final["risk_description"],
        "severity_counts": final["severity_counts"],
        "module_scores": final["module_scores"],
        "all_findings": final["all_findings"],
    })


@app.route("/health")
def health():
    return jsonify({"status": "PhishGuard is running ✅"})


if __name__ == "__main__":
    print("=" * 50)
    print("  PhishGuard — Phishing & Vulnerability Scanner")
    print("  Running at http://127.0.0.1:5000")
    print("=" * 50)
    app.run(debug=True, host="0.0.0.0", port=5000)
