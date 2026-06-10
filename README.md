# 🛡️ PhishGuard — Phishing Detection & Vulnerability Scanner

A Python-based security tool that analyzes any URL for phishing indicators and web vulnerabilities, then rates the overall risk as a percentage score.

> Built as an academic cybersecurity project. For educational use only.

---

## Features

| Module | What it checks |
|---|---|
| **URL Analyzer** | HTTPS, domain age, typosquatting, suspicious TLDs, brand impersonation, IP-based hostnames |
| **SSL Checker** | Certificate validity, expiry date, trusted issuer, hostname mismatch |
| **Header Checker** | CSP, X-Frame-Options, HSTS, X-Content-Type-Options, server version leakage |
| **Page Scanner** | Hidden forms, external form actions, hidden iframes, social engineering scripts |
| **Scoring Engine** | Weighted aggregation → final risk % with severity labels |

---

## Tech Stack

- **Backend:** Python 3, Flask, Requests, BeautifulSoup4
- **Frontend:** HTML5, CSS3, Vanilla JavaScript
- **Libraries:** python-whois, ssl (stdlib), socket (stdlib)

---

## Setup & Run

```bash
# 1. Clone the repo
git clone https://github.com/nirajsharma-bit/PhishGuard.git
cd PhishGuard

# 2. Create virtual environment
python -m venv venv
source venv/bin/activate      # Linux/Mac
venv\Scripts\activate         # Windows

# 3. Install dependencies
pip install -r requirements.txt

# 4. Run the app
python app.py
```

Then open your browser at: **http://localhost:5000**

---

## API Usage

You can also use the REST API directly:

```bash
curl -X POST http://localhost:5000/analyze \
     -H "Content-Type: application/json" \
     -d '{"url": "https://example.com"}'
```

**Response:**
```json
{
  "url": "https://example.com",
  "final_score": 23,
  "risk_level": "Low",
  "risk_icon": "🟢",
  "risk_description": "Minor concerns detected...",
  "severity_counts": { "critical": 0, "high": 1, "medium": 2, ... },
  "module_scores": {
    "URL Analyzer": 10,
    "SSL Checker": 0,
    "Header Checker": 45,
    "Page Scanner": 20
  },
  "all_findings": [...]
}
```

---

## Risk Levels

| Score | Level | Meaning |
|---|---|---|
| 80–100% | 🔴 Critical | Strong phishing indicators — do NOT proceed |
| 60–79%  | 🟠 High     | Multiple red flags — avoid entering personal info |
| 40–59%  | 🟡 Medium   | Some suspicious signs — proceed with caution |
| 20–39%  | 🟢 Low      | Minor concerns — mostly safe |
| 0–19%   | ✅ Safe     | No significant threats detected |

---

## Project Structure

```
PhishGuard/
├── app.py                   # Flask entry point
├── requirements.txt
├── README.md
├── scanner/
│   ├── __init__.py
│   ├── url_analyzer.py      # URL-level phishing checks
│   ├── page_scanner.py      # HTML content analysis
│   ├── header_checker.py    # HTTP security headers
│   ├── ssl_checker.py       # SSL certificate checks
│   └── scoring_engine.py    # Final risk aggregation
└── templates/
    └── index.html           # Frontend UI
```

---


---

## Author

Made by Niraj Sharma · GitHub Project Submission
