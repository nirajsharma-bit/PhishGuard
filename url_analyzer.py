"""
url_analyzer.py
Checks the URL itself for phishing signals:
- HTTPS usage
- Domain age (via WHOIS)
- Typosquatting / brand impersonation
- Suspicious TLDs
- Excessive subdomains
- IP address used as hostname
- URL length
"""

import re
import socket
from urllib.parse import urlparse
from datetime import datetime

try:
    import whois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False

# Known brands commonly impersonated in phishing
KNOWN_BRANDS = [
    "google", "facebook", "paypal", "apple", "amazon", "microsoft",
    "netflix", "instagram", "twitter", "linkedin", "dropbox", "bank",
    "chase", "wellsfargo", "citibank", "hsbc", "yahoo", "gmail",
    "outlook", "office365", "whatsapp", "telegram"
]

# Suspicious TLDs often abused in phishing
SUSPICIOUS_TLDS = [
    ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".click",
    ".download", ".loan", ".work", ".party", ".win", ".stream",
    ".gdn", ".men", ".date", ".faith", ".review", ".cricket"
]

# Legit well-known domains (to reduce false positives)
WHITELIST = [
    "google.com", "facebook.com", "paypal.com", "apple.com",
    "amazon.com", "microsoft.com", "netflix.com", "instagram.com",
    "twitter.com", "linkedin.com", "github.com", "wikipedia.org"
]


def analyze_url(url: str) -> dict:
    """
    Analyze a URL for phishing indicators.
    Returns a dict of findings and a weighted score.
    """
    findings = []
    score = 0  # Higher = more suspicious

    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    path = parsed.path or ""
    full_url = url.lower()

    # --- Check 1: HTTPS ---
    if parsed.scheme != "https":
        findings.append({
            "check": "No HTTPS",
            "detail": "Site uses HTTP instead of HTTPS — data is unencrypted.",
            "severity": "high",
            "weight": 20
        })
        score += 20
    else:
        findings.append({
            "check": "HTTPS present",
            "detail": "Connection is encrypted with HTTPS.",
            "severity": "safe",
            "weight": 0
        })

    # --- Check 2: IP address as hostname ---
    ip_pattern = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
    if ip_pattern.match(hostname):
        findings.append({
            "check": "IP address used as hostname",
            "detail": f"URL uses a raw IP ({hostname}) instead of a domain name — common in phishing.",
            "severity": "critical",
            "weight": 30
        })
        score += 30

    # --- Check 3: URL length ---
    if len(url) > 100:
        findings.append({
            "check": "Unusually long URL",
            "detail": f"URL is {len(url)} characters long. Long URLs often hide malicious destinations.",
            "severity": "medium",
            "weight": 10
        })
        score += 10

    # --- Check 4: Suspicious TLD ---
    for tld in SUSPICIOUS_TLDS:
        if hostname.endswith(tld):
            findings.append({
                "check": f"Suspicious TLD ({tld})",
                "detail": f"The domain extension '{tld}' is frequently abused for free/malicious hosting.",
                "severity": "high",
                "weight": 20
            })
            score += 20
            break

    # --- Check 5: Brand impersonation in domain ---
    is_whitelisted = any(hostname == w or hostname.endswith("." + w) for w in WHITELIST)
    if not is_whitelisted:
        for brand in KNOWN_BRANDS:
            if brand in hostname:
                findings.append({
                    "check": f"Brand impersonation detected ({brand})",
                    "detail": f"Hostname '{hostname}' contains the brand name '{brand}' but is NOT the official domain.",
                    "severity": "critical",
                    "weight": 35
                })
                score += 35
                break

    # --- Check 6: Excessive subdomains ---
    parts = hostname.split(".")
    if len(parts) > 4:
        findings.append({
            "check": "Too many subdomains",
            "detail": f"Hostname has {len(parts) - 2} subdomains. Attackers use deep subdomains to bury the real domain.",
            "severity": "medium",
            "weight": 10
        })
        score += 10

    # --- Check 7: Hyphens in domain (common in phishing) ---
    domain = ".".join(parts[-2:]) if len(parts) >= 2 else hostname
    if hostname.count("-") >= 3:
        findings.append({
            "check": "Multiple hyphens in domain",
            "detail": f"Domain '{domain}' has {hostname.count('-')} hyphens — a common typosquatting pattern.",
            "severity": "medium",
            "weight": 10
        })
        score += 10

    # --- Check 8: Sensitive keywords in URL path ---
    sensitive_keywords = ["login", "signin", "verify", "account", "secure",
                          "update", "confirm", "banking", "password", "credential"]
    found_keywords = [kw for kw in sensitive_keywords if kw in full_url]
    if found_keywords:
        findings.append({
            "check": "Sensitive keywords in URL",
            "detail": f"URL contains: {', '.join(found_keywords)}. Phishing pages often use these words.",
            "severity": "medium",
            "weight": 15
        })
        score += 15

    # --- Check 9: Domain age via WHOIS ---
    if WHOIS_AVAILABLE and not ip_pattern.match(hostname):
        try:
            w = whois.whois(hostname)
            creation_date = w.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            if creation_date:
                age_days = (datetime.now() - creation_date).days
                if age_days < 30:
                    findings.append({
                        "check": "Very new domain",
                        "detail": f"Domain is only {age_days} days old. Phishing domains are usually newly registered.",
                        "severity": "high",
                        "weight": 25
                    })
                    score += 25
                elif age_days < 180:
                    findings.append({
                        "check": "Recently registered domain",
                        "detail": f"Domain is {age_days} days old (less than 6 months).",
                        "severity": "medium",
                        "weight": 10
                    })
                    score += 10
                else:
                    findings.append({
                        "check": "Established domain",
                        "detail": f"Domain is {age_days} days old — relatively established.",
                        "severity": "safe",
                        "weight": 0
                    })
        except Exception:
            findings.append({
                "check": "WHOIS lookup failed",
                "detail": "Could not retrieve domain registration info.",
                "severity": "info",
                "weight": 5
            })
            score += 5

    return {
        "module": "URL Analyzer",
        "score": min(score, 100),
        "findings": findings
    }
