"""
header_checker.py
Checks HTTP response headers for missing or misconfigured security headers:
- Content-Security-Policy (CSP)
- X-Frame-Options
- Strict-Transport-Security (HSTS)
- X-Content-Type-Options
- Referrer-Policy
- Permissions-Policy
"""

import requests

TIMEOUT = 8

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    )
}

# Security headers to check: (header_name, severity_if_missing, score_if_missing, description)
SECURITY_HEADERS = [
    (
        "Content-Security-Policy",
        "high", 20,
        "CSP prevents injection attacks (XSS). Without it, attackers can inject malicious scripts."
    ),
    (
        "X-Frame-Options",
        "high", 20,
        "Prevents clickjacking — embedding this site inside a hidden iframe to steal clicks."
    ),
    (
        "Strict-Transport-Security",
        "high", 15,
        "HSTS forces browsers to always use HTTPS — prevents SSL stripping attacks."
    ),
    (
        "X-Content-Type-Options",
        "medium", 10,
        "Prevents browsers from MIME-sniffing responses — can prevent certain injection attacks."
    ),
    (
        "Referrer-Policy",
        "low", 5,
        "Controls how much referrer info is sent — affects user privacy."
    ),
    (
        "Permissions-Policy",
        "low", 5,
        "Controls browser feature access (camera, mic, location). Missing = uncontrolled access."
    ),
]


def check_headers(url: str) -> dict:
    """
    Fetch HTTP headers from the URL and check for security header presence.
    Returns findings and a score contribution.
    """
    findings = []
    score = 0

    try:
        response = requests.head(url, headers=HEADERS, timeout=TIMEOUT,
                                 allow_redirects=True, verify=False)
        resp_headers = {k.lower(): v for k, v in response.headers.items()}

    except requests.exceptions.ConnectionError:
        findings.append({
            "check": "Could not fetch headers",
            "detail": "Connection failed — unable to retrieve HTTP headers.",
            "severity": "info",
            "weight": 0
        })
        return {"module": "Header Checker", "score": 0, "findings": findings}

    except Exception as e:
        findings.append({
            "check": "Header fetch error",
            "detail": f"Error: {str(e)[:100]}",
            "severity": "info",
            "weight": 0
        })
        return {"module": "Header Checker", "score": 0, "findings": findings}

    # --- Check each security header ---
    for header_name, severity, weight, description in SECURITY_HEADERS:
        header_key = header_name.lower()
        if header_key not in resp_headers:
            findings.append({
                "check": f"Missing: {header_name}",
                "detail": description,
                "severity": severity,
                "weight": weight
            })
            score += weight
        else:
            findings.append({
                "check": f"Present: {header_name}",
                "detail": f"Value: {resp_headers[header_key][:80]}",
                "severity": "safe",
                "weight": 0
            })

    # --- Check for server information leakage ---
    if "server" in resp_headers:
        server_val = resp_headers["server"]
        if any(tech in server_val.lower() for tech in ["apache/", "nginx/", "php/", "iis/"]):
            findings.append({
                "check": "Server version exposed",
                "detail": f"Server header reveals version info: '{server_val}'. Attackers can target known vulnerabilities.",
                "severity": "medium",
                "weight": 10
            })
            score += 10

    # --- Check for X-Powered-By leakage ---
    if "x-powered-by" in resp_headers:
        findings.append({
            "check": "Technology stack exposed (X-Powered-By)",
            "detail": f"'{resp_headers['x-powered-by']}' reveals backend tech — aids attackers in targeting exploits.",
            "severity": "low",
            "weight": 5
        })
        score += 5

    return {
        "module": "Header Checker",
        "score": min(score, 100),
        "findings": findings
    }
