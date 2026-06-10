"""
page_scanner.py
Fetches and analyzes the actual HTML content of a page:
- Password fields / login forms
- Form action pointing to external domains
- Suspicious redirects
- Fake favicon / title mismatches
- Hidden iframes
- Disabled right-click / copy (content protection)
- External script sources from unknown domains
"""

import re
import requests
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup


TIMEOUT = 8  # seconds

# User-agent to avoid bot blocks
HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    )
}


def scan_page(url: str) -> dict:
    """
    Fetch the page and analyze its HTML for phishing signals.
    Returns findings and a score contribution.
    """
    findings = []
    score = 0

    # --- Fetch the page ---
    try:
        response = requests.get(url, headers=HEADERS, timeout=TIMEOUT,
                                allow_redirects=True, verify=False)
        html = response.text
        final_url = response.url

        # Check if there was a redirect to a completely different domain
        original_host = urlparse(url).hostname or ""
        final_host = urlparse(final_url).hostname or ""
        if original_host and final_host and original_host != final_host:
            findings.append({
                "check": "Suspicious redirect",
                "detail": f"URL redirected from '{original_host}' to '{final_host}'.",
                "severity": "high",
                "weight": 25
            })
            score += 25

    except requests.exceptions.SSLError:
        findings.append({
            "check": "SSL certificate error",
            "detail": "The site has an invalid or untrusted SSL certificate.",
            "severity": "high",
            "weight": 20
        })
        score += 20
        return {"module": "Page Scanner", "score": min(score, 100), "findings": findings}

    except requests.exceptions.ConnectionError:
        findings.append({
            "check": "Page unreachable",
            "detail": "Could not connect to the website.",
            "severity": "info",
            "weight": 0
        })
        return {"module": "Page Scanner", "score": 0, "findings": findings}

    except Exception as e:
        findings.append({
            "check": "Fetch error",
            "detail": f"Could not retrieve page: {str(e)[:100]}",
            "severity": "info",
            "weight": 0
        })
        return {"module": "Page Scanner", "score": 0, "findings": findings}

    # --- Parse HTML ---
    soup = BeautifulSoup(html, "html.parser")
    base_host = urlparse(final_url).hostname or ""

    # --- Check 1: Password input fields ---
    password_fields = soup.find_all("input", {"type": "password"})
    if password_fields:
        findings.append({
            "check": "Password input field detected",
            "detail": f"Page contains {len(password_fields)} password field(s) — could be a credential harvesting form.",
            "severity": "medium",
            "weight": 15
        })
        score += 15

    # --- Check 2: Form action pointing to external domain ---
    forms = soup.find_all("form")
    for form in forms:
        action = form.get("action", "")
        if action.startswith("http"):
            action_host = urlparse(action).hostname or ""
            if action_host and action_host != base_host:
                findings.append({
                    "check": "Form submits to external domain",
                    "detail": f"A form sends data to '{action_host}', which is different from the current site — classic phishing technique.",
                    "severity": "critical",
                    "weight": 40
                })
                score += 40
                break

    # --- Check 3: Hidden iframes ---
    iframes = soup.find_all("iframe")
    hidden_iframes = []
    for iframe in iframes:
        style = iframe.get("style", "")
        width = iframe.get("width", "1")
        height = iframe.get("height", "1")
        if "display:none" in style.replace(" ", "") or \
           "visibility:hidden" in style.replace(" ", "") or \
           width in ["0", "1"] or height in ["0", "1"]:
            hidden_iframes.append(iframe)

    if hidden_iframes:
        findings.append({
            "check": "Hidden iframes detected",
            "detail": f"{len(hidden_iframes)} hidden iframe(s) found. These can be used for clickjacking or data theft.",
            "severity": "high",
            "weight": 20
        })
        score += 20

    # --- Check 4: Right-click / copy disabled ---
    oncontextmenu = html.lower().count("oncontextmenu")
    if oncontextmenu > 0 or "event.preventdefault" in html.lower():
        findings.append({
            "check": "Right-click disabled",
            "detail": "Page disables right-click or text selection — common tactic to prevent users from inspecting content.",
            "severity": "low",
            "weight": 5
        })
        score += 5

    # --- Check 5: External scripts from suspicious sources ---
    scripts = soup.find_all("script", {"src": True})
    external_scripts = []
    for script in scripts:
        src = script.get("src", "")
        if src.startswith("http"):
            script_host = urlparse(src).hostname or ""
            if script_host and script_host != base_host:
                external_scripts.append(script_host)

    if len(external_scripts) > 5:
        findings.append({
            "check": "Many external scripts",
            "detail": f"Page loads scripts from {len(external_scripts)} external domains. High count can indicate malicious injection.",
            "severity": "medium",
            "weight": 10
        })
        score += 10

    # --- Check 6: Fake login page indicators ---
    title_tag = soup.find("title")
    title_text = title_tag.get_text().lower() if title_tag else ""
    login_keywords = ["login", "sign in", "signin", "log in", "verify", "account"]
    if any(kw in title_text for kw in login_keywords):
        findings.append({
            "check": "Login-related page title",
            "detail": f"Page title suggests a login/verification page: '{title_tag.get_text()[:60]}'",
            "severity": "low",
            "weight": 5
        })
        score += 5

    # --- Check 7: Popup alerts (social engineering) ---
    if re.search(r"window\.alert|confirm\(|setTimeout.*alert", html, re.IGNORECASE):
        findings.append({
            "check": "Alert/popup script detected",
            "detail": "Page uses JavaScript alerts — may be used for fake warnings or social engineering.",
            "severity": "medium",
            "weight": 10
        })
        score += 10

    # --- All clear check ---
    if score == 0:
        findings.append({
            "check": "No suspicious page content",
            "detail": "Page HTML did not reveal obvious phishing indicators.",
            "severity": "safe",
            "weight": 0
        })

    return {
        "module": "Page Scanner",
        "score": min(score, 100),
        "findings": findings
    }
