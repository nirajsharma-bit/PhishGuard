"""
ssl_checker.py
Checks SSL/TLS certificate details:
- Certificate validity
- Expiry date
- Self-signed detection
- Certificate issuer trust
- Hostname mismatch
"""

import ssl
import socket
from datetime import datetime
from urllib.parse import urlparse


def check_ssl(url: str) -> dict:
    """
    Retrieve and analyze the SSL certificate for the given URL.
    Returns findings and a score contribution.
    """
    findings = []
    score = 0

    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    if parsed.scheme != "https":
        findings.append({
            "check": "No SSL — site uses HTTP",
            "detail": "This site does not use HTTPS at all. No SSL certificate to check.",
            "severity": "high",
            "weight": 25
        })
        return {
            "module": "SSL Checker",
            "score": 25,
            "findings": findings
        }

    # --- Fetch SSL certificate ---
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=8) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()

    except ssl.SSLCertVerificationError as e:
        findings.append({
            "check": "SSL certificate verification failed",
            "detail": f"Certificate is invalid or untrusted: {str(e)[:120]}",
            "severity": "critical",
            "weight": 40
        })
        return {"module": "SSL Checker", "score": 40, "findings": findings}

    except ssl.CertificateError as e:
        findings.append({
            "check": "Certificate hostname mismatch",
            "detail": f"The certificate does not match the domain: {str(e)[:120]}",
            "severity": "critical",
            "weight": 40
        })
        return {"module": "SSL Checker", "score": 40, "findings": findings}

    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        findings.append({
            "check": "SSL connection failed",
            "detail": f"Could not establish SSL connection: {str(e)[:100]}",
            "severity": "info",
            "weight": 0
        })
        return {"module": "SSL Checker", "score": 0, "findings": findings}

    except Exception as e:
        findings.append({
            "check": "SSL check error",
            "detail": f"Unexpected error: {str(e)[:100]}",
            "severity": "info",
            "weight": 0
        })
        return {"module": "SSL Checker", "score": 0, "findings": findings}

    # --- Check expiry ---
    try:
        not_after = cert.get("notAfter", "")
        if not_after:
            expiry_date = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
            days_left = (expiry_date - datetime.utcnow()).days

            if days_left < 0:
                findings.append({
                    "check": "SSL certificate EXPIRED",
                    "detail": f"Certificate expired {abs(days_left)} days ago on {expiry_date.strftime('%d %b %Y')}.",
                    "severity": "critical",
                    "weight": 40
                })
                score += 40
            elif days_left < 15:
                findings.append({
                    "check": "SSL certificate expiring very soon",
                    "detail": f"Certificate expires in {days_left} days ({expiry_date.strftime('%d %b %Y')}).",
                    "severity": "high",
                    "weight": 20
                })
                score += 20
            elif days_left < 60:
                findings.append({
                    "check": "SSL certificate expiring soon",
                    "detail": f"Certificate expires in {days_left} days ({expiry_date.strftime('%d %b %Y')}).",
                    "severity": "medium",
                    "weight": 5
                })
                score += 5
            else:
                findings.append({
                    "check": "SSL certificate valid",
                    "detail": f"Certificate valid for {days_left} more days (expires {expiry_date.strftime('%d %b %Y')}).",
                    "severity": "safe",
                    "weight": 0
                })
    except Exception:
        pass

    # --- Check issuer ---
    issuer = dict(x[0] for x in cert.get("issuer", []))
    issuer_org = issuer.get("organizationName", "Unknown")
    issuer_cn = issuer.get("commonName", "Unknown")

    trusted_issuers = [
        "let's encrypt", "digicert", "comodo", "globalsign", "geotrust",
        "sectigo", "godaddy", "entrust", "verisign", "amazon", "google trust"
    ]
    issuer_lower = issuer_org.lower()
    is_trusted = any(t in issuer_lower for t in trusted_issuers)

    if not is_trusted:
        findings.append({
            "check": "Untrusted or unknown certificate issuer",
            "detail": f"Issued by: '{issuer_org}'. Not a widely-recognized CA — could be self-signed.",
            "severity": "high",
            "weight": 20
        })
        score += 20
    else:
        findings.append({
            "check": "Trusted certificate issuer",
            "detail": f"Certificate issued by '{issuer_org}' — a recognized Certificate Authority.",
            "severity": "safe",
            "weight": 0
        })

    # --- Check Subject Alternative Names ---
    san = cert.get("subjectAltName", [])
    san_domains = [v for (t, v) in san if t == "DNS"]
    if san_domains:
        findings.append({
            "check": "SAN domains present",
            "detail": f"Certificate covers: {', '.join(san_domains[:5])}{'...' if len(san_domains) > 5 else ''}",
            "severity": "safe",
            "weight": 0
        })

    return {
        "module": "SSL Checker",
        "score": min(score, 100),
        "findings": findings
    }
