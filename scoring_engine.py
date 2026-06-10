"""
scoring_engine.py
Aggregates scores from all scanner modules into a final risk percentage.
Each module has a different weight in the final score.
"""

# How much each module contributes to the final score (must sum to 100)
MODULE_WEIGHTS = {
    "URL Analyzer": 35,
    "Page Scanner": 30,
    "Header Checker": 20,
    "SSL Checker": 15,
}

# Risk level thresholds
RISK_LEVELS = [
    (80, "Critical",  "🔴", "This URL shows strong indicators of phishing or malicious activity. Do NOT proceed."),
    (60, "High",      "🟠", "Multiple serious red flags detected. Avoid entering any personal information."),
    (40, "Medium",    "🟡", "Some suspicious indicators found. Proceed with caution and verify the site."),
    (20, "Low",       "🟢", "Minor concerns detected. Site appears mostly safe but review the findings."),
    (0,  "Safe",      "✅", "No significant threats detected. Site appears to be safe."),
]


def calculate_final_score(module_results: list) -> dict:
    """
    Takes a list of module result dicts and returns the final aggregated score,
    risk level, and a structured summary.
    """
    weighted_score = 0.0
    total_weight = 0.0

    for result in module_results:
        module_name = result.get("module", "")
        module_score = result.get("score", 0)
        weight = MODULE_WEIGHTS.get(module_name, 10)

        weighted_score += module_score * (weight / 100)
        total_weight += weight

    # Normalize to 0-100
    final_score = min(round(weighted_score), 100)

    # Determine risk level
    risk_label = "Unknown"
    risk_icon = "❓"
    risk_description = ""
    for threshold, label, icon, desc in RISK_LEVELS:
        if final_score >= threshold:
            risk_label = label
            risk_icon = icon
            risk_description = desc
            break

    # Count findings by severity
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "safe": 0, "info": 0}
    all_findings = []
    for result in module_results:
        for finding in result.get("findings", []):
            severity = finding.get("severity", "info")
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            all_findings.append({
                "module": result.get("module", ""),
                **finding
            })

    # Sort findings: critical first, safe last
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "safe": 5}
    all_findings.sort(key=lambda x: severity_order.get(x.get("severity", "info"), 4))

    return {
        "final_score": final_score,
        "risk_level": risk_label,
        "risk_icon": risk_icon,
        "risk_description": risk_description,
        "severity_counts": severity_counts,
        "module_scores": {r["module"]: r["score"] for r in module_results},
        "all_findings": all_findings,
    }
