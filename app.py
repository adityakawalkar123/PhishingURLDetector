"""
============================================================
  Phishing URL Detection Tool - Flask Backend
  Author: Cybersecurity Mini Project
  Description: Analyzes URLs for phishing indicators using
               multiple heuristic-based security checks.
============================================================
"""

from flask import Flask, render_template, request, jsonify
from urllib.parse import urlparse
import re
import math

# ─────────────────────────────────────────────
#  Flask Application Initialization
# ─────────────────────────────────────────────
import os
app = Flask(
    __name__,
    template_folder=os.path.join(os.path.dirname(__file__), 'templates'),
    static_folder=os.path.join(os.path.dirname(__file__), 'templates/static'),
    static_url_path='/static'
)


# ─────────────────────────────────────────────
#  SECURITY CHECK FUNCTIONS
# ─────────────────────────────────────────────

def check_https(url: str) -> dict:
    """
    Check 1: HTTPS Protocol Security Check
    -------------------------------------------
    Phishing sites often use HTTP (not HTTPS) to avoid
    the cost and process of obtaining an SSL certificate.
    Legitimate sites almost always use HTTPS.

    Returns a dict with score, flag, and description.
    """
    is_http = url.lower().startswith("http://")
    return {
        "name": "HTTPS Check",
        "icon": "🔒",
        "passed": not is_http,
        "score": 20 if is_http else 0,
        "detail": "Uses insecure HTTP protocol (no SSL/TLS)" if is_http
                  else "Secure HTTPS protocol detected"
    }


def check_domain_length(parsed_url) -> dict:
    """
    Check 2: Domain Length Analysis
    -------------------------------------------
    Phishing URLs tend to have very long domain names
    to disguise the real domain. Legitimate sites typically
    have short, recognizable domain names.
    Threshold: >30 chars is suspicious, >50 is high risk.
    """
    domain = parsed_url.netloc or parsed_url.path
    length = len(domain)

    if length > 50:
        score = 25
        detail = f"Domain is excessively long ({length} chars) — very suspicious"
        passed = False
    elif length > 30:
        score = 15
        detail = f"Domain is unusually long ({length} chars) — potentially suspicious"
        passed = False
    else:
        score = 0
        detail = f"Domain length is normal ({length} chars)"
        passed = True

    return {
        "name": "Domain Length",
        "icon": "📏",
        "passed": passed,
        "score": score,
        "detail": detail
    }


def check_suspicious_keywords(url: str) -> dict:
    """
    Check 3: Suspicious Keyword Detection
    -------------------------------------------
    Phishing URLs commonly include words like 'login',
    'verify', 'secure', 'bank', 'update', 'password', and
    'account' to impersonate legitimate services.
    Each keyword found adds to the risk score.
    """
    # List of common phishing keywords
    phishing_keywords = [
        "login", "verify", "secure", "bank", "account",
        "update", "password", "signin", "confirm", "auth",
        "paypal", "amazon", "apple", "microsoft", "support",
        "billing", "free", "winner", "urgent", "suspend"
    ]

    url_lower = url.lower()
    found_keywords = [kw for kw in phishing_keywords if kw in url_lower]
    score = min(len(found_keywords) * 10, 30)  # Cap at 30 points

    return {
        "name": "Suspicious Keywords",
        "icon": "🔍",
        "passed": len(found_keywords) == 0,
        "score": score,
        "detail": f"Found {len(found_keywords)} suspicious keyword(s): {', '.join(found_keywords)}"
                  if found_keywords else "No suspicious keywords detected"
    }


def check_ip_address(url: str) -> dict:
    """
    Check 4: IP Address Instead of Domain Name
    -------------------------------------------
    Using a raw IP address (e.g., http://192.168.1.1/login)
    is a common phishing tactic to hide the true identity
    of the server. Legitimate sites use human-readable domains.
    """
    # IPv4 pattern inside a URL
    ip_pattern = re.compile(
        r'(https?://)?(\d{1,3}\.){3}\d{1,3}'
    )
    has_ip = bool(ip_pattern.search(url))

    return {
        "name": "IP Address Usage",
        "icon": "🌐",
        "passed": not has_ip,
        "score": 25 if has_ip else 0,
        "detail": "URL uses an IP address instead of a domain name — high risk indicator"
                  if has_ip else "URL uses a proper domain name (not an IP)"
    }


def check_special_characters(url: str) -> dict:
    """
    Check 5: Special Characters & Excessive Hyphens
    -------------------------------------------
    The '@' symbol in a URL can redirect to a different
    host (e.g., http://google.com@evil.com goes to evil.com).
    Multiple hyphens in a domain are common in spoofing
    (e.g., secure-paypal-login.com).
    """
    issues = []
    score = 0

    if "@" in url:
        issues.append("'@' character detected (can redirect to different host)")
        score += 20

    # Count hyphens in the domain only
    parsed = urlparse(url if "://" in url else "http://" + url)
    domain = parsed.netloc
    hyphen_count = domain.count("-")

    if hyphen_count >= 3:
        issues.append(f"Excessive hyphens in domain ({hyphen_count} found)")
        score += 15
    elif hyphen_count >= 2:
        issues.append(f"Multiple hyphens in domain ({hyphen_count} found)")
        score += 5

    # Check for double slashes after protocol
    if re.search(r'(?<=[^:])//+', url):
        issues.append("Suspicious double slashes in URL path")
        score += 10

    # Check for encoded characters (often used in obfuscation)
    if re.search(r'%[0-9a-fA-F]{2}', url):
        issues.append("URL-encoded characters detected (possible obfuscation)")
        score += 10

    score = min(score, 30)  # Cap at 30 points

    return {
        "name": "Special Characters",
        "icon": "⚠️",
        "passed": len(issues) == 0,
        "score": score,
        "detail": "; ".join(issues) if issues else "No suspicious special characters found"
    }


def check_subdomain_count(parsed_url) -> dict:
    """
    Check 6: Excessive Subdomains
    -------------------------------------------
    Phishing sites often use multiple subdomains to mimic
    legitimate sites (e.g., paypal.secure.login.evil.com).
    The real domain is always at the end, not at the beginning.
    """
    domain = parsed_url.netloc or parsed_url.path
    # Remove port if present
    domain = domain.split(":")[0]
    parts = domain.split(".")

    # Count meaningful subdomain levels (exclude TLDs)
    subdomain_count = max(0, len(parts) - 2)

    if subdomain_count >= 3:
        score = 20
        detail = f"Too many subdomains ({subdomain_count}) — classic phishing pattern"
        passed = False
    elif subdomain_count == 2:
        score = 10
        detail = f"Multiple subdomains detected ({subdomain_count}) — slightly suspicious"
        passed = False
    else:
        score = 0
        detail = f"Normal subdomain count ({subdomain_count})"
        passed = True

    return {
        "name": "Subdomain Count",
        "icon": "🔗",
        "passed": passed,
        "score": score,
        "detail": detail
    }


# ─────────────────────────────────────────────
#  RISK CLASSIFICATION
# ─────────────────────────────────────────────

def classify_risk(total_score: int) -> dict:
    """
    Classify the URL risk level based on total score.
    -------------------------------------------
    Score 0–25   → Safe
    Score 26–55  → Suspicious
    Score 56+    → High Risk (Possible Phishing)
    """
    if total_score <= 25:
        return {
            "level": "SAFE",
            "label": "Safe",
            "color": "#00ff88",
            "bg": "#00ff8815",
            "description": "This URL appears to be safe based on our analysis.",
            "emoji": "✅"
        }
    elif total_score <= 55:
        return {
            "level": "SUSPICIOUS",
            "label": "Suspicious",
            "color": "#ffaa00",
            "bg": "#ffaa0015",
            "description": "This URL shows some suspicious characteristics. Proceed with caution.",
            "emoji": "⚠️"
        }
    else:
        return {
            "level": "HIGH_RISK",
            "label": "High Risk — Possible Phishing",
            "color": "#ff3366",
            "bg": "#ff336615",
            "description": "This URL shows multiple phishing indicators. Do NOT visit this site.",
            "emoji": "🚨"
        }


# ─────────────────────────────────────────────
#  MAIN ANALYSIS FUNCTION
# ─────────────────────────────────────────────

def analyze_url(url: str) -> dict:
    """
    Master analysis function — runs all security checks
    on the given URL and returns a complete report.

    Parameters:
        url (str): The URL string entered by the user.

    Returns:
        dict: Full analysis report including checks, score, and classification.
    """
    # Normalize URL for parsing
    normalized = url.strip()
    if not re.match(r'https?://', normalized, re.IGNORECASE):
        normalized_for_parse = "http://" + normalized
    else:
        normalized_for_parse = normalized

    try:
        parsed = urlparse(normalized_for_parse)
    except Exception:
        return {"error": "Invalid URL format. Please enter a valid URL."}

    # ── Run all checks ──────────────────────────────
    checks = [
        check_https(normalized),
        check_domain_length(parsed),
        check_suspicious_keywords(normalized),
        check_ip_address(normalized),
        check_special_characters(normalized),
        check_subdomain_count(parsed),
    ]

    # ── Tally total risk score ──────────────────────
    total_score = sum(c["score"] for c in checks)
    total_score = min(total_score, 100)  # Cap at 100

    # ── Classify risk ───────────────────────────────
    risk = classify_risk(total_score)

    return {
        "url": url,
        "normalized": normalized,
        "checks": checks,
        "total_score": total_score,
        "risk": risk,
        "checks_passed": sum(1 for c in checks if c["passed"]),
        "checks_failed": sum(1 for c in checks if not c["passed"]),
        "total_checks": len(checks)
    }


# ─────────────────────────────────────────────
#  FLASK ROUTES
# ─────────────────────────────────────────────

@app.route("/")
def index():
    """Render the main dashboard page."""
    return render_template("index.html")


@app.route("/analyze", methods=["POST"])
def analyze():
    """
    API endpoint to receive a URL and return analysis results.
    Accepts: JSON body with 'url' field
    Returns: JSON analysis report
    """
    data = request.get_json()

    if not data or "url" not in data:
        return jsonify({"error": "No URL provided."}), 400

    url = data["url"].strip()

    if not url:
        return jsonify({"error": "URL cannot be empty."}), 400

    if len(url) > 2000:
        return jsonify({"error": "URL is too long (max 2000 characters)."}), 400

    result = analyze_url(url)
    return jsonify(result)


# ─────────────────────────────────────────────
#  ENTRY POINT
# ─────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 55)
    print("  🛡️  Phishing URL Detection Tool — Running")
    print("  Visit: http://127.0.0.1:5000")
    print("=" * 55)
    app.run(debug=True, port=5000)
