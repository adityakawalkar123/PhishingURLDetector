# PhishGuard — Phishing URL Detection Tool
### Cybersecurity Mini Project Documentation

---

## Project Aim

To design and implement a lightweight, heuristic-based URL analysis tool that detects potential phishing websites using pattern recognition and structural URL analysis — without requiring external threat-intelligence APIs or databases.

---

## Project Description

PhishGuard is a web-based cybersecurity tool built with Python (Flask) on the backend and HTML/CSS/JavaScript on the frontend. It accepts any URL from the user and runs it through **6 independent security checks**. Each check assigns a risk score, which is accumulated into a total risk score (0–100). The final verdict classifies the URL as:

| Score Range | Classification              |
|-------------|----------------------------|
| 0 – 25      | ✅ Safe                     |
| 26 – 55     | ⚠️ Suspicious               |
| 56 – 100    | 🚨 High Risk (Possible Phishing) |

The interface is styled as a cybersecurity operations dashboard with glowing UI elements, animated scan effects, and a 3D layered panel design.

---

## Step-by-Step Working Explanation

### Step 1: User Input
The user enters a URL into the input field and clicks **"ANALYZE URL"** (or presses Enter).

### Step 2: Frontend Validation
JavaScript checks that the input is not empty. If empty, the input box shakes and an error is shown inline.

### Step 3: Loading Animation
A full-screen overlay appears, cycling through scan step messages while a progress bar fills — simulating a realistic analysis sequence.

### Step 4: API Request
The frontend sends a `POST` request to `/analyze` with the URL in the JSON body:
```json
{ "url": "http://example.com" }
```

### Step 5: Backend URL Parsing
Flask receives the URL and normalizes it. `urllib.parse.urlparse()` decomposes the URL into components: scheme, netloc (domain), path, query, fragment.

### Step 6: Security Checks (6 total)
Each check function analyzes one aspect of the URL and returns:
- `name`: The check name
- `passed`: Boolean — whether the URL passed the check
- `score`: Risk contribution (0–30 per check)
- `detail`: Human-readable explanation

### Step 7: Risk Scoring and Classification
All 6 scores are summed (capped at 100). The `classify_risk()` function maps the score to a verdict level with color and description.

### Step 8: JSON Response
The backend returns a structured JSON response containing the check results, total score, and risk classification.

### Step 9: UI Rendering
JavaScript dynamically:
- Renders the verdict banner with the appropriate color theme
- Animates the circular score ring with a smooth CSS transition
- Animates the score counter from 0 to the final value
- Renders one card per check, color-coded by severity
- Updates the status bar

---

## Security Checks Explained

### 1. HTTPS Check (`check_https`)
- **Why:** HTTP means no SSL/TLS encryption. Phishing sites often use HTTP to avoid certificate costs.
- **Method:** Check if URL starts with `http://`
- **Risk Score:** 20 if HTTP, 0 if HTTPS

### 2. Domain Length Analysis (`check_domain_length`)
- **Why:** Phishing domains are often very long to obscure the real domain.
- **Method:** `len(parsed_url.netloc)`
- **Risk Score:** 25 if >50 chars, 15 if >30 chars, 0 otherwise

### 3. Suspicious Keyword Detection (`check_suspicious_keywords`)
- **Why:** Phishing URLs frequently include trust-inducing words to deceive users.
- **Keywords:** login, verify, secure, bank, account, update, password, confirm, auth, paypal, amazon, etc.
- **Method:** `if keyword in url.lower()`
- **Risk Score:** 10 per keyword, capped at 30

### 4. IP Address Detection (`check_ip_address`)
- **Why:** Using a raw IP like `http://192.168.1.1/login` hides the real server identity.
- **Method:** Regex pattern `(\d{1,3}\.){3}\d{1,3}`
- **Risk Score:** 25 if IP detected

### 5. Special Characters Check (`check_special_characters`)
- **Why:** The `@` character in a URL body redirects to a different host. Excessive hyphens are used in spoofing domains. Percent-encoding can hide malicious content.
- **Method:** String search + regex
- **Risk Score:** 20 for `@`, 15 for 3+ hyphens, 10 for `//`, 10 for `%xx` encoding

### 6. Subdomain Count (`check_subdomain_count`)
- **Why:** `paypal.secure-login.evil.com` has 2 subdomains. The real domain is `evil.com`, not PayPal.
- **Method:** Count `.` splits in netloc
- **Risk Score:** 20 if 3+ subdomains, 10 if 2 subdomains

---

## Important Functions Used

| Function | Module | Purpose |
|----------|--------|---------|
| `urlparse(url)` | `urllib.parse` | Decomposes URL into components |
| `re.compile(pattern)` | `re` | Compiles regex for IP detection |
| `re.search(pattern, string)` | `re` | Checks for pattern matches in URL |
| `str.lower()` | Built-in | Case-insensitive keyword matching |
| `str.count(char)` | Built-in | Count hyphens in domain |
| `str.startswith(prefix)` | Built-in | Check HTTP/HTTPS protocol |
| `jsonify(data)` | Flask | Convert dict to JSON response |
| `request.get_json()` | Flask | Parse incoming JSON request body |
| `min(value, cap)` | Built-in | Cap score contributions |

---

## Expected Output

### Safe URL (`https://www.google.com`)
```
Risk Score: 0 / 100
Verdict: ✅ SAFE
Checks: All 6 passed
```

### Suspicious URL (`http://paypal-secure.verify-account.com`)
```
Risk Score: ~45 / 100
Verdict: ⚠️ SUSPICIOUS
Failed Checks: HTTPS (20), Keywords: paypal, verify, secure, account (30)
Passed Checks: IP Address, Special Chars, Subdomain, Length
```

### High Risk URL (`http://192.168.1.1/login/verify/bank@secure`)
```
Risk Score: 85+ / 100
Verdict: 🚨 HIGH RISK — POSSIBLE PHISHING
Failed Checks: HTTPS (20), IP Address (25), Keywords (30), @ symbol (20)
```

---

## Conclusion

PhishGuard successfully demonstrates how URL-level heuristic analysis can be applied to detect likely phishing websites without needing external databases. The combination of 6 independent checks — each targeting a well-known phishing pattern — provides a robust, fast, and lightweight detection mechanism. The modern cybersecurity dashboard interface makes the tool accessible and visually informative.

The project achieves its aim of serving as an educational and practical intermediate-level cybersecurity tool, reinforcing concepts of:
- URL structure and parsing
- Pattern recognition with regex
- Risk scoring models
- Secure web development with Flask

---

## Future Improvements

1. **WHOIS Lookup** — Check domain registration age. Newly registered domains (<30 days) are a major phishing indicator.

2. **DNS Blacklist Integration** — Query PhishTank, Google Safe Browsing API, or OpenPhish in real time.

3. **TLS Certificate Validation** — Verify the SSL certificate validity, issuer, and match against the domain name.

4. **Redirect Chain Analysis** — Follow HTTP redirects to expose the final destination URL.

5. **Levenshtein Distance Check** — Detect typosquatting (e.g., `paypa1.com`, `g00gle.com`) using string similarity algorithms.

6. **Machine Learning Model** — Train a classifier (e.g., Random Forest) on the UCI Phishing Dataset for higher accuracy than rule-based scoring.

7. **Browser Extension** — Package as a Chrome/Firefox extension to analyze URLs in real time during browsing.

8. **Bulk URL Scanning** — Accept a list of URLs (CSV upload) and export a full threat report.

9. **User History** — Store past scan results locally (localStorage) for quick reference.

10. **Confidence Score** — Display confidence percentage alongside each check for more nuanced feedback.

---

## Project Structure

```
PhishingURLDetector/
│
├── app.py                   # Flask backend — all analysis logic
├── requirements.txt         # Python dependencies (Flask only)
├── PROJECT_DOCS.md          # This documentation file
│
├── templates/
│   └── index.html           # Main HTML — cybersecurity dashboard UI
│
└── static/
    ├── css/
    │   └── style.css        # All styling — parallax, glow, 3D effects
    └── js/
        └── main.js          # Frontend logic — API calls, UI rendering
```

---

## How to Run

```bash
# 1. Navigate to project folder
cd PhishingURLDetector

# 2. Install Flask
pip install flask

# 3. Run the server
python app.py

# 4. Open browser
# Visit: http://127.0.0.1:5000
```

---

*PhishGuard v2.4 · Intermediate Cybersecurity Mini Project*
