# SessionGuard — Web Application Session Hijacking Detection System

A cybersecurity project for detecting session hijacking vulnerabilities in web applications.

---

## Overview

SessionGuard analyzes web applications for session management security flaws.

I am currently in my 3rd year of B.Tech CSE at 
[Lovely Proffesional University], Gaya, Bihar. I built this project 
out of interest in cybersecurity after studying 
session management in my Network Security subject.

I wanted to go beyond the theory and actually 
build something that tests real websites — 
so this is the result of that curiosity.

## What I Learned

Before this project I had no idea how session management 
actually works in real web applications. 

Building this taught me:
- How browsers and servers exchange cookies
- Why HttpOnly flag matters in XSS attacks  
- How to use Python requests library properly
- How Flask routing and APIs work
- That security is not just theory — it can be tested!

Honestly the OWASP documentation was confusing at first
but after reading it 3-4 times it started making sense.


### What It Detects

| Check | OWASP Reference | Severity |
|---|---|---|
| Missing HttpOnly cookie flag | WSTG-SESS-02 | HIGH |
| Missing Secure cookie flag | WSTG-SESS-02 | HIGH |
| Missing SameSite attribute | WSTG-SESS-02 | MEDIUM |
| Weak/predictable session IDs | WSTG-SESS-01 | HIGH |
| Session fixation vulnerability | WSTG-SESS-03 | HIGH |
| Session over HTTP (unencrypted) | WSTG-SESS-02 | HIGH |
| Missing HSTS header | A02:2021 | MEDIUM |
| Missing Content-Security-Policy | A03:2021 | MEDIUM |
| No session timeout | WSTG-SESS-07 | MEDIUM |
| Weak cache control | WSTG-SESS-08 | LOW |
| Missing X-Frame-Options | A05:2021 | LOW |

---

## Project Structure


session-hijack-detector/
├── app.py                  # Flask web application (routes + API)
├── scanner.py              # Core scanning engine (HTTP requests)
├── cookie_analyzer.py      # Cookie security flag analysis
├── session_analyzer.py     # Session security & header analysis
├── requirements.txt        # Python dependencies
├── README.md               # This file
└── templates/
    ├── index.html          # Landing page + URL scanner
    ├── dashboard.html      # Security dashboard with charts
    └── report.html         # Detailed vulnerability report


---

## Installation & Setup

### Prerequisites

- Python 3.8 or higher
- pip (Python package manager)
- Internet access (for scanning external targets)

### Step-by-Step Installation

**1. Clone or download the project**
```bash
git clone <repo-url>
cd session-hijack-detector
```

**2. Create a virtual environment (recommended)**
```bash
python -m venv venv

venv\Scripts\activate


source venv/bin/activate
```

**3. Install dependencies**
```bash
pip install -r requirements.txt
```

**4. Run the application**
```bash
python app.py
```

**5. Open in browser**
```
http://localhost:5000
```

---

## Usage

### Web Interface

1. Navigate to `http://localhost:5000`
2. Enter a target URL (e.g., `https://example.com`)
3. Click **SCAN** or press Enter
4. View real-time scan progress
5. Explore results in the Dashboard and Report pages

### Demo Mode

Click **⚡ DEMO MODE** on the scanner page to see a simulated scan against a vulnerable application (no real network request — safe for offline demo).

### Quick Test URLs

- `http://testphp.vulnweb.com` — Intentionally vulnerable PHP app (Acunetix)
- `http://demo.testfire.net` — IBM demo banking app
- `https://httpbin.org` — HTTP testing service (low risk)
- `https://example.com` — Minimal cookies (low risk)

### API Usage

```bash
# Scan a target
curl -X POST http://localhost:5000/api/scan \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com"}'

# Run demo scan
curl -X POST http://localhost:5000/api/scan \
  -H "Content-Type: application/json" \
  -d '{"url": "https://demo.example.com", "demo": true}'
```

---

## Technical Architecture

```
Browser
  │
  ├─ GET /          → index.html      (URL input + scan trigger)
  ├─ GET /dashboard → dashboard.html  (charts + cookie table)
  ├─ GET /report    → report.html     (full vulnerability report)
  │
  └─ POST /api/scan/stream  ← SSE streaming scan results
           │
           └── scanner.py::run_scan()
                 ├── cookie_analyzer.py::analyze_all_cookies()
                 └── session_analyzer.py::analyze_session()
```

### Scan Pipeline

1. **URL Validation** — Normalize and validate URL format
2. **SSL Check** — Verify TLS certificate validity
3. **HTTP Request** — Fetch target with realistic browser headers
4. **Cookie Extraction** — Parse Set-Cookie headers
5. **Cookie Analysis** — Check HttpOnly, Secure, SameSite, entropy
6. **Session Analysis** — Check headers, fixation, timeout, transport
7. **Report Generation** — Aggregate findings with OWASP references

---

## Security Notes

> **⚠ Ethical Use Only**
>
> This tool is designed for security research, penetration testing, and educational purposes. Only scan web applications you own or have explicit written permission to test. Unauthorized scanning may violate computer crime laws.

### Limitations

- This tool performs **passive analysis** (no active exploitation)
- Cookie attribute detection depends on what the server sends in headers
- Session fixation detection is heuristic (no actual login flow)
- Some servers block automated requests

---

## OWASP References

- [OWASP Testing Guide v4.2 — Session Management Testing](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/)
- [OWASP Top 10 A07:2021](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/)
- [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
- [OWASP Cookie Security Guide](https://owasp.org/www-community/controls/SecureCookieAttribute)

---

## Tech Stack

| Layer | Technology |
|---|---|
| Backend | Python 3.8+, Flask 3.0 |
| HTTP Client | Requests 2.31 |
| HTML Parser | BeautifulSoup 4 |
| CLI Output | Tabulate 0.9 |
| Frontend | HTML5, CSS3, TailwindCSS CDN |
| Charts | Chart.js 4.4 |
| Fonts | Google Fonts (Rajdhani, Share Tech Mono, Exo 2) |

---


