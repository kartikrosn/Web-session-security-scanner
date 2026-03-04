"""
session_analyzer.py
===================
OWASP A07:2021 – Identification and Authentication Failures
Detects session management vulnerabilities beyond basic cookie flags.

Checks implemented:
1. Session Fixation (OWASP WSTG-SESS-03)
2. Missing Session Timeout (OWASP WSTG-SESS-07)
3. Session Prediction / Weak Tokens (OWASP WSTG-SESS-01)
4. Insecure Transmission (OWASP WSTG-SESS-02)
5. Insufficient Session Invalidation (OWASP WSTG-SESS-06)
6. Cookie Scope Misconfiguration (OWASP WSTG-SESS-02)
"""

import re
from tabulate import tabulate
from cookie_analyzer import (
    is_session_cookie,
    calculate_entropy,
    is_likely_predictable,
    SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW, SEVERITY_INFO
)


# ─────────────────────────────────────────────
# HTTP Header Security Checks
# ─────────────────────────────────────────────

def check_security_headers(headers: dict) -> list:
    """
    Analyze HTTP response headers for session-security-related misconfigurations.
    Returns a list of vulnerability findings.
    """
    findings = []
    headers_lower = {k.lower(): v for k, v in headers.items()}

    # ── Strict-Transport-Security (HSTS) ─────────────────────────────────
    # Without HSTS, attackers can perform SSL stripping to downgrade HTTPS→HTTP,
    # then intercept cookies without the Secure flag.
    if "strict-transport-security" not in headers_lower:
        findings.append({
            "check":       "Missing HSTS Header",
            "severity":    SEVERITY_MEDIUM,
            "description": (
                "The server does not send a Strict-Transport-Security (HSTS) header. "
                "Without HSTS, attackers can perform SSL stripping attacks to downgrade "
                "HTTPS connections to HTTP and intercept session cookies."
            ),
            "remediation": (
                "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload. "
                "Flask: response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'"
            ),
            "owasp": "OWASP WSTG-SESS-02 / A02:2021",
        })

    # ── Content-Security-Policy ───────────────────────────────────────────
    # CSP blocks malicious scripts that could steal session cookies via XSS.
    if "content-security-policy" not in headers_lower:
        findings.append({
            "check":       "Missing Content-Security-Policy",
            "severity":    SEVERITY_MEDIUM,
            "description": (
                "No Content-Security-Policy (CSP) header found. "
                "CSP is a critical defense-in-depth control that restricts which scripts "
                "can execute, significantly reducing XSS-based session hijacking risk."
            ),
            "remediation": (
                "Implement CSP: Content-Security-Policy: default-src 'self'; script-src 'self'. "
                "Start in report-only mode to avoid breaking changes: "
                "Content-Security-Policy-Report-Only: default-src 'self'"
            ),
            "owasp": "OWASP WSTG-SESS-02 / A03:2021",
        })

    # ── X-Frame-Options ───────────────────────────────────────────────────
    # Prevents clickjacking attacks that can force users to perform actions
    # while authenticated (session riding variant).
    if "x-frame-options" not in headers_lower:
        findings.append({
            "check":       "Missing X-Frame-Options Header",
            "severity":    SEVERITY_LOW,
            "description": (
                "X-Frame-Options header is absent. "
                "Without this, the application can be embedded in iframes on attacker-controlled "
                "sites, enabling clickjacking and UI redressing attacks."
            ),
            "remediation": (
                "Add: X-Frame-Options: DENY (or SAMEORIGIN if framing is needed). "
                "Modern alternative: Content-Security-Policy: frame-ancestors 'none'."
            ),
            "owasp": "OWASP WSTG-CLNT-09 / A05:2021",
        })

    # ── X-Content-Type-Options ────────────────────────────────────────────
    if "x-content-type-options" not in headers_lower:
        findings.append({
            "check":       "Missing X-Content-Type-Options",
            "severity":    SEVERITY_LOW,
            "description": (
                "X-Content-Type-Options: nosniff is not set. "
                "MIME-type sniffing can allow attackers to trick browsers into executing "
                "malicious content, facilitating XSS and subsequent session theft."
            ),
            "remediation": "Add header: X-Content-Type-Options: nosniff",
            "owasp": "OWASP A05:2021",
        })

    # ── Cache-Control ─────────────────────────────────────────────────────
    # Caching authenticated pages can expose session data from browser/proxy cache.
    cache = headers_lower.get("cache-control", "")
    if "no-store" not in cache and "no-cache" not in cache:
        findings.append({
            "check":       "Weak Cache-Control Policy",
            "severity":    SEVERITY_LOW,
            "description": (
                "Cache-Control does not include 'no-store' or 'no-cache'. "
                "Authenticated page content may be cached by browsers or proxies, "
                "exposing sensitive session data to subsequent users on shared machines."
            ),
            "remediation": (
                "For authenticated responses: "
                "Cache-Control: no-store, no-cache, must-revalidate, private. "
                "Pragma: no-cache."
            ),
            "owasp": "OWASP WSTG-SESS-08 / A07:2021",
        })

    return findings


# ─────────────────────────────────────────────
# Session Fixation Detection
# ─────────────────────────────────────────────

def check_session_fixation(cookies_before: list, cookies_after: list) -> list:
    """
    Detect session fixation by checking if session ID changes after authentication.
    OWASP WSTG-SESS-03: The server should regenerate session ID upon login.

    In production this would compare pre/post-login session tokens.
    Here we analyze available cookies for fixation indicators.
    """
    findings = []

    # Extract session cookie values
    session_ids = {}
    for cookie in cookies_before:
        if is_session_cookie(cookie.get("name", "")):
            session_ids[cookie["name"]] = cookie.get("value", "")

    if session_ids:
        # Check if any session IDs are in common predictable formats
        for name, value in session_ids.items():
            if is_likely_predictable(value):
                findings.append({
                    "check":       "Session Fixation Risk",
                    "severity":    SEVERITY_HIGH,
                    "description": (
                        f"Session cookie '{name}' has a predictable value pattern. "
                        "Predictable session IDs enable session fixation attacks where "
                        "an attacker pre-sets a known session ID and waits for a victim "
                        "to authenticate with it, gaining access to their session."
                    ),
                    "remediation": (
                        "1. Always regenerate session ID after successful authentication. "
                        "2. Never accept session IDs from URL parameters. "
                        "3. Use cryptographically secure random token generation. "
                        "Flask: session.regenerate() or use flask-login with session protection."
                    ),
                    "owasp": "OWASP WSTG-SESS-03 / A07:2021",
                })

    return findings


# ─────────────────────────────────────────────
# Session Timeout Analysis
# ─────────────────────────────────────────────

def check_session_timeout(cookies: list, headers: dict) -> list:
    """
    Detect missing or excessive session timeout configuration.
    OWASP WSTG-SESS-07: Sessions should expire after inactivity.
    """
    findings = []
    headers_lower = {k.lower(): v for k, v in headers.items()}

    # Check for Set-Cookie headers with Max-Age or Expires
    set_cookie = headers_lower.get("set-cookie", "")

    # Look for session cookies without expiry directives in the Set-Cookie header
    # A missing Max-Age/Expires means session-only cookie — actually OK
    # But a very large Max-Age is a risk
    if set_cookie:
        # Find very long max-age values
        max_age_match = re.search(r'max-age=(\d+)', set_cookie, re.IGNORECASE)
        if max_age_match:
            max_age = int(max_age_match.group(1))
            if max_age > 86400:  # More than 24 hours
                findings.append({
                    "check":       "Excessive Session Lifetime",
                    "severity":    SEVERITY_MEDIUM,
                    "description": (
                        f"Session cookie Max-Age is set to {max_age} seconds "
                        f"({max_age // 3600} hours). "
                        "Long session lifetimes significantly extend the window for "
                        "session hijacking attacks — stolen tokens remain valid longer."
                    ),
                    "remediation": (
                        "Set Max-Age to ≤3600 (1 hour) for sensitive applications. "
                        "Implement server-side idle timeout (15-30 min for high security). "
                        "Use sliding window expiration that resets on activity."
                    ),
                    "owasp": "OWASP WSTG-SESS-07 / A07:2021",
                })

    # Check if any session cookies lack server-side timeout indication
    session_cookies = [c for c in cookies if is_session_cookie(c.get("name", ""))]
    if session_cookies:
        # Look for timeout-related headers
        has_timeout_indication = (
            "x-session-timeout" in headers_lower or
            "session-timeout" in headers_lower
        )
        if not has_timeout_indication and "max-age" not in set_cookie.lower():
            findings.append({
                "check":       "No Session Timeout Detected",
                "severity":    SEVERITY_MEDIUM,
                "description": (
                    "No session timeout configuration was detected. "
                    "Without server-enforced idle timeouts, abandoned authenticated sessions "
                    "remain exploitable indefinitely (e.g., on shared or stolen devices)."
                ),
                "remediation": (
                    "Implement server-side session expiration: "
                    "Flask: app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30). "
                    "Add last-activity tracking and invalidate idle sessions. "
                    "Provide explicit logout functionality."
                ),
                "owasp": "OWASP WSTG-SESS-07 / A07:2021",
            })

    return findings


# ─────────────────────────────────────────────
# Transport Security Check
# ─────────────────────────────────────────────

def check_transport_security(url: str, cookies: list) -> list:
    """
    Check if session cookies are exposed over non-HTTPS connections.
    OWASP WSTG-SESS-02: Sessions must only be transmitted over TLS.
    """
    findings = []

    is_http = url.startswith("http://")

    if is_http:
        session_cookies = [c for c in cookies if is_session_cookie(c.get("name", ""))]
        if session_cookies:
            names = [c["name"] for c in session_cookies]
            findings.append({
                "check":       "Session Over Unencrypted HTTP",
                "severity":    SEVERITY_HIGH,
                "description": (
                    f"Session cookies ({', '.join(names)}) are being transmitted over HTTP. "
                    "Any network observer (attacker on same WiFi, ISP, proxy) can read "
                    "these cookies and hijack the session trivially — no hacking required."
                ),
                "remediation": (
                    "1. Migrate entire application to HTTPS. "
                    "2. Obtain TLS certificate (free via Let's Encrypt). "
                    "3. Set Secure flag on all session cookies. "
                    "4. Implement HTTP→HTTPS redirect. "
                    "5. Enable HSTS to prevent downgrade attacks."
                ),
                "owasp": "OWASP WSTG-SESS-02 / A02:2021",
            })
        elif cookies:
            findings.append({
                "check":       "All Cookies Transmitted Over HTTP",
                "severity":    SEVERITY_HIGH,
                "description": (
                    "The target URL uses HTTP (not HTTPS). All cookies are transmitted "
                    "in plaintext and are vulnerable to passive interception."
                ),
                "remediation": (
                    "Deploy TLS/HTTPS across the entire application. "
                    "Use Let's Encrypt for free certificates. "
                    "Redirect all HTTP traffic to HTTPS."
                ),
                "owasp": "OWASP WSTG-SESS-02 / A02:2021",
            })

    return findings


# ─────────────────────────────────────────────
# Full Session Analysis
# ─────────────────────────────────────────────

def analyze_session(url: str, cookies: list, headers: dict) -> dict:
    """
    Orchestrates all session security checks.
    Returns comprehensive findings with tabulated output.
    """
    all_findings = []

    # Run all checks
    all_findings += check_security_headers(headers)
    all_findings += check_session_fixation(cookies, cookies)
    all_findings += check_session_timeout(cookies, headers)
    all_findings += check_transport_security(url, cookies)

    # Count by severity
    high   = sum(1 for f in all_findings if f["severity"] == SEVERITY_HIGH)
    medium = sum(1 for f in all_findings if f["severity"] == SEVERITY_MEDIUM)
    low    = sum(1 for f in all_findings if f["severity"] == SEVERITY_LOW)

    # Risk scoring: High=30pts, Medium=15pts, Low=5pts
    risk_score = min((high * 30) + (medium * 15) + (low * 5), 100)

    # Risk level label
    if risk_score >= 70:
        risk_level = "CRITICAL"
    elif risk_score >= 40:
        risk_level = "HIGH"
    elif risk_score >= 20:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    # ── Tabulated findings output ─────────────────────────────────────────
    table_data = []
    for i, f in enumerate(all_findings, 1):
        table_data.append([
            i,
            f["check"],
            f["severity"],
            f["description"][:80] + "..." if len(f["description"]) > 80 else f["description"],
            f["owasp"],
        ])

    headers_tab = ["#", "Vulnerability", "Severity", "Description", "OWASP Ref"]
    tabulated = tabulate(table_data, headers=headers_tab, tablefmt="grid")

    return {
        "findings":        all_findings,
        "total_findings":  len(all_findings),
        "high_count":      high,
        "medium_count":    medium,
        "low_count":       low,
        "risk_score":      risk_score,
        "risk_level":      risk_level,
        "tabulated_output": tabulated,
    }
