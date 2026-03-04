"""
cookie_analyzer.py
==================
OWASP A07:2021 - Identification and Authentication Failures
Analyzes HTTP cookies for security misconfigurations that enable session hijacking.

Key checks based on OWASP Testing Guide (WSTG-SESS-02):
- HttpOnly: Prevents JavaScript access (mitigates XSS-based session theft)
- Secure: Ensures cookie only sent over HTTPS (mitigates MITM attacks)
- SameSite: Controls cross-site request inclusion (mitigates CSRF + session riding)
- Session ID Entropy: Weak/predictable IDs are easily guessed or brute-forced
- Expiration: Persistent sessions increase hijacking window
"""

import re
import math
import hashlib
from tabulate import tabulate


# ─────────────────────────────────────────────
# Constants & OWASP References
# ─────────────────────────────────────────────

# Common session cookie name patterns (OWASP WSTG-SESS-01)
SESSION_COOKIE_PATTERNS = [
    r'^sess(ion)?[_-]?id$',
    r'^(php)?sess(id)?$',
    r'^jsessionid$',
    r'^asp\.?net[_-]?session[_-]?id$',
    r'^auth[_-]?token$',
    r'^access[_-]?token$',
    r'^user[_-]?token$',
    r'^sid$',
    r'^token$',
    r'^connect\.sid$',
    r'^laravel[_-]?session$',
    r'^django[_-]?session$',
    r'^rack\.session$',
]

# Minimum recommended session ID entropy (OWASP: at least 128 bits)
MIN_SESSION_ID_LENGTH = 16
SECURE_SESSION_ID_LENGTH = 32

# Severity levels
SEVERITY_HIGH   = "HIGH"
SEVERITY_MEDIUM = "MEDIUM"
SEVERITY_LOW    = "LOW"
SEVERITY_INFO   = "INFO"

# OWASP references
OWASP_REFS = {
    "httponly":        "OWASP WSTG-SESS-02 / A07:2021",
    "secure":          "OWASP WSTG-SESS-02 / A02:2021",
    "samesite":        "OWASP WSTG-SESS-02 / A01:2021",
    "entropy":         "OWASP WSTG-SESS-01 / A07:2021",
    "expiry":          "OWASP WSTG-SESS-06 / A07:2021",
    "fixation":        "OWASP WSTG-SESS-03 / A07:2021",
    "session_timeout": "OWASP WSTG-SESS-07 / A07:2021",
}


# ─────────────────────────────────────────────
# Entropy Calculator
# ─────────────────────────────────────────────

def calculate_entropy(value: str) -> float:
    """
    Shannon entropy calculation.
    Higher entropy = more random = harder to predict/guess.
    OWASP recommends session IDs with at least 64 bits of entropy.
    Formula: H = -Σ p(x) * log2(p(x))
    """
    if not value:
        return 0.0
    freq = {}
    for ch in value:
        freq[ch] = freq.get(ch, 0) + 1
    total = len(value)
    entropy = 0.0
    for count in freq.values():
        prob = count / total
        entropy -= prob * math.log2(prob)
    # Estimated bits of entropy = entropy_per_char * length
    return round(entropy * total, 2)


def is_likely_predictable(value: str) -> bool:
    """
    Detect obviously weak/predictable session IDs.
    Checks for sequential numbers, dictionary words, common patterns.
    """
    if not value:
        return True
    # All same character
    if len(set(value)) <= 2:
        return True
    # Purely numeric (timestamps, counters)
    if value.isdigit():
        return True
    # Very short
    if len(value) < MIN_SESSION_ID_LENGTH:
        return True
    # Low entropy threshold
    if calculate_entropy(value) < 30:
        return True
    return False


# ─────────────────────────────────────────────
# Cookie Security Checker
# ─────────────────────────────────────────────

def is_session_cookie(name: str) -> bool:
    """Determine if a cookie is likely a session/auth cookie."""
    name_lower = name.lower()
    for pattern in SESSION_COOKIE_PATTERNS:
        if re.match(pattern, name_lower):
            return True
    return False


def analyze_cookie(cookie: dict) -> dict:
    """
    Full security analysis of a single cookie.
    Returns a structured result with all security findings.

    cookie dict keys (from requests library):
    - name, value, domain, path, secure, expires, httponly, samesite, rest
    """
    name  = cookie.get("name", "unknown")
    value = cookie.get("value", "")
    findings = []

    # ── 1. HttpOnly Flag (OWASP WSTG-SESS-02) ─────────────────────────────
    # Without HttpOnly, JavaScript (including injected XSS payloads) can read
    # the cookie via document.cookie — enabling session theft.
    httponly = cookie.get("httponly", False)
    if not httponly:
        findings.append({
            "check":       "Missing HttpOnly Flag",
            "severity":    SEVERITY_HIGH,
            "description": (
                f"Cookie '{name}' lacks the HttpOnly attribute. "
                "This allows JavaScript to access the cookie value via document.cookie, "
                "making it vulnerable to Cross-Site Scripting (XSS) based session hijacking."
            ),
            "remediation": (
                "Set the HttpOnly flag on all session cookies. "
                "In Flask: set_cookie(name, value, httponly=True). "
                "In PHP: session_set_cookie_params(['httponly' => true])."
            ),
            "owasp": OWASP_REFS["httponly"],
        })

    # ── 2. Secure Flag (OWASP WSTG-SESS-02) ──────────────────────────────
    # Without Secure flag, the cookie is transmitted over HTTP, allowing
    # man-in-the-middle attackers to intercept it (e.g., on public WiFi).
    secure = cookie.get("secure", False)
    if not secure:
        findings.append({
            "check":       "Missing Secure Flag",
            "severity":    SEVERITY_HIGH,
            "description": (
                f"Cookie '{name}' lacks the Secure attribute. "
                "The cookie will be transmitted over unencrypted HTTP connections, "
                "enabling passive eavesdropping and man-in-the-middle session hijacking."
            ),
            "remediation": (
                "Set the Secure flag on all session cookies to ensure transmission only over HTTPS. "
                "In Flask: set_cookie(name, value, secure=True). "
                "Also enforce HSTS to prevent SSL stripping attacks."
            ),
            "owasp": OWASP_REFS["secure"],
        })

    # ── 3. SameSite Flag (OWASP WSTG-SESS-02) ────────────────────────────
    # Without SameSite, cookies are sent with cross-site requests, enabling
    # Cross-Site Request Forgery (CSRF) and session riding attacks.
    samesite = cookie.get("samesite", None)
    if not samesite:
        findings.append({
            "check":       "Missing SameSite Attribute",
            "severity":    SEVERITY_MEDIUM,
            "description": (
                f"Cookie '{name}' has no SameSite attribute. "
                "The browser will send this cookie with cross-site requests, "
                "enabling CSRF attacks and cross-site session riding."
            ),
            "remediation": (
                "Set SameSite=Strict for maximum protection (prevents all cross-site sending). "
                "Use SameSite=Lax if you need cookies sent on top-level navigation. "
                "Avoid SameSite=None unless required (and pair with Secure flag)."
            ),
            "owasp": OWASP_REFS["samesite"],
        })
    elif samesite.lower() == "none":
        findings.append({
            "check":       "Weak SameSite=None Policy",
            "severity":    SEVERITY_MEDIUM,
            "description": (
                f"Cookie '{name}' uses SameSite=None, meaning it is sent with all "
                "cross-site requests. This provides no CSRF protection and increases "
                "the session hijacking attack surface."
            ),
            "remediation": (
                "Upgrade to SameSite=Strict or SameSite=Lax where possible. "
                "SameSite=None is only appropriate for cross-origin API endpoints "
                "and must always be paired with the Secure flag."
            ),
            "owasp": OWASP_REFS["samesite"],
        })

    # ── 4. Session ID Entropy / Predictability (OWASP WSTG-SESS-01) ──────
    # Weak session IDs can be guessed or brute-forced by attackers.
    # OWASP requires at least 128 bits of entropy for session tokens.
    if is_session_cookie(name):
        entropy = calculate_entropy(value)
        if is_likely_predictable(value):
            findings.append({
                "check":       "Predictable / Weak Session ID",
                "severity":    SEVERITY_HIGH,
                "description": (
                    f"Session cookie '{name}' has a low-entropy value (entropy ≈ {entropy} bits). "
                    f"Value length: {len(value)} chars. "
                    "Weak session IDs are vulnerable to brute-force or prediction attacks, "
                    "allowing attackers to forge valid session tokens."
                ),
                "remediation": (
                    "Generate session IDs using a cryptographically secure random number generator. "
                    "Python: secrets.token_hex(32) produces 256-bit tokens. "
                    "Minimum length: 32 characters (128-bit entropy). "
                    "Never use user data, timestamps, or sequential numbers as session IDs."
                ),
                "owasp": OWASP_REFS["entropy"],
            })
        elif len(value) < SECURE_SESSION_ID_LENGTH:
            findings.append({
                "check":       "Short Session ID",
                "severity":    SEVERITY_MEDIUM,
                "description": (
                    f"Session cookie '{name}' value is only {len(value)} characters. "
                    "Short session IDs reduce the keyspace and increase brute-force feasibility."
                ),
                "remediation": (
                    "Use session IDs of at least 32 characters (128 bits of entropy). "
                    "OWASP recommends 64 characters for high-security applications."
                ),
                "owasp": OWASP_REFS["entropy"],
            })

    # ── 5. Session Expiration (OWASP WSTG-SESS-07) ────────────────────────
    # Persistent sessions (no expiry or very long expiry) extend the hijacking
    # window significantly. Stolen tokens remain valid for longer.
    expires = cookie.get("expires", None)
    max_age = cookie.get("max-age", None)

    if expires is None and max_age is None:
        # Session cookie (no expiry) — acceptable, but flag for awareness
        pass  # Session cookies expire when browser closes — this is actually OK
    elif expires and isinstance(expires, (int, float)) and expires > 0:
        # Far-future expiry (over 1 day in seconds from now)
        import time
        now = time.time()
        if expires - now > 86400:  # more than 24 hours
            findings.append({
                "check":       "Long-lived Session Cookie",
                "severity":    SEVERITY_LOW,
                "description": (
                    f"Cookie '{name}' has a persistent expiry far in the future. "
                    "Long session lifetimes increase the window of opportunity for attackers "
                    "to exploit stolen session tokens."
                ),
                "remediation": (
                    "Implement server-side session expiration (30 min idle timeout). "
                    "Use short-lived tokens with refresh mechanisms. "
                    "Invalidate sessions on logout — do not rely solely on cookie expiry."
                ),
                "owasp": OWASP_REFS["session_timeout"],
            })

    # Compute overall cookie risk score
    score = 0
    for f in findings:
        if f["severity"] == SEVERITY_HIGH:
            score += 30
        elif f["severity"] == SEVERITY_MEDIUM:
            score += 15
        elif f["severity"] == SEVERITY_LOW:
            score += 5

    return {
        "name":          name,
        "value_preview": value[:20] + "..." if len(value) > 20 else value,
        "value_length":  len(value),
        "entropy":       calculate_entropy(value),
        "is_session":    is_session_cookie(name),
        "httponly":      httponly,
        "secure":        secure,
        "samesite":      samesite or "Not Set",
        "expires":       str(expires) if expires else "Session",
        "findings":      findings,
        "risk_score":    min(score, 100),
        "is_vulnerable": len(findings) > 0,
    }


def analyze_all_cookies(cookies: list) -> dict:
    """
    Analyze a list of cookie dicts and return aggregated results.
    Includes tabulated output for CLI display.
    """
    results = [analyze_cookie(c) for c in cookies]

    total         = len(results)
    vulnerable    = sum(1 for r in results if r["is_vulnerable"])
    session_cookies = sum(1 for r in results if r["is_session"])
    high_risk     = sum(1 for r in results for f in r["findings"] if f["severity"] == SEVERITY_HIGH)
    medium_risk   = sum(1 for r in results for f in r["findings"] if f["severity"] == SEVERITY_MEDIUM)
    low_risk      = sum(1 for r in results for f in r["findings"] if f["severity"] == SEVERITY_LOW)

    # Overall risk score = average of all cookie scores
    overall_score = round(sum(r["risk_score"] for r in results) / total, 1) if total > 0 else 0

    # ── Tabulated Summary (for CLI/report) ─────────────────────────────────
    table_data = []
    for r in results:
        table_data.append([
            r["name"],
            "✓" if r["httponly"] else "✗",
            "✓" if r["secure"]   else "✗",
            r["samesite"],
            r["entropy"],
            "SESSION" if r["is_session"] else "OTHER",
            r["risk_score"],
        ])

    headers = ["Cookie Name", "HttpOnly", "Secure", "SameSite", "Entropy", "Type", "Risk Score"]
    tabulated = tabulate(table_data, headers=headers, tablefmt="grid")

    return {
        "cookies":        results,
        "summary": {
            "total":           total,
            "vulnerable":      vulnerable,
            "session_cookies": session_cookies,
            "high_risk":       high_risk,
            "medium_risk":     medium_risk,
            "low_risk":        low_risk,
            "overall_score":   overall_score,
        },
        "tabulated_output": tabulated,
    }
