"""
scanner.py
==========
Core scanning engine for the Web Application Session Hijacking Detection System.
Orchestrates HTTP requests, cookie extraction, and analysis modules.

OWASP Testing Guide References:
- WSTG-SESS-01: Testing for Session Management Schema
- WSTG-SESS-02: Testing for Cookies Attributes
- WSTG-SESS-03: Testing for Session Fixation
- WSTG-SESS-07: Testing Session Timeout
"""

import time
import socket
import ssl
import requests
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from cookie_analyzer import analyze_all_cookies
from session_analyzer import analyze_session


# ─────────────────────────────────────────────
# HTTP Client Configuration
# ─────────────────────────────────────────────

# Realistic browser headers to avoid bot detection
DEFAULT_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate",
    "Connection": "close",
}

# Timeout for HTTP requests (seconds)
REQUEST_TIMEOUT = 15

# Maximum redirects to follow
MAX_REDIRECTS = 5


# ─────────────────────────────────────────────
# URL Normalizer
# ─────────────────────────────────────────────

def normalize_url(url: str) -> str:
    """
    Ensure URL has a scheme. Default to https://.
    Validates the URL format before scanning.
    """
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url


def validate_url(url: str) -> tuple[bool, str]:
    """
    Validate the URL is well-formed and reachable.
    Returns (is_valid, error_message).
    """
    try:
        parsed = urlparse(url)
        if not parsed.netloc:
            return False, "Invalid URL: No hostname found."
        if parsed.scheme not in ("http", "https"):
            return False, "Invalid URL: Only http/https supported."
        return True, ""
    except Exception as e:
        return False, f"URL parsing error: {str(e)}"


# ─────────────────────────────────────────────
# SSL/TLS Certificate Check
# ─────────────────────────────────────────────

def check_ssl_certificate(hostname: str) -> dict:
    """
    Check if the host has a valid SSL/TLS certificate.
    Expired or missing certs indicate insecure transport.
    """
    result = {
        "has_ssl":   False,
        "valid":     False,
        "issuer":    None,
        "expires":   None,
        "error":     None,
    }
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                result["has_ssl"] = True
                result["valid"]   = True
                result["issuer"]  = dict(x[0] for x in cert.get("issuer", []))
                result["expires"] = cert.get("notAfter", "Unknown")
    except ssl.SSLCertVerificationError as e:
        result["has_ssl"] = True
        result["valid"]   = False
        result["error"]   = f"SSL Certificate invalid: {str(e)}"
    except (socket.timeout, ConnectionRefusedError):
        result["error"] = "Could not connect on port 443"
    except Exception as e:
        result["error"] = str(e)
    return result


# ─────────────────────────────────────────────
# HTTP Response Fetcher
# ─────────────────────────────────────────────

def fetch_target(url: str) -> dict:
    """
    Send HTTP GET request to target URL.
    Returns response data including headers, cookies, and body.
    Handles redirects, timeouts, and SSL errors gracefully.
    """
    scan_start = time.time()

    try:
        session = requests.Session()
        session.max_redirects = MAX_REDIRECTS

        response = session.get(
            url,
            headers=DEFAULT_HEADERS,
            timeout=REQUEST_TIMEOUT,
            verify=True,          # Verify SSL cert
            allow_redirects=True,
        )

        scan_time = round(time.time() - scan_start, 3)

        # Extract cookies as structured dicts
        cookies_list = []
        for cookie in response.cookies:
            cookie_dict = {
                "name":     cookie.name,
                "value":    cookie.value or "",
                "domain":   cookie.domain,
                "path":     cookie.path,
                "secure":   cookie.secure,
                "expires":  cookie.expires,
                "httponly": cookie.has_nonstandard_attr("HttpOnly") or
                            getattr(cookie, "_rest", {}).get("HttpOnly") is not None or
                            "httponly" in str(cookie).lower(),
                "samesite": None,
            }

            # Extract SameSite from _rest attributes
            rest = getattr(cookie, "_rest", {})
            for key in rest:
                if key.lower() == "samesite":
                    cookie_dict["samesite"] = rest[key]
                    break

            cookies_list.append(cookie_dict)

        # Also parse Set-Cookie headers for additional cookie attributes
        # (requests.cookies doesn't always capture all attributes)
        raw_set_cookie = response.headers.get("Set-Cookie", "")
        if raw_set_cookie and not cookies_list:
            # Manually parse if requests missed it
            cookies_list = parse_set_cookie_header(raw_set_cookie)

        return {
            "success":      True,
            "url":          response.url,           # Final URL after redirects
            "original_url": url,
            "status_code":  response.status_code,
            "headers":      dict(response.headers),
            "cookies":      cookies_list,
            "html":         response.text[:50000],  # Limit HTML storage
            "scan_time":    scan_time,
            "redirect_count": len(response.history),
            "error":        None,
        }

    except requests.exceptions.SSLError as e:
        return {
            "success": False,
            "error":   f"SSL Error: {str(e)}. The site may have an invalid certificate.",
            "cookies": [],
            "headers": {},
        }
    except requests.exceptions.ConnectionError as e:
        return {
            "success": False,
            "error":   f"Connection failed: Could not reach {url}. Check if the URL is correct.",
            "cookies": [],
            "headers": {},
        }
    except requests.exceptions.Timeout:
        return {
            "success": False,
            "error":   f"Request timed out after {REQUEST_TIMEOUT}s. The server may be slow or unreachable.",
            "cookies": [],
            "headers": {},
        }
    except Exception as e:
        return {
            "success": False,
            "error":   f"Unexpected error: {str(e)}",
            "cookies": [],
            "headers": {},
        }


def parse_set_cookie_header(header_value: str) -> list:
    """
    Manually parse Set-Cookie header into structured cookie dict.
    Handles multiple Set-Cookie headers joined by newlines.
    """
    cookies = []
    for cookie_str in header_value.split("\n"):
        if not cookie_str.strip():
            continue
        parts = [p.strip() for p in cookie_str.split(";")]
        if not parts:
            continue

        # First part is name=value
        name_val = parts[0].split("=", 1)
        if len(name_val) < 2:
            continue

        cookie = {
            "name":     name_val[0].strip(),
            "value":    name_val[1].strip(),
            "domain":   None,
            "path":     "/",
            "secure":   False,
            "expires":  None,
            "httponly": False,
            "samesite": None,
        }

        for part in parts[1:]:
            part_lower = part.lower()
            if part_lower == "httponly":
                cookie["httponly"] = True
            elif part_lower == "secure":
                cookie["secure"] = True
            elif part_lower.startswith("samesite="):
                cookie["samesite"] = part.split("=", 1)[1].strip()
            elif part_lower.startswith("domain="):
                cookie["domain"] = part.split("=", 1)[1].strip()
            elif part_lower.startswith("path="):
                cookie["path"] = part.split("=", 1)[1].strip()
            elif part_lower.startswith("max-age="):
                try:
                    cookie["max-age"] = int(part.split("=", 1)[1])
                except ValueError:
                    pass

        cookies.append(cookie)
    return cookies


# ─────────────────────────────────────────────
# HTML Meta Tag Parser
# ─────────────────────────────────────────────

def extract_meta_info(html: str) -> dict:
    """
    Parse HTML to extract additional security-relevant metadata:
    - Inline scripts (potential XSS vectors)
    - Form actions (CSRF indicators)
    - External resources
    """
    try:
        soup = BeautifulSoup(html, "html.parser")
        return {
            "title":        soup.title.string if soup.title else "Unknown",
            "forms":        len(soup.find_all("form")),
            "scripts":      len(soup.find_all("script")),
            "inline_scripts": len([s for s in soup.find_all("script") if s.string]),
            "iframes":      len(soup.find_all("iframe")),
            "external_links": len([a for a in soup.find_all("a", href=True)
                                    if a["href"].startswith("http")]),
        }
    except Exception:
        return {"title": "Parse Error", "forms": 0, "scripts": 0,
                "inline_scripts": 0, "iframes": 0, "external_links": 0}


# ─────────────────────────────────────────────
# Main Scanner Orchestrator
# ─────────────────────────────────────────────

def run_scan(url: str) -> dict:
    """
    Main entry point. Orchestrates the full security scan pipeline:
    1. Normalize & validate URL
    2. Check SSL certificate
    3. Fetch HTTP response
    4. Analyze cookies (cookie_analyzer)
    5. Analyze session security (session_analyzer)
    6. Extract HTML metadata
    7. Compile final report

    Returns a comprehensive dict with all scan results.
    """
    # Step 1: Normalize URL
    url = normalize_url(url)

    # Step 2: Validate URL format
    is_valid, validation_error = validate_url(url)
    if not is_valid:
        return {"success": False, "error": validation_error, "url": url}

    parsed = urlparse(url)
    hostname = parsed.hostname

    # Step 3: SSL check (non-blocking)
    ssl_info = {}
    if parsed.scheme == "https":
        ssl_info = check_ssl_certificate(hostname)

    # Step 4: Fetch the target
    fetch_result = fetch_target(url)
    if not fetch_result["success"]:
        return {
            "success": False,
            "error":   fetch_result["error"],
            "url":     url,
            "ssl":     ssl_info,
        }

    cookies  = fetch_result["cookies"]
    headers  = fetch_result["headers"]
    html     = fetch_result.get("html", "")

    # Step 5: Cookie analysis
    cookie_analysis = analyze_all_cookies(cookies)

    # Step 6: Session analysis
    session_analysis = analyze_session(url, cookies, headers)

    # Step 7: HTML metadata
    meta_info = extract_meta_info(html)

    # Step 8: Merge all vulnerability findings
    all_findings = (
        [f for c in cookie_analysis["cookies"] for f in c["findings"]] +
        session_analysis["findings"]
    )

    # Deduplicate by check name
    seen = set()
    unique_findings = []
    for f in all_findings:
        if f["check"] not in seen:
            seen.add(f["check"])
            unique_findings.append(f)

    # Overall risk score (weighted average)
    cookie_score  = cookie_analysis["summary"]["overall_score"]
    session_score = session_analysis["risk_score"]
    overall_score = round((cookie_score * 0.4) + (session_score * 0.6), 1)

    if overall_score >= 70:
        overall_risk = "CRITICAL"
        risk_color   = "#ff2d55"
    elif overall_score >= 40:
        overall_risk = "HIGH"
        risk_color   = "#ff6b35"
    elif overall_score >= 20:
        overall_risk = "MEDIUM"
        risk_color   = "#ffd60a"
    else:
        overall_risk = "LOW"
        risk_color   = "#30d158"

    return {
        "success":        True,
        "url":            fetch_result["url"],
        "original_url":   url,
        "hostname":       hostname,
        "status_code":    fetch_result["status_code"],
        "scan_time":      fetch_result["scan_time"],
        "redirect_count": fetch_result["redirect_count"],
        "ssl":            ssl_info,
        "cookies":        cookie_analysis,
        "session":        session_analysis,
        "findings":       unique_findings,
        "meta":           meta_info,
        "headers":        headers,
        "summary": {
            "total_cookies":     cookie_analysis["summary"]["total"],
            "vulnerable_cookies": cookie_analysis["summary"]["vulnerable"],
            "session_cookies":   cookie_analysis["summary"]["session_cookies"],
            "total_findings":    len(unique_findings),
            "high_count":        sum(1 for f in unique_findings if f["severity"] == "HIGH"),
            "medium_count":      sum(1 for f in unique_findings if f["severity"] == "MEDIUM"),
            "low_count":         sum(1 for f in unique_findings if f["severity"] == "LOW"),
            "overall_score":     overall_score,
            "overall_risk":      overall_risk,
            "risk_color":        risk_color,
        },
        "tabulated_cookies":  cookie_analysis["tabulated_output"],
        "tabulated_findings": session_analysis["tabulated_output"],
    }


# ─────────────────────────────────────────────
# Demo / Test Mode
# ─────────────────────────────────────────────

def get_demo_scan(url: str) -> dict:
    """
    Returns a simulated scan result for demonstration purposes.
    Used when the real target is unreachable or for testing the UI.
    Simulates a vulnerable web application (e.g., DVWA, WebGoat).
    """
    demo_cookies = [
        # Simulated vulnerable PHP session cookie
        {
            "name": "PHPSESSID",
            "value": "12345",           # Predictable!
            "domain": urlparse(url).hostname or "demo.local",
            "path": "/",
            "secure": False,            # Missing Secure flag
            "httponly": False,          # Missing HttpOnly flag
            "samesite": None,           # No SameSite
            "expires": None,
        },
        # Simulated auth token with no security flags
        {
            "name": "auth_token",
            "value": "user_1_admin",    # Predictable + contains user info
            "domain": urlparse(url).hostname or "demo.local",
            "path": "/",
            "secure": False,
            "httponly": False,
            "samesite": "None",         # Weak SameSite
            "expires": None,
        },
        # Simulated tracking cookie (less critical)
        {
            "name": "_ga",
            "value": "GA1.2.1234567890.1234567890",
            "domain": urlparse(url).hostname or "demo.local",
            "path": "/",
            "secure": False,
            "httponly": False,
            "samesite": None,
            "expires": 1893456000,
        },
    ]

    demo_headers = {
        "Content-Type": "text/html; charset=utf-8",
        "Server": "Apache/2.4.41 (Ubuntu)",
        "X-Powered-By": "PHP/7.4.3",
        # Intentionally missing security headers for demo
    }

    cookie_analysis  = analyze_all_cookies(demo_cookies)
    session_analysis = analyze_session(url, demo_cookies, demo_headers)

    all_findings = (
        [f for c in cookie_analysis["cookies"] for f in c["findings"]] +
        session_analysis["findings"]
    )

    seen = set()
    unique_findings = []
    for f in all_findings:
        if f["check"] not in seen:
            seen.add(f["check"])
            unique_findings.append(f)

    overall_score = 78
    return {
        "success":        True,
        "url":            url,
        "original_url":   url,
        "hostname":       urlparse(url).hostname or "demo.local",
        "status_code":    200,
        "scan_time":      0.847,
        "redirect_count": 0,
        "is_demo":        True,
        "ssl":            {"has_ssl": False, "valid": False, "error": "Demo mode"},
        "cookies":        cookie_analysis,
        "session":        session_analysis,
        "findings":       unique_findings,
        "meta": {
            "title":          "Demo Vulnerable Application",
            "forms":          3,
            "scripts":        5,
            "inline_scripts": 2,
            "iframes":        0,
            "external_links": 12,
        },
        "headers": demo_headers,
        "summary": {
            "total_cookies":     3,
            "vulnerable_cookies": 3,
            "session_cookies":   2,
            "total_findings":    len(unique_findings),
            "high_count":        sum(1 for f in unique_findings if f["severity"] == "HIGH"),
            "medium_count":      sum(1 for f in unique_findings if f["severity"] == "MEDIUM"),
            "low_count":         sum(1 for f in unique_findings if f["severity"] == "LOW"),
            "overall_score":     overall_score,
            "overall_risk":      "CRITICAL",
            "risk_color":        "#ff2d55",
        },
        "tabulated_cookies":  cookie_analysis["tabulated_output"],
        "tabulated_findings": session_analysis["tabulated_output"],
    }
