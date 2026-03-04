"""
app.py
======
Flask web application for the Session Hijacking Detection System.
Provides REST API endpoints and serves the frontend.

Run: python app.py
Then open: http://localhost:5000
"""

import json
import time
from flask import Flask, render_template, request, jsonify, Response, stream_with_context
from scanner import run_scan, get_demo_scan, normalize_url, validate_url



app = Flask(__name__)
app.config["SECRET_KEY"] = "Kartik SessionHijack2025!"
app.config["JSON_SORT_KEYS"] = False

@app.route("/")
def index():
    """Landing page with URL scanner form."""
    return render_template("index.html")


@app.route("/dashboard")
def dashboard():
    """Security dashboard page (results rendered via JS from API)."""
    return render_template("dashboard.html")


@app.route("/report")
def report():
    """Detailed vulnerability report page."""
    return render_template("report.html")

@app.route("/api/scan", methods=["POST"])
def api_scan():
    """
    Main scan endpoint.
    Accepts JSON: { "url": "https://example.com", "demo": false }
    Returns comprehensive scan results.
    """
    data = request.get_json(silent=True) or {}
    url  = data.get("url", "").strip()
    use_demo = data.get("demo", False)

    if not url:
        return jsonify({"success": False, "error": "URL is required."}), 400

    url = normalize_url(url)

    is_valid, error = validate_url(url)
    if not is_valid:
        return jsonify({"success": False, "error": error}), 400

    if use_demo:
        result = get_demo_scan(url)
    else:
        result = run_scan(url)

    status_code = 200 if result.get("success") else 502
    return jsonify(result), status_code


@app.route("/api/scan/stream", methods=["POST"])
def api_scan_stream():
    """
    Streaming scan endpoint using Server-Sent Events (SSE).
    Sends real-time progress updates to the frontend.
    """
    data = request.get_json(silent=True) or {}
    url  = data.get("url", "").strip()
    use_demo = data.get("demo", False)

    if not url:
        def error_stream():
            yield f"data: {json.dumps({'type': 'error', 'message': 'URL is required'})}\n\n"
        return Response(stream_with_context(error_stream()), mimetype="text/event-stream")

    url = normalize_url(url)

    def generate():
        """Generator that yields SSE events during scan progression."""

        def send(event_type: str, payload: dict):
            return f"data: {json.dumps({'type': event_type, **payload})}\n\n"

        yield send("progress", {"step": 1, "total": 6, "message": "Validating URL..."})
        time.sleep(0.3)

        is_valid, error = validate_url(url)
        if not is_valid:
            yield send("error", {"message": error})
            return

        yield send("progress", {"step": 2, "total": 6, "message": "Checking SSL/TLS certificate..."})
        time.sleep(0.4)

        yield send("progress", {"step": 3, "total": 6, "message": "Sending HTTP request..."})
        time.sleep(0.3)

        yield send("progress", {"step": 4, "total": 6, "message": "Extracting cookies..."})
        time.sleep(0.3)

        yield send("progress", {"step": 5, "total": 6, "message": "Analyzing session security..."})

        
        if use_demo:
            result = get_demo_scan(url)
        else:
            result = run_scan(url)

        time.sleep(0.4)
        yield send("progress", {"step": 6, "total": 6, "message": "Generating report..."})
        time.sleep(0.3)

        yield send("complete", {"result": result})

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={
            "Cache-Control":  "no-cache",
            "X-Accel-Buffering": "no",
        }
    )


@app.route("/api/demo-targets", methods=["GET"])
def demo_targets():
    """
    Returns a list of demo/test URLs for demonstration purposes.
    These simulate different vulnerability profiles.
    """
    targets = [
        {
            "url":         "http://testphp.vulnweb.com",
            "name":        "VulnWeb Test PHP",
            "description": "Intentionally vulnerable PHP site (Acunetix demo)",
            "risk":        "HIGH",
        },
        {
            "url":         "http://demo.testfire.net",
            "name":        "AltoroMutual Demo Bank",
            "description": "IBM AppScan demo banking application",
            "risk":        "HIGH",
        },
        {
            "url":         "https://httpbin.org",
            "name":        "HTTPBin (Low Risk)",
            "description": "HTTP testing service - minimal cookies",
            "risk":        "LOW",
        },
        {
            "url":         "https://example.com",
            "name":        "Example.com (Minimal)",
            "description": "IANA example domain - basic headers only",
            "risk":        "LOW",
        },
    ]
    return jsonify({"targets": targets})


@app.route("/api/health", methods=["GET"])
def health():
    """Health check endpoint."""
    return jsonify({"status": "ok", "version": "1.0.0"})


@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Endpoint not found"}), 404


@app.errorhandler(500)
def server_error(e):
    return jsonify({"error": "Internal server error"}), 500


if __name__ == "__main__":
    print("""
╔══════════════════════════════════════════════════════════════╗
║   Web Application Session Hijacking Detection System v1.0   ║
║   Final Year Cybersecurity Project                          ║
╠══════════════════════════════════════════════════════════════╣
║   Open: http://localhost:5000                               ║
║   API:  http://localhost:5000/api/scan                      ║
╚══════════════════════════════════════════════════════════════╝
    """)
    app.run(
        host="0.0.0.0",
        port=5000,
        debug=True,   
        threaded=True,
    )
