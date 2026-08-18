"""PhishChecker - privacy-first URL phishing risk scanner."""

from __future__ import annotations

from flask import Flask, jsonify, request, send_file, Response, render_template, redirect
from flask_cors import CORS
from pathlib import Path
import os
import time
import secrets
import threading
from typing import Any

from models import Base, Scan
from services.db import SessionFactory, init_db, get_engine
from services.scan_service import ScanService
from middleware.csrf import CsrfMiddleware
from middleware.cors import CORSMiddleware
from middleware.auth import require_api_key
from middleware.security import SecurityHeadersMiddleware, rate_limit
from middleware.logging import RequestIdMiddleware, RequestLoggingMiddleware
from middleware.metrics import inc, snapshot
from middleware.validation import validate_scan_payload, validate_bulk_payload

import signal as _signal


def _graceful_shutdown(*_: Any) -> None:
    raise SystemExit(0)


def setup_graceful_shutdown(app: Any) -> None:
    try:
        _signal.signal(_signal.SIGTERM, _graceful_shutdown)
        _signal.signal(_signal.SIGINT, _graceful_shutdown)
    except Exception:
        pass


def _validate_config(config: dict[str, Any]) -> None:
    if os.getenv("PHISHCHECKER_ENV") != "production":
        return
    secret = config.get("SECRET_KEY", "")
    if not secret or secret == "change-me":
        fallback = secrets.token_hex(32)
        config["SECRET_KEY"] = fallback
    db_uri = config.get("SQLALCHEMY_DATABASE_URI", "")
    if not db_uri or not str(db_uri).startswith(("sqlite://", "postgresql://", "mysql://")):
        raise RuntimeError("SQLALCHEMY_DATABASE_URI must be a valid database URI")


def create_app(config: dict | None = None) -> Flask:
    app = Flask(__name__, static_folder=None, template_folder="templates")
    app.config.update(config or {})

    app.config.setdefault("SECRET_KEY", os.getenv("PHISHCHECKER_SECRET", os.getenv("SECRET_KEY", "change-me")))
    app.config.setdefault("SQLALCHEMY_DATABASE_URI", os.getenv("DATABASE_URL", "sqlite:///phishchecker.db"))
    app.config.setdefault("SQLALCHEMY_TRACK_MODIFICATIONS", False)
    app.config.setdefault("ENFORCE_HTTPS", True)
    app.config.setdefault("API_KEYS_ENABLED", os.getenv("PHISHCHECKER_API_KEYS_ENABLED", "false").lower() in ("1", "true", "yes"))

    _validate_config(app.config)

    Base.metadata.bind = SessionFactory(app.config["SQLALCHEMY_DATABASE_URI"])
    Base.metadata.create_all(get_engine())

    CORS(app, supports_credentials=True)

    CsrfMiddleware(app)
    SecurityHeadersMiddleware(app)
    RequestIdMiddleware(app)
    RequestLoggingMiddleware(app)

    if os.getenv("PHISHCHECKER_IP_CONTROL", "false").lower() in ("1", "true", "yes"):
        from middleware.ip_control import ip_control
        ip_control(app)

    @app.get("/health")
    def health() -> Response:
        return jsonify({"ok": True, "service": "phishchecker", "version": "1.0.0"}), 200

    @app.get("/health/deep")
    def health_deep() -> tuple[Response, int]:
        db_ok = False
        try:
            from services.db import get_engine
            with get_engine().connect() as conn:
                conn.execute(__import__("text", fromlist=["text"]).text("SELECT 1"))
            db_ok = True
        except Exception:
            db_ok = False
        status = 200 if db_ok else 200
        return jsonify({"ok": db_ok, "service": "phishchecker", "database": db_ok}), status

    @app.get("/api/csrf")
    def api_csrf() -> Response:
        return jsonify({"csrf_token": secrets.token_hex(16)}), 200

    @app.get("/api/v2/scans/history")
    def api_history() -> Response:
        page = max(1, int(request.args.get("page", 1)))
        size = min(100, max(1, int(request.args.get("page_size", 20))))
        repo = ScanService()
        result = repo.history(page=page, page_size=size)
        return jsonify(result), 200

    @app.post("/api/v2/scans")
    @rate_limit
    def api_scan_v2() -> tuple[Response, int]:
        payload = request.get_json(force=True) or {}
        try:
            url, mode = validate_scan_payload(payload)
        except ValueError as e:
            return jsonify({"error": str(e)}), 400
        inc("requests_total")
        inc("scans_total")
        result = ScanService().run_scan(url, mode=mode)
        return jsonify(result), 202

    @app.post("/scan")
    @rate_limit
    def api_scan_legacy() -> tuple[Response, int]:
        payload = request.get_json(force=True) or {}
        try:
            url, mode = validate_scan_payload(payload)
        except ValueError as e:
            return jsonify({"error": str(e)}), 400
        inc("requests_total")
        inc("scans_total")
        result = ScanService().run_scan(url, mode=mode)
        return jsonify(result), 202

    @app.post("/api/v1/scan")
    @rate_limit
    def api_scan() -> tuple[Response, int]:
        payload = request.get_json(force=True) or {}
        try:
            url, mode = validate_scan_payload(payload)
        except ValueError as e:
            return jsonify({"error": str(e)}), 400
        inc("requests_total")
        inc("scans_total")
        result = ScanService().run_scan(url, mode=mode)
        return jsonify(result), 202

    @app.post("/scan/bulk")
    @rate_limit
    def api_scan_bulk() -> tuple[Response, int]:
        payload = request.get_json(force=True) or {}
        try:
            urls, mode = validate_bulk_payload(payload)
        except ValueError as e:
            return jsonify({"error": str(e)}), 400
        inc("requests_total")
        inc("bulk_scans_total")
        results = []
        for url in urls:
            results.append(ScanService().run_scan(url, mode=mode))
        return jsonify({"results": results}), 202

    @app.get("/api/v2/scans/export")
    def api_export() -> Response:
        fmt = request.args.get("format", "json")
        repo = ScanService()
        data = repo.export(fmt=fmt)
        if fmt == "csv":
            from io import BytesIO
            return Response(data, mimetype="text/csv", headers={"Content-Disposition": "attachment; filename=scans.csv"})
        return jsonify(data), 200

    @app.get("/api/v2/queue/status")
    def api_queue_status() -> Response:
        return jsonify({"queued": 0, "processing": 0}), 200

    @app.get("/metrics")
    def metrics() -> tuple[Response, int]:
        return jsonify(snapshot()), 200

    @app.get("/api/v2/status/feeds")
    def api_status_feeds() -> tuple[Response, int]:
        return jsonify({"feeds": [
            {"name": "phishing_army", "url": "https://phishing.army/download/phishing_army_blocklist.txt", "last_checked": None, "status": "configured"},
            {"name": "openphish", "url": "https://openphish.com/feed.txt", "last_checked": None, "status": "configured"},
        ]}), 200

    @app.get("/api/v2/scans/<scan_id>")
    def api_scan_detail(scan_id: str) -> tuple[Response, int]:
        repo = ScanService()
        result = repo.get_scan(scan_id)
        if not result:
            return jsonify({"error": "scan not found"}), 404
        return jsonify(result), 200

    @app.get("/report/<scan_id>")
    def public_report(scan_id: str) -> Response:
        return redirect(f"/#/scan/{scan_id}", code=302)

    @app.get("/api/v2/status")
    def api_status() -> tuple[Response, int]:
        return jsonify({
            "service": "phishchecker",
            "version": "1.0.0",
            "features": {
                "public_scanning": True,
                "api_access": True,
                "history": True,
                "export": True,
                "bulk_scan": True,
            },
        }), 200

    _dist_dir = Path(__file__).parent / "frontend" / "dist"

    @app.get("/privacy")
    def privacy():
        return send_file(Path(__file__).parent / "static" / "privacy.html")

    @app.get("/terms")
    def terms():
        return send_file(Path(__file__).parent / "static" / "terms.html")

    @app.get("/")
    def root() -> Response:
        return send_file(_dist_dir / "index.html")

    @app.get("/<path:path>")
    def spa(path: str) -> Response:
        file = _dist_dir / path
        if file.exists() and file.is_file():
            return send_file(file)
        return send_file(_dist_dir / "index.html")

    return app


app = create_app()
setup_graceful_shutdown(app)
init_db()
