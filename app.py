"""PhishChecker - privacy-first URL phishing risk scanner."""

from __future__ import annotations

from flask import Flask, jsonify, request, send_file, Response
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


def create_app(config: dict | None = None) -> Flask:
    app = Flask(__name__, static_folder=None, template_folder="templates")
    app.config.update(config or {})

    app.config.setdefault("SECRET_KEY", os.getenv("PHISHCHECKER_SECRET", os.getenv("SECRET_KEY", "change-me")))
    app.config.setdefault("SQLALCHEMY_DATABASE_URI", os.getenv("DATABASE_URL", "sqlite:///phishchecker.db"))
    app.config.setdefault("SQLALCHEMY_TRACK_MODIFICATIONS", False)
    app.config.setdefault("ENFORCE_HTTPS", True)
    app.config.setdefault("API_KEYS_ENABLED", os.getenv("PHISHCHECKER_API_KEYS_ENABLED", "false").lower() in ("1", "true", "yes"))

    Base.metadata.bind = SessionFactory(app.config["SQLALCHEMY_DATABASE_URI"])
    Base.metadata.create_all(get_engine())

    CORS(app, supports_credentials=True)

    CsrfMiddleware(app)

    @app.get("/health")
    def health() -> Response:
        return jsonify({"ok": True, "service": "phishchecker", "version": "1.0.0"}), 200

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
    def api_scan_v2() -> Response:
        payload = request.get_json(force=True) or {}
        url = payload.get("url")
        if not url:
            return jsonify({"error": "url is required"}), 400
        mode = payload.get("mode", "standard")
        result = ScanService().run_scan(url, mode=mode)
        return jsonify(result), 202

    @app.post("/scan")
    def api_scan_legacy() -> Response:
        payload = request.get_json(force=True) or {}
        url = payload.get("url")
        if not url:
            return jsonify({"error": "url is required"}), 400
        result = ScanService().run_scan(url, mode="standard")
        return jsonify(result), 202

    @app.post("/api/v1/scan")
    def api_scan() -> Response:
        payload = request.get_json(force=True) or {}
        url = payload.get("url")
        if not url:
            return jsonify({"error": "url is required"}), 400
        result = ScanService().run_scan(url, mode="standard")
        return jsonify(result), 202

    @app.post("/scan/bulk")
    def api_scan_bulk() -> Response:
        payload = request.get_json(force=True) or {}
        urls = payload.get("urls", [])
        if not urls:
            return jsonify({"error": "urls is required"}), 400
        if len(urls) > 20:
            return jsonify({"error": "Max 20 URLs per bulk check"}), 400
        mode = payload.get("mode", "quick")
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

    @app.get("/api/v2/status/feeds")
    def api_status_feeds() -> Response:
        return jsonify({"feeds": []}), 200

    @app.get("/api/v2/scans/<scan_id>")
    def api_scan_detail(scan_id: str) -> Response:
        repo = ScanService()
        result = repo.get_scan(scan_id)
        if not result:
            return jsonify({"error": "scan not found"}), 404
        return jsonify(result), 200

    _dist_dir = Path(__file__).parent / "frontend" / "dist"

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


init_db()
