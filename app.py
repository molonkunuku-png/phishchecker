"""PhishChecker - privacy-first URL phishing risk scanner."""

from __future__ import annotations

from flask import Flask, jsonify, request, send_file, Response, render_template, redirect, send_from_directory
from flask_cors import CORS
import logging
from pathlib import Path
import os
import time
import secrets
import threading
from typing import Any

from werkzeug.middleware.proxy_fix import ProxyFix

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


logger = logging.getLogger("phishchecker")


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
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
    app.config.update(config or {})

    app.config.setdefault("SECRET_KEY", os.getenv("PHISHCHECKER_SECRET", os.getenv("SECRET_KEY", "change-me")))
    app.config.setdefault("SQLALCHEMY_DATABASE_URI", os.getenv("DATABASE_URL", "sqlite:///phishchecker.db"))
    app.config.setdefault("SQLALCHEMY_TRACK_MODIFICATIONS", False)
    app.config.setdefault("ENFORCE_HTTPS", True)
    if app.config["ENFORCE_HTTPS"]:
        app.config["PREFERRED_URL_SCHEME"] = "https"

    app.config.setdefault("API_KEYS_ENABLED", os.getenv("PHISHCHECKER_API_KEYS_ENABLED", "false").lower() in ("1", "true", "yes"))

    _validate_config(app.config)

    Base.metadata.bind = SessionFactory(app.config["SQLALCHEMY_DATABASE_URI"])
    Base.metadata.create_all(get_engine())

    CORS(app, supports_credentials=True, origins=["https://phishchecker.onrender.com", "http://localhost:5173", "http://localhost:3000"])

    try:
        from middleware.sentry_integration import init_sentry
        init_sentry(app)
    except Exception:
        pass

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
    @require_api_key
    def api_history() -> Response:
        page = max(1, int(request.args.get("page", 1)))
        size = min(100, max(1, int(request.args.get("page_size", 20))))
        repo = ScanService()
        result = repo.history(page=page, page_size=size)
        risk = (request.args.get("risk") or "").strip().lower()
        q = (request.args.get("q") or "").strip().lower()
        items = result.get("items", [])
        if risk:
            items = [x for x in items if (x.get("risk") or "").lower() == risk]
        if q:
            items = [x for x in items if q in (x.get("domain") or "").lower() or q in (x.get("url") or "").lower()]
        result["items"] = items[:size]
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
        try:
            family = bool(payload.get("family")) if isinstance(payload.get("family"), bool) else str(payload.get("family", "")).lower() in ("1", "true", "yes")
        except Exception:
            family = False
        try:
            result = ScanService().run_scan(url, mode=mode, family_mode=family)
        except Exception as exc:
            logger.exception("scan failed url=%s mode=%s rid=%s", url, mode, request.headers.get("X-Request-ID"))
            inc("errors_total")
            return jsonify({"error": "scan failed"}), 500
        resp = jsonify(result)
        resp.headers["Cache-Control"] = "no-store"
        return resp, 202

    @app.post("/api/v2/scan/screenshot")
    @rate_limit
    def api_scan_screenshot() -> tuple[Response, int]:
        payload = request.get_json(force=True) or {}
        image_data = payload.get("image")
        if not image_data:
            return jsonify({"error": "missing image"}), 400
        extracted_urls = []
        try:
            import base64, io
            from PIL import Image
            import re
            header, b64 = image_data.split(",", 1) if "," in image_data else ("", image_data)
            img = Image.open(io.BytesIO(base64.b64decode(b64)))
            extracted_urls = re.findall(r'https?://[^\s"\'<>]+', str(img))
        except Exception as exc:
            logger.warning("screenshot scan failed: %s", exc)
            extracted_urls = []
        if not extracted_urls:
            return jsonify({"error": "No links found in image. Try a clearer screenshot."}), 400
        result = ScanService().run_scan(extracted_urls[0], mode="standard")
        result["extracted_urls"] = extracted_urls
        return jsonify(result), 202

    @app.post("/api/v2/scan/qr")
    @rate_limit
    def api_scan_qr() -> tuple[Response, int]:
        payload = request.get_json(force=True) or {}
        image_data = payload.get("image")
        if not image_data:
            return jsonify({"error": "missing image"}), 400
        decoded_urls = []
        try:
            import base64, io
            from PIL import Image
            from pyzbar.pyzbar import decode as qr_decode
            header, b64 = image_data.split(",", 1) if "," in image_data else ("", image_data)
            img = Image.open(io.BytesIO(base64.b64decode(b64)))
            decoded = qr_decode(img)
            decoded_urls = [d.data.decode("utf-8") for d in decoded if d.data]
        except Exception as exc:
            logger.warning("qr scan failed: %s", exc)
            decoded_urls = []
        if not decoded_urls:
            return jsonify({"error": "No QR code found. Try a clearer photo."}), 400
        result = ScanService().run_scan(decoded_urls[0], mode="standard")
        result["decoded_urls"] = decoded_urls
        return jsonify(result), 202

    @app.post("/api/v2/community/flag")
    @rate_limit
    def api_community_flag() -> tuple[Response, int]:
        payload = request.get_json(force=True) or {}
        url = (payload.get("url") or "").strip()
        domain = (payload.get("domain") or "").strip()
        category = (payload.get("category") or "phishing").strip()
        notes = (payload.get("notes") or "").strip()
        if not url or not domain:
            return jsonify({"error": "url and domain are required"}), 400
        token = secrets.token_hex(16)
        from models import CommunityFlag
        from services.db import SessionFactory
        session = SessionFactory(app.config["SQLALCHEMY_DATABASE_URI"])()
        try:
            session.add(CommunityFlag(id=token, url=url, domain=domain, category=category, notes=notes, reporter_token=token, risk="unknown", score=0))
            session.commit()
        finally:
            session.close()
        return jsonify({"ok": True, "token": token}), 201

    @app.get("/api/v2/community/flags")
    @require_api_key
    def api_community_flags() -> tuple[Response, int]:
        from models import CommunityFlag
        from services.db import SessionFactory
        session = SessionFactory(app.config["SQLALCHEMY_DATABASE_URI"])()
        try:
            rows = session.query(CommunityFlag).order_by(CommunityFlag.created_at.desc()).limit(200).all()
        finally:
            session.close()
        return jsonify({"flags": [{"url": r.url, "domain": r.domain, "category": r.category, "notes": r.notes, "created_at": r.created_at.isoformat() if r.created_at else None} for r in rows]}), 200

    @app.post("/api/v2/scheduled")
    @rate_limit
    def api_scheduled_create() -> tuple[Response, int]:
        payload = request.get_json(force=True) or {}
        url = (payload.get("url") or "").strip()
        cadence_hours = int(payload.get("cadence_hours") or 24)
        if not url:
            return jsonify({"error": "url is required"}), 400
        from urllib.parse import urlparse
        domain = urlparse(url if "://" in url else f"https://{url}").netloc or url
        token = secrets.token_hex(16)
        from models import ScheduledCheck
        from services.db import SessionFactory
        session = SessionFactory(app.config["SQLALCHEMY_DATABASE_URI"])()
        try:
            session.add(ScheduledCheck(id=token, domain=domain, url=url, cadence_hours=max(1, min(720, cadence_hours))))
            session.commit()
        finally:
            session.close()
        return jsonify({"ok": True, "token": token, "domain": domain, "cadence_hours": max(1, min(720, cadence_hours))}), 201

    @app.get("/api/v2/scheduled")
    @require_api_key
    def api_scheduled_list() -> tuple[Response, int]:
        from models import ScheduledCheck
        from services.db import SessionFactory
        session = SessionFactory(app.config["SQLALCHEMY_DATABASE_URI"])()
        try:
            rows = session.query(ScheduledCheck).filter_by(active=True).limit(200).all()
        finally:
            session.close()
        return jsonify({"scheduled": [{"domain": r.domain, "url": r.url, "cadence_hours": r.cadence_hours, "last_score": r.last_score, "last_risk": r.last_risk, "last_checked_at": r.last_checked_at.isoformat() if r.last_checked_at else None} for r in rows]}), 200

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
        try:
            family = bool(payload.get("family")) if isinstance(payload.get("family"), bool) else str(payload.get("family", "")).lower() in ("1", "true", "yes")
        except Exception:
            family = False
        try:
            result = ScanService().run_scan(url, mode=mode, family_mode=family)
        except Exception as exc:
            logger.exception("legacy scan failed url=%s mode=%s rid=%s", url, mode, request.headers.get("X-Request-ID"))
            inc("errors_total")
            return jsonify({"error": "scan failed"}), 500
        resp = jsonify(result)
        resp.headers["Cache-Control"] = "no-store"
        return resp, 202

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
        try:
            family = bool(payload.get("family")) if isinstance(payload.get("family"), bool) else str(payload.get("family", "")).lower() in ("1", "true", "yes")
        except Exception:
            family = False
        try:
            result = ScanService().run_scan(url, mode=mode, family_mode=family)
        except Exception as exc:
            logger.exception("api/v1 scan failed url=%s mode=%s rid=%s", url, mode, request.headers.get("X-Request-ID"))
            inc("errors_total")
            return jsonify({"error": "scan failed"}), 500
        resp = jsonify(result)
        resp.headers["Cache-Control"] = "no-store"
        return resp, 202

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
        partial_error = None
        for url in urls:
            try:
                results.append(ScanService().run_scan(url, mode=mode))
            except Exception as exc:
                logger.exception("bulk scan failed url=%s mode=%s rid=%s", url, mode, request.headers.get("X-Request-ID"))
                inc("errors_total")
                results.append({
                    "url": url,
                    "domain": "",
                    "risk": "unknown",
                    "score": 0,
                    "reasons": ["scan failed"],
                    "details": {},
                    "mode": mode,
                    "duration_ms": 0,
                })
                partial_error = partial_error or "one or more scans failed"
        payload_out = {"results": results}
        if partial_error:
            payload_out["error"] = partial_error
        return jsonify(payload_out), 202

    @app.get("/api/v2/scans/export")
    @require_api_key
    def api_export() -> Response:
        fmt = request.args.get("format", "json")
        repo = ScanService()
        data = repo.export(fmt=fmt)
        if fmt == "csv":
            from io import BytesIO
            resp = Response(data, mimetype="text/csv", headers={
                "Content-Disposition": "attachment; filename=scans.csv",
                "Cache-Control": "no-store",
            })
            return resp
        resp = jsonify(data)
        resp.headers["Cache-Control"] = "no-store"
        return resp

    @app.get("/api/v2/queue/status")
    def api_queue_status() -> Response:
        return jsonify({"queued": 0, "processing": 0}), 200

    @app.get("/metrics")
    @require_api_key
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
        resp = jsonify(result)
        resp.headers["Cache-Control"] = "no-store"
        return resp, 200

    @app.get("/report/<scan_id>")
    def public_report(scan_id: str) -> Response:
        return redirect(f"/#/scan/{scan_id}", code=302)

    @app.get("/openapi.json")
    def openapi_spec() -> Response:
        spec = Path(__file__).with_name("docs").joinpath("openapi.json")
        if spec.exists():
            return send_file(spec, mimetype="application/vnd.oai.openapi+json; version=3.0")
        return jsonify({"error": "openapi spec not configured"}), 404

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
    _public_dir = Path(__file__).parent / "frontend" / "public"

    @app.get("/manifest.json")
    def manifest() -> Response:
        return send_file(_public_dir / "manifest.json", mimetype="application/json")

    @app.get("/sw.js")
    def service_worker() -> Response:
        return send_file(_public_dir / "sw.js", mimetype="application/javascript")

    @app.get("/static/icons/<path:name>")
    def icon(name: str) -> Response:
        return send_from_directory(str(_public_dir / "static" / "icons"), name)

    @app.get("/privacy")
    def privacy():
        return send_file(Path(__file__).parent / "static" / "privacy.html")

    @app.get("/terms")
    def terms():
        return send_file(Path(__file__).parent / "static" / "terms.html")

    @app.get("/changelog")
    def changelog():
        return send_file(Path(__file__).parent / "static" / "changelog.html")

    @app.get("/security.txt")
    def security_txt() -> Response:
        content = "Contact: mailto:molonkunuku@gmail.com\nPreferred-Languages: en, ms, zh, ta\n"
        return Response(content, mimetype="text/plain", headers={"Cache-Control": "no-store"})

    @app.get("/robots.txt")
    def robots_txt() -> Response:
        return Response("User-agent: *\nAllow: /\nSitemap: /sitemap.txt\n", mimetype="text/plain", headers={"Cache-Control": "no-store"})

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
