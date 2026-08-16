"""CSRF middleware."""

from __future__ import annotations

from flask import request, jsonify, g


class CsrfMiddleware:
    def __init__(self, app=None):
        if app is not None:
            app.before_request(self._check)

    def _check(self):
        if request.method in ("POST", "PATCH", "DELETE", "PUT"):
            if request.path.startswith("/api/"):
                token = request.headers.get("X-CSRF-Token")
                if not token:
                    return jsonify({"error": "invalid or missing CSRF token"}), 403
            g.csrf_token = request.headers.get("X-CSRF-Token")
