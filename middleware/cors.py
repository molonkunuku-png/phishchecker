"""CORS middleware."""

from __future__ import annotations

from typing import Any
from flask import request, Response


class CORSMiddleware:
    def __init__(self, app=None, *, allow_origins=None):
        self.allow_origins = allow_origins or []
        if app is not None:
            app.after_request(self.after)
            app.register_error_handler(Exception, self._force_options)

    def after(self, response: Response) -> Response:
        origin = request.headers.get("Origin")
        if origin:
            allowed = self.allow_origins or ["*"]
            if "*" in allowed or origin in allowed:
                response.headers["Access-Control-Allow-Origin"] = origin
                response.headers["Access-Control-Allow-Credentials"] = "true"
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, PATCH, DELETE, OPTIONS"
        response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization, X-CSRF-Token, X-Admin-Secret"
        return response

    def _force_options(self, exc: Any) -> Response:
        if request.method == "OPTIONS":
            return self.after(Response("", status=204))
        raise exc
