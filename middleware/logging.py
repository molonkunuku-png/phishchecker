"""Request ID + structured logging middleware."""

from __future__ import annotations

import logging
import time
import uuid
from typing import Any

from flask import request, g

logger = logging.getLogger("phishchecker")


class RequestIdMiddleware:
    def __init__(self, app=None):
        if app is not None:
            app.before_request(self.before)
            app.after_request(self.after)

    def before(self):
        g.request_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))
        g.start_ts = time.perf_counter()

    def after(self, response):
        rid = getattr(g, "request_id", None)
        if rid:
            response.headers["X-Request-ID"] = rid
        return response


class RequestLoggingMiddleware:
    def __init__(self, app=None):
        if app is not None:
            app.before_request(self.before)
            app.after_request(self.after)

    def before(self):
        g.start_ts = time.perf_counter()

    def after(self, response):
        try:
            rid = getattr(g, "request_id", "—")
            dt = time.perf_counter() - getattr(g, "start_ts", time.perf_counter())
            logger.info(
                "http %s %s %s %s %sms rid=%s",
                request.method,
                request.path,
                response.status_code,
                (request.remote_addr or "—"),
                int(dt * 1000),
                rid,
            )
        except Exception:
            pass
        return response
