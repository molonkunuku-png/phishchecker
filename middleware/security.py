"""Security headers and IP rate limiting."""

from __future__ import annotations

import os
import time
from threading import Lock
from typing import Any

from flask import request, jsonify

_RATE: dict[str, list[float]] = {}
_RATE_LIMIT = int(os.getenv("PHISHCHECKER_RATE_LIMIT", "60"))
_RATE_WINDOW = int(os.getenv("PHISHCHECKER_RATE_WINDOW", "60"))
_LOCK = Lock()


class SecurityHeadersMiddleware:
    def __init__(self, app=None):
        if app is not None:
            app.after_request(self.after)

    def after(self, response):
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
        if request.is_secure:
            response.headers.setdefault("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
        return response


def _check_rate(ip: str) -> bool:
    now = time.time()
    window_start = now - _RATE_WINDOW
    with _LOCK:
        timestamps = _RATE.get(ip, [])
        timestamps = [t for t in timestamps if t > window_start]
        timestamps.append(now)
        _RATE[ip] = timestamps
        return len(timestamps) > _RATE_LIMIT


def rate_limit(fn: Any) -> Any:
    from functools import wraps

    @wraps(fn)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        ip = request.remote_addr or "unknown"
        if _check_rate(ip):
            return jsonify({"error": "rate limit exceeded"}), 429
        return fn(*args, **kwargs)

    return wrapper
