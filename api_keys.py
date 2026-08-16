"""API key validation and optional rate limiting."""

from __future__ import annotations

import os
import time
from threading import Lock
from typing import Any

from flask import request, jsonify

_KEYS: list[str] = []
_LOCK = Lock()
_RATE: dict[str, list[float]] = {}
_RATE_LIMIT = int(os.getenv("PHISHCHECKER_RATE_LIMIT", "60"))
_RATE_WINDOW = int(os.getenv("PHISHCHECKER_RATE_WINDOW", "60"))


def _load_keys() -> list[str]:
    raw = os.getenv("PHISHCHECKER_API_KEYS", "")
    keys = [k.strip() for k in raw.split(",") if k.strip()]
    if not keys:
        keys = [k.strip() for k in os.getenv("API_KEYS", "").split(",") if k.strip()]
    return keys


def _check_rate(key: str) -> bool:
    now = time.time()
    window_start = now - _RATE_WINDOW
    with _LOCK:
        timestamps = _RATE.get(key, [])
        timestamps = [t for t in timestamps if t > window_start]
        timestamps.append(now)
        _RATE[key] = timestamps
        return len(timestamps) > _RATE_LIMIT


def require_api_key_or_rate_limit(fn: Any) -> Any:
    from functools import wraps

    @wraps(fn)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        key = request.headers.get("X-Api-Key") or request.args.get("api_key") or ""
        keys = _load_keys()
        if keys:
            if not key or key not in keys:
                return jsonify({"error": "invalid or missing API key"}), 401
        rate_key = key or (request.remote_addr or "unknown")
        if _check_rate(rate_key):
            return jsonify({"error": "rate limit exceeded"}), 429
        return fn(*args, **kwargs)

    return wrapper
