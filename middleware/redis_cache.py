"""Optional Redis cache wrapper for scan results."""

from __future__ import annotations

import json
import os
from typing import Any


def make_redis_client():  # pragma: no cover
    host = os.getenv("PHISHCHECKER_REDIS_HOST")
    if not host:
        return None
    try:
        import redis  # type: ignore
        return redis.Redis.from_url(os.getenv("PHISHCHECKER_REDIS_URL", f"redis://{host}:6379/0"))
    except Exception:
        return None


def cache_get(client: Any, key: str) -> Any | None:
    try:
        raw = client.get(key)
        if raw is None:
            return None
        return json.loads(raw)
    except Exception:
        return None


def cache_set(client: Any, key: str, value: Any, ttl_seconds: int = 600) -> None:
    try:
        client.setex(key, ttl_seconds, json.dumps(value))
    except Exception:
        pass
