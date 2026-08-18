"""In-memory LRU cache for repeated scan results."""

from __future__ import annotations

import hashlib
import json
import threading
import time
from collections import OrderedDict
from typing import Any


class ScanCache:
    def __init__(self, ttl_seconds: int = 600, max_size: int = 512) -> None:
        self.ttl_seconds = ttl_seconds
        self.max_size = max_size
        self._store: OrderedDict[str, tuple[float, Any]] = OrderedDict()
        self._lock = threading.Lock()

    def _make_key(self, url: str, mode: str) -> str:
        return hashlib.sha256(f"{mode}:{url}".encode()).hexdigest()

    def get(self, url: str, mode: str) -> Any | None:
        key = self._make_key(url, mode)
        with self._lock:
            item = self._store.get(key)
            if not item:
                return None
            ts, data = item
            if time.time() - ts > self.ttl_seconds:
                self._store.pop(key, None)
                return None
            self._store.move_to_end(key)
            return data

    def put(self, url: str, mode: str, data: Any) -> None:
        key = self._make_key(url, mode)
        with self._lock:
            self._store[key] = (time.time(), data)
            if len(self._store) > self.max_size:
                self._store.popitem(last=False)

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {"size": len(self._store), "ttl_seconds": self.ttl_seconds, "max_size": self.max_size}
