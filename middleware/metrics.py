"""Lightweight metrics for PhishChecker."""

from __future__ import annotations

from threading import Lock
from typing import Any

_metrics = {
    "requests_total": 0,
    "requests_429": 0,
    "scans_total": 0,
    "bulk_scans_total": 0,
    "errors_total": 0,
}
_LOCK = Lock()


def inc(name: str, amount: int = 1) -> None:
    with _LOCK:
        _metrics[name] = _metrics.get(name, 0) + amount


def snapshot() -> dict[str, Any]:
    with _LOCK:
        return dict(_metrics)
