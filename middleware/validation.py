"""Request validation helpers."""

from __future__ import annotations

import re
from typing import Any


_URL_RE = re.compile(r"^https?://[^\s]+$")


def validate_scan_payload(payload: dict[str, Any]) -> tuple[str, str]:
    url = (payload.get("url") or "").strip()
    if not url:
        raise ValueError("url is required")
    if len(url) > 2048:
        raise ValueError("url too long")
    if "<" in url or ">" in url or ".." in url.lower() or "%00" in url.lower():
        raise ValueError("invalid url format")
    mode = (payload.get("mode") or "standard").strip().lower()
    if mode not in {"quick", "standard", "it"}:
        raise ValueError("invalid mode")
    return url, mode


def validate_bulk_payload(payload: dict[str, Any]) -> tuple[list[str], str]:
    urls = payload.get("urls") or []
    if not urls:
        raise ValueError("urls is required")
    if len(urls) > 20:
        raise ValueError("max 20 urls per bulk check")
    out = []
    for u in urls:
        if not isinstance(u, str):
            raise ValueError("urls must be strings")
        u = u.strip()
        if not u:
            continue
        if len(u) > 2048:
            raise ValueError("url too long")
        out.append(u)
    if not out:
        raise ValueError("urls is required")
    mode = (payload.get("mode") or "quick").strip().lower()
    if mode not in {"quick", "standard", "it"}:
        raise ValueError("invalid mode")
    return out, mode
