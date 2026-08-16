"""Utility helpers."""

from __future__ import annotations

import re
from typing import Any


def sanitize_url(url: str | None) -> str | None:
    if not url:
        return url
    return url.replace("<", "&lt;").replace(">", "&gt;").replace("&", "&amp;").replace('"', "&quot;")


def extract_domain(url: str) -> str:
    try:
        parsed = __import__("urllib.parse").parse.urlparse(url if "://" in url else f"https://{url}")
        host = (parsed.netloc or parsed.path or "").split(":")[0].strip()
        return host.lower()
    except Exception:
        return ""
