"""IP access control middleware."""

from __future__ import annotations

import ipaddress
import os
from typing import Any

from flask import request, jsonify

_ALLOWLIST = os.getenv("PHISHCHECKER_IP_ALLOWLIST", "")
_BLOCKLIST = os.getenv("PHISHCHECKER_IP_BLOCKLIST", "")


def _parse_list(raw: str) -> set[str]:
    return {item.strip() for item in raw.split(",") if item.strip()}


_ALLOWLIST_SET = _parse_list(_ALLOWLIST)
_BLOCKLIST_SET = _parse_list(_BLOCKLIST)


def ip_control(fn: Any) -> Any:
    from functools import wraps

    @wraps(fn)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        ip = request.remote_addr or ""
        if ip:
            if ip in _BLOCKLIST_SET:
                return jsonify({"error": "access denied"}), 403
            if _ALLOWLIST_SET and ip not in _ALLOWLIST_SET:
                return jsonify({"error": "access denied"}), 403
        return fn(*args, **kwargs)

    return wrapper
