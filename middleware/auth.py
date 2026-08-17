"""Auth middleware shim."""

from __future__ import annotations

from typing import Any

from api_keys import require_api_key as _require_api_key


def require_api_key(fn: Any) -> Any:
    return _require_api_key(fn)
