"""Optional Sentry integration."""

from __future__ import annotations

import os
from typing import Any


def init_sentry(app: Any) -> None:
    dsn = os.getenv("PHISHCHECKER_SENTRY_DSN")
    if not dsn:
        return
    try:
        import sentry_sdk  # type: ignore
        from sentry_sdk.integrations.flask import FlaskIntegration  # type: ignore
        sentry_sdk.init(dsn=dsn, integrations=[FlaskIntegration()], traces_sample_rate=0.0)
    except Exception:
        pass
