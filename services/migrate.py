"""Lightweight migration helper."""

from __future__ import annotations

from typing import Any


def migrate(conn: Any) -> None:
    try:
        dialect = conn.dialect.name
        if dialect == "sqlite":
            conn.exec_driver_sql("PRAGMA journal_mode=WAL")
        elif dialect == "postgresql":
            conn.exec_driver_sql("SET statement_timeout = 5000")
    except Exception:
        pass
