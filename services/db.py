"""Database session factory and initialization."""

from __future__ import annotations

from typing import Any
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from models import Base


_ENGINE = None
_SessionFactory = None


def make_engine(db_uri: str) -> Any:
    return create_engine(db_uri, future=True, connect_args={"check_same_thread": False} if "sqlite" in db_uri else {})


def SessionFactory(db_uri: str | None = None) -> sessionmaker:
    global _ENGINE, _SessionFactory
    if _SessionFactory is None:
        uri = db_uri or "sqlite:///phishchecker.db"
        _ENGINE = make_engine(uri)
        _SessionFactory = sessionmaker(bind=_ENGINE, autoflush=False, autocommit=False, future=True)
    return _SessionFactory


def get_engine() -> Any:
    global _ENGINE
    if _ENGINE is None:
        _ENGINE = make_engine("sqlite:///phishchecker.db")
    return _ENGINE


def init_db(db_uri: str | None = None) -> None:
    global _ENGINE, _SessionFactory
    uri = db_uri or "sqlite:///phishchecker.db"
    _ENGINE = make_engine(uri)
    _SessionFactory = sessionmaker(bind=_ENGINE, autoflush=False, autocommit=False, future=True)
    Base.metadata.create_all(_ENGINE)
    try:
        with _ENGINE.connect() as conn:
            cols = {row[1] for row in conn.execute(text("PRAGMA table_info(scans)")).fetchall()}
            if "started_at" in cols and "duration_ms" in cols:
                conn.execute(text("CREATE INDEX IF NOT EXISTS idx_scans_started ON scans(started_at DESC)"))
                conn.commit()
    except Exception:
        pass
