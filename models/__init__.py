"""Data models."""

from __future__ import annotations

from datetime import datetime
from typing import Any
from sqlalchemy import Column, String, Float, Integer, Text, Boolean, DateTime, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

Base = declarative_base()


class Scan(Base):
    __tablename__ = "scans"

    id = Column(String(64), primary_key=True)
    url = Column(Text, nullable=False)
    domain = Column(String(255), nullable=False)
    risk = Column(String(32), nullable=False, default="unknown")
    score = Column(Integer, nullable=False, default=0)
    reasons = Column(Text, nullable=False, default="")
    details = Column(Text, nullable=False, default="")
    mode = Column(String(32), nullable=False, default="standard")
    started_at = Column(DateTime, nullable=True)
    finished_at = Column(DateTime, nullable=True)
    duration_ms = Column(Integer, nullable=True)

    def reasons_list(self) -> list[str]:
        return [r.strip() for r in (self.reasons or "").split("\n") if r.strip()]

    def details_dict(self) -> dict[str, Any]:
        try:
            return dict(__import__("json").loads(self.details or "{}"))
        except Exception:
            return {"raw": self.details}
