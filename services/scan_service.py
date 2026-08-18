"""Scan service - persistence and retrieval."""

from __future__ import annotations

import csv
import io
import json
from datetime import datetime, timezone
from typing import Any
from models import Base, Scan
from services.db import SessionFactory
from scanner import run_scan


class ScanService:
    def run_scan(self, url: str, mode: str = "standard") -> dict[str, Any]:
        result = run_scan(url, mode=mode)
        result["id"] = self._persist(result)
        return result

    def _persist(self, result: dict[str, Any]) -> str:
        try:
            session = SessionFactory()()
            started = datetime.fromisoformat(result.get("started_at", "")) if result.get("started_at") else None
            finished = datetime.fromisoformat(result.get("finished_at", "")) if result.get("finished_at") else None
            scan = Scan(
                id=result.get("id") or f"{int(datetime.now(timezone.utc).timestamp()*1000)}",
                url=result.get("url", ""),
                domain=result.get("domain", ""),
                risk=result.get("risk", "unknown"),
                score=int(result.get("score", 0) or 0),
                reasons="\n".join(result.get("reasons", [])),
                details=json.dumps(result.get("details", {})),
                mode=result.get("mode", "standard"),
                started_at=started,
                finished_at=finished,
                duration_ms=int(result.get("duration_ms", 0) or 0),
            )
            session.add(scan)
            session.commit()
            return scan.id
        except Exception:
            try:
                session.rollback()
            except Exception:
                pass
            return result.get("id") or ""

    def history(self, page: int = 1, page_size: int = 20) -> dict[str, Any]:
        session = SessionFactory()()
        try:
            q = session.query(Scan).order_by(Scan.started_at.desc() if Scan.started_at is not None else Scan.id.desc())
            total = q.count()
            items = q.offset((page - 1) * page_size).limit(page_size).all()
            return {
                "items": [
                    {
                        "id": s.id,
                        "url": s.url,
                        "domain": s.domain,
                        "risk": s.risk,
                        "score": s.score,
                        "mode": s.mode,
                        "started_at": s.started_at.isoformat() if s.started_at else None,
                        "finished_at": s.finished_at.isoformat() if s.finished_at else None,
                        "duration_ms": s.duration_ms,
                        "reasons": s.reasons_list(),
                    }
                    for s in items
                ],
                "count": total,
                "page": page,
                "page_size": page_size,
            }
        except Exception:
            return {"items": [], "count": 0, "page": page, "page_size": page_size}
        finally:
            session.close()

    def get_scan(self, scan_id: str) -> dict[str, Any] | None:
        session = SessionFactory()()
        try:
            s = session.query(Scan).filter(Scan.id == scan_id).first()
            if not s:
                return None
            return {
                "id": s.id,
                "url": s.url,
                "domain": s.domain,
                "risk": s.risk,
                "score": s.score,
                "reasons": s.reasons_list(),
                "details": s.details_dict(),
                "mode": s.mode,
                "started_at": s.started_at.isoformat() if s.started_at else None,
                "finished_at": s.finished_at.isoformat() if s.finished_at else None,
                "duration_ms": s.duration_ms,
            }
        except Exception:
            return None
        finally:
            session.close()

    def export(self, fmt: str = "json") -> Any:
        session = SessionFactory()()
        try:
            items = session.query(Scan).order_by(Scan.started_at.desc()).all()
            fieldnames = ["id", "url", "domain", "risk", "score", "mode", "started_at"]
            rows = [
                {
                    "id": s.id,
                    "url": s.url,
                    "domain": s.domain,
                    "risk": s.risk,
                    "score": s.score,
                    "mode": s.mode,
                    "started_at": s.started_at.isoformat() if s.started_at else "",
                }
                for s in items
            ]
            if fmt == "csv":
                buf = io.StringIO()
                fieldnames = ["id", "url", "domain", "risk", "score", "mode", "started_at", "finished_at", "duration_ms"]
                writer = csv.DictWriter(buf, fieldnames=fieldnames)
                writer.writeheader()
                for s in items:
                    writer.writerow({
                        "id": s.id,
                        "url": s.url,
                        "domain": s.domain,
                        "risk": s.risk,
                        "score": s.score,
                        "mode": s.mode,
                        "started_at": s.started_at.isoformat() if s.started_at else "",
                        "finished_at": s.finished_at.isoformat() if s.finished_at else "",
                        "duration_ms": s.duration_ms or "",
                    })
                return buf.getvalue().encode("utf-8-sig")
            return {"items": rows}
        except Exception:
            return {"items": []}
        finally:
            session.close()
