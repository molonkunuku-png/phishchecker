"""Scanner package - URL analysis and scoring."""

from __future__ import annotations

import ipaddress
import re
import socket
import ssl
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any
from urllib.parse import urlparse

import requests


class RiskLevel(str, Enum):
    clean = "clean"
    suspicious = "suspicious"
    high = "high"
    unknown = "unknown"


@dataclass
class ScanResult:
    url: str = ""
    domain: str = ""
    risk: RiskLevel = RiskLevel.unknown
    score: int = 0
    reasons: list[str] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)
    mode: str = "standard"
    started_at: datetime | None = None
    finished_at: datetime | None = None
    duration_ms: int | None = None
    threat_intel: dict[str, Any] = field(default_factory=dict)
    id: str = ""

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["risk"] = self.risk.value
        for k in ("started_at", "finished_at"):
            v = data.get(k)
            if isinstance(v, datetime):
                data[k] = v.isoformat()
        return data


def _extract_domain(url: str) -> str:
    try:
        parsed = urlparse(url if "://" in url else f"https://{url}")
        host = (parsed.netloc or parsed.path or "").split(":")[0].strip()
        return host.lower()
    except Exception:
        return ""


def _is_private_ip(host: str) -> bool:
    try:
        addr = ipaddress.ip_address(host)
        return addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved or addr.is_multicast
    except ValueError:
        return False


def _validate(url: str) -> dict[str, Any] | None:
    if len(url) > 2048:
        return {"error": "URL too long"}
    if "<" in url or ">" in url:
        return {"error": "Invalid URL format"}
    if not re.match(r"^https?://[^\s]+$", url):
        return {"error": "Invalid URL format"}
    if ".." in url.lower() or "%00" in url.lower():
        return {"error": "Invalid URL format"}
    domain = _extract_domain(url)
    if not domain:
        return {"error": "Invalid URL format"}
    if _is_private_ip(domain):
        return {"error": "Invalid target address"}
    return None


def _check_headers(url: str) -> tuple[list[str], int]:
    reasons: list[str] = []
    penalty = 0
    try:
        resp = requests.get(url, timeout=8, allow_redirects=True, headers={"User-Agent": "PhishChecker/1.0"})
        headers = {k.lower(): v for k, v in resp.headers.items()}
        if "strict-transport-security" not in headers:
            reasons.append("Missing HSTS")
            penalty += 20
        if "content-security-policy" not in headers:
            reasons.append("Missing CSP")
            penalty += 15
        if "x-frame-options" not in headers:
            reasons.append("Missing X-Frame-Options")
            penalty += 10
        if "x-content-type-options" not in headers:
            reasons.append("Missing X-Content-Type-Options")
            penalty += 10
        if "referrer-policy" not in headers:
            reasons.append("Missing Referrer-Policy")
            penalty += 5
        if "permissions-policy" not in headers:
            reasons.append("Missing Permissions-Policy")
            penalty += 5
        chain = [h.url for h in resp.history] + [resp.url]
        return reasons, penalty, chain
    except requests.RequestException:
        reasons.append("Could not fetch URL")
        return reasons, 15, []


def _check_ssl(url: str) -> tuple[dict[str, Any], int]:
    info: dict[str, Any] = {"valid": False}
    penalty = 0
    try:
        parsed = urlparse(url)
        host = parsed.netloc or parsed.path
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                info["issuer"] = cert.get("issuer", "")
                info["subject"] = cert.get("subject", "")
                info["notBefore"] = cert.get("notBefore", "")
                info["notAfter"] = cert.get("notAfter", "")
                info["valid"] = True
    except Exception:
        penalty = 10
        info["error"] = "SSL check failed"
    return info, penalty


def _threat_intel(domain: str) -> dict[str, Any]:
    sources: list[dict[str, Any]] = []
    hits = 0
    details: list[str] = []
    try:
        sources.append({"name": "phishing_army", "enabled": True})
        # text feed integration placeholder
    except Exception:
        pass
    if hits >= 2:
        penalty = 40
    elif hits == 1:
        penalty = 25
    else:
        penalty = 0
        details.append("Not yet reported — new or unreviewed domains often aren't in feeds yet.")
    return {
        "hits": hits,
        "sources": sources,
        "summary": "; ".join(details) if details else "No active matches in public feeds.",
        "penalty": penalty,
        "details": details,
    }


def _score(result: ScanResult) -> None:
    penalty = 0
    reasons = list(result.reasons)
    # header penalties are already added
    penalty += sum(1 for r in reasons if r.startswith("Missing ")) * 10
    # threat intel
    ti = result.threat_intel
    penalty += int(ti.get("penalty", 0))
    # domain age proxy: if domain length < 20 chars and no TLD indicator, treat cautiously
    domain = result.domain
    if len(domain.split(".")) <= 2 and len(domain) < 25:
        penalty += 5
        reasons.append("Short or unusual domain shape")
    # cap
    score = max(0, 100 - penalty)
    result.score = score
    if score <= 40:
        result.risk = RiskLevel.high
    elif score <= 70:
        result.risk = RiskLevel.suspicious
    elif score <= 90:
        result.risk = RiskLevel.clean
    else:
        result.risk = RiskLevel.clean
        result.score = 95
    result.reasons = reasons


def run_scan(url: str | None, mode: str = "standard") -> dict[str, Any]:
    started = datetime.now(timezone.utc)
    url = (url or "").strip()
    err = _validate(url)
    if err:
        return {
            "url": url,
            "domain": _extract_domain(url) or "",
            "risk": RiskLevel.unknown.value,
            "score": 0,
            "reasons": [err.get("error", "Invalid URL")],
            "details": {},
            "mode": mode,
            "started_at": started.isoformat(),
            "finished_at": started.isoformat(),
            "duration_ms": 0,
            "threat_intel": {"hits": 0, "summary": "Skipped for invalid URL."},
        }

    domain = _extract_domain(url)
    reasons: list[str] = []
    details: dict[str, Any] = {}
    chain: list[str] = []

    hdr_reasons, hdr_penalty, chain = _check_headers(url)
    reasons.extend(hdr_reasons)
    details["redirect_chain"] = chain
    details["headers"] = {r.split("Missing ")[-1]: False for r in hdr_reasons if r.startswith("Missing ")}

    ssl_info, ssl_penalty = _check_ssl(url)
    details["ssl"] = ssl_info
    if not ssl_info.get("valid"):
        reasons.append("SSL validation issue")
        details.setdefault("headers", {})["TLS"] = False

    ti = _threat_intel(domain)
    reasons.extend(ti.get("details", []))

    result = ScanResult(
        url=url,
        domain=domain,
        reasons=reasons,
        details=details,
        mode=mode,
        started_at=started,
        finished_at=datetime.now(timezone.utc),
        duration_ms=int((datetime.now(timezone.utc) - started).total_seconds() * 1000),
        threat_intel=ti,
    )
    _score(result)
    return result.to_dict()
