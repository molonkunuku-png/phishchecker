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


def _check_headers(url: str, mode: str = "standard") -> tuple[list[str], int, list[str]]:
    reasons: list[str] = []
    penalty = 0
    timeout = 5 if mode == "quick" else (15 if mode == "it" else 8)
    try:
        resp = requests.get(url, timeout=timeout, allow_redirects=True, headers={"User-Agent": "PhishChecker/1.0"})
        headers = {k.lower(): v for k, v in resp.headers.items()}
        required = ["strict-transport-security", "content-security-policy", "x-frame-options", "x-content-type-options", "referrer-policy", "permissions-policy"]
        weights = {"strict-transport-security": 20, "content-security-policy": 15, "x-frame-options": 10, "x-content-type-options": 10, "referrer-policy": 5, "permissions-policy": 5}
        if mode == "quick":
            required = ["strict-transport-security", "content-security-policy", "x-frame-options"]
            weights = {"strict-transport-security": 20, "content-security-policy": 15, "x-frame-options": 10}
        elif mode == "it":
            weights = {k: v * 2 for k, v in weights.items()}
        for h in required:
            label = h.replace("-", " ").title().replace(" ", "-")
            if headers.get(h):
                continue
            reasons.append(f"Missing {label}")
            penalty += weights.get(h, 5)
        chain = [h.url for h in resp.history] + [resp.url]
        return reasons, penalty, chain
    except requests.RequestException:
        reasons.append("Could not fetch URL")
        return reasons, 15 if mode != "it" else 20, []


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
                from datetime import datetime
                fmt = "%b %d %H:%M:%S %Y %Z"
                try:
                    start_raw = cert.get("notBefore") if isinstance(cert, dict) else None
                    end_raw = cert.get("notAfter") if isinstance(cert, dict) else None
                    start = datetime.strptime((start_raw or ""), fmt)
                    end = datetime.strptime((end_raw or ""), fmt)
                    age_days = max(0, (end - start).days)
                    info["lifetime_days"] = age_days
                    info["age_days"] = max(0, (datetime.now(timezone.utc).replace(tzinfo=None) - start).days)
                except Exception:
                    info["age_days"] = None
    except Exception:
        penalty = 10
        info["error"] = "SSL check failed"
    return info, penalty


def _threat_intel(domain: str) -> dict[str, Any]:
    sources: list[dict[str, Any]] = []
    hits = 0
    details: list[str] = []
    seen: set[str] = set()
    feeds = [
        ("phishing_army", "https://phishing.army/download/phishing_army_blocklist.txt"),
        ("openphish", "https://openphish.com/feed.txt"),
    ]
    for name, url in feeds:
        try:
            r = requests.get(url, timeout=3, headers={"User-Agent": "PhishChecker/1.0"})
            if r.ok:
                for line in r.text.splitlines():
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    try:
                        host = urlparse(line).netloc or urlparse("https://" + line).netloc
                    except Exception:
                        host = line
                    if host and host.lower() == domain.lower() and host.lower() not in seen:
                        seen.add(host.lower())
                        hits += 1
                        details.append(f"Listed in {name} from current")
                        sources.append({"name": name, "url": url, "hit": True})
        except requests.RequestException:
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


def _score(result: ScanResult, penalty: int = 0) -> None:
    reasons = list(result.reasons)
    ti = result.threat_intel
    penalty += int(ti.get("penalty", 0))
    domain = result.domain
    if len(domain.split(".")) <= 2 and len(domain) < 25:
        penalty += 5
        reasons.append("Short or unusual domain shape")
    score = max(5, 100 - penalty)
    result.score = score
    if score < 50:
        result.risk = RiskLevel.high
    elif score < 80:
        result.risk = RiskLevel.suspicious
    else:
        result.risk = RiskLevel.clean
    if any("SSL validation issue" in r for r in reasons):
        if result.risk == RiskLevel.clean:
            result.risk = RiskLevel.suspicious
        elif result.risk == RiskLevel.suspicious and score < 80:
            result.risk = RiskLevel.high
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

    hdr_reasons, hdr_penalty, chain = _check_headers(url, mode)
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
    _score(result, penalty=hdr_penalty + ssl_penalty)
    if "score_math" not in result.details:
        result.details["score_math"] = {
            "base": 100,
            "header_penalty": hdr_penalty,
            "ssl_penalty": ssl_penalty,
            "threat_intel_penalty": int(ti.get("penalty", 0)),
            "domain_penalty": 5 if (len(domain.split(".")) <= 2 and len(domain) < 25) else 0,
            "total_penalty": max(0, 100 - result.score),
            "final_score": result.score,
        }
    return result.to_dict()
