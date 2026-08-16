import json

import pytest
from app import create_app
from services.db import init_db, get_engine
from models import Base


@pytest.fixture(autouse=True)
def app():
    init_db("sqlite://")
    Base.metadata.create_all(get_engine())
    app = create_app({"TESTING": True, "WTF_CSRF_ENABLED": False, "SQLALCHEMY_DATABASE_URI": "sqlite://"})
    return app


@pytest.fixture
def client(app):
    return app.test_client()


def test_health(client):
    r = client.get("/health")
    assert r.status_code == 200
    assert r.get_json()["ok"] is True


def test_scan_legacy(client):
    r = client.post("/scan", json={"url": "https://example.com"}, headers={"X-CSRF-Token": "test", "Content-Type": "application/json"})
    assert r.status_code == 202
    data = r.get_json()
    assert data["url"] == "https://example.com"
    assert "risk" in data
    assert "score" in data


def test_api_v2_scan(client):
    r = client.post("/api/v2/scans", json={"url": "https://example.org", "mode": "quick"}, headers={"X-CSRF-Token": "test", "Content-Type": "application/json"})
    assert r.status_code == 202
    data = r.get_json()
    assert data["domain"] == "example.org"


def test_bulk_scan(client):
    r = client.post("/scan/bulk", json={"urls": ["https://example.com", "https://example.org"], "mode": "quick"}, headers={"X-CSRF-Token": "test", "Content-Type": "application/json"})
    assert r.status_code == 202
    data = r.get_json()
    assert len(data["results"]) == 2


def test_history(client):
    r = client.get("/api/v2/scans/history")
    assert r.status_code == 200
    data = r.get_json()
    assert "items" in data
    assert "count" in data


def test_export_json(client):
    r = client.get("/api/v2/scans/export")
    assert r.status_code == 200
    data = r.get_json()
    assert "items" in data


def test_scan_detail_not_found(client):
    r = client.get("/api/v2/scans/does-not-exist")
    assert r.status_code == 404


def test_queue_status(client):
    r = client.get("/api/v2/queue/status")
    assert r.status_code == 200
    assert r.get_json()["queued"] == 0


def test_status_feeds(client):
    r = client.get("/api/v2/status/feeds")
    assert r.status_code == 200
