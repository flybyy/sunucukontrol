import os
os.environ.setdefault("PANEL_ENV", "test")
os.environ.setdefault("SESSION_SECRET", "test-secret-only-for-tests-01234567890123456789")
from fastapi.testclient import TestClient
from app.main import app


def test_health():
    with TestClient(app) as client:
        r = client.get("/healthz")
        assert r.status_code == 200
        assert r.json()["version"] == "4.0.0"


def test_protected():
    with TestClient(app) as client:
        assert client.get("/api/overview").status_code == 401
        assert client.get("/api/container/any/inspect").status_code == 401
        assert client.post("/api/container/any/action/stop").status_code in (401, 403)
