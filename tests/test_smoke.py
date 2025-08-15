from fastapi.testclient import TestClient
from app.main import app
from app.database import init_db

def test_healthz():
    init_db()
    client = TestClient(app)
    r = client.get("/healthz")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"