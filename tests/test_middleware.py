from fastapi.testclient import TestClient

from xpulse.backend.app import app


def test_middleware_blocks_signature_attack() -> None:
    client = TestClient(app)
    response = client.post("/simulate/xss", json={"post": "<script>alert(1)</script>"})
    assert response.status_code in {200, 403}
    dashboard = client.get("/cyberagent/dashboard")
    assert dashboard.status_code == 200
    events = dashboard.json()["events"]
    assert any("xss" in event["attack_type"] for event in events)


def test_xpulse_feed_is_available() -> None:
    client = TestClient(app)
    response = client.get("/api/feed")
    assert response.status_code == 200
    assert "posts" in response.json()

