"""HTTP-level checks. These need FastAPI (installed by backend/requirements.txt)."""

import httpx
import pytest

pytest.importorskip("fastapi")

from fastapi.testclient import TestClient  # noqa: E402

from backend.app import ai_analyzer, service  # noqa: E402
from backend.app.main import app  # noqa: E402

client = TestClient(app)


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    def refuse(*args, **kwargs):
        raise httpx.ConnectError("network disabled in tests")

    monkeypatch.setattr(ai_analyzer.httpx, "post", refuse)
    monkeypatch.setattr(
        service,
        "check_url_reputation",
        lambda urls: {"status": "unavailable", "checked_count": 0, "threats": [], "message": ""},
    )


def test_analyze_check_mode_returns_a_report():
    response = client.post(
        "/analyze",
        json={"message": "Your bank account will be blocked today. Share your OTP immediately."},
    )

    body = response.json()
    assert response.status_code == 200
    assert body["mode"] == "check"
    assert body["risk_level"] == "high"
    assert body["url_reputation"] is None


def test_analyze_ask_mode_returns_an_answer_not_a_report():
    response = client.post("/analyze", json={"message": "Fake email kaise pehchane?", "mode": "ask"})

    body = response.json()
    assert response.status_code == 200
    assert body["mode"] == "ask"
    assert body["detected_language"] == "hinglish"
    assert "risk_score" not in body


def test_hindi_text_survives_the_json_round_trip():
    response = client.post("/analyze", json={"message": "फर्जी ईमेल कैसे पहचानें?", "mode": "ask"})

    assert response.status_code == 200
    assert "ईमेल" in response.json()["answer"]["text"]


@pytest.mark.parametrize("payload", [{"message": ""}, {"message": "x", "mode": "bogus"}, {}])
def test_invalid_requests_are_rejected(payload):
    assert client.post("/analyze", json=payload).status_code == 422
