from unittest.mock import Mock

from backend.app import ai_analyzer


def test_low_risk_fallback_does_not_show_generic_warning_as_signal():
    result = ai_analyzer._fallback(
        "en",
        detector_result={
            "risk_score": 0,
            "risk_level": "low",
            "indicators": ["No configured scam indicators were detected."],
            "recommendations": [
                "No strong scam patterns were detected by these rules."
            ],
        },
    )

    assert result["suspicious_signals"] == []
    assert result["status"] == "unavailable"


def test_prize_scam_fallback_preserves_detector_evidence():
    result = ai_analyzer._fallback(
        "en",
        detector_result={
            "risk_score": 25,
            "risk_level": "medium",
            "indicators": [
                "A prize, reward, payment, or money-transfer pattern was detected.",
                "A processing fee was offered",
            ],
            "recommendations": [
                "Do not pay a fee or send money to claim an unexpected prize or reward."
            ],
        },
    )

    assert len(result["suspicious_signals"]) > 0
    assert any("prize" in item.lower() for item in result["suspicious_signals"])
    assert len(result["recommended_actions"]) > 0


def test_ai_empty_arrays_use_deterministic_fallback(monkeypatch):
    response = Mock()
    response.raise_for_status.return_value = None
    response.json.return_value = {
        "message": {
            "content": (
                '{"summary":"The message asks for an OTP.",'
                '"suspicious_signals":[],"recommended_actions":[]}'
            )
        }
    }

    monkeypatch.setattr(ai_analyzer.httpx, "post", lambda *args, **kwargs: response)

    result = ai_analyzer.analyze_with_ai(
        "Share your OTP immediately.",
        {
            "risk_score": 60,
            "risk_level": "high",
            "indicators": ["The message requests sensitive credentials or an OTP."],
            "recommendations": ["Never share an OTP, PIN, or password with anyone."],
            "url_reputation": {"status": "not_checked"},
        },
        language="en",
    )

    assert result["status"] == "available"
    assert result["suspicious_signals"]
    assert result["recommended_actions"]


def test_ai_unavailable_returns_fallback_without_changing_score(monkeypatch):
    def raise_connection_error(*args, **kwargs):
        raise ai_analyzer.httpx.ConnectError("test connection failure")

    monkeypatch.setattr(ai_analyzer.httpx, "post", raise_connection_error)

    detector_result = {
        "risk_score": 60,
        "risk_level": "high",
        "indicators": ["The message requests sensitive credentials or an OTP."],
        "recommendations": ["Never share an OTP, PIN, or password with anyone."],
        "url_reputation": {"status": "not_checked"},
    }

    result = ai_analyzer.analyze_with_ai(
        "Share your OTP immediately.",
        detector_result,
        language="en",
    )

    assert result["status"] == "unavailable"
    assert detector_result["risk_score"] == 60
    assert detector_result["risk_level"] == "high"
    assert result["suspicious_signals"]
    assert result["recommended_actions"]
