import httpx

from backend.app import safe_browsing


def test_empty_url_list_does_not_call_api(monkeypatch):
    def fail_if_called(*args, **kwargs):
        raise AssertionError("API should not be called for an empty URL list")

    monkeypatch.setattr(safe_browsing.httpx, "get", fail_if_called)
    monkeypatch.setattr(safe_browsing.httpx, "post", fail_if_called)

    result = safe_browsing.check_url_reputation([])

    assert result["status"] == "not_checked"
    assert result["checked_count"] == 0
    assert result["threats"] == []


def test_missing_api_key_returns_unavailable(monkeypatch):
    monkeypatch.setattr(safe_browsing, "API_KEY", "")

    result = safe_browsing.check_url_reputation(
        ["https://example.com"]
    )

    assert result["status"] == "unavailable"
    assert result["checked_count"] == 0


def test_known_threat_is_reported(monkeypatch):
    monkeypatch.setattr(safe_browsing, "API_KEY", "test-key")

    def mock_post(*args, **kwargs):
        assert kwargs["json"]["threatInfo"]["threatEntries"] == [
            {"url": "https://example.com"}
        ]

        return httpx.Response(
            200,
            json={
                "matches": [
                    {
                        "threatType": "SOCIAL_ENGINEERING",
                        "platformType": "ANY_PLATFORM",
                        "threat": {
                            "url": "https://example.com"
                        },
                    }
                ]
            },
            request=httpx.Request("POST", safe_browsing.SAFE_BROWSING_URL),
        )

    monkeypatch.setattr(safe_browsing.httpx, "post", mock_post)

    result = safe_browsing.check_url_reputation(
        ["https://example.com"]
    )

    assert result["status"] == "unsafe"
    assert result["checked_count"] == 1
    assert len(result["threats"]) == 1
    assert result["threats"][0]["threat_type"] == "SOCIAL_ENGINEERING"


def test_no_known_threat_is_reported(monkeypatch):
    monkeypatch.setattr(safe_browsing, "API_KEY", "test-key")

    def mock_post(*args, **kwargs):
        return httpx.Response(
            200,
            json={},
            request=httpx.Request("POST", safe_browsing.SAFE_BROWSING_URL),
        )

    monkeypatch.setattr(safe_browsing.httpx, "post", mock_post)

    result = safe_browsing.check_url_reputation(
        ["https://example.com"]
    )

    assert result["status"] == "no_known_threat"
    assert result["checked_count"] == 1
    assert result["threats"] == []


def test_api_error_returns_unavailable(monkeypatch):
    monkeypatch.setattr(safe_browsing, "API_KEY", "test-key")

    def mock_post(*args, **kwargs):
        request = httpx.Request(
            "POST",
            safe_browsing.SAFE_BROWSING_URL,
        )
        raise httpx.ConnectError("Simulated connection error", request=request)

    monkeypatch.setattr(safe_browsing.httpx, "post", mock_post)

    result = safe_browsing.check_url_reputation(
        ["https://example.com"]
    )

    assert result["status"] == "unavailable"
    assert result["checked_count"] == 0
    assert result["threats"] == []


def test_duplicate_urls_are_checked_once(monkeypatch):
    monkeypatch.setattr(safe_browsing, "API_KEY", "test-key")
    captured = {}

    def mock_post(*args, **kwargs):
        captured["entries"] = kwargs["json"]["threatInfo"]["threatEntries"]

        return httpx.Response(
            200,
            json={},
            request=httpx.Request("POST", safe_browsing.SAFE_BROWSING_URL),
        )

    monkeypatch.setattr(safe_browsing.httpx, "post", mock_post)

    result = safe_browsing.check_url_reputation(
        [
            "https://example.com",
            "https://example.com",
        ]
    )

    assert result["status"] == "no_known_threat"
    assert result["checked_count"] == 1
    assert captured["entries"] == [
        {"url": "https://example.com"}
    ]