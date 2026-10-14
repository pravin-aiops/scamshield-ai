
from app.detector import analyze_message, extract_urls, get_hostname, is_shortener


def test_otp_scam_is_high_risk():
    message = (
        "Your bank account will be blocked today. "
        "Share your OTP immediately to keep it active."
    )

    result = analyze_message(message)

    assert result["risk_score"] == 80
    assert result["risk_level"] == "high"
    assert len(result["indicators"]) >= 3


def test_normal_lunch_message_is_low_risk():
    message = (
        "Hi, we are meeting for lunch at 1 PM. "
        "Please let me know if you are joining."
    )

    result = analyze_message(message)

    assert result["risk_score"] == 0
    assert result["risk_level"] == "low"


def test_url_is_flagged_as_unverified():
    result = analyze_message(
        "Please visit http://example.com for details."
    )

    assert result["risk_score"] == 10
    assert result["risk_level"] == "low"
    assert any(
        "destination has not been verified" in indicator
        for indicator in result["indicators"]
    )


def test_shortened_url_gets_additional_points():
    result = analyze_message(
        "Please visit https://bit.ly/example for details."
    )

    assert result["risk_score"] == 25
    assert result["risk_level"] == "medium"
    assert any(
        "URL-shortening service" in indicator
        for indicator in result["indicators"]
    )


def test_prize_and_processing_fee_message():
    message = (
        "Congratulations! You won a free prize. "
        "Pay a processing fee now to claim your reward."
    )

    result = analyze_message(message)

    assert result["risk_score"] == 25
    assert result["risk_level"] == "medium"
    assert any(
        "prize, reward, payment" in indicator
        for indicator in result["indicators"]
    )


def test_empty_message_returns_zero_score():
    result = analyze_message("   ")

    assert result["risk_score"] == 0
    assert result["risk_level"] == "low"
    assert result["indicators"] == []


def test_extract_urls_removes_trailing_punctuation():
    urls = extract_urls(
        "Visit https://example.com/path?id=123. Then check www.example.org!"
    )

    assert urls == [
        "https://example.com/path?id=123",
        "www.example.org",
    ]


def test_hostname_extracts_normal_https_url():
    assert get_hostname("https://example.com/path?id=123") == "example.com"


def test_hostname_handles_www_url():
    assert get_hostname("www.example.com") == "www.example.com"


def test_misleading_hostname_is_not_rewritten():
    assert (
        get_hostname("https://example.com.evil.test")
        == "example.com.evil.test"
    )


def test_invalid_hostname_is_rejected():
    assert get_hostname("not-a-valid-url") == ""
    assert get_hostname("https://bad host.com") == ""


def test_invalid_port_is_rejected():
    assert get_hostname("https://example.com:99999") == ""


def test_shortener_detection_does_not_match_lookalikes():
    assert is_shortener("bit.ly") is True
    assert is_shortener("sub.bit.ly") is True
    assert is_shortener("notbit.ly.example.test") is False
    assert is_shortener("example.com") is False


def test_invalid_url_format_is_reported():
    result = analyze_message(
        "Open https://bad host.com for details."
    )

    assert any(
        "invalid or unsupported format" in indicator
        for indicator in result["indicators"]
    )


def test_https_url_is_not_declared_safe():
    result = analyze_message(
        "Please visit https://example.com for details."
    )

    assert result["risk_score"] == 10
    assert any(
        "destination has not been verified" in indicator
        for indicator in result["indicators"]
    )
