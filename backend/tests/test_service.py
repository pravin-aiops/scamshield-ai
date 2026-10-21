"""End-to-end behaviour of the two modes, without network access."""

from unittest.mock import Mock

import httpx
import pytest

from backend.app import ai_analyzer, service


@pytest.fixture(autouse=True)
def no_real_network(monkeypatch):
    """Model and Safe Browsing are unavailable unless a test replaces them."""

    def refuse(*args, **kwargs):
        raise httpx.ConnectError("network disabled in tests")

    monkeypatch.setattr(ai_analyzer.httpx, "post", refuse)
    monkeypatch.setattr(
        service,
        "check_url_reputation",
        lambda urls: {
            "status": "unavailable",
            "checked_count": 0,
            "threats": [],
            "message": "URL reputation checking could not be completed.",
        },
    )


def fake_model(monkeypatch, content):
    response = Mock()
    response.raise_for_status.return_value = None
    response.json.return_value = {"message": {"content": content}}
    monkeypatch.setattr(ai_analyzer.httpx, "post", lambda *a, **k: response)


# ---------------------------------------------------------------- check mode
def test_otp_threat_is_high_risk_without_url_panel():
    result = service.run_analysis(
        "Your bank account will be blocked today. Share your OTP immediately.",
        "auto",
        "check",
    )

    assert result["mode"] == "check"
    assert result["risk_level"] == "high"
    assert result["risk_score"] == 60
    assert result["urls"] == []
    assert result["url_reputation"] is None
    categories = [item["category"] for item in result["findings"]]
    assert "credentials" in categories and "urgency" in categories
    assert any("OTP" in item["evidence"] for item in result["findings"])
    assert result["actions"]
    assert result["assessment_note"]


def test_normal_message_is_not_flagged():
    result = service.run_analysis("Hi, lunch at 1 PM? Let me know.", "auto", "check")

    assert result["risk_level"] == "low"
    assert result["risk_score"] == 0
    assert result["findings"] == []
    assert result["url_reputation"] is None
    assert result["ai_analysis"]["status"] == "skipped"


def test_genuine_otp_sms_with_warning_is_low_risk():
    result = service.run_analysis(
        "482913 is your OTP for HDFC NetBanking login. Do not share it with anyone.",
        "auto",
        "check",
    )

    assert result["risk_level"] == "low"
    assert result["findings"] == []


def test_scammer_cannot_hide_behind_do_not_tell_anyone():
    result = service.run_analysis(
        "Do not tell anyone and share your OTP now or your account will be blocked",
        "en",
        "check",
    )

    assert result["risk_level"] == "high"


def test_url_present_and_check_failed_is_reported_as_unavailable():
    result = service.run_analysis("Update KYC at http://sbi-kyc.xyz/login now", "en", "check")

    reputation = result["url_reputation"]
    assert reputation is not None
    assert reputation["status"] == "unavailable"
    assert reputation["checked_count"] == 0
    assert reputation["url_count"] == 1
    assert reputation["urls"] == [{"url": "http://sbi-kyc.xyz/login", "status": "unavailable"}]


def test_no_known_threat_is_never_called_safe(monkeypatch):
    monkeypatch.setattr(
        service,
        "check_url_reputation",
        lambda urls: {
            "status": "no_known_threat",
            "checked_count": len(urls),
            "threats": [],
            "message": "No known threat was reported. This does not guarantee that the URLs are safe.",
        },
    )

    result = service.run_analysis("Details at https://example.com", "en", "check")

    assert result["url_reputation"]["status"] == "no_known_threat"
    assert result["url_reputation"]["checked_count"] == 1
    assert result["risk_level"] == "low"


def test_known_threat_raises_risk_and_adds_evidence(monkeypatch):
    monkeypatch.setattr(
        service,
        "check_url_reputation",
        lambda urls: {
            "status": "unsafe",
            "checked_count": len(urls),
            "threats": [{"url": urls[0], "threat_type": "SOCIAL_ENGINEERING", "platform_type": "ANY_PLATFORM"}],
            "message": "Google Safe Browsing reported one or more known threats.",
        },
    )

    result = service.run_analysis("Visit https://evil.example.com now", "en", "check")

    assert result["risk_level"] == "high"
    assert result["findings"][0]["category"] == "url_threat"
    assert result["url_reputation"]["urls"][0]["status"] == "threat_found"


def test_url_counts_reflect_unique_urls(monkeypatch):
    def fake_check(urls):
        return {"status": "no_known_threat", "checked_count": len(set(urls)), "threats": [], "message": ""}

    monkeypatch.setattr(service, "check_url_reputation", fake_check)

    result = service.run_analysis("a https://example.com b https://example.com c https://example.org", "en", "check")

    assert result["url_reputation"]["checked_count"] == 2
    assert result["url_reputation"]["url_count"] == 2


def test_ai_summary_is_used_when_valid(monkeypatch):
    fake_model(
        monkeypatch,
        '{"summary":"The message asks you to share an OTP under threat of blocking your account, which is a common pressure tactic."}',
    )

    result = service.run_analysis("Your account will be blocked. Share your OTP immediately.", "en", "check")

    assert result["ai_analysis"]["status"] == "available"
    assert result["ai_analysis"]["summary_source"] == "ai"
    assert result["risk_score"] == 60  # the model cannot change the score


def test_ai_summary_in_wrong_language_falls_back_to_rules(monkeypatch):
    fake_model(monkeypatch, '{"summary":"This message asks for an OTP and threatens your account with blocking."}')

    result = service.run_analysis("Aapka account band ho jayega, turant OTP bhejo", "auto", "check")

    assert result["detected_language"] == "hinglish"
    assert result["ai_analysis"]["summary_source"] == "rules"
    assert ai_analyzer._matches_language(result["ai_analysis"]["summary"], "hinglish")


def test_model_failure_is_reported_honestly_and_report_still_works():
    result = service.run_analysis("Your account will be blocked. Share your OTP immediately.", "en", "check")

    assert result["ai_analysis"]["status"] == "unavailable"
    assert result["ai_analysis"]["summary_source"] == "rules"
    assert result["risk_level"] == "high"
    assert result["findings"] and result["actions"]


def test_check_report_is_localised_in_devanagari():
    result = service.run_analysis("अपना ओटीपी तुरंत भेजें, नहीं तो आपका खाता बंद हो जाएगा।", "auto", "check")

    assert result["detected_language"] == "hi"
    assert result["risk_level"] == "high"
    assert ai_analyzer._matches_language(result["findings"][0]["label"], "hi")
    assert ai_analyzer._matches_language(result["actions"][0], "hi")
    assert ai_analyzer._matches_language(result["ai_analysis"]["summary"], "hi")


def test_question_pasted_in_check_mode_suggests_ask_mode():
    result = service.run_analysis("Fake OTP kaise pehchane?", "auto", "check")

    assert result["risk_level"] == "low"
    assert result["suggest_ask_mode"] is True


# ------------------------------------------------------------------ ask mode
@pytest.mark.parametrize(
    "question, language",
    [
        ("Fake email kaise pehchane?", "hinglish"),
        ("Fake email कैसे पहचानें?", "hi"),
        ("फर्जी ईमेल कैसे पहचानें?", "hi"),
        ("How do I identify a fake email?", "en"),
        ("Mujhe UPI scam samjhao", "hinglish"),
        ("UPI collect scam kya hai?", "hinglish"),
        ("What should I do if I accidentally shared my OTP?", "en"),
    ],
)
def test_language_detection_matches_spec(question, language):
    assert ai_analyzer.detect_response_language(question) == language


@pytest.mark.parametrize(
    "question, language",
    [
        ("Fake email kaise pehchane?", "hinglish"),
        ("फर्जी ईमेल कैसे पहचानें?", "hi"),
        ("How do I identify a phishing email?", "en"),
        ("Fake OTP message kaise identify karein?", "hinglish"),
        ("UPI collect scam kya hai?", "hinglish"),
    ],
)
def test_question_gets_answer_in_matching_language_without_report_data(question, language):
    result = service.run_analysis(question, "auto", "ask")

    assert result["mode"] == "ask"
    assert result["detected_language"] == language
    assert result["in_scope"] is True
    for forbidden in ("risk_score", "risk_level", "indicators", "findings", "url_reputation"):
        assert forbidden not in result
    answer = result["answer"]
    assert answer["steps"]
    assert ai_analyzer._matches_language(answer["text"], language)
    assert all(ai_analyzer._matches_language(step, language) for step in answer["steps"])
    assert answer["source"] == "knowledge_base"  # model is unreachable in this test


def test_shared_otp_question_gets_urgent_steps_and_never_uses_model(monkeypatch):
    fake_model(monkeypatch, '{"answer":"never used"}')

    result = service.run_analysis("What should I do if I accidentally shared my OTP?", "auto", "ask")

    answer = result["answer"]
    assert answer["topic"] == "shared_otp"
    assert answer["source"] == "knowledge_base"
    assert "1930" in answer["text"]


def test_valid_model_answer_is_used_for_question(monkeypatch):
    fake_model(
        monkeypatch,
        '{"answer":"To spot a fake email, look at the full sender address and the domain after the @ sign instead of '
        'the display name. Be careful with urgent threats, requests for a password or OTP, unexpected attachments and '
        'links that do not match the company. For example, an email that says your account will close unless you '
        'click and sign in is a classic phishing attempt, so open the official website or app yourself."}',
    )

    result = service.run_analysis("How do I identify a phishing email?", "auto", "ask")

    assert result["answer"]["source"] == "ai"
    assert result["answer"]["steps"]


def test_wrong_language_model_answer_is_rejected(monkeypatch):
    fake_model(
        monkeypatch,
        '{"answer":"To spot a fake email, look at the full sender address and the domain after the @ sign instead of '
        'the display name. Be careful with urgent threats, requests for a password or OTP, unexpected attachments and '
        'links that do not match the company, and open the official website or app yourself."}',
    )

    result = service.run_analysis("Fake email kaise pehchane?", "auto", "ask")

    assert result["answer"]["source"] == "knowledge_base"
    assert result["answer"]["ai_status"] == "rejected"
    assert ai_analyzer._matches_language(result["answer"]["text"], "hinglish")


def test_unrelated_question_is_out_of_scope():
    result = service.run_analysis("What is the capital of France?", "auto", "ask")

    assert result["in_scope"] is False
    assert result["answer"]["source"] == "scope"
    assert "risk_score" not in result


def test_ai_can_be_switched_off(monkeypatch):
    monkeypatch.setenv("AI_ENABLED", "false")
    fake_model(monkeypatch, '{"answer":"should not be called"}')

    result = service.run_analysis("How do I identify a phishing email?", "auto", "ask")

    assert result["answer"]["ai_status"] == "skipped"


import pytest as _pytest


@_pytest.mark.parametrize(
    "question",
    [
        "Dhokhe ka msg kese samjhe?",
        "Dhokha wala message kaise pehchane?",
        "thagi se kaise bachein",
        "धोखे वाला मैसेज कैसे पहचानें?",
        "How do I spot a scam message?",
    ],
)
def test_everyday_scam_questions_are_in_scope(question):
    from backend.app.service import run_analysis

    result = run_analysis(question, "auto", "ask")

    assert result["in_scope"] is True
    assert result["answer"]["topic"] != "out_of_scope"
    assert result["answer"]["text"]
    assert "risk_score" not in result and "url_reputation" not in result


def test_unrelated_question_is_still_out_of_scope():
    from backend.app.service import run_analysis

    assert run_analysis("What is the capital of France?", "auto", "ask")["in_scope"] is False


# ------------------------------------------------------------ unknown sender
import pytest as _pytest2

STRANGER_TEXT = "I got message from unknown number\nHi Alex, are we still meeting for lunch tomorrow at the country club?"


def test_stranger_message_without_warning_signs_keeps_its_score_but_gets_context():
    from backend.app.service import run_analysis

    result = run_analysis(STRANGER_TEXT, "auto", "check")

    assert result["risk_level"] == "low" and result["risk_score"] == 0
    assert result["sender_context"]["unknown"] is True
    assert result["sender_context"]["source"] == "text"
    assert len(result["sender_context"]["steps"]) == 3


def test_person_can_state_that_the_sender_is_unknown():
    from backend.app.service import run_analysis

    result = run_analysis("Hi Alex, are we still meeting for lunch?", "auto", "check", sender="unknown")

    assert result["sender_context"]["source"] == "user"
    assert result["risk_score"] == 0


def test_known_sender_or_plain_message_has_no_context_card():
    from backend.app.service import run_analysis

    assert run_analysis("Hi Alex, lunch tomorrow?", "auto", "check")["sender_context"] is None
    assert run_analysis(STRANGER_TEXT, "auto", "check", sender="known")["sender_context"] is None


@_pytest2.mark.parametrize(
    "text, language",
    [
        ("Anjaan number se message aaya: aapka parcel ruka hai", "hinglish"),
        ("अनजान नंबर से संदेश आया: आपका पार्सल रुका है", "hi"),
    ],
)
def test_unknown_sender_context_follows_message_language(text, language):
    from backend.app.service import run_analysis

    result = run_analysis(text, "auto", "check")

    assert result["detected_language"] == language
    assert result["sender_context"] and result["sender_context"]["title"]


def test_unknown_sender_never_changes_the_score():
    from backend.app.service import run_analysis

    scam = "Share your OTP immediately or your account will be blocked"
    plain = run_analysis(scam, "auto", "check")
    flagged = run_analysis(scam, "auto", "check", sender="unknown")

    assert plain["risk_score"] == flagged["risk_score"]
