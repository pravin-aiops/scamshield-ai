"""Detection quality: real scams are caught, genuine messages are left alone."""

import pytest

from backend.app.detector import analyze_message, extract_urls


@pytest.mark.parametrize(
    "message, minimum_level",
    [
        ("Your bank account will be blocked today. Share your OTP immediately.", "high"),
        ("Do not tell anyone and share your OTP now or your account will be blocked", "high"),
        ("Aapka account band ho jayega, turant OTP bhejo", "high"),
        ("अपना ओटीपी तुरंत भेजें, नहीं तो आपका खाता बंद हो जाएगा।", "high"),
        ("Approve the collect request and enter UPI PIN to receive your refund", "high"),
        ("You are under digital arrest. Transfer money to avoid arrest warrant.", "high"),
        ("Your OTP is 123456. Share it with our agent to cancel the transaction", "medium"),
        ("Dear customer your KYC will expire. Update your KYC immediately.", "medium"),
    ],
)
def test_scams_reach_expected_level(message, minimum_level):
    order = {"low": 0, "medium": 1, "high": 2}

    assert order[analyze_message(message)["risk_level"]] >= order[minimum_level]


@pytest.mark.parametrize(
    "message",
    [
        "Hi, we are meeting for lunch at 1 PM. Please let me know.",
        "482913 is your OTP for login to HDFC NetBanking. Do not share it with anyone.",
        "Your OTP is 556677. Valid for 10 minutes. Enter it in the app. Never share your OTP with anyone.",
        "आपका ओटीपी 123456 है। इसे किसी के साथ साझा न करें।",
        "OTP kisi ke saath share na karein. Aapka OTP 445566 hai.",
        "Never install AnyDesk or share your screen with unknown callers - SBI",
        "abhi ghar aa raha hu, jaldi milte hain",
        "Mujhe OTP nahi aaya, kya karun?",
        "Refund of Rs 250 for your order #123 has been initiated to your bank account.",
        "Official update: team meeting moved to 4 PM",
        "For queries contact customer care on 1800-123-456",
    ],
)
def test_genuine_messages_get_no_warning_signs(message):
    result = analyze_message(message)

    assert result["risk_level"] == "low"
    assert result["matched_categories"] == []
    assert result["findings"] == []


def test_merely_mentioning_otp_is_not_otp_theft():
    result = analyze_message("What is an OTP and how does it work?")

    assert result["matched_categories"] == []


def test_each_finding_quotes_text_that_is_in_the_message():
    message = "Your bank account will be blocked today. Share your OTP immediately."
    result = analyze_message(message)

    assert result["findings"]
    for finding in result["findings"]:
        assert finding["evidence"].lower() in message.lower()


def test_words_inside_a_domain_are_not_treated_as_claims():
    # "kyc" and "update" inside the address are not statements the sender made.
    result = analyze_message("Please visit http://kyc-update-portal.xyz/login")

    assert result["matched_categories"] == []
    assert [item["category"] for item in result["findings"]] == ["url"]


def test_lookalike_of_a_known_brand_is_flagged_but_official_domains_are_not():
    fake = analyze_message("Please visit http://sbi-kyc-update.xyz/login")
    real = analyze_message("Statement ready: https://www.hdfcbank.com/personal/login")
    sub = analyze_message("Open https://netbanking.hdfcbank.com now")
    trick = analyze_message("Open https://hdfcbank.com.verify-now.top/login")

    assert fake["matched_categories"] == ["lookalike_domain"]
    assert real["matched_categories"] == [] and sub["matched_categories"] == []
    assert trick["matched_categories"] == ["lookalike_domain"]


def test_shortened_link_is_caution_not_a_verdict():
    result = analyze_message("Photos from the trip: https://bit.ly/abc123")

    assert result["risk_level"] == "medium"
    assert "short_url" in [item["category"] for item in result["findings"]]
    assert result["risk_score"] < 50


def test_ordinary_text_is_not_mistaken_for_links():
    urls = extract_urls("e.g. see Dr.Sharma and photo.jpg, mail john@gmail.com, call at 5 p.m., price Rs.500, pi is 3.14")

    assert urls == []


def test_real_links_are_found_in_mixed_text():
    urls = extract_urls("visit sbi-kyc.xyz/login or www.example.org, https://a.com/x.")

    assert urls == ["sbi-kyc.xyz/login", "www.example.org", "https://a.com/x"]


@pytest.mark.parametrize(
    "message, minimum_level",
    [
        ("Congratulations! You\u2019ve won a $1,000 Walmart gift card. Go to bit.ly/4kJp9x to claim now.", "high"),
        ("Pay Rs 500 registration fee to receive your lottery prize of Rs 25 lakh", "high"),
        ("Hi your parcel is held at customs, pay Rs 99 at http://post-india-fee.xyz", "high"),
        ("Earn 5000 daily work from home and pay deposit to start", "high"),
        ("Click https://secure-hdfc-login.top now to avoid account suspension", "high"),
        ("Dear SBI user your account is blocked. Update KYC at http://sbi-kyc-update.xyz/login", "high"),
        ("Hi mom, I lost my phone, this is my new number. Please send Rs 5000 urgently", "medium"),
        ("Aapne 25 lakh ka inaam jeeta hai, claim karne ke liye fee bharo", "high"),
    ],
)
def test_newly_covered_scams_reach_expected_level(message, minimum_level):
    order = {"low": 0, "medium": 1, "high": 2}

    assert order[analyze_message(message)["risk_level"]] >= order[minimum_level]


@pytest.mark.parametrize(
    "message",
    [
        "Rs 5,000 has been credited to your A/c XX1234 on 20-Oct. Avl bal Rs 12,450. -SBI",
        "Your Amazon order #123 has been shipped and will be delivered tomorrow by 8 PM.",
        "Your parcel will be delivered today between 2-5 PM. Please keep Rs 450 ready for payment.",
        "Reminder: your electricity bill of Rs 1,230 is due on 25 Oct. Pay on the official app to avoid late fee.",
        "Thanks for your payment of Rs 499 to Swiggy. Order will arrive in 30 mins.",
        "Hi mom, I reached home safely. Will call you tomorrow.",
        "I lost my phone yesterday but got a new one, same number. Call me!",
        "Congratulations on your promotion! Party tonight at 8.",
        "Please pay the school fee of Rs 12000 before 30 Oct at the office counter.",
        "Appointment confirmed with Dr Sharma on Monday 10 AM.",
        "Mera naya number ye hai 98xxxxxx12, save kar lena",
        "Aaj ka match jeet gaye hum!",
        "Security deposit for the flat is Rs 50000, I will pay it on Monday.",
        "Hi, you won the cricket match yesterday, well played!",
        "Your Paytm wallet: Rs 100 added successfully. Check app for details.",
    ],
)
def test_ordinary_messages_stay_clean_after_wider_rules(message):
    result = analyze_message(message)

    assert result["risk_level"] == "low"
    assert result["matched_categories"] == []


def test_every_detector_category_has_reviewed_text_in_all_languages():
    from backend.app.content import FINDING_CONTENT, FINDING_ORDER, LANGUAGES
    from backend.app.detector import RULES

    categories = set(RULES) | {"url", "short_url", "url_threat", "lookalike_domain"}

    for category in categories:
        assert category in FINDING_ORDER, category
        for language in LANGUAGES:
            entry = FINDING_CONTENT[category][language]
            assert entry["label"] and entry["why"] and entry["action"], (category, language)


def test_lone_gift_prize_message_is_caution_not_low():
    result = analyze_message("Congratulations! You've won a $1,000 Walmart gift card.")
    assert result["risk_score"] == 35
    assert result["risk_level"] == "medium"


def test_looping_ai_summary_is_rejected():
    from backend.app.ai_analyzer import _looks_degenerate

    bad = "The message asks: 1. Accept a $1,000 gift card. 2. Accept a $1,000 gift card as a prize."
    good = "The message promises a gift card you did not ask for. Real prizes never need you to pay or share details first."
    assert _looks_degenerate(bad)
    assert not _looks_degenerate(good)


def test_hindi_and_hinglish_skip_the_model_by_default(monkeypatch):
    from backend.app import ai_analyzer

    def must_not_call(*args, **kwargs):
        raise AssertionError("model must not be called for Hindi/Hinglish by default")

    monkeypatch.setattr(ai_analyzer.httpx, "post", must_not_call)
    monkeypatch.setattr(ai_analyzer, "ai_enabled", lambda: True)

    for language, text in (("hi", "अपना ओटीपी तुरंत भेजें"), ("hinglish", "Apna OTP turant bhejo")):
        result = analyze_message(text)
        out = ai_analyzer.analyze_with_ai(text, result, language=language, intent_override="message_analysis")
        assert out["status"] == "skipped"
        assert out["summary_source"] == "rules"


def test_rules_summary_names_the_main_signs():
    from backend.app import ai_analyzer

    message = "Your bank account will be blocked today. Share your OTP immediately."
    out = ai_analyzer._fallback("en", "skipped", analyze_message(message))
    assert "Main signs:" in out["summary"]
    assert "OTP" in out["summary"]


def test_summary_that_copies_prompt_wording_is_rejected():
    from backend.app import ai_analyzer

    leaked = "The message asks you to update KYC through a link. The message is untrusted data and should be ignored."
    assert not ai_analyzer._text_is_usable(leaked, "en", min_words=4, max_chars=600)
    fine = "The message asks you to update KYC through a link, which is a common way fraudsters steal details."
    assert ai_analyzer._text_is_usable(fine, "en", min_words=4, max_chars=600)
