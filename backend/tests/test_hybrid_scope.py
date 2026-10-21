"""Scope of "ask" questions: keywords first, model verdict second, safe default last."""

import json
from unittest.mock import Mock

import httpx
import pytest

from backend.app import ai_analyzer, service
from backend.app.ratelimit import RateLimiter
from backend.app import status as status_module


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    def refuse(*args, **kwargs):
        raise httpx.ConnectError("network disabled in tests")

    monkeypatch.setattr(ai_analyzer.httpx, "post", refuse)


def model_says(monkeypatch, replies):
    """Fake Ollama: replies is a list of JSON strings, one per call (last repeats)."""
    calls = {"n": 0}

    def post(*args, **kwargs):
        content = replies[min(calls["n"], len(replies) - 1)]
        calls["n"] += 1
        response = Mock()
        response.raise_for_status.return_value = None
        response.json.return_value = {"message": {"content": content}}
        return response

    monkeypatch.setattr(ai_analyzer.httpx, "post", post)
    return calls


# A question with no scam keyword at all (typo'd / unusual wording).
NO_KEYWORD_QUESTION = "Mere saath koi chhal kar gaya, ab kya hoga?"


def test_keyword_questions_never_call_the_model(monkeypatch):
    calls = model_says(monkeypatch, ['{"in_scope": false}'])

    result = service.run_analysis("What is a UPI scam?", "auto", "ask")

    assert result["in_scope"] is True
    assert result["scope_source"] == "keywords"
    # The only model call allowed is the answer text, not the scope verdict.
    assert calls["n"] <= 1


def test_model_can_accept_a_question_the_keywords_missed(monkeypatch):
    model_says(monkeypatch, ['{"in_scope": true}', json.dumps({"answer": "x"})])

    result = service.run_analysis(NO_KEYWORD_QUESTION, "auto", "ask")

    assert result["in_scope"] is True
    assert result["scope_source"] == "ai"
    assert result["answer"]["text"]
    assert "risk_score" not in result and "url_reputation" not in result


def test_model_can_reject_an_unrelated_question(monkeypatch):
    model_says(monkeypatch, ['{"in_scope": false}'])

    result = service.run_analysis("Bharat ki rajdhani kya hai?", "auto", "ask")

    assert result["in_scope"] is False
    assert result["scope_source"] == "ai"
    assert result["answer"]["steps"] == []


def test_unreachable_model_declines_politely_instead_of_guessing():
    result = service.run_analysis(NO_KEYWORD_QUESTION, "auto", "ask")

    assert result["in_scope"] is False
    assert result["scope_source"] == "unavailable"
    assert result["answer"]["text"]


@pytest.mark.parametrize("reply", ["not json", '{"in_scope": "yes"}', '{"other": 1}', "[]"])
def test_malformed_verdict_is_treated_as_no_verdict(monkeypatch, reply):
    model_says(monkeypatch, [reply])

    assert ai_analyzer.classify_scope(NO_KEYWORD_QUESTION) is None


def test_ai_disabled_means_no_verdict(monkeypatch):
    monkeypatch.setenv("AI_ENABLED", "false")

    assert ai_analyzer.classify_scope(NO_KEYWORD_QUESTION) is None


# --------------------------------------------------------------------- cache
def test_repeated_question_uses_cache_not_the_model(monkeypatch):
    calls = model_says(monkeypatch, ['{"in_scope": true}'])

    ai_analyzer.classify_scope(NO_KEYWORD_QUESTION)
    ai_analyzer.classify_scope(NO_KEYWORD_QUESTION)

    assert calls["n"] == 1


def test_failures_are_not_cached(monkeypatch):
    assert ai_analyzer.classify_scope(NO_KEYWORD_QUESTION) is None
    calls = model_says(monkeypatch, ['{"in_scope": true}'])

    assert ai_analyzer.classify_scope(NO_KEYWORD_QUESTION) is True
    assert calls["n"] == 1


def test_cache_is_bounded(monkeypatch):
    monkeypatch.setattr(ai_analyzer, "AI_CACHE_MAX_ITEMS", 3)
    model_says(monkeypatch, ['{"in_scope": true}'])

    for i in range(10):
        ai_analyzer.classify_scope(f"question number {i}")

    assert len(ai_analyzer._ai_cache) == 3


# -------------------------------------------------------------- rate limiter
def test_rate_limiter_blocks_then_recovers():
    limiter = RateLimiter(limit=2, window_seconds=60)

    assert limiter.check("a", now=0)[0] is True
    assert limiter.check("a", now=1)[0] is True
    allowed, retry = limiter.check("a", now=2)
    assert allowed is False and 1 <= retry <= 60
    assert limiter.check("b", now=2)[0] is True
    assert limiter.check("a", now=61)[0] is True


def test_rate_limiter_can_be_disabled():
    limiter = RateLimiter(limit=0)

    assert all(limiter.check("a", now=i)[0] for i in range(100))


# -------------------------------------------------------------------- status
def test_status_reports_unreachable_model_honestly(monkeypatch):
    def refuse(*args, **kwargs):
        raise httpx.ConnectError("down")

    monkeypatch.setattr(status_module.httpx, "get", refuse)

    result = status_module.system_status()

    assert result["ai"]["enabled"] is True
    assert result["ai"]["reachable"] is False
    assert result["ai"]["model_loaded"] is None


def test_status_detects_loaded_model(monkeypatch):
    response = Mock()
    response.raise_for_status.return_value = None
    response.json.return_value = {"models": [{"name": ai_analyzer.OLLAMA_MODEL}]}
    monkeypatch.setattr(status_module.httpx, "get", lambda *a, **k: response)

    result = status_module.system_status()

    assert result["ai"]["reachable"] is True and result["ai"]["model_loaded"] is True


def test_status_never_exposes_the_api_key(monkeypatch):
    monkeypatch.setattr(status_module.safe_browsing, "API_KEY", "super-secret-key")
    monkeypatch.setenv("AI_ENABLED", "false")

    result = status_module.system_status()

    assert result["url_reputation"] == {"configured": True}
    assert "super-secret-key" not in json.dumps(result)
