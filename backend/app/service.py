"""Request handling for the /analyze endpoint.

Kept free of web-framework imports so it can be tested directly.

Two separate modes share nothing but language detection:

* "check" - a pasted message is analysed and returned as a structured risk
  report (score, evidence, actions, optional URL reputation).
* "ask"   - a general question is answered conversationally. No risk score, no
  indicators and no URL reputation are produced for a question.
"""

import re
from typing import Any

from .ai_analyzer import (
    analyze_with_ai,
    answer_question,
    assessment_note,
    build_findings,
    classify_scope,
    detect_response_language,
    localized_actions,
)
from .content import LANGUAGES, OUT_OF_SCOPE, SENDER_UNKNOWN
from .detector import analyze_message, extract_urls
from .safe_browsing import check_url_reputation

SCOPE_PATTERN = re.compile(
    r"\b(?:scams?|scammers?|fraud|fraudsters?|phishing|cyber.?crime|cyber.?safety|online safety|fake|"
    r"e-?mail|mail|message|msg|msgs|sms|text|call|calls|whatsapp|upi|otp|bank|payment|paise|"
    r"link|url|identity theft|hacked?|hacking|account security|digital arrest|extortion|"
    r"blackmail|thag\w*|dhokh\w*|dhoka\w*|jaal\w*|loot\w*|ghotala|kyc|aadhaar|aadhar|qr|pin|"
    r"password|cvv|cheating|cheat|suspicious|spam|lottery|prize|refund|loan|courier|parcel|"
    r"sandesh|1930|pehchan\w*|pahchan\w*|safe|safety|surakshit|suraksha)\b"
    r"|धोख|ठग|साइबर|स्कैम|फर्जी|नकली|ईमेल|मैसेज|संदेश|यूपीआई|ओटीपी|फिशिंग|डिजिटल अरेस्ट|"
    r"केवाईसी|पासवर्ड|लिंक|पिन|हैक|जालसाज़|जालसाज|लॉटरी|कॉल",
    re.IGNORECASE,
)

# The person may mention in the text that they do not know the sender.
UNKNOWN_SENDER_PATTERN = re.compile(
    r"\b(?:unknown|unfamiliar|strange|random)\s+(?:number|sender|person|id|contact|user|account|profile)\b"
    r"|\bfrom\s+(?:a\s+)?(?:stranger|someone\s+i\s+(?:don'?t|do\s+not)\s+know)\b"
    r"|\b(?:don'?t|do\s+not|dont)\s+know\s+(?:the\s+)?(?:sender|person|who)\b"
    r"|\b(?:anjaan|anjan|ajnabi)\s+(?:number|sender|insaan|vyakti|id|log)\b"
    r"|अनजान\s*(?:नंबर|व्यक्ति|सेंडर|आईडी|लोग)|अज्ञात\s*(?:नंबर|प्रेषक)",
    re.IGNORECASE,
)

QUESTION_HINT = re.compile(
    r"\b(?:how|what|why|when|which|can i|should i|kaise|kese|kya|kyun|kyu|samjhao|batao|bataiye)\b|क्या|कैसे|क्यों|समझा",
    re.IGNORECASE,
)


def _normalise(url: str) -> str:
    return url.strip().lower().rstrip("/")


def _shape_reputation(reputation: dict[str, Any], urls: list[str]) -> dict[str, Any]:
    """Add a per-URL status list so the UI never has to guess."""
    unique_urls = list(dict.fromkeys(urls))
    status = reputation.get("status")
    threats = reputation.get("threats", [])
    threat_urls = {
        _normalise(item.get("url", ""))
        for item in threats
        if isinstance(item, dict) and item.get("url")
    }

    items: list[dict[str, str]] = []

    for url in unique_urls:
        if status == "unsafe":
            url_status = "threat_found" if _normalise(url) in threat_urls else "no_known_threat"
        elif status == "no_known_threat":
            url_status = "no_known_threat"
        elif status == "unavailable":
            url_status = "unavailable"
        else:
            url_status = "not_checked"

        items.append({"url": url, "status": url_status})

    # Google reported a threat but echoed a URL form we could not match. Never
    # hide that: mark every submitted URL as part of the threat report.
    if status == "unsafe" and not any(item["status"] == "threat_found" for item in items):
        for item in items:
            item["status"] = "threat_found"

    return {
        "status": status,
        "checked_count": reputation.get("checked_count", 0),
        "url_count": len(unique_urls),
        "threats": threats,
        "message": reputation.get("message", ""),
        "urls": items,
    }


def _level_for(score: int) -> str:
    return "high" if score >= 50 else "medium" if score >= 25 else "low"


def sender_context(message: str, sender: str | None, language: str) -> dict[str, Any] | None:
    """Context card for a message from a stranger. Never changes the score.

    "known" (stated by the person) wins over anything written in the text.
    """
    if sender == "known":
        return None

    if sender == "unknown":
        source = "user"
    elif UNKNOWN_SENDER_PATTERN.search(message):
        source = "text"
    else:
        return None

    content = SENDER_UNKNOWN[language]
    return {"unknown": True, "source": source, "title": content["title"], "text": content["text"], "steps": list(content["steps"])}


def check_message(message: str, language: str, sender: str | None = None) -> dict[str, Any]:
    """Mode "check": structured risk report for a pasted message."""
    result = analyze_message(message)
    urls = result.get("urls", [])
    reputation = None

    # The URL panel exists only when the message really contains a URL.
    if urls:
        raw = check_url_reputation(urls)
        reputation = _shape_reputation(raw, urls)

        if raw.get("status") == "unsafe":
            result["risk_score"] = min(100, result.get("risk_score", 0) + 50)
            result["risk_level"] = _level_for(result["risk_score"])
            result.setdefault("indicators", []).append(
                "Google Safe Browsing reported a known threat URL."
            )
            result.setdefault("recommendations", []).append(
                "Do not open this URL or enter personal information."
            )
            threat_url = next(
                (t.get("url") for t in raw.get("threats", []) if isinstance(t, dict) and t.get("url")),
                urls[0],
            )
            result.setdefault("findings", []).insert(
                0, {"category": "url_threat", "evidence": threat_url}
            )

    ai = analyze_with_ai(message, result, language=language, intent_override="message_analysis")

    looks_like_question = (
        result["risk_level"] == "low"
        and not result.get("findings")
        and "?" in message
        and bool(QUESTION_HINT.search(message))
    )

    return {
        "mode": "check",
        "detected_language": language,
        "risk_score": result["risk_score"],
        "risk_level": result["risk_level"],
        "findings": build_findings(result, language),
        "actions": localized_actions(result, language),
        "urls": urls,
        "url_reputation": reputation,
        "assessment_note": assessment_note(language),
        "ai_analysis": ai,
        "suggest_ask_mode": looks_like_question,
        "sender_context": sender_context(message, sender, language),
        # English detector text, kept for API consumers that already use it.
        "indicators": result.get("indicators", []),
        "recommendations": result.get("recommendations", []),
        "matched_categories": result.get("matched_categories", []),
    }


def ask_question(message: str, language: str) -> dict[str, Any]:
    """Mode "ask": a conversational answer. No score, indicators or URL data."""
    suggest_check = bool(extract_urls(message))

    # Scope is decided in two steps. Known scam words are accepted instantly and
    # deterministically. If none is found, the model is asked for a strict
    # yes/no so spelling variants ("dhokhe", "msg") still work. With no usable
    # verdict (model off or unreachable) the question is politely declined.
    in_scope = bool(SCOPE_PATTERN.search(message))
    scope_source = "keywords"

    if not in_scope:
        verdict = classify_scope(message)
        if verdict is True:
            in_scope = True
            scope_source = "ai"
        elif verdict is False:
            scope_source = "ai"
        else:
            scope_source = "unavailable"

    if not in_scope:
        return {
            "mode": "ask",
            "detected_language": language,
            "in_scope": False,
            "scope_source": scope_source,
            "answer": {
                "text": OUT_OF_SCOPE[language],
                "steps": [],
                "source": "scope",
                "topic": "out_of_scope",
                "ai_status": "skipped",
            },
            "suggest_check_mode": suggest_check,
        }

    answer = answer_question(message, language)

    return {
        "mode": "ask",
        "detected_language": language,
        "in_scope": True,
        "scope_source": scope_source,
        "answer": answer,
        "suggest_check_mode": suggest_check,
    }


def run_analysis(
    message: str,
    language: str = "auto",
    mode: str = "check",
    sender: str | None = None,
) -> dict[str, Any]:
    """Entry point used by the API layer."""
    text = (message or "").strip()
    resolved = detect_response_language(text) if language == "auto" else language

    if resolved not in LANGUAGES:
        resolved = "en"

    if mode == "ask":
        return ask_question(text, resolved)

    return check_message(text, resolved, sender)
