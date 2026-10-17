from typing import Literal

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from .detector import analyze_message, extract_urls
from .safe_browsing import check_url_reputation
from .ai_analyzer import analyze_with_ai


app = FastAPI(
    title="ScamShield AI API",
    description="API for scam message risk analysis.",
    version="0.2.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)


class AnalyzeRequest(BaseModel):
    message: str = Field(
        ...,
        min_length=1,
        max_length=10000,
        description="Message to analyse for potential scam indicators.",
    )
    language: Literal["en", "hi"] = Field(
        default="en",
        description="Language for the AI explanation: English (en) or Hindi (hi).",
    )


@app.get("/health", tags=["Health"])
def health_check():
    return {
        "status": "healthy",
        "service": "scamshield-ai-api",
        "version": "0.2.0",
    }


@app.get("/", tags=["Root"])
def root():
    return {
        "message": "Welcome to ScamShield AI API",
        "docs": "/docs",
    }


@app.post("/analyze", tags=["Scam Analysis"])
def analyze(request: AnalyzeRequest):
    # Keep the established rule-based detector as the primary scorer.
    result = analyze_message(request.message)

    # Check URLs with the existing Google Safe Browsing integration.
    urls = extract_urls(request.message)
    reputation = check_url_reputation(urls)
    result["url_reputation"] = reputation

    # Preserve existing behavior for known threat URLs.
    if reputation["status"] == "unsafe":
        result["risk_score"] = min(100, result.get("risk_score", 0) + 50)
        score = result["risk_score"]

        if score >= 50:
            result["risk_level"] = "high"
        elif score >= 25:
            result["risk_level"] = "medium"
        else:
            result["risk_level"] = "low"

        result.setdefault("indicators", []).append(
            "Google Safe Browsing reported a known threat URL."
        )
        result.setdefault("recommendations", []).append(
            "Do not open this URL or enter personal information."
        )

    # AI explains the message in the selected UI language. It does not set
    # or change the detector's risk score or risk level.
    result["ai_analysis"] = analyze_with_ai(
        request.message,
        result,
        language=request.language,
    )

    return result
