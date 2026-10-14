
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from .detector import analyze_message, extract_urls
from .safe_browsing import check_url_reputation


app = FastAPI(
    title="ScamShield AI API",
    description="API for scam message risk analysis.",
    version="0.1.0",
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


@app.get("/health", tags=["Health"])
def health_check():
    return {
        "status": "healthy",
        "service": "scamshield-ai-api",
        "version": "0.1.0",
    }


@app.get("/", tags=["Root"])
def root():
    return {
        "message": "Welcome to ScamShield AI API",
        "docs": "/docs",
    }


@app.post("/analyze", tags=["Scam Analysis"])
def analyze(request: AnalyzeRequest):
    # Run the existing message detector first.
    result = analyze_message(request.message)

    # Extract URLs using the existing detector's URL extraction logic.
    urls = extract_urls(request.message)

    # Check URL reputation. If Google is unavailable, the existing
    # detector result is preserved.
    reputation = check_url_reputation(urls)
    result["url_reputation"] = reputation

    if reputation["status"] == "unsafe":
        # Raise the score for a URL reported as a known threat.
        result["risk_score"] = min(
            100,
            result.get("risk_score", 0) + 50,
        )

        # Recalculate the risk level using existing thresholds.
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

    return result