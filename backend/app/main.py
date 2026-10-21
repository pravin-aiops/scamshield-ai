import os
from typing import Literal

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from .ratelimit import RateLimiter
from .service import run_analysis
from .status import system_status

VERSION = "0.5.0"

app = FastAPI(
    title="ScamShield AI API",
    description="API for scam message risk analysis and scam-safety questions.",
    version=VERSION,
)

# In Docker the browser reaches the API through the nginx /api proxy on the same
# origin, so CORS only matters for the Vite dev server.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)

# Requests per client per minute on /analyze. 0 switches the limit off.
limiter = RateLimiter(limit=int(os.getenv("RATE_LIMIT_PER_MINUTE", "30")))


class AnalyzeRequest(BaseModel):
    message: str = Field(..., min_length=1, max_length=10000)
    # "auto" detects English, Hindi (Devanagari) or Hinglish from the message.
    language: Literal["en", "hi", "hinglish", "auto"] = "auto"
    # "check" returns a risk report; "ask" answers a general scam question.
    mode: Literal["check", "ask"] = "check"
    # Optional: the person says whether they know who sent the message.
    sender: Literal["unknown", "known"] | None = None


def _client_key(request: Request) -> str:
    # Behind the nginx proxy the real address arrives in X-Forwarded-For. This is
    # fine for abuse protection but it is not an authentication mechanism.
    forwarded = request.headers.get("x-forwarded-for", "").split(",")[0].strip()
    return forwarded or (request.client.host if request.client else "unknown")


@app.get("/health")
def health_check():
    return {"status": "healthy", "service": "scamshield-ai-api", "version": VERSION}


@app.get("/status")
def status():
    """What the optional AI model and URL checker are doing right now."""
    return {"version": VERSION, **system_status()}


@app.get("/")
def root():
    return {"message": "Welcome to ScamShield AI API", "docs": "/docs"}


@app.post("/analyze")
def analyze(payload: AnalyzeRequest, request: Request):
    allowed, retry_after = limiter.check(_client_key(request))

    if not allowed:
        raise HTTPException(
            status_code=429,
            detail="Too many requests. Please wait a moment and try again.",
            headers={"Retry-After": str(retry_after)},
        )

    return run_analysis(payload.message, payload.language, payload.mode, payload.sender)
