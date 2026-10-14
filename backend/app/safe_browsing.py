import os
from pathlib import Path
from typing import Any

import httpx
from dotenv import load_dotenv


PROJECT_ROOT = Path(__file__).resolve().parents[2]
load_dotenv(PROJECT_ROOT / ".env")

API_KEY = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "").strip()

SAFE_BROWSING_URL = (
    "https://safebrowsing.googleapis.com/v4/threatMatches:find"
)

MAX_URLS_PER_REQUEST = 500
REQUEST_TIMEOUT = 5.0


def check_url_reputation(urls: list[str]) -> dict[str, Any]:
    """Check URLs against Google's Safe Browsing threat lists."""

    if not urls:
        return {
            "status": "not_checked",
            "checked_count": 0,
            "threats": [],
            "message": "No URLs were found in the message.",
        }

    if not API_KEY:
        return {
            "status": "unavailable",
            "checked_count": 0,
            "threats": [],
            "message": "URL reputation checking is not configured.",
        }

    unique_urls = list(dict.fromkeys(urls))
    threats: list[dict[str, Any]] = []
    checked_count = 0

    for start in range(0, len(unique_urls), MAX_URLS_PER_REQUEST):
        batch = unique_urls[start:start + MAX_URLS_PER_REQUEST]

        payload = {
            "client": {
                "clientId": "scamshield-ai",
                "clientVersion": "0.1.0",
            },
            "threatInfo": {
                "threatTypes": [
                    "MALWARE",
                    "SOCIAL_ENGINEERING",
                    "UNWANTED_SOFTWARE",
                    "POTENTIALLY_HARMFUL_APPLICATION",
                ],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [
                    {"url": url} for url in batch
                ],
            },
        }

        try:
            response = httpx.post(
                SAFE_BROWSING_URL,
                params={"key": API_KEY},
                json=payload,
                timeout=REQUEST_TIMEOUT,
            )
            response.raise_for_status()
            data = response.json()

        except (httpx.HTTPError, ValueError):
            return {
                "status": "unavailable",
                "checked_count": checked_count,
                "threats": [],
                "message": (
                    "URL reputation checking could not be completed."
                ),
            }

        checked_count += len(batch)

        for match in data.get("matches", []):
            threat = match.get("threat", {})
            threats.append(
                {
                    "url": threat.get("url", ""),
                    "threat_type": match.get("threatType", "UNKNOWN"),
                    "platform_type": match.get("platformType", "UNKNOWN"),
                }
            )

    if threats:
        return {
            "status": "unsafe",
            "checked_count": checked_count,
            "threats": threats,
            "message": (
                "Google Safe Browsing reported one or more known threats."
            ),
        }

    return {
        "status": "no_known_threat",
        "checked_count": checked_count,
        "threats": [],
        "message": (
            "No known threat was reported. This does not guarantee "
            "that the URLs are safe."
        ),
    }