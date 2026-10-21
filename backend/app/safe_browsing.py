
import logging
import os
from pathlib import Path
from typing import Any

import httpx
from dotenv import load_dotenv


logger = logging.getLogger(__name__)

PROJECT_ROOT = Path(__file__).resolve().parents[2]
load_dotenv(PROJECT_ROOT / ".env")

API_KEY = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "").strip()

SAFE_BROWSING_URL = (
    "https://safebrowsing.googleapis.com/v4/threatMatches:find"
)

MAX_URLS_PER_REQUEST = 50
REQUEST_TIMEOUT = 5.0

THREAT_TYPES = [
    "MALWARE",
    "SOCIAL_ENGINEERING",
    "UNWANTED_SOFTWARE",
    "POTENTIALLY_HARMFUL_APPLICATION",
]


def _result(
    status: str,
    checked_count: int,
    threats: list[dict[str, Any]],
    message: str,
) -> dict[str, Any]:
    """Return a consistent URL reputation response."""
    return {
        "status": status,
        "checked_count": checked_count,
        "threats": threats,
        "message": message,
    }


def check_url_reputation(urls: list[str]) -> dict[str, Any]:
    """
    Check URLs against Google's Safe Browsing threat lists.

    Status values:
      - not_checked: no URLs were supplied
      - unavailable: the check could not be completed
      - unsafe: Google reported one or more known threats
      - no_known_threat: no known threat was reported

    A no_known_threat result does not guarantee that a URL is safe.
    """

    if not urls:
        return _result(
            status="not_checked",
            checked_count=0,
            threats=[],
            message="No URLs were found in the message.",
        )

    if not API_KEY:
        logger.warning(
            "Safe Browsing check skipped: API key is not configured."
        )
        return _result(
            status="unavailable",
            checked_count=0,
            threats=[],
            message="URL reputation checking is not configured.",
        )

    # Remove empty values and duplicates while preserving input order.
    unique_urls = list(
        dict.fromkeys(
            url.strip()
            for url in urls
            if isinstance(url, str) and url.strip()
        )
    )

    if not unique_urls:
        return _result(
            status="not_checked",
            checked_count=0,
            threats=[],
            message="No valid URLs were supplied for reputation checking.",
        )

    threats: list[dict[str, Any]] = []
    checked_count = 0

    for start in range(0, len(unique_urls), MAX_URLS_PER_REQUEST):
        batch = unique_urls[start : start + MAX_URLS_PER_REQUEST]

        payload = {
            "client": {
                "clientId": "scamshield-ai",
                "clientVersion": "0.2.0",
            },
            "threatInfo": {
                "threatTypes": THREAT_TYPES,
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [
                    {"url": url}
                    for url in batch
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

            if not isinstance(data, dict):
                logger.warning(
                    "Safe Browsing returned an unexpected response format."
                )
                return _result(
                    status="unavailable",
                    checked_count=checked_count,
                    threats=[],
                    message=(
                        "URL reputation checking could not be completed."
                    ),
                )

        except httpx.HTTPStatusError as exc:
            status_code = exc.response.status_code

            # Do not log the request URL because it contains the API key.
            try:
                error_data = exc.response.json()
                error_info = (
                    error_data.get("error", {})
                    if isinstance(error_data, dict)
                    else {}
                )
                error_status = error_info.get("status", "UNKNOWN")
            except ValueError:
                error_status = "UNKNOWN"

            logger.warning(
                "Safe Browsing API returned HTTP %s; status=%s.",
                status_code,
                error_status,
            )

            return _result(
                status="unavailable",
                checked_count=checked_count,
                threats=[],
                message=(
                    "URL reputation checking could not be completed."
                ),
            )

        except (httpx.HTTPError, ValueError) as exc:
            # Log the exception type, not the request URL or API key.
            logger.warning(
                "Safe Browsing request failed (%s).",
                type(exc).__name__,
            )

            return _result(
                status="unavailable",
                checked_count=checked_count,
                threats=[],
                message=(
                    "URL reputation checking could not be completed."
                ),
            )

        checked_count += len(batch)

        matches = data.get("matches", [])

        if not isinstance(matches, list):
            logger.warning(
                "Safe Browsing returned an unexpected matches field."
            )
            return _result(
                status="unavailable",
                checked_count=checked_count,
                threats=[],
                message=(
                    "URL reputation checking could not be completed."
                ),
            )

        for match in matches:
            if not isinstance(match, dict):
                continue

            threat = match.get("threat", {})

            if not isinstance(threat, dict):
                threat = {}

            threats.append(
                {
                    "url": threat.get("url", ""),
                    "threat_type": match.get(
                        "threatType", "UNKNOWN"
                    ),
                    "platform_type": match.get(
                        "platformType", "UNKNOWN"
                    ),
                }
            )

    if threats:
        return _result(
            status="unsafe",
            checked_count=checked_count,
            threats=threats,
            message=(
                "Google Safe Browsing reported one or more known threats."
            ),
        )

    return _result(
        status="no_known_threat",
        checked_count=checked_count,
        threats=[],
        message=(
            "No known threat was reported. This does not guarantee "
            "that the URLs are safe."
        ),
    )
