"""Honest runtime status of the optional services.

Reports what is configured and reachable right now. It never claims a service
works unless it actually answered.
"""

from typing import Any

import httpx

from . import ai_analyzer
from . import safe_browsing


def system_status(timeout: float = 2.0) -> dict[str, Any]:
    ai: dict[str, Any] = {
        "enabled": ai_analyzer.ai_enabled(),
        "model": ai_analyzer.OLLAMA_MODEL,
        "reachable": None,
        "model_loaded": None,
    }

    if ai["enabled"]:
        try:
            response = httpx.get(f"{ai_analyzer.OLLAMA_BASE_URL}/api/tags", timeout=timeout)
            response.raise_for_status()
            names = [item.get("name", "") for item in response.json().get("models", [])]
            ai["reachable"] = True
            ai["model_loaded"] = any(
                name == ai_analyzer.OLLAMA_MODEL or name.startswith(ai_analyzer.OLLAMA_MODEL + ":")
                for name in names
            )
        except (httpx.HTTPError, ValueError, AttributeError):
            ai["reachable"] = False

    return {
        "ai": ai,
        # Only says whether a key is configured; the key itself is never exposed.
        "url_reputation": {"configured": bool(safe_browsing.API_KEY)},
    }
