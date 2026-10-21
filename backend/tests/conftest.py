import pytest

try:
    from backend.app import ai_analyzer
except ImportError:  # pragma: no cover - tests importing "app.*" directly
    ai_analyzer = None


@pytest.fixture(autouse=True)
def _fresh_ai_cache():
    """Model output is cached in memory; every test starts with an empty cache."""
    if ai_analyzer is not None:
        ai_analyzer.clear_ai_cache()
    yield
    if ai_analyzer is not None:
        ai_analyzer.clear_ai_cache()
