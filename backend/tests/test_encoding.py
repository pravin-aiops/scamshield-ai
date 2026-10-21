"""Guard against UTF-8 corruption (mojibake) in source files."""

from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
FILES = [
    *sorted((ROOT / "backend" / "app").glob("*.py")),
    ROOT / "frontend" / "src" / "App.tsx",
    ROOT / "frontend" / "src" / "App.css",
]

# What UTF-8 text looks like after being decoded as Windows-1252 / Latin-1.
BROKEN_SEQUENCES = [
    "à¥",  # Devanagari danda decoded wrongly
    "à¤",
    "â\u0080",
    "â˜",  # moon/sun symbols decoded wrongly
    "Ã¢",
    "Ã ",
    "�",        # replacement character
]


@pytest.mark.parametrize("path", [p for p in FILES if p.exists()], ids=lambda p: p.name)
def test_source_files_are_clean_utf8(path):
    text = path.read_text(encoding="utf-8")

    for sequence in BROKEN_SEQUENCES:
        assert sequence not in text, f"{path.name} contains corrupted text {sequence!r}"


def test_hindi_content_is_real_devanagari():
    content = (ROOT / "backend" / "app" / "content.py").read_text(encoding="utf-8")

    assert "ओटीपी" in content
    assert "धोखाधड़ी" in content or "स्कैम" in content
