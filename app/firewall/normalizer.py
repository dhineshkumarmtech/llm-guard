"""Normalize prompt text for security analysis."""

import re
import unicodedata


def normalize_prompt(text: str) -> str:
    """Normalize Unicode, lowercase text, and collapse repeated whitespace."""
    text = unicodedata.normalize("NFKC", text)
    text = text.casefold()
    text = re.sub(r"\s+", " ", text)
    return text.strip()
