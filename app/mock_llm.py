"""Mock LLM backend used for local development and testing."""

from typing import Any


def generate_response(prompt: str) -> dict[str, Any]:
    """Generate a predictable fake LLM response."""
    return {
        "model": "mock-llm-v1",
        "response": f"Mock LLM response to: {prompt}",
    }
