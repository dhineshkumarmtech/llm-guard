"""Proxy logic for forwarding prompts to the mock LLM."""

from typing import Any

from app.mock_llm import generate_response


def forward_prompt(prompt: str) -> dict[str, Any]:
    """Forward a prompt to the mock LLM backend."""
    return generate_response(prompt)
