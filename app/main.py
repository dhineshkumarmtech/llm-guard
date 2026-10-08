
"""Main FastAPI application for LLM-Guard."""

from fastapi import FastAPI


app = FastAPI(
    title="LLM-Guard",
    description="Generative AI Prompt Firewall",
    version="0.1.0",
)


@app.get("/health")
def health_check() -> dict[str, str]:
    """Return the current health status of the gateway."""
    return {
        "status": "ok",
        "service": "llm-guard",
        "version": "0.1.0",
    }
