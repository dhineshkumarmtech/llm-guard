"""Main FastAPI application for LLM-Guard."""

from typing import Any

from fastapi import FastAPI
from pydantic import BaseModel

from app.proxy import forward_prompt


app = FastAPI(
    title="LLM-Guard",
    description="Generative AI Prompt Firewall",
    version="0.2.0",
)


class ProxyRequest(BaseModel):
    """Request body for the proxy endpoint."""

    prompt: str


@app.get("/health")
def health_check() -> dict[str, str]:
    """Return the current health status of the gateway."""
    return {
        "status": "ok",
        "service": "llm-guard",
        "version": "0.2.0",
    }


@app.post("/proxy")
def proxy_prompt(request: ProxyRequest) -> dict[str, Any]:
    """Forward a prompt to the mock LLM backend."""
    return forward_prompt(request.prompt)
