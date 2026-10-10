"""Main FastAPI application for LLM-Guard."""

from time import perf_counter
from typing import Any
from uuid import uuid4

from fastapi import FastAPI, Request
from pydantic import BaseModel

from app.config import settings
from app.logger import log_event
from app.proxy import forward_prompt


app = FastAPI(
    title="LLM-Guard",
    description="Generative AI Prompt Firewall",
    version="0.3.0",
)


class ProxyRequest(BaseModel):
    """Request body for the proxy endpoint."""

    prompt: str


@app.middleware("http")
async def log_requests(request: Request, call_next: Any) -> Any:
    """Attach a unique ID to each request and log its outcome."""
    request_id = str(uuid4())
    request.state.request_id = request_id
    start_time = perf_counter()
    status_code = 500

    try:
        response = await call_next(request)
        status_code = response.status_code
        response.headers["X-Request-ID"] = request_id
        return response
    finally:
        duration_ms = round((perf_counter() - start_time) * 1000, 2)

        if settings.enable_request_logging:
            log_event(
                "http_request",
                request_id=request_id,
                method=request.method,
                path=request.url.path,
                status_code=status_code,
                duration_ms=duration_ms,
            )


@app.get("/health")
def health_check() -> dict[str, str]:
    """Return the current health status of the gateway."""
    return {
        "status": "ok",
        "service": "llm-guard",
        "version": "0.3.0",
    }


@app.post("/proxy")
def proxy_prompt(request: ProxyRequest) -> dict[str, Any]:
    """Forward a prompt to the mock LLM backend."""
    return forward_prompt(request.prompt)
