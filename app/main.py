"""Main FastAPI application for LLM-Guard."""

import os
from html import escape
from time import perf_counter
from typing import Any
from uuid import uuid4

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

from app.config import settings
from app.dlp.detectors import (
    inspect_sensitive_data,
    redact_sensitive_data,
)
from app.firewall.ml import classify_prompt, is_suspicious
from app.firewall.rules import inspect_prompt
from app.firewall.scoring import calculate_hybrid_risk
from app.logger import get_events, log_event
from app.output_guard import inspect_output, redact_output
from app.proxy import forward_prompt
from app.rate_limit import check_rate_limit
from app.security import API_KEY_HEADER, get_configured_api_key, is_valid_api_key
from app.self_check import run_security_checks


app = FastAPI(
    title="LLM-Guard",
    description="Generative AI Prompt Firewall",
    version="0.3.0",
)

PROTECTED_PATHS = {
    "/proxy",
    "/events",
    "/dashboard",
    "/security-check",
}


class ProxyRequest(BaseModel):
    """Request body for the proxy endpoint."""

    prompt: str


@app.middleware("http")
async def security_and_logging_middleware(
    request: Request,
    call_next: Any,
) -> Any:
    """Assign request IDs, enforce authentication and rate limits, and log results."""
    request_id = str(uuid4())
    request.state.request_id = request_id
    start_time = perf_counter()
    status_code = 500

    try:
        path = request.url.path

        # Require an API key for protected endpoints.
        if path in PROTECTED_PATHS:
            if get_configured_api_key() is None:
                response = JSONResponse(
                    status_code=503,
                    content={
                        "detail": (
                            "API authentication is not configured. "
                            "Set LLM_GUARD_API_KEY."
                        )
                    },
                )
                status_code = response.status_code
                response.headers["X-Request-ID"] = request_id
                return response

            if not is_valid_api_key(request.headers.get(API_KEY_HEADER)):
                log_event(
                    "authentication_failed",
                    request_id=request_id,
                    path=path,
                    reason="missing_or_invalid_key",
                )
                response = JSONResponse(
                    status_code=401,
                    content={"detail": "Missing or invalid API key."},
                    headers={"WWW-Authenticate": API_KEY_HEADER},
                )
                status_code = response.status_code
                response.headers["X-Request-ID"] = request_id
                return response

        # Apply rate limiting to proxy requests after authentication.
        if path == "/proxy" and request.method == "POST":
            client_host = request.client.host if request.client else "unknown"

            try:
                limit = int(os.getenv("LLM_GUARD_RATE_LIMIT", "60"))
                window = int(os.getenv("LLM_GUARD_RATE_WINDOW_SECONDS", "60"))
            except ValueError:
                limit, window = 60, 60

            # Invalid settings fall back to safe, positive defaults.
            if limit < 1 or window < 1:
                limit, window = 60, 60

            if not check_rate_limit(
                client_key=client_host,
                limit=limit,
                window_seconds=window,
            ):
                log_event(
                    "rate_limit_exceeded",
                    request_id=request_id,
                    client=client_host,
                    limit=limit,
                    window_seconds=window,
                )
                response = JSONResponse(
                    status_code=429,
                    content={"detail": "Too many requests. Please try again later."},
                    headers={"Retry-After": str(window)},
                )
                status_code = response.status_code
                response.headers["X-Request-ID"] = request_id
                return response

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
def proxy_prompt(
    payload: ProxyRequest,
    http_request: Request,
) -> dict[str, Any]:
    """Inspect prompts using rules, ML, hybrid scoring, and DLP."""
    request_id = http_request.state.request_id
    threshold = settings.risk_threshold

    # Stage 1: inspect the prompt using deterministic security rules.
    matches = inspect_prompt(payload.prompt)

    # Stage 2: obtain the ML model's estimated injection probability.
    ml_result = classify_prompt(payload.prompt)
    ml_probability = float(ml_result["malicious_probability"])

    # Stage 3: combine rule findings and the ML probability.
    risk = calculate_hybrid_risk(matches, ml_probability)
    risk_score = float(risk["risk_score"])

    log_event(
        "hybrid_risk_assessed",
        request_id=request_id,
        risk_score=risk["risk_score"],
        risk_level=risk["risk_level"],
        rule_finding_count=risk["rule_finding_count"],
        ml_probability=risk["ml_probability"],
        threshold=threshold,
    )

    # Preserve the existing deterministic rule-based blocking behavior.
    if matches:
        log_event(
            "prompt_blocked",
            request_id=request_id,
            matched_rules=matches,
            risk_assessment=risk,
        )
        raise HTTPException(
            status_code=403,
            detail={
                "error": "Prompt blocked by LLM-Guard",
                "matched_rules": matches,
                "risk_assessment": risk,
            },
        )

    # Stage 4: enforce the ML check and hybrid risk threshold.
    ml_flagged = is_suspicious(payload.prompt, threshold)

    if ml_flagged or risk_score >= threshold:
        if ml_flagged:
            error_message = "Prompt blocked by ML classifier"
            event_name = "ml_prompt_blocked"
        else:
            error_message = "Prompt blocked by hybrid risk score"
            event_name = "hybrid_risk_blocked"

        log_event(
            event_name,
            request_id=request_id,
            predicted_label=ml_result["label"],
            malicious_probability=ml_probability,
            threshold=threshold,
            risk_assessment=risk,
        )
        raise HTTPException(
            status_code=403,
            detail={
                "error": error_message,
                "classification": ml_result,
                "threshold": threshold,
                "risk_assessment": risk,
            },
        )

    # Stage 5: detect sensitive data in the incoming prompt.
    input_findings = inspect_sensitive_data(payload.prompt)
    prompt_to_forward = payload.prompt

    if input_findings:
        log_event(
            "dlp_detected",
            request_id=request_id,
            direction="input",
            mode=settings.mode,
            findings=input_findings,
            risk_assessment=risk,
        )

        if settings.mode == "block":
            raise HTTPException(
                status_code=403,
                detail={
                    "error": "Prompt blocked by DLP",
                    "findings": input_findings,
                },
            )

        if settings.mode == "redact":
            prompt_to_forward = redact_sensitive_data(payload.prompt)

    # Stage 6: forward accepted input to the development mock LLM.
    result = forward_prompt(prompt_to_forward)
    response_text = result.get("response")

    # Stage 7: inspect the response before returning it to the client.
    if isinstance(response_text, str):
        output_findings = inspect_output(response_text)

        if output_findings:
            log_event(
                "output_guard_detected",
                request_id=request_id,
                mode=settings.mode,
                findings=output_findings,
                risk_assessment=risk,
            )

            if settings.mode == "block":
                raise HTTPException(
                    status_code=502,
                    detail={
                        "error": "LLM response blocked by output guard",
                        "findings": output_findings,
                    },
                )

            if settings.mode == "redact":
                result["response"] = redact_output(response_text)

    # Keep the existing successful response structure unchanged.
    return result


@app.get("/events")
def read_events(
    limit: int = Query(default=100, ge=1, le=1000),
) -> dict[str, Any]:
    """Return recent audit events, newest first."""
    events = get_events(limit=limit)
    return {"count": len(events), "events": events}


@app.get("/security-check")
def security_check() -> dict[str, Any]:
    """Report security configuration without exposing secret values."""
    return run_security_checks()


@app.get("/dashboard", response_class=HTMLResponse)
def dashboard() -> HTMLResponse:
    """Serve a small browser-based audit dashboard."""
    page = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>LLM-Guard Security Dashboard</title>
<style>
body { font-family: system-ui, sans-serif; max-width: 1050px; margin: 2rem auto; padding: 0 1rem; }
input, button { padding: .65rem; margin: .25rem 0; }
input[type=password] { width: min(25rem, 90%); }
table { border-collapse: collapse; width: 100%; margin-top: 1rem; }
th, td { text-align: left; padding: .55rem; border-bottom: 1px solid #ddd; overflow-wrap: anywhere; }
small { color: #555; }
</style>
</head>
<body>
<h1>LLM-Guard Security Dashboard</h1>
<p>Enter your API key to load recent audit events. The key is not saved by this page.</p>
<label for="apiKey">API key</label><br>
<input id="apiKey" type="password" autocomplete="off" placeholder="X-API-Key">
<button id="loadButton" type="button">Load events</button>
<p id="status" role="status">Waiting for authentication.</p>
<table>
<thead><tr><th>Time</th><th>Event</th><th>Path</th><th>Status</th><th>Risk</th></tr></thead>
<tbody id="events"></tbody>
</table>
<script>
const button = document.getElementById("loadButton");
button.addEventListener("click", async () => {
  const key = document.getElementById("apiKey").value;
  const status = document.getElementById("status");
  const body = document.getElementById("events");
  body.replaceChildren();
  status.textContent = "Loading events...";
  try {
    const response = await fetch("/events?limit=100", {
      headers: { "X-API-Key": key }
    });
    if (!response.ok) {
      status.textContent = "Request failed: HTTP " + response.status;
      return;
    }
    const data = await response.json();
    for (const event of data.events) {
      const row = document.createElement("tr");
      const values = [
        event.timestamp || "",
        event.event || "",
        event.path || "",
        event.status_code ?? "",
        event.risk_level || ""
      ];
      for (const value of values) {
        const cell = document.createElement("td");
        cell.textContent = String(value);
        row.appendChild(cell);
      }
      body.appendChild(row);
    }
    status.textContent = "Loaded " + data.count + " events.";
  } catch (_) {
    status.textContent = "Could not load events. Check the server connection.";
  }
});
</script>
</body>
</html>"""
    return HTMLResponse(content=page)
