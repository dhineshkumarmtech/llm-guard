"""Main FastAPI application for LLM-Guard."""

from time import perf_counter
from typing import Any
from uuid import uuid4

from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel

from app.config import settings
from app.dlp.detectors import (
    inspect_sensitive_data,
    redact_sensitive_data,
)
from app.firewall.ml import classify_prompt, is_suspicious
from app.firewall.rules import inspect_prompt
from app.firewall.scoring import calculate_hybrid_risk
from app.logger import log_event
from app.output_guard import inspect_output, redact_output
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
