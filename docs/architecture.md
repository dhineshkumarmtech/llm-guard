# LLM-Guard Architecture

## 1. Overview

LLM-Guard is a Generative AI Prompt Firewall. It is a security gateway that sits between a user and a Large Language Model (LLM).

Its purpose is to inspect prompts before they reach the model and inspect model responses before they reach the user.

The current project uses a mock LLM for development and testing. It does not require a paid AI API.

## 2. Request Flow

1. A client sends a prompt to `POST /proxy`.
2. FastAPI middleware assigns a unique request ID and logs the HTTP request.
3. The input firewall checks for known prompt-injection and jailbreak patterns.
4. The DLP module checks for supported email, phone-number, and API-key patterns.
5. Depending on the configured mode, the prompt is allowed, redacted, or blocked.
6. The proxy forwards an accepted prompt to the mock LLM.
7. The output guard inspects the response for sensitive data and common system-prompt disclosure phrases.
8. The response is returned, redacted, or blocked according to the configured mode.

## 3. Main Components

### `app/main.py`

Defines the FastAPI application, `/health`, `/proxy`, request-ID middleware, and the order in which security checks run.

### `app/config.py`

Defines runtime settings:

- `allow`: pass detected sensitive data without modifying it.
- `redact`: replace detected sensitive values with placeholders.
- `block`: reject detected sensitive data.

### `app/firewall/rules.py`

Contains regular-expression rules for known prompt-injection, jailbreak, and system-prompt extraction phrases.

### `app/dlp/detectors.py`

Detects supported email addresses, phone-number-like strings, and selected API-key formats. It can replace detected values with placeholders.

### `app/output_guard.py`

Inspects mock LLM output for sensitive data and common phrases that may indicate system-prompt disclosure.

### `app/proxy.py` and `app/mock_llm.py`

Forward prompts to a predictable mock model during development and testing.

### `app/logger.py`

Writes structured JSON events, including request metadata and security detections.

### `tests/`

Contains automated tests for configuration, logging, endpoints, firewall rules, DLP, and output inspection.

## 4. API Endpoints

### Health check

`GET /health`

Returns the service status and version.

### Prompt proxy

`POST /proxy`

Accepts JSON such as:

```json
{
  "prompt": "Explain how a firewall works."
}
```

A normal prompt should return a mock LLM response. A prompt that matches a blocking security rule may receive HTTP 403. An unsafe mock LLM response may receive HTTP 502 when the output guard blocks it.

## 5. Security Modes

| Mode | Input handling | Output handling |
|---|---|---|
| `allow` | Preserve detected sensitive data | Preserve detected sensitive data |
| `redact` | Replace detected values | Redact sensitive values or mask suspected prompt disclosure |
| `block` | Reject sensitive input | Reject responses with detected findings |

The independent prompt-injection firewall continues to block matched prompts.

## 6. Limitations

- The detectors use rules and regular expressions, not a comprehensive security model.
- Phone-number detection may produce false positives.
- API-key detection covers selected formats, not every secret type.
- System-prompt disclosure detection uses phrases and cannot reliably identify every leak.
- The mock LLM is for testing, not production AI inference.
- This project is a prototype and requires additional testing before production use.

## 7. Running the Project

Activate the virtual environment and start the server:

```bash
source venv/bin/activate
python -m uvicorn app.main:app --reload
```

Open the API documentation at `http://127.0.0.1:8000/docs`.

Run the automated tests:

```bash
python -m pytest -v
```
