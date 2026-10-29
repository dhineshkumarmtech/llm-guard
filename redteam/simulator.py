"""Run controlled red-team cases against the local LLM-Guard API."""

import argparse
import json
import os
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_PAYLOADS = PROJECT_ROOT / "redteam" / "payloads.json"


def load_payloads(path: Path) -> list[dict]:
    """Load and validate test cases from JSON."""
    with path.open("r", encoding="utf-8") as file:
        payloads = json.load(file)

    if not isinstance(payloads, list):
        raise ValueError("Payload file must contain a JSON list.")

    required = {"id", "category", "prompt", "expected_blocked"}

    for case in payloads:
        if not isinstance(case, dict) or not required.issubset(case):
            raise ValueError("A test case is missing required fields.")
        if not isinstance(case["prompt"], str):
            raise ValueError("Each prompt must be a string.")
        if not isinstance(case["expected_blocked"], bool):
            raise ValueError("expected_blocked must be true or false.")

    return payloads


def run_case(
    base_url: str,
    case: dict,
    timeout: float = 5.0,
    api_key: str | None = None,
) -> dict:
    """Send one test prompt and record the HTTP result."""
    request = Request(
        f"{base_url.rstrip('/')}/proxy",
        data=json.dumps({"prompt": case["prompt"]}).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            **({"X-API-Key": api_key} if api_key else {}),
        },
        method="POST",
    )

    status_code = None
    error = None

    try:
        with urlopen(request, timeout=timeout) as response:
            status_code = response.status
    except HTTPError as exc:
        status_code = exc.code
    except (URLError, TimeoutError, OSError) as exc:
        error = str(exc)

    blocked = status_code == 403

    return {
        "id": case["id"],
        "category": case["category"],
        "expected_blocked": case["expected_blocked"],
        "blocked": blocked,
        "status_code": status_code,
        "passed": error is None and blocked == case["expected_blocked"],
        "error": error,
    }


def calculate_metrics(results: list[dict]) -> dict:
    """Calculate basic attack-detection and false-positive metrics."""
    tp = sum(r["expected_blocked"] and r["blocked"] for r in results)
    fn = sum(r["expected_blocked"] and not r["blocked"] for r in results)
    fp = sum(not r["expected_blocked"] and r["blocked"] for r in results)
    tn = sum(not r["expected_blocked"] and not r["blocked"] for r in results)

    return {
        "total": len(results),
        "passed": sum(r["passed"] for r in results),
        "true_positives": tp,
        "false_negatives": fn,
        "false_positives": fp,
        "true_negatives": tn,
        "detection_rate_percent": round(100 * tp / (tp + fn), 2)
        if tp + fn else 0.0,
        "false_positive_rate_percent": round(100 * fp / (fp + tn), 2)
        if fp + tn else 0.0,
    }


def main() -> None:
    """Run all test cases and print a summary."""
    parser = argparse.ArgumentParser(
        description="Test the local LLM-Guard proxy."
    )
    parser.add_argument(
        "--url",
        default="http://127.0.0.1:8000",
        help="Base URL of the running LLM-Guard API.",
    )
    parser.add_argument(
        "--payloads",
        type=Path,
        default=DEFAULT_PAYLOADS,
        help="Path to the JSON test cases.",
    )
    parser.add_argument(
        "--api-key",
        default=os.getenv("LLM_GUARD_API_KEY"),
        help="API key; defaults to LLM_GUARD_API_KEY environment variable.",
    )
    args = parser.parse_args()

    try:
        payloads = load_payloads(args.payloads)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        parser.error(f"Could not load payloads: {exc}")

    results = []
    print("\nLLM-Guard Red-Team Simulator")
    print(f"Target: {args.url}")
    print("-" * 65)

    for case in payloads:
        result = run_case(args.url, case, api_key=args.api_key)
        results.append(result)

        if result["error"]:
            outcome = f"ERROR: {result['error']}"
        else:
            label = "BLOCKED" if result["blocked"] else "ALLOWED"
            outcome = f"HTTP {result['status_code']} | {label}"

        marker = "PASS" if result["passed"] else "FAIL"
        print(f"{marker} | {case['id']} | {outcome}")

    metrics = calculate_metrics(results)

    print("\nSummary")
    print("-" * 65)
    print(f"Cases:                 {metrics['total']}")
    print(f"Expected behavior met: {metrics['passed']}/{metrics['total']}")
    print(f"True positives:        {metrics['true_positives']}")
    print(f"False negatives:       {metrics['false_negatives']}")
    print(f"False positives:       {metrics['false_positives']}")
    print(f"True negatives:        {metrics['true_negatives']}")
    print(f"Attack detection rate: {metrics['detection_rate_percent']}%")
    print(f"False-positive rate:   {metrics['false_positive_rate_percent']}%")


if __name__ == "__main__":
    main()
