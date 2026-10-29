"""Shared test configuration."""

import os

# This is a disposable test key, never a production secret.
os.environ.setdefault("LLM_GUARD_API_KEY", "test-only-llm-guard-key")
