# tests/test_router.py
# Unit tests for the model routing engine.

import pytest
from sentinel_ai.router import route


def _make_policy() -> dict:
    """Helper to create a test policy dict.

    Returns:
        Policy dict matching hipaa.json structure.
    """
    return {
        "framework": "HIPAA",
        "approved_models": ["groq/openai-gpt-oss-120b", "ollama/llama3.1"],
        "blocked_models": ["openai/gpt-4", "anthropic/claude-3-opus"],
        "redaction_strategy": "mask",
        "redaction_placeholder": "[REDACTED-{TYPE}]",
        "agent_name": "Prime",
    }


class TestRouter:
    """Tests for the model routing engine."""

    def test_block_decision_returns_block_notice(self) -> None:
        """BLOCK decision should return a block notice without calling any model."""
        decision = {
            "decision": "BLOCK",
            "model_tier": "none",
            "reason": "Contains high-sensitivity PHI (SSN).",
        }
        result = route("test query", decision, _make_policy())
        assert result["model_used"] == "none"
        assert "BLOCKED" in result["response"]
        assert result["cost"] == 0.0

    def test_block_includes_reason(self) -> None:
        """Block notice should include the specific reason."""
        decision = {
            "decision": "BLOCK",
            "model_tier": "none",
            "reason": "SSN detected in query.",
        }
        result = route("test query", decision, _make_policy())
        assert "SSN detected" in result["response"]

    def test_allow_routes_to_model(self) -> None:
        """ALLOW decision should attempt to route to an approved model."""
        decision = {
            "decision": "ALLOW",
            "model_tier": "compliant",
            "reason": "No PHI detected.",
        }
        result = route("What is aspirin used for?", decision, _make_policy())
        # In test environment, cascadeflow may not be available,
        # so we check for a valid response structure
        assert "response" in result
        assert "model_used" in result
        assert "cost" in result
        assert "latency_ms" in result

    def test_redact_routes_after_redaction(self) -> None:
        """REDACT decision should apply redactions before routing."""
        decision = {
            "decision": "REDACT",
            "model_tier": "compliant",
            "reason": "Diagnosis detected, eligible for redaction.",
            "redactions": [
                {"type": "diagnosis", "value": "Type 2 Diabetes", "start": 25, "end": 40},
            ],
        }
        query = "The patient has been with Type 2 Diabetes for 5 years."
        result = route(query, decision, _make_policy())
        assert "response" in result
        assert result.get("redacted") is True
        assert result.get("redaction_count", 0) >= 1

    def test_unknown_decision_treated_as_block(self) -> None:
        """Unknown decision type should be treated as BLOCK for safety."""
        decision = {
            "decision": "UNKNOWN",
            "model_tier": "none",
            "reason": "Unknown decision.",
        }
        result = route("test query", decision, _make_policy())
        assert result["model_used"] == "none"
        assert "blocked" in result["response"].lower() or "Unknown" in result["response"]

    def test_allow_result_has_correct_shape(self) -> None:
        """ALLOW result should have all expected keys."""
        decision = {
            "decision": "ALLOW",
            "model_tier": "compliant",
            "reason": "Clean query.",
        }
        result = route("Hello", decision, _make_policy())
        expected_keys = {"response", "model_used", "cost", "latency_ms", "escalated"}
        assert expected_keys.issubset(set(result.keys()))
