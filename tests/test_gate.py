# tests/test_gate.py
# Unit tests for the compliance gate evaluation logic.

import pytest
from sentinel_ai.gate import evaluate


def _make_detection(entities: list, phi_detected: bool = True, confidence: float = 0.9) -> dict:
    """Helper to create a detection result dict for testing.

    Args:
        entities: List of entity dicts.
        phi_detected: Whether PHI was detected.
        confidence: Overall confidence score.

    Returns:
        Detection result dict matching detect_phi() output format.
    """
    return {
        "entities": entities,
        "confidence": confidence,
        "method": "regex",
        "phi_detected": phi_detected,
        "entity_count": len(entities),
        "query_hash": "testhash123",
    }


def _make_policy() -> dict:
    """Helper to create a test policy dict.

    Returns:
        Policy dict matching hipaa.json structure.
    """
    return {
        "framework": "HIPAA",
        "approved_models": ["groq/openai-gpt-oss-120b", "ollama/llama3.1"],
        "blocked_models": ["openai/gpt-4", "anthropic/claude-3-opus", "openai/gpt-4o"],
        "redaction_strategy": "mask",
        "agent_name": "Prime",
    }


class TestGateEvaluation:
    """Tests for the compliance gate evaluate() function."""

    def test_allow_no_phi(self) -> None:
        """Query with no PHI should be ALLOWED."""
        detection = _make_detection([], phi_detected=False, confidence=0.0)
        result = evaluate(detection, _make_policy(), "client-001")
        assert result["decision"] == "ALLOW"
        assert result["model_tier"] == "compliant"

    def test_block_ssn(self) -> None:
        """Query with SSN should be BLOCKED (high-sensitivity)."""
        entities = [{"type": "ssn", "value": "123-45-6789", "start": 0, "end": 11}]
        detection = _make_detection(entities)
        result = evaluate(detection, _make_policy(), "client-001")
        assert result["decision"] == "BLOCK"
        assert result["model_tier"] == "none"

    def test_block_medical_record_number(self) -> None:
        """Query with MRN should be BLOCKED."""
        entities = [{"type": "medical_record_number", "value": "MRN: 12345678", "start": 0, "end": 14}]
        detection = _make_detection(entities)
        result = evaluate(detection, _make_policy(), "client-001")
        assert result["decision"] == "BLOCK"

    def test_redact_diagnosis(self) -> None:
        """Query with diagnosis (redact-eligible) should get REDACT decision."""
        entities = [{"type": "diagnosis", "value": "Type 2 Diabetes", "start": 0, "end": 15}]
        detection = _make_detection(entities)
        result = evaluate(detection, _make_policy(), "client-001")
        assert result["decision"] == "REDACT"
        assert result["model_tier"] == "compliant"
        assert "redactions" in result

    def test_redact_patient_name(self) -> None:
        """Query with patient name should get REDACT decision."""
        entities = [{"type": "patient_name", "value": "John Smith", "start": 0, "end": 10}]
        detection = _make_detection(entities)
        result = evaluate(detection, _make_policy(), "client-001")
        assert result["decision"] == "REDACT"

    def test_redact_email(self) -> None:
        """Query with email should get REDACT decision."""
        entities = [{"type": "email", "value": "test@example.com", "start": 0, "end": 16}]
        detection = _make_detection(entities)
        result = evaluate(detection, _make_policy(), "client-001")
        assert result["decision"] == "REDACT"

    def test_block_noncompliant_model(self) -> None:
        """Requesting a blocked model should result in BLOCK regardless of content."""
        detection = _make_detection([], phi_detected=False, confidence=0.0)
        result = evaluate(
            detection, _make_policy(), "client-001",
            requested_model="openai/gpt-4",
        )
        assert result["decision"] == "BLOCK"
        assert "openai/gpt-4" in result["reason"]

    def test_block_noncompliant_model_claude(self) -> None:
        """Requesting Claude 3 Opus should result in BLOCK."""
        detection = _make_detection([], phi_detected=False, confidence=0.0)
        result = evaluate(
            detection, _make_policy(), "client-001",
            requested_model="anthropic/claude-3-opus",
        )
        assert result["decision"] == "BLOCK"

    def test_escalation_from_recall(self) -> None:
        """Client with prior BLOCK history should face escalated enforcement."""
        entities = [{"type": "diagnosis", "value": "Depression", "start": 0, "end": 10}]
        detection = _make_detection(entities, confidence=0.8)
        recall = [{"decision": "BLOCK", "client_id": "client-repeat"}]
        result = evaluate(detection, _make_policy(), "client-repeat", hindsight_recall=recall)
        assert result["decision"] == "BLOCK"
        assert result.get("escalated_from_recall") is True

    def test_mixed_block_and_redact_entities(self) -> None:
        """Mix of block-trigger and redact-eligible entities should BLOCK."""
        entities = [
            {"type": "ssn", "value": "123-45-6789", "start": 0, "end": 11},
            {"type": "patient_name", "value": "Jane Doe", "start": 20, "end": 28},
        ]
        detection = _make_detection(entities)
        result = evaluate(detection, _make_policy(), "client-001")
        assert result["decision"] == "BLOCK"
