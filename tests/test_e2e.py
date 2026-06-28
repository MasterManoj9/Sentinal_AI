# tests/test_e2e.py
# End-to-end tests for Sentinel AI.
# Runs all 3 demo scenarios and verifies the expected compliance decisions.

import pytest
from sentinel_ai.scenarios import (
    scenario_block_phi,
    scenario_redact_medical,
    scenario_attack_noncompliant,
)


class TestEndToEnd:
    """End-to-end tests running the full Prime compliance pipeline."""

    def test_scenario_1_block_phi(self) -> None:
        """Scenario 1: Patient query with SSN + diagnosis + name should be BLOCKED.

        A query containing a Social Security Number is high-sensitivity PHI
        that cannot be safely redacted. Prime must block it entirely.
        """
        result = scenario_block_phi()
        assert result["decision"] == "BLOCK", (
            f"Expected BLOCK for SSN-containing query, got {result['decision']}. "
            f"Reason: {result.get('reason', 'no reason')}"
        )
        assert result["phi_detected"] is True
        assert result["entity_count"] >= 1

    def test_scenario_2_redact_medical(self) -> None:
        """Scenario 2: Query with diagnosis but no high-sensitivity PII should be REDACTED.

        A query containing medical diagnosis and doctor name (but no SSN, MRN, etc.)
        should be redacted and then routed to an approved model.
        """
        result = scenario_redact_medical()
        assert result["decision"] == "REDACT", (
            f"Expected REDACT for diagnosis-only query, got {result['decision']}. "
            f"Reason: {result.get('reason', 'no reason')}"
        )
        # Verify model used is from the approved list
        approved_names = ["openai-gpt-oss-120b", "llama3.1"]
        model_used = result.get("model_used", "none")
        # cascadeflow may return combined model names (e.g., 'llama3.1+openai-gpt-oss-120b')
        # so we check if any approved model name appears within the returned name
        if model_used != "none":
            model_is_approved = any(name in model_used for name in approved_names)
            assert model_is_approved, (
                f"Model '{model_used}' does not contain any approved model name: {approved_names}"
            )

    def test_scenario_3_attack_noncompliant(self) -> None:
        """Scenario 3: Query requesting GPT-4 should be BLOCKED.

        A query explicitly requesting a non-compliant model (openai/gpt-4)
        must be blocked at the gate level with a reason mentioning the model.
        """
        result = scenario_attack_noncompliant()
        assert result["decision"] == "BLOCK", (
            f"Expected BLOCK for non-compliant model request, got {result['decision']}. "
            f"Reason: {result.get('reason', 'no reason')}"
        )
        # The reason should mention the non-compliant model
        reason = result.get("reason", "").lower()
        assert "gpt-4" in reason or "not approved" in reason or "blocked" in reason, (
            f"Block reason should mention the non-compliant model. Got: {result.get('reason', '')}"
        )

    def test_all_scenarios_produce_audit_ids(self) -> None:
        """All scenarios should produce valid audit trail entry IDs."""
        results = [
            scenario_block_phi(),
            scenario_redact_medical(),
            scenario_attack_noncompliant(),
        ]
        for i, result in enumerate(results):
            assert "audit_id" in result, f"Scenario {i+1} missing audit_id"
            assert len(result["audit_id"]) > 0, f"Scenario {i+1} has empty audit_id"
