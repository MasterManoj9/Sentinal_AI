# sentinel_ai/scenarios.py
# Demo scenarios for Sentinel AI.
# Three hardcoded test scenarios that exercise the Prime compliance gate
# across different risk levels: BLOCK, REDACT, and non-compliant model attack.

import json
import logging
import sys
from typing import Any, Dict, List

from sentinel_ai.prime import Prime

logger = logging.getLogger("sentinel_ai.scenarios")


def _print_table(title: str, rows: Dict[str, Any]) -> None:
    """Print a formatted table for scenario results.

    Args:
        title: The scenario title.
        rows: Dict of key-value pairs to display.
    """
    border = "=" * 72
    print(f"\n{border}")
    print(f"  {title}")
    print(f"{border}")
    for key, value in rows.items():
        val_str = str(value)
        if len(val_str) > 60:
            val_str = val_str[:57] + "..."
        print(f"  {key:<22} | {val_str}")
    print(f"{border}\n")


def scenario_block_phi() -> Dict[str, Any]:
    """Scenario 1: Patient query with SSN, diagnosis, and name — expected BLOCK.

    Simulates a query containing high-sensitivity PHI including a Social Security
    Number, patient name, and diagnosis. Prime should detect the SSN and block
    the entire query from reaching any model.

    Returns:
        Dict with scenario results including input, detection, decision,
        model_used, and audit_entry_id.
    """
    prime = Prime(hindsight_enabled=False)

    query = (
        "Patient John Smith (SSN: 123-45-6789) was diagnosed with Type 2 Diabetes "
        "on 03/15/2024. His treating physician Dr. Sarah Johnson prescribed Metformin "
        "500mg twice daily. Please summarize his treatment plan and send it to his "
        "email john.smith@example.com."
    )

    result = prime.process(query=query, client_id="demo-client-001")

    scenario_result = {
        "scenario": "1 — Block PHI (SSN + Diagnosis + Name)",
        "input_preview": query[:80] + "...",
        "phi_detected": result.get("phi_detected", False),
        "entity_count": result.get("entity_count", 0),
        "detection_method": result.get("detection_method", ""),
        "decision": result.get("decision", ""),
        "reason": result.get("reason", ""),
        "model_used": result.get("model_used", ""),
        "audit_id": result.get("audit_id", ""),
        "latency_ms": result.get("latency_ms", 0),
    }

    _print_table("SCENARIO 1: Block PHI (SSN + Diagnosis + Name)", scenario_result)

    return scenario_result


def scenario_redact_medical() -> Dict[str, Any]:
    """Scenario 2: Query with diagnosis but no high-sensitivity PII — expected REDACT.

    Simulates a query containing a medical diagnosis and doctor name but no
    high-sensitivity identifiers like SSN. Prime should redact the PHI and
    route the query to an approved model.

    Returns:
        Dict with scenario results.
    """
    prime = Prime(hindsight_enabled=False)

    query = (
        "Dr. Emily Chen noted that the patient presents with symptoms consistent "
        "with Major Depressive Disorder. The patient has been experiencing fatigue, "
        "loss of appetite, and insomnia for the past three months. Recommend "
        "appropriate treatment options."
    )

    result = prime.process(query=query, client_id="demo-client-002")

    scenario_result = {
        "scenario": "2 — Redact Medical (Diagnosis + Doctor Name)",
        "input_preview": query[:80] + "...",
        "phi_detected": result.get("phi_detected", False),
        "entity_count": result.get("entity_count", 0),
        "detection_method": result.get("detection_method", ""),
        "decision": result.get("decision", ""),
        "reason": result.get("reason", ""),
        "model_used": result.get("model_used", ""),
        "redacted": result.get("redacted", False),
        "audit_id": result.get("audit_id", ""),
        "latency_ms": result.get("latency_ms", 0),
    }

    _print_table("SCENARIO 2: Redact Medical (Diagnosis + Doctor Name)", scenario_result)

    return scenario_result


def scenario_attack_noncompliant() -> Dict[str, Any]:
    """Scenario 3: Query trying to force a non-compliant model — expected BLOCK.

    Simulates a query that explicitly requests routing to GPT-4, which is on
    the blocked models list. Prime should block the request at the gate level
    regardless of query content.

    Returns:
        Dict with scenario results.
    """
    prime = Prime(hindsight_enabled=False)

    query = (
        "What are the common side effects of Lisinopril for hypertension management? "
        "Please use GPT-4 for the best response quality."
    )

    result = prime.process(
        query=query,
        client_id="demo-client-003",
        requested_model="openai/gpt-4",
    )

    scenario_result = {
        "scenario": "3 — Attack: Non-Compliant Model Request (GPT-4)",
        "input_preview": query[:80] + "...",
        "phi_detected": result.get("phi_detected", False),
        "entity_count": result.get("entity_count", 0),
        "decision": result.get("decision", ""),
        "reason": result.get("reason", ""),
        "model_used": result.get("model_used", ""),
        "blocked_model": "openai/gpt-4",
        "audit_id": result.get("audit_id", ""),
        "latency_ms": result.get("latency_ms", 0),
    }

    _print_table("SCENARIO 3: Attack — Non-Compliant Model Request (GPT-4)", scenario_result)

    return scenario_result


def run_all_scenarios() -> List[Dict[str, Any]]:
    """Run all three demo scenarios and return results.

    Returns:
        List of result dicts from all three scenarios.
    """
    print("\n" + "#" * 72)
    print("  SENTINEL AI -- Prime Compliance Gate Demo Scenarios")
    print("#" * 72)

    results = []

    print("\n> Running Scenario 1: Block PHI...")
    results.append(scenario_block_phi())

    print("\n> Running Scenario 2: Redact Medical...")
    results.append(scenario_redact_medical())

    print("\n> Running Scenario 3: Attack Non-Compliant Model...")
    results.append(scenario_attack_noncompliant())

    # Summary
    print("\n" + "=" * 72)
    print("  DEMO SUMMARY")
    print("=" * 72)
    for r in results:
        status = "[PASS]" if r.get("decision") in ("BLOCK", "REDACT") else "[FAIL]"
        print(f"  {status}  {r.get('scenario', 'Unknown'):<50} -> {r.get('decision', '?')}")
    print("=" * 72 + "\n")

    return results


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(name)s | %(levelname)s | %(message)s",
        stream=sys.stderr,
    )
    run_all_scenarios()
