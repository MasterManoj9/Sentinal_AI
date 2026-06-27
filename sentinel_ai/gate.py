# sentinel_ai/gate.py
# Compliance gate for Sentinel AI.
# Evaluates PHI detection results against the loaded policy and
# historical recall from Hindsight to produce ALLOW / REDACT / BLOCK decisions.

import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger("sentinel_ai.gate")

# Entity types that trigger an automatic BLOCK (high-sensitivity identifiers)
BLOCK_TRIGGER_TYPES = {
    "ssn",
    "medical_record_number",
    "account_number",
    "biometric",
    "full_face_photo",
    "certificate_license",
    "device_id",
    "vehicle_id",
}

# Entity types that can be safely redacted and the query re-routed
REDACT_ELIGIBLE_TYPES = {
    "patient_name",
    "doctor_name",
    "diagnosis",
    "prescription",
    "dob",
    "phone",
    "email",
    "address",
    "ip_address",
    "url",
}


def evaluate(
    detection_result: Dict[str, Any],
    policy: Dict[str, Any],
    client_id: str,
    hindsight_recall: Optional[List[Dict[str, Any]]] = None,
    requested_model: Optional[str] = None,
) -> Dict[str, Any]:
    """Evaluate a query's detection results against the compliance policy.

    Combines regex + LLM detection results, cross-references with Hindsight
    recall history, and produces one of three decisions:
      - ALLOW: No PHI found, query can proceed.
      - REDACT: PHI found but can be safely masked; route to approved model.
      - BLOCK: High-sensitivity PHI found or non-compliant model requested.

    Args:
        detection_result: Output from detect_phi().
        policy: The loaded compliance policy dict.
        client_id: Identifier for the requesting client.
        hindsight_recall: Past decisions recalled from Hindsight memory.
        requested_model: Model explicitly requested by the client (if any).

    Returns:
        Dict with keys: decision, model_tier, reason, and optionally
        redactions, blocked_entity, escalated_from_recall.
    """
    if hindsight_recall is None:
        hindsight_recall = []

    entities = detection_result.get("entities", [])
    phi_detected = detection_result.get("phi_detected", False)
    confidence = detection_result.get("confidence", 0.0)
    approved_models = policy.get("approved_models", [])
    blocked_models = policy.get("blocked_models", [])

    # ── Check 1: Non-compliant model explicitly requested ──
    if requested_model and requested_model in blocked_models:
        logger.warning(
            f"Client '{client_id}' requested blocked model '{requested_model}'."
        )
        return {
            "decision": "BLOCK",
            "model_tier": "none",
            "reason": (
                f"Requested model '{requested_model}' is not approved under "
                f"{policy.get('framework', 'HIPAA')} compliance policy. "
                f"Approved models: {', '.join(approved_models)}."
            ),
            "blocked_model": requested_model,
        }

    # ── Check 2: No PHI detected → ALLOW ──
    if not phi_detected or not entities:
        logger.info(f"No PHI detected for client '{client_id}'. Decision: ALLOW.")
        return {
            "decision": "ALLOW",
            "model_tier": "compliant",
            "reason": "No protected health information detected in the query.",
        }

    # ── Check 3: Categorize detected entities ──
    entity_types = {e.get("type", "unknown").lower() for e in entities}
    block_triggers = entity_types & BLOCK_TRIGGER_TYPES
    redact_eligible = entity_types & REDACT_ELIGIBLE_TYPES
    unknown_types = entity_types - BLOCK_TRIGGER_TYPES - REDACT_ELIGIBLE_TYPES

    # ── Check 4: Cross-reference with Hindsight recall ──
    escalated = False
    if hindsight_recall:
        for past_decision in hindsight_recall:
            past_action = past_decision.get("decision", "")
            past_client = past_decision.get("client_id", "")
            if past_client == client_id and past_action == "BLOCK":
                # This client has been blocked before — escalate severity
                escalated = True
                logger.info(
                    f"Client '{client_id}' has prior BLOCK history. Escalating."
                )
                break

    # ── Decision logic ──

    # High-sensitivity entities or repeat offender → BLOCK
    if block_triggers or (escalated and confidence > 0.6):
        trigger_list = list(block_triggers) if block_triggers else list(entity_types)
        first_trigger = trigger_list[0] if trigger_list else "unknown"
        trigger_entity = next(
            (e for e in entities if e.get("type", "").lower() == first_trigger),
            entities[0],
        )
        reason_parts = [
            f"Query contains high-sensitivity PHI ({', '.join(trigger_list)}).",
        ]
        if escalated:
            reason_parts.append(
                f"Client '{client_id}' has prior compliance violations."
            )
        reason_parts.append(
            f"Blocked entity type: {first_trigger}. "
            f"Value preview: '{trigger_entity.get('value', '?')[:8]}...'."
        )
        return {
            "decision": "BLOCK",
            "model_tier": "none",
            "reason": " ".join(reason_parts),
            "blocked_entity": first_trigger,
            "entity_count": len(entities),
            "escalated_from_recall": escalated,
        }

    # Redactable entities only → REDACT then ALLOW
    if redact_eligible or unknown_types:
        redaction_list = [
            {
                "type": e.get("type", "unknown"),
                "value": e.get("value", ""),
                "start": e.get("start", 0),
                "end": e.get("end", 0),
            }
            for e in entities
        ]
        return {
            "decision": "REDACT",
            "model_tier": "compliant",
            "reason": (
                f"Query contains PHI ({', '.join(entity_types)}) eligible for redaction. "
                f"Applying {policy.get('redaction_strategy', 'mask')} strategy before routing "
                f"to approved model."
            ),
            "redactions": redaction_list,
            "entity_count": len(entities),
        }

    # Fallback: if we somehow get here, BLOCK for safety
    return {
        "decision": "BLOCK",
        "model_tier": "none",
        "reason": "Unable to classify detected PHI. Blocking as a precaution.",
        "entity_count": len(entities),
    }
