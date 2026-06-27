# sentinel_ai/router.py
# Model routing engine for Sentinel AI.
# Integrates with cascadeflow to route queries only to approved, compliant models.
# Handles escalation when the primary model cannot produce a quality response.

import logging
import time
from typing import Any, Dict, Optional

from sentinel_ai.redact import redact_text

logger = logging.getLogger("sentinel_ai.router")


def _route_via_cascadeflow(query: str, approved_models: list, policy: Dict[str, Any]) -> Dict[str, Any]:
    """Route a query through cascadeflow using only approved models.

    Args:
        query: The (possibly redacted) query text.
        approved_models: List of model identifiers approved by the policy.
        policy: The full policy dict.

    Returns:
        Dict with response, model_used, cost, latency_ms, and escalated flag.
    """
    start_time = time.time()

    try:
        from cascadeflow import CascadeFlow

        cascade = CascadeFlow()

        response = cascade.generate(
            prompt=query,
            models=approved_models,
        )

        latency_ms = round((time.time() - start_time) * 1000, 2)

        if response and hasattr(response, "text"):
            model_used = getattr(response, "model", approved_models[0]) if hasattr(response, "model") else approved_models[0]
            cost = getattr(response, "cost", 0.0) if hasattr(response, "cost") else 0.0

            return {
                "response": response.text,
                "model_used": str(model_used),
                "cost": float(cost) if cost else 0.0,
                "latency_ms": latency_ms,
                "escalated": False,
            }

        # If primary model returned empty, try escalation to fallback
        if len(approved_models) > 1:
            logger.info(f"Primary model returned empty. Escalating to {approved_models[1]}.")
            response = cascade.generate(
                prompt=query,
                models=[approved_models[1]],
            )
            latency_ms = round((time.time() - start_time) * 1000, 2)

            if response and hasattr(response, "text"):
                return {
                    "response": response.text,
                    "model_used": approved_models[1],
                    "cost": getattr(response, "cost", 0.0) if hasattr(response, "cost") else 0.0,
                    "latency_ms": latency_ms,
                    "escalated": True,
                }

        latency_ms = round((time.time() - start_time) * 1000, 2)
        return {
            "response": "[Sentinel AI] Approved models did not return a response. Please try again.",
            "model_used": "none",
            "cost": 0.0,
            "latency_ms": latency_ms,
            "escalated": True,
        }

    except ImportError:
        latency_ms = round((time.time() - start_time) * 1000, 2)
        logger.warning("cascadeflow is not installed. Returning simulated response.")
        return {
            "response": (
                "[Sentinel AI — Simulated] cascadeflow is not available. "
                "In production, this query would be routed to an approved model. "
                f"Approved models: {', '.join(approved_models)}."
            ),
            "model_used": f"{approved_models[0]}" if approved_models else "none",
            "cost": 0.0,
            "latency_ms": latency_ms,
            "escalated": False,
        }

    except Exception as e:
        latency_ms = round((time.time() - start_time) * 1000, 2)
        logger.error(f"cascadeflow routing failed: {e}")
        return {
            "response": f"[Sentinel AI] Routing error: {str(e)}. Query was not sent to any model.",
            "model_used": "none",
            "cost": 0.0,
            "latency_ms": latency_ms,
            "escalated": False,
        }


def route(query: str, decision: Dict[str, Any], policy: Dict[str, Any]) -> Dict[str, Any]:
    """Route a query based on the compliance gate decision.

    - BLOCK: Returns a block notice without calling any model.
    - REDACT: Applies redactions first, then routes to an approved model.
    - ALLOW: Routes directly to the cheapest approved model, with escalation.

    Args:
        query: The original query text.
        decision: The gate decision dict from evaluate().
        policy: The loaded compliance policy dict.

    Returns:
        Dict with keys: response, model_used, cost, latency_ms, escalated.
    """
    decision_type = decision.get("decision", "BLOCK")
    approved_models = policy.get("approved_models", [])

    # ── BLOCK: Do not route ──
    if decision_type == "BLOCK":
        reason = decision.get("reason", "Query blocked by compliance policy.")
        logger.warning(f"Query BLOCKED: {reason}")
        return {
            "response": (
                f"[Sentinel AI — BLOCKED] Your query has been blocked by the "
                f"{policy.get('agent_name', 'Prime')} compliance gate. "
                f"Reason: {reason}"
            ),
            "model_used": "none",
            "cost": 0.0,
            "latency_ms": 0.0,
            "escalated": False,
        }

    # ── REDACT: Apply redactions, then route ──
    if decision_type == "REDACT":
        redactions = decision.get("redactions", [])
        placeholder = policy.get("redaction_placeholder", "[REDACTED-{TYPE}]")
        redacted_query = redact_text(query, redactions, placeholder)
        logger.info(f"Query redacted ({len(redactions)} entities). Routing to approved model.")

        result = _route_via_cascadeflow(redacted_query, approved_models, policy)
        result["redacted"] = True
        result["redaction_count"] = len(redactions)
        return result

    # ── ALLOW: Route directly ──
    if decision_type == "ALLOW":
        logger.info("Query allowed. Routing to approved model.")
        result = _route_via_cascadeflow(query, approved_models, policy)
        result["redacted"] = False
        result["redaction_count"] = 0
        return result

    # Fallback: unknown decision type, treat as BLOCK
    logger.error(f"Unknown decision type '{decision_type}'. Blocking for safety.")
    return {
        "response": "[Sentinel AI] Unknown compliance decision. Query blocked for safety.",
        "model_used": "none",
        "cost": 0.0,
        "latency_ms": 0.0,
        "escalated": False,
    }
