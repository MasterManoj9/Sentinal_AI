# sentinel_ai/router.py
# Model routing engine for Sentinel AI.
# Integrates with cascadeflow's CascadeAgent to route queries only to
# approved, compliant models. Handles escalation when the primary model
# cannot produce a quality response.

import asyncio
import logging
import os
import time
from typing import Any, Dict, List, Optional

from sentinel_ai.redact import redact_text

logger = logging.getLogger("sentinel_ai.router")

# Cached CascadeAgent instance
_cascade_agent: Optional[Any] = None


def _get_cascade_agent(approved_models: List[str], policy: Dict[str, Any]) -> Optional[Any]:
    """Initialize a CascadeAgent with only approved models from the policy.

    Uses cascadeflow's ModelConfig to set up each model with the correct
    provider and API key.

    Args:
        approved_models: List of approved model identifiers (e.g., 'groq/openai-gpt-oss-120b').
        policy: The full compliance policy dict.

    Returns:
        CascadeAgent instance, or None if cascadeflow is unavailable.
    """
    global _cascade_agent
    if _cascade_agent is not None:
        return _cascade_agent

    try:
        from cascadeflow import CascadeAgent, ModelConfig

        groq_api_key = os.getenv("GROQ_API_KEY", "")

        models = []
        for model_id in approved_models:
            parts = model_id.split("/", 1)
            provider = parts[0] if len(parts) > 1 else "groq"
            model_name = parts[1] if len(parts) > 1 else model_id

            model_config_kwargs: Dict[str, Any] = {
                "name": model_name,
                "provider": provider,
                "cost": 0.001 if provider == "groq" else 0.0,
                "max_tokens": 4096,
                "temperature": 0.7,
            }

            if provider == "groq" and groq_api_key:
                model_config_kwargs["api_key"] = groq_api_key
                model_config_kwargs["base_url"] = "https://api.groq.com/openai/v1"

            if provider == "ollama":
                model_config_kwargs["base_url"] = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434/v1")
                model_config_kwargs["api_key"] = "ollama"
                model_config_kwargs["cost"] = 0.0

            models.append(ModelConfig(**model_config_kwargs))

        agent = CascadeAgent(
            models=models,
            enable_cascade=True,
            verbose=False,
        )

        _cascade_agent = agent
        logger.info(f"CascadeAgent initialized with {len(models)} approved models.")
        return agent

    except ImportError:
        logger.warning("cascadeflow is not installed. Model routing will use simulated responses.")
        return None
    except Exception as e:
        logger.warning(f"CascadeAgent initialization failed: {e}. Using simulated responses.")
        return None


def _run_async(coro: Any) -> Any:
    """Run an async coroutine synchronously.

    Handles the case where there's already a running event loop.

    Args:
        coro: The coroutine to run.

    Returns:
        The result of the coroutine.
    """
    try:
        loop = asyncio.get_running_loop()
        # We're inside an async context (e.g., FastAPI)
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor() as pool:
            return pool.submit(asyncio.run, coro).result()
    except RuntimeError:
        # No event loop running, safe to use asyncio.run
        return asyncio.run(coro)


def _route_via_cascadeflow(query: str, approved_models: List[str], policy: Dict[str, Any]) -> Dict[str, Any]:
    """Route a query through cascadeflow using only approved models.

    Args:
        query: The (possibly redacted) query text.
        approved_models: List of model identifiers approved by the policy.
        policy: The full policy dict.

    Returns:
        Dict with response, model_used, cost, latency_ms, and escalated flag.
    """
    start_time = time.time()

    agent = _get_cascade_agent(approved_models, policy)
    if agent is None:
        latency_ms = round((time.time() - start_time) * 1000, 2)
        return {
            "response": (
                "[Sentinel AI — Simulated] cascadeflow is not available. "
                "In production, this query would be routed to an approved model. "
                f"Approved models: {', '.join(approved_models)}."
            ),
            "model_used": approved_models[0] if approved_models else "none",
            "cost": 0.0,
            "latency_ms": latency_ms,
            "escalated": False,
        }

    try:
        result = _run_async(agent.run(
            query=query,
            max_tokens=1024,
            temperature=0.7,
            domain_hint="medical",
        ))

        latency_ms = round((time.time() - start_time) * 1000, 2)

        response_text = ""
        model_used = approved_models[0] if approved_models else "none"
        cost = 0.0
        escalated = False

        if result:
            response_text = getattr(result, "content", "") or getattr(result, "text", "") or ""
            model_used = getattr(result, "model_used", model_used) or model_used
            cost = getattr(result, "total_cost", 0.0) or getattr(result, "cost", 0.0) or 0.0
            escalated = getattr(result, "escalated", False) or False

        if not response_text:
            response_text = (
                "[Sentinel AI] Approved model returned an empty response. "
                "The query was compliant and routed successfully."
            )

        return {
            "response": response_text,
            "model_used": str(model_used),
            "cost": float(cost),
            "latency_ms": latency_ms,
            "escalated": escalated,
        }

    except Exception as e:
        latency_ms = round((time.time() - start_time) * 1000, 2)
        logger.error(f"cascadeflow routing failed: {e}")
        return {
            "response": (
                f"[Sentinel AI] Routing error: {str(e)}. "
                f"The query was compliant but the model call failed. "
                f"Approved models: {', '.join(approved_models)}."
            ),
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
