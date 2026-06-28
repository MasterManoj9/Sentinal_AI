# sentinel_ai/memory.py
# Hindsight memory integration for Sentinel AI.
# Provides persistent, cross-session memory for the Prime agent using
# the Hindsight client SDK (hindsight-client). Stores and recalls past
# compliance decisions, enabling pattern recognition and adaptive enforcement.

import asyncio
import concurrent.futures
import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger("sentinel_ai.memory")

# In-memory fallback store when Hindsight is unavailable
_fallback_store: Dict[str, List[Dict[str, Any]]] = {}

# Cached Hindsight client
_hindsight_client: Optional[Any] = None


def _get_hindsight_client() -> Optional[Any]:
    """Attempt to initialize and return a Hindsight client.

    Uses the HINDSIGHT_BASE_URL and HINDSIGHT_API_KEY environment variables.
    For Hindsight Cloud, set HINDSIGHT_BASE_URL to
    https://api.hindsight.vectorize.io.
    For self-hosted, set it to your server URL (e.g., http://localhost:8888).

    Returns:
        Hindsight client instance, or None if unavailable.
    """
    global _hindsight_client
    if _hindsight_client is not None:
        return _hindsight_client

    try:
        from hindsight_client import Hindsight

        base_url = os.getenv("HINDSIGHT_BASE_URL", "https://api.hindsight.vectorize.io")
        api_key = os.getenv("HINDSIGHT_API_KEY", "")

        if not api_key:
            logger.warning("HINDSIGHT_API_KEY not set. Using fallback in-memory store.")
            return None

        client = Hindsight(
            base_url=base_url,
            api_key=api_key,
            user_agent="sentinel-ai-prime/1.0.0",
        )
        _hindsight_client = client
        logger.info("Hindsight client initialized successfully.")
        return client

    except ImportError:
        logger.warning("hindsight-client not installed. Using fallback in-memory store.")
        return None
    except Exception as e:
        logger.warning(f"Hindsight initialization failed: {e}. Using fallback store.")
        return None


def _get_bank_id(client_id: str) -> str:
    """Get the Hindsight memory bank ID for a client.

    Uses HINDSIGHT_BANK_ID env var if set, otherwise uses the client_id itself.

    Args:
        client_id: The client identifier.

    Returns:
        The memory bank ID to use.
    """
    return os.getenv("HINDSIGHT_BANK_ID", client_id)


def _run_async(coro: Any) -> Any:
    """Run an async coroutine synchronously, even inside an existing event loop."""
    try:
        loop = asyncio.get_running_loop()
        with concurrent.futures.ThreadPoolExecutor() as pool:
            return pool.submit(asyncio.run, coro).result()
    except RuntimeError:
        return asyncio.run(coro)


def recall_rules(client_id: str) -> List[Dict[str, Any]]:
    """Recall past compliance decisions for a given client from Hindsight.

    Queries the Hindsight memory bank using semantic similarity to find
    the most relevant past rules and learned patterns for this client.

    Args:
        client_id: The client identifier to query history for.

    Returns:
        List of past decision dicts. Returns empty list if Hindsight is unavailable.
    """
    try:
        client = _get_hindsight_client()
        if client is None:
            return _fallback_recall(client_id)

        bank_id = _get_bank_id(client_id)

        response = _run_async(client.arecall(
            bank_id=bank_id,
            query=f"compliance decisions and violations for client {client_id}",
            tags=[f"client:{client_id}"],
            tags_match="any",
            max_tokens=2048,
            budget="low",
        ))

        results: List[Dict[str, Any]] = []
        if response and hasattr(response, "results") and response.results:
            for result in response.results[:5]:
                results.append({
                    "decision": getattr(result, "text", ""),
                    "client_id": client_id,
                    "relevance": getattr(result, "score", 0.0) if hasattr(result, "score") else 0.0,
                    "source": "hindsight",
                })

        logger.info(f"Recalled {len(results)} memories for client '{client_id}' from Hindsight.")
        return results

    except Exception as e:
        logger.warning(f"Hindsight recall failed: {e}. Using fallback store.")
        return _fallback_recall(client_id)


def store_decision(
    client_id: str,
    query_hash: str,
    decision: Dict[str, Any],
    outcome: Dict[str, Any],
) -> None:
    """Store a compliance decision in Hindsight for future recall.

    Uses the retain() method to persist the decision with full metadata
    so the Prime agent can learn from past enforcement actions.

    Args:
        client_id: The client identifier.
        query_hash: SHA-256 hash of the original query text.
        decision: The gate decision dict (decision, reason, etc.).
        outcome: The routing outcome dict (response, model_used, cost, etc.).
    """
    timestamp = datetime.now(timezone.utc)
    decision_type = decision.get("decision", "unknown")
    reason = decision.get("reason", "")
    model_used = outcome.get("model_used", "none")
    cost = outcome.get("cost", 0.0)

    memory_content = (
        f"Client '{client_id}' query was {decision_type}. "
        f"Reason: {reason}. Model used: {model_used}. Cost: {cost}. "
        f"Query hash: {query_hash[:16]}. "
        f"Entity count: {decision.get('entity_count', 0)}."
    )

    metadata = {
        "client_id": client_id,
        "query_hash": query_hash[:16],
        "decision": decision_type,
        "model_used": model_used,
    }

    try:
        client = _get_hindsight_client()
        if client is None:
            _fallback_store_decision(client_id, {**metadata, "reason": reason, "cost": cost, "timestamp": timestamp.isoformat()}, memory_content)
            return

        bank_id = _get_bank_id(client_id)

        _run_async(client.aretain(
            bank_id=bank_id,
            content=memory_content,
            timestamp=timestamp,
            context=f"Sentinel AI Prime compliance decision: {decision_type}",
            metadata=metadata,
            tags=[f"client:{client_id}", f"decision:{decision_type}", "sentinel-ai"],
        ))

        logger.info(f"Stored decision in Hindsight for client '{client_id}': {decision_type}")

    except Exception as e:
        logger.warning(f"Hindsight store failed: {e}. Storing in fallback.")
        _fallback_store_decision(client_id, {**metadata, "reason": reason, "cost": cost, "timestamp": timestamp.isoformat()}, memory_content)


def reflect(client_id: str) -> Dict[str, Any]:
    """Use Hindsight's reflect feature to surface patterns for a client.

    Generates a contextual answer analyzing compliance trends, repeated
    violations, or improvements over time.

    Args:
        client_id: The client identifier to analyze.

    Returns:
        Dict with pattern analysis.
    """
    try:
        client = _get_hindsight_client()
        if client is None:
            return _fallback_reflect(client_id)

        bank_id = _get_bank_id(client_id)

        response = _run_async(client.areflect(
            bank_id=bank_id,
            query=(
                f"Analyze the compliance history for client '{client_id}'. "
                f"What patterns do you see? How many queries were blocked vs allowed? "
                f"Are there any recurring violations or improvements over time?"
            ),
            budget="mid",
            context="Sentinel AI compliance pattern analysis",
            tags=[f"client:{client_id}"],
            tags_match="any",
        ))

        if response and hasattr(response, "text") and response.text:
            return {
                "client_id": client_id,
                "analysis": response.text,
                "source": "hindsight",
            }

        return _fallback_reflect(client_id)

    except Exception as e:
        logger.warning(f"Hindsight reflect failed: {e}. Using fallback analysis.")
        return _fallback_reflect(client_id)


# ─── Fallback in-memory implementations ───


def _fallback_recall(client_id: str) -> List[Dict[str, Any]]:
    """Recall decisions from the in-memory fallback store.

    Args:
        client_id: The client identifier.

    Returns:
        List of up to 5 most recent decisions for the client.
    """
    decisions = _fallback_store.get(client_id, [])
    return decisions[-5:]


def _fallback_store_decision(
    client_id: str,
    metadata: Dict[str, Any],
    memory_text: str,
) -> None:
    """Store a decision in the in-memory fallback store.

    Args:
        client_id: The client identifier.
        metadata: Decision metadata dict.
        memory_text: Human-readable summary of the decision.
    """
    if client_id not in _fallback_store:
        _fallback_store[client_id] = []

    _fallback_store[client_id].append({
        **metadata,
        "memory_text": memory_text,
    })

    logger.info(f"Stored decision in fallback memory for client '{client_id}'.")


def _fallback_reflect(client_id: str) -> Dict[str, Any]:
    """Perform basic pattern analysis on the fallback store.

    Args:
        client_id: The client identifier.

    Returns:
        Dict with analysis summary.
    """
    decisions = _fallback_store.get(client_id, [])

    if not decisions:
        return {
            "client_id": client_id,
            "analysis": "No decision history available for this client.",
            "source": "fallback",
            "total_decisions": 0,
        }

    total = len(decisions)
    blocks = sum(1 for d in decisions if d.get("decision") == "BLOCK")
    redacts = sum(1 for d in decisions if d.get("decision") == "REDACT")
    allows = sum(1 for d in decisions if d.get("decision") == "ALLOW")

    block_rate = round(blocks / total * 100, 1) if total > 0 else 0.0

    violations: Dict[str, int] = {}
    for d in decisions:
        reason = d.get("reason", "")
        if "ssn" in reason.lower():
            violations["SSN exposure"] = violations.get("SSN exposure", 0) + 1
        if "patient_name" in reason.lower():
            violations["Patient name"] = violations.get("Patient name", 0) + 1
        if "diagnosis" in reason.lower():
            violations["Diagnosis"] = violations.get("Diagnosis", 0) + 1

    return {
        "client_id": client_id,
        "source": "fallback",
        "total_decisions": total,
        "allow_count": allows,
        "redact_count": redacts,
        "block_count": blocks,
        "block_rate_percent": block_rate,
        "common_violations": violations,
        "analysis": (
            f"Client '{client_id}' has {total} recorded decisions. "
            f"Block rate: {block_rate}%. "
            f"Breakdown: {allows} ALLOW, {redacts} REDACT, {blocks} BLOCK."
        ),
    }
