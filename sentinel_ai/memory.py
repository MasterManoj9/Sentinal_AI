# sentinel_ai/memory.py
# Hindsight memory integration for Sentinel AI.
# Provides persistent, cross-session memory for the Prime agent using
# the Hindsight SDK. Stores and recalls past compliance decisions,
# enabling pattern recognition and adaptive enforcement over time.

import logging
import hashlib
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger("sentinel_ai.memory")

# In-memory fallback store when Hindsight is unavailable
_fallback_store: Dict[str, List[Dict[str, Any]]] = {}


def _get_hindsight_client() -> Optional[Any]:
    """Attempt to initialize and return a Hindsight client.

    Returns:
        Hindsight client instance, or None if unavailable.
    """
    try:
        from hindsight_sdk import Hindsight
        import os

        api_key = os.getenv("HINDSIGHT_API_KEY", "")
        if not api_key:
            logger.warning("HINDSIGHT_API_KEY not set. Using fallback in-memory store.")
            return None

        client = Hindsight(api_key=api_key)
        return client

    except ImportError:
        logger.warning("hindsight-sdk not installed. Using fallback in-memory store.")
        return None
    except Exception as e:
        logger.warning(f"Hindsight initialization failed: {e}. Using fallback store.")
        return None


def recall_rules(client_id: str) -> List[Dict[str, Any]]:
    """Recall past compliance decisions for a given client from Hindsight.

    Queries the Hindsight vector store for the top-5 most relevant
    past rules and learned patterns for this client.

    Args:
        client_id: The client identifier to query history for.

    Returns:
        List of up to 5 past decision dicts, each with keys like
        decision, timestamp, query_hash, etc. Returns empty list
        if Hindsight is unavailable.
    """
    try:
        client = _get_hindsight_client()
        if client is None:
            # Use fallback store
            return _fallback_recall(client_id)

        results = client.recall(
            query=f"compliance decisions for client {client_id}",
            metadata_filter={"client_id": client_id},
            top_k=5,
        )

        if results and hasattr(results, "memories"):
            return [
                {
                    "decision": mem.metadata.get("decision", "unknown"),
                    "timestamp": mem.metadata.get("timestamp", ""),
                    "query_hash": mem.metadata.get("query_hash", ""),
                    "client_id": mem.metadata.get("client_id", client_id),
                    "reason": mem.metadata.get("reason", ""),
                    "model_used": mem.metadata.get("model_used", ""),
                    "relevance": getattr(mem, "score", 0.0),
                }
                for mem in results.memories[:5]
            ]

        return []

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

    Persists the decision with full metadata so the Prime agent can
    learn from past enforcement actions and surface patterns.

    Args:
        client_id: The client identifier.
        query_hash: SHA-256 hash of the original query text.
        decision: The gate decision dict (decision, reason, etc.).
        outcome: The routing outcome dict (response, model_used, cost, etc.).
    """
    timestamp = datetime.now(timezone.utc).isoformat()
    decision_type = decision.get("decision", "unknown")
    reason = decision.get("reason", "")
    model_used = outcome.get("model_used", "none")
    cost = outcome.get("cost", 0.0)

    memory_text = (
        f"Client '{client_id}' query was {decision_type}. "
        f"Reason: {reason}. Model used: {model_used}. Cost: {cost}."
    )

    metadata = {
        "client_id": client_id,
        "query_hash": query_hash,
        "decision": decision_type,
        "reason": reason,
        "model_used": model_used,
        "cost": cost,
        "timestamp": timestamp,
        "entity_count": decision.get("entity_count", 0),
    }

    try:
        client = _get_hindsight_client()
        if client is None:
            _fallback_store_decision(client_id, metadata, memory_text)
            return

        client.memorize(
            text=memory_text,
            metadata=metadata,
        )
        logger.info(f"Stored decision in Hindsight for client '{client_id}': {decision_type}")

    except Exception as e:
        logger.warning(f"Hindsight store failed: {e}. Storing in fallback.")
        _fallback_store_decision(client_id, metadata, memory_text)


def reflect(client_id: str) -> Dict[str, Any]:
    """Use Hindsight's reflect feature to surface patterns for a client.

    Analyzes accumulated decisions to identify trends, repeated violations,
    or compliance improvements over time.

    Args:
        client_id: The client identifier to analyze.

    Returns:
        Dict with pattern analysis including total_decisions, block_rate,
        common_violations, and recommendations.
    """
    try:
        client = _get_hindsight_client()
        if client is None:
            return _fallback_reflect(client_id)

        results = client.reflect(
            query=f"patterns and trends for client {client_id}",
            metadata_filter={"client_id": client_id},
        )

        if results and hasattr(results, "text"):
            return {
                "client_id": client_id,
                "analysis": results.text,
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
    return decisions[-5:]  # Return last 5


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

    # Find most common violation types
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
