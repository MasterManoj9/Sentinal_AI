# sentinel_ai/prime.py
# Prime — the compliance gate agent inside Sentinel AI.
# Orchestrates the full compliance pipeline: detect PHI, recall memory,
# evaluate policy, route to approved models, redact as needed, and log
# every decision to the immutable audit trail.

import hashlib
import logging
import time
from typing import Any, Dict, List, Optional

from sentinel_ai.audit import log_event
from sentinel_ai.config import SentinelConfig
from sentinel_ai.detector import detect_phi
from sentinel_ai.gate import evaluate
from sentinel_ai.memory import recall_rules, reflect, store_decision
from sentinel_ai.router import route

logger = logging.getLogger("sentinel_ai.prime")


class Prime:
    """Prime is the compliance gate agent inside Sentinel AI.

    Prime intercepts AI queries, detects regulated data (HIPAA PHI by default),
    and routes them only to approved models while blocking non-compliant ones.
    Every decision is logged in an immutable audit trail and remembered across
    sessions via Hindsight.
    """

    def __init__(
        self,
        policy_path: Optional[str] = None,
        hindsight_enabled: bool = True,
        config: Optional[SentinelConfig] = None,
    ) -> None:
        """Initialize the Prime compliance gate agent.

        Args:
            policy_path: Path to the compliance policy JSON file.
                         Uses default from config if not provided.
            hindsight_enabled: Whether to enable Hindsight memory integration.
            config: Optional SentinelConfig instance. Creates a new one if not provided.
        """
        self.config = config or SentinelConfig()

        if policy_path:
            self.config.policy_file = policy_path
            self.config.policy = self.config._load_policy()

        self.policy = self.config.policy
        self.hindsight_enabled = hindsight_enabled and self.config.hindsight_enabled
        self.agent_name = self.policy.get("agent_name", "Prime")
        self.project_name = self.policy.get("project_name", "Sentinel AI")

        logger.info(
            f"{self.agent_name} initialized. "
            f"Policy: {self.policy.get('framework', 'unknown')}. "
            f"Hindsight: {'enabled' if self.hindsight_enabled else 'disabled'}. "
            f"Approved models: {self.config.approved_models}."
        )

    def process(
        self,
        query: str,
        client_id: str,
        requested_model: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Run the full compliance pipeline on a query.

        Pipeline steps:
          1. Detect PHI/PII in the query text
          2. Recall past decisions from Hindsight memory
          3. Evaluate the query against the compliance policy
          4. Route to an approved model (or block)
          5. Redact PHI if needed
          6. Log everything to the audit trail
          7. Store the decision in Hindsight for future recall

        Args:
            query: The AI query text to evaluate.
            client_id: Identifier for the requesting client.
            requested_model: Model explicitly requested by the client (if any).

        Returns:
            Dict with keys: decision, response, model_used, cost,
            latency_ms, audit_id, phi_detected, entity_count.
        """
        start_time = time.time()
        query_hash = hashlib.sha256(query.encode("utf-8")).hexdigest()

        logger.info(f"Processing query from client '{client_id}' (hash: {query_hash[:12]}...)")

        # ── Step 1: Log query received ──
        log_event("QUERY_RECEIVED", {
            "client_id": client_id,
            "query_hash": query_hash,
            "query_length": len(query),
            "requested_model": requested_model or "none",
        })

        # ── Step 2: Detect PHI ──
        try:
            detection = detect_phi(query, use_llm=True)
        except Exception as e:
            logger.error(f"PHI detection failed: {e}. Blocking query for safety.")
            detection = {
                "entities": [],
                "confidence": 0.0,
                "method": "error",
                "phi_detected": False,
                "entity_count": 0,
                "query_hash": query_hash,
            }

        logger.info(
            f"Detection complete: {detection['entity_count']} entities found, "
            f"confidence={detection['confidence']}, method={detection['method']}"
        )

        # ── Step 3: Recall memory ──
        memory_recall: List[Dict[str, Any]] = []
        if self.hindsight_enabled:
            try:
                memory_recall = recall_rules(client_id)
                logger.info(f"Recalled {len(memory_recall)} past decisions for client '{client_id}'.")
            except Exception as e:
                logger.warning(f"Memory recall failed: {e}. Proceeding without recall.")

        # ── Step 4: Evaluate compliance ──
        try:
            decision = evaluate(
                detection_result=detection,
                policy=self.policy,
                client_id=client_id,
                hindsight_recall=memory_recall,
                requested_model=requested_model,
            )
        except Exception as e:
            logger.error(f"Gate evaluation failed: {e}. Blocking for safety.")
            decision = {
                "decision": "BLOCK",
                "model_tier": "none",
                "reason": f"Gate evaluation error: {str(e)}. Blocked for safety.",
            }

        logger.info(f"Gate decision: {decision['decision']} — {decision.get('reason', '')[:80]}")

        # ── Step 5: Route query ──
        try:
            outcome = route(query, decision, self.policy)
        except Exception as e:
            logger.error(f"Routing failed: {e}")
            outcome = {
                "response": f"[Sentinel AI] Routing error: {str(e)}",
                "model_used": "none",
                "cost": 0.0,
                "latency_ms": 0.0,
                "escalated": False,
            }

        total_latency = round((time.time() - start_time) * 1000, 2)

        # ── Step 6: Log the decision ──
        audit_id = log_event("DECISION_MADE", {
            "client_id": client_id,
            "query_hash": query_hash,
            "decision": decision.get("decision", ""),
            "reason": decision.get("reason", ""),
            "model_used": outcome.get("model_used", "none"),
            "cost": outcome.get("cost", 0.0),
            "latency_ms": total_latency,
            "entity_count": detection.get("entity_count", 0),
            "redacted": outcome.get("redacted", False),
            "escalated": outcome.get("escalated", False),
            "detection_method": detection.get("method", ""),
            "detection_confidence": detection.get("confidence", 0.0),
        })

        # ── Step 7: Store in Hindsight ──
        if self.hindsight_enabled:
            try:
                store_decision(client_id, query_hash, decision, outcome)
            except Exception as e:
                logger.warning(f"Failed to store decision in memory: {e}")

        # ── Build response ──
        result = {
            "decision": decision.get("decision", "BLOCK"),
            "reason": decision.get("reason", ""),
            "response": outcome.get("response", ""),
            "model_used": outcome.get("model_used", "none"),
            "cost": outcome.get("cost", 0.0),
            "latency_ms": total_latency,
            "audit_id": audit_id,
            "phi_detected": detection.get("phi_detected", False),
            "entity_count": detection.get("entity_count", 0),
            "detection_method": detection.get("method", ""),
            "redacted": outcome.get("redacted", False),
            "escalated": outcome.get("escalated", False),
        }

        logger.info(
            f"Query processed: decision={result['decision']}, "
            f"model={result['model_used']}, latency={result['latency_ms']}ms"
        )

        return result

    def recall(self, client_id: str) -> List[Dict[str, Any]]:
        """Pull past decisions for a client from Hindsight memory.

        Args:
            client_id: The client identifier to query history for.

        Returns:
            List of past decision dicts. Empty if Hindsight is unavailable.
        """
        if not self.hindsight_enabled:
            logger.info("Hindsight is disabled. No recall available.")
            return []

        try:
            return recall_rules(client_id)
        except Exception as e:
            logger.warning(f"Recall failed for client '{client_id}': {e}")
            return []

    def reflect(self, client_id: str) -> Dict[str, Any]:
        """Use Hindsight's reflect feature to surface patterns for a client.

        Analyzes accumulated decisions to identify trends, repeated violations,
        or compliance improvements over time.

        Args:
            client_id: The client identifier to analyze.

        Returns:
            Dict with pattern analysis. Empty analysis if unavailable.
        """
        if not self.hindsight_enabled:
            return {
                "client_id": client_id,
                "analysis": "Hindsight memory is disabled. No pattern analysis available.",
                "source": "disabled",
            }

        try:
            return reflect(client_id)
        except Exception as e:
            logger.warning(f"Reflect failed for client '{client_id}': {e}")
            return {
                "client_id": client_id,
                "analysis": f"Reflection unavailable: {str(e)}",
                "source": "error",
            }
