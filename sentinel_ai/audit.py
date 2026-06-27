# sentinel_ai/audit.py
# Append-only audit logging for Sentinel AI.
# Every compliance decision made by Prime is recorded as a JSONL entry
# to both an audit log file and stdout. Entries are immutable — they
# are never overwritten or deleted.

import json
import logging
import os
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("sentinel_ai.audit")

# Default audit log path
_audit_log_path: str = os.getenv("AUDIT_LOG_PATH", "audit.log")


def _get_audit_path() -> Path:
    """Resolve the audit log file path.

    Returns:
        Path object pointing to the audit log file.
    """
    path = Path(_audit_log_path)
    if not path.is_absolute():
        project_root = Path(__file__).parent.parent
        path = project_root / path
    return path


def log_event(
    event_type: str,
    payload: Dict[str, Any],
    audit_path: Optional[str] = None,
) -> str:
    """Append a structured audit event to the immutable log.

    Each event is written as a single JSON line (JSONL format) to the
    audit log file, and also emitted to stdout for live visibility.

    Args:
        event_type: Type of event (e.g., 'QUERY_RECEIVED', 'DECISION_MADE',
                    'QUERY_ROUTED', 'QUERY_BLOCKED').
        payload: Dict containing event-specific data such as client_id,
                 query_hash, decision, model_used, cost, latency_ms, etc.
        audit_path: Optional override for the audit log file path.

    Returns:
        The generated audit_id (UUID) for this event.
    """
    audit_id = str(uuid.uuid4())
    timestamp = datetime.now(timezone.utc).isoformat()

    entry = {
        "audit_id": audit_id,
        "timestamp": timestamp,
        "event": event_type,
        "agent": payload.get("agent", "Prime"),
        "project": payload.get("project", "Sentinel AI"),
        "client_id": payload.get("client_id", "unknown"),
        "query_hash": payload.get("query_hash", ""),
        "decision": payload.get("decision", ""),
        "reason": payload.get("reason", ""),
        "model_used": payload.get("model_used", ""),
        "cost": payload.get("cost", 0.0),
        "latency_ms": payload.get("latency_ms", 0.0),
        "entity_count": payload.get("entity_count", 0),
        "redacted": payload.get("redacted", False),
        "metadata": {
            k: v
            for k, v in payload.items()
            if k
            not in {
                "agent",
                "project",
                "client_id",
                "query_hash",
                "decision",
                "reason",
                "model_used",
                "cost",
                "latency_ms",
                "entity_count",
                "redacted",
            }
        },
    }

    entry_json = json.dumps(entry, default=str)

    # Append to audit log file (immutable, append-only)
    log_path = Path(audit_path) if audit_path else _get_audit_path()
    try:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(entry_json + "\n")
    except Exception as e:
        logger.error(f"Failed to write audit log to {log_path}: {e}")

    # Also write to stdout for live demo visibility
    try:
        print(f"[AUDIT] {entry_json}", file=sys.stdout, flush=True)
    except Exception:
        pass  # Never crash on stdout write failure

    logger.info(f"Audit event logged: {event_type} | audit_id={audit_id}")
    return audit_id


def read_recent(limit: int = 20, audit_path: Optional[str] = None) -> List[Dict[str, Any]]:
    """Read the most recent audit log entries.

    Args:
        limit: Maximum number of entries to return.
        audit_path: Optional override for the audit log file path.

    Returns:
        List of the most recent audit entry dicts, newest first.
    """
    log_path = Path(audit_path) if audit_path else _get_audit_path()

    if not log_path.exists():
        return []

    entries: List[Dict[str, Any]] = []
    try:
        with open(log_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        entries.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
    except Exception as e:
        logger.error(f"Failed to read audit log: {e}")
        return []

    # Return most recent entries first
    return list(reversed(entries[-limit:]))


def read_by_client(client_id: str, audit_path: Optional[str] = None) -> List[Dict[str, Any]]:
    """Read all audit log entries for a specific client.

    Args:
        client_id: The client identifier to filter by.
        audit_path: Optional override for the audit log file path.

    Returns:
        List of audit entry dicts for the given client, newest first.
    """
    log_path = Path(audit_path) if audit_path else _get_audit_path()

    if not log_path.exists():
        return []

    entries: List[Dict[str, Any]] = []
    try:
        with open(log_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        entry = json.loads(line)
                        if entry.get("client_id") == client_id:
                            entries.append(entry)
                    except json.JSONDecodeError:
                        continue
    except Exception as e:
        logger.error(f"Failed to read audit log: {e}")
        return []

    return list(reversed(entries))


def get_stats(audit_path: Optional[str] = None) -> Dict[str, Any]:
    """Get aggregate statistics from the audit log.

    Args:
        audit_path: Optional override for the audit log file path.

    Returns:
        Dict with total_events, decision breakdown, unique clients, etc.
    """
    all_entries = read_recent(limit=100000, audit_path=audit_path)

    if not all_entries:
        return {"total_events": 0, "unique_clients": 0}

    decisions = [e.get("decision", "") for e in all_entries if e.get("decision")]
    clients = {e.get("client_id", "") for e in all_entries}
    total_cost = sum(e.get("cost", 0.0) for e in all_entries)

    return {
        "total_events": len(all_entries),
        "unique_clients": len(clients),
        "total_cost": round(total_cost, 6),
        "decisions": {
            "ALLOW": decisions.count("ALLOW"),
            "REDACT": decisions.count("REDACT"),
            "BLOCK": decisions.count("BLOCK"),
        },
    }
