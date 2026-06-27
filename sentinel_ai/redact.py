# sentinel_ai/redact.py
# PHI redaction utilities for Sentinel AI.
# Replaces detected PHI entities with type-annotated redaction markers
# while preserving the overall text structure and readability.

import logging
from typing import Any, Dict, List

logger = logging.getLogger("sentinel_ai.redact")


def redact_text(text: str, entities: List[Dict[str, Any]], placeholder_template: str = "[REDACTED-{TYPE}]") -> str:
    """Replace detected PHI entities in text with redaction markers.

    Processes entities from end-to-start to preserve character positions.
    Each entity is replaced with a typed placeholder like [REDACTED-SSN].

    Args:
        text: The original text containing PHI.
        entities: List of entity dicts, each with 'type', 'value', 'start', 'end'.
        placeholder_template: Template string for the redaction marker.
                              '{TYPE}' is replaced with the entity type in uppercase.

    Returns:
        The text with all detected entities replaced by redaction markers.
    """
    if not entities:
        return text

    # Sort entities by start position in reverse order so we can replace
    # from end to start without shifting character positions
    sorted_entities = sorted(entities, key=lambda e: e.get("start", 0), reverse=True)

    redacted = text
    applied_count = 0

    for entity in sorted_entities:
        entity_type = entity.get("type", "UNKNOWN").upper()
        start = entity.get("start", -1)
        end = entity.get("end", -1)
        value = entity.get("value", "")

        placeholder = placeholder_template.replace("{TYPE}", entity_type)

        if start >= 0 and end > start and end <= len(redacted):
            # Use positional replacement
            redacted = redacted[:start] + placeholder + redacted[end:]
            applied_count += 1
        elif value and value in redacted:
            # Fallback: use value-based replacement (first occurrence only)
            redacted = redacted.replace(value, placeholder, 1)
            applied_count += 1
        else:
            logger.warning(
                f"Could not redact entity '{entity_type}' — "
                f"position ({start}:{end}) out of range or value not found."
            )

    logger.info(f"Redacted {applied_count}/{len(entities)} entities in text.")
    return redacted


def redact_for_logging(text: str, entities: List[Dict[str, Any]]) -> str:
    """Create a redacted version of text suitable for audit logs.

    Similar to redact_text but uses a compact format for log readability.

    Args:
        text: The original text.
        entities: List of detected entity dicts.

    Returns:
        Redacted text with compact markers.
    """
    return redact_text(text, entities, placeholder_template="[***{TYPE}***]")


def get_redaction_summary(entities: List[Dict[str, Any]]) -> Dict[str, int]:
    """Generate a summary of redactions by entity type.

    Args:
        entities: List of detected entity dicts.

    Returns:
        Dict mapping entity type to count of redactions.
    """
    summary: Dict[str, int] = {}
    for entity in entities:
        etype = entity.get("type", "unknown").upper()
        summary[etype] = summary.get(etype, 0) + 1
    return summary
