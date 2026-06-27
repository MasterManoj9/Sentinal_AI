# sentinel_ai/detector.py
# PHI / PII detection engine for Sentinel AI.
# Uses a two-pass approach: regex pattern matching followed by an optional
# LLM-based contextual verification pass via cascadeflow.

import re
import hashlib
import logging
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("sentinel_ai.detector")

# ─── Regex patterns for common PHI/PII identifiers ───

PHI_PATTERNS: Dict[str, re.Pattern] = {
    "ssn": re.compile(
        r"\b(\d{3}[-–—.\s]?\d{2}[-–—.\s]?\d{4})\b"
    ),
    "phone": re.compile(
        r"\b(\+?1?[-.\s]?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4})\b"
    ),
    "email": re.compile(
        r"\b([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})\b"
    ),
    "dob": re.compile(
        r"\b((?:0[1-9]|1[0-2])[/\-](?:0[1-9]|[12]\d|3[01])[/\-](?:19|20)\d{2})\b"
        r"|\b((?:19|20)\d{2}[/\-](?:0[1-9]|1[0-2])[/\-](?:0[1-9]|[12]\d|3[01]))\b"
        r"|\b((?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\.?\s+\d{1,2},?\s+\d{4})\b",
        re.IGNORECASE,
    ),
    "medical_record_number": re.compile(
        r"\b(MRN[:\s#]*\d{4,12})\b", re.IGNORECASE
    ),
    "ip_address": re.compile(
        r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b"
    ),
    "address": re.compile(
        r"\b(\d{1,6}\s+(?:[A-Z][a-z]+\s*){1,4}(?:St(?:reet)?|Ave(?:nue)?|Blvd|Boulevard|Dr(?:ive)?|Ln|Lane|Rd|Road|Ct|Court|Way|Pl(?:ace)?|Cir(?:cle)?)\.?(?:\s*(?:#|Apt|Suite|Unit)\s*\w+)?)\b",
        re.IGNORECASE,
    ),
    "account_number": re.compile(
        r"\b(?:account|acct)[:\s#]*(\d{6,17})\b", re.IGNORECASE
    ),
    "certificate_license": re.compile(
        r"\b(?:license|cert(?:ificate)?|DEA)[:\s#]*([A-Z]{1,2}\d{5,10})\b", re.IGNORECASE
    ),
    "vehicle_id": re.compile(
        r"\b(VIN[:\s]*[A-HJ-NPR-Z0-9]{17})\b", re.IGNORECASE
    ),
    "device_id": re.compile(
        r"\b(?:device[_\s]?id|UDI|serial)[:\s#]*([A-Z0-9\-]{6,30})\b", re.IGNORECASE
    ),
    "url": re.compile(
        r"(https?://[^\s,;\"'<>]+)"
    ),
}

# Contextual keywords that strongly suggest the presence of PHI even
# without matching a structured regex pattern.
CONTEXTUAL_PHI_KEYWORDS: Dict[str, List[str]] = {
    "patient_name": [
        r"\bpatient(?:\s+name)?[:\s]+([A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,3})",
        r"\bname[:\s]+([A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,3})",
        r"\bMr\.?\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+)?)",
        r"\bMrs\.?\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+)?)",
        r"\bDr\.?\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+)?)",
    ],
    "doctor_name": [
        r"\b(?:doctor|physician|Dr\.?)\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+)?)",
        r"\b(?:attending|treating|referring)\s+(?:physician|doctor)[:\s]+([A-Z][a-z]+(?:\s+[A-Z][a-z]+)?)",
    ],
    "diagnosis": [
        r"\b(?:diagnos(?:is|ed)|condition|disorder)[:\s]+([^\n,;]{3,60})",
        r"\bICD[\-\s]?10[:\s]*([A-Z]\d{2}(?:\.\d{1,4})?)",
    ],
    "prescription": [
        r"\b(?:prescri(?:ption|bed)|medication|med|Rx)[:\s]+([^\n,;]{3,60})",
        r"\b(\d+\s*mg\s+[A-Za-z]+(?:\s+[A-Za-z]+)?)\b",
    ],
}


class PHIEntity:
    """Represents a detected PHI entity in the text."""

    def __init__(
        self,
        entity_type: str,
        value: str,
        start: int,
        end: int,
        method: str = "regex",
        confidence: float = 1.0,
    ) -> None:
        """Initialize a PHI entity.

        Args:
            entity_type: Category of the PHI (e.g., 'ssn', 'patient_name').
            value: The matched text.
            start: Start character position in the original text.
            end: End character position in the original text.
            method: Detection method ('regex', 'llm', or 'both').
            confidence: Confidence score from 0.0 to 1.0.
        """
        self.entity_type = entity_type
        self.value = value
        self.start = start
        self.end = end
        self.method = method
        self.confidence = confidence

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation.

        Returns:
            Dict with entity type, value, positions, method, and confidence.
        """
        return {
            "type": self.entity_type,
            "value": self.value,
            "start": self.start,
            "end": self.end,
            "method": self.method,
            "confidence": self.confidence,
        }


def _regex_scan(text: str) -> List[PHIEntity]:
    """Run regex patterns over the text to find structured PHI.

    Args:
        text: The input text to scan.

    Returns:
        List of PHIEntity objects found by regex matching.
    """
    entities: List[PHIEntity] = []
    seen_spans: set = set()

    # Structured patterns
    for phi_type, pattern in PHI_PATTERNS.items():
        for match in pattern.finditer(text):
            span = (match.start(), match.end())
            if span not in seen_spans:
                seen_spans.add(span)
                value = match.group(0).strip()
                entities.append(
                    PHIEntity(
                        entity_type=phi_type,
                        value=value,
                        start=match.start(),
                        end=match.end(),
                        method="regex",
                        confidence=0.95,
                    )
                )

    # Contextual keyword patterns
    for phi_type, patterns in CONTEXTUAL_PHI_KEYWORDS.items():
        for pat_str in patterns:
            pat = re.compile(pat_str, re.IGNORECASE)
            for match in pat.finditer(text):
                span = (match.start(), match.end())
                if span not in seen_spans:
                    seen_spans.add(span)
                    # Use the captured group if available, otherwise full match
                    value = match.group(1) if match.lastindex else match.group(0)
                    entities.append(
                        PHIEntity(
                            entity_type=phi_type,
                            value=value.strip(),
                            start=match.start(),
                            end=match.end(),
                            method="regex",
                            confidence=0.80,
                        )
                    )

    return entities


def _llm_verify(text: str, regex_entities: List[PHIEntity]) -> Tuple[List[PHIEntity], float]:
    """Use cascadeflow with a small model to verify and catch contextual PHI.

    This is a second-pass verification that looks for PHI that regex might miss,
    such as diagnosis names, prescription names, and doctor names in free text.

    Args:
        text: The original input text.
        regex_entities: Entities already found by regex.

    Returns:
        Tuple of (additional entities found by LLM, confidence score).
    """
    additional_entities: List[PHIEntity] = []
    llm_confidence: float = 0.0

    try:
        from cascadeflow import CascadeFlow

        cascade = CascadeFlow()

        prompt = (
            "You are a HIPAA PHI detection system. Analyze the following text and identify "
            "any Protected Health Information (PHI) that might be present. Look specifically for:\n"
            "- Patient names\n- Doctor/physician names\n- Diagnoses or medical conditions\n"
            "- Prescription/medication names\n- Medical record numbers\n- Any other HIPAA PHI\n\n"
            f"Text to analyze:\n{text}\n\n"
            "Respond ONLY with a JSON array of objects, each with keys: "
            '"type", "value", "reason". If no PHI found, respond with [].'
        )

        response = cascade.generate(
            prompt=prompt,
            models=["groq/openai-gpt-oss-120b", "ollama/llama3.1"],
        )

        if response and hasattr(response, "text"):
            import json
            try:
                # Try to extract JSON from the response
                resp_text = response.text.strip()
                # Handle responses wrapped in markdown code blocks
                if resp_text.startswith("```"):
                    resp_text = resp_text.split("\n", 1)[-1].rsplit("```", 1)[0].strip()

                found = json.loads(resp_text)
                if isinstance(found, list):
                    existing_values = {e.value.lower() for e in regex_entities}
                    for item in found:
                        if isinstance(item, dict) and "value" in item:
                            if item["value"].lower() not in existing_values:
                                additional_entities.append(
                                    PHIEntity(
                                        entity_type=item.get("type", "unknown"),
                                        value=item["value"],
                                        start=text.lower().find(item["value"].lower()),
                                        end=text.lower().find(item["value"].lower()) + len(item["value"]),
                                        method="llm",
                                        confidence=0.85,
                                    )
                                )
                    llm_confidence = 0.85
            except (json.JSONDecodeError, ValueError):
                logger.warning("LLM response was not valid JSON; skipping LLM entities.")

    except ImportError:
        logger.warning("cascadeflow not available; skipping LLM verification pass.")
    except Exception as e:
        logger.warning(f"LLM verification failed: {e}; continuing with regex results only.")

    return additional_entities, llm_confidence


def detect_phi(text: str, use_llm: bool = True) -> Dict[str, Any]:
    """Detect Protected Health Information (PHI) in the given text.

    Uses a two-pass approach:
      1. Regex pass for structured patterns (SSN, phone, email, etc.)
      2. Optional LLM pass via cascadeflow for contextual PHI (diagnoses, names, etc.)

    Args:
        text: The text to scan for PHI.
        use_llm: Whether to run the LLM second-pass verification.

    Returns:
        Dict with keys:
            - entities: List of detected entity dicts
            - confidence: Overall confidence score (0.0 - 1.0)
            - method: Detection method used ('regex', 'llm', or 'both')
            - phi_detected: Boolean indicating if any PHI was found
            - entity_count: Total number of entities detected
            - query_hash: SHA-256 hash of the input text
    """
    if not text or not text.strip():
        return {
            "entities": [],
            "confidence": 0.0,
            "method": "regex",
            "phi_detected": False,
            "entity_count": 0,
            "query_hash": hashlib.sha256(b"").hexdigest(),
        }

    # Step 1: Regex scan
    regex_entities = _regex_scan(text)
    method = "regex"
    overall_confidence = max((e.confidence for e in regex_entities), default=0.0)

    # Step 2: Optional LLM verification pass
    llm_entities: List[PHIEntity] = []
    if use_llm and regex_entities:
        llm_entities, llm_conf = _llm_verify(text, regex_entities)
        if llm_entities:
            method = "both"
            overall_confidence = max(overall_confidence, llm_conf)
        elif regex_entities:
            # LLM didn't find extra, but we still confirmed with regex
            method = "regex"
    elif use_llm and not regex_entities:
        # No regex hits — still try LLM for contextual PHI
        llm_entities, llm_conf = _llm_verify(text, [])
        if llm_entities:
            method = "llm"
            overall_confidence = llm_conf

    all_entities = regex_entities + llm_entities

    # Sort by position in text
    all_entities.sort(key=lambda e: e.start)

    query_hash = hashlib.sha256(text.encode("utf-8")).hexdigest()

    return {
        "entities": [e.to_dict() for e in all_entities],
        "confidence": round(overall_confidence, 3),
        "method": method,
        "phi_detected": len(all_entities) > 0,
        "entity_count": len(all_entities),
        "query_hash": query_hash,
    }
