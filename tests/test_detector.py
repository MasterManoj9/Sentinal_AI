# tests/test_detector.py
# Unit tests for the PHI/PII detection engine.

import pytest
from sentinel_ai.detector import detect_phi, _regex_scan, PHIEntity


class TestRegexDetection:
    """Tests for regex-based PHI detection."""

    def test_detect_ssn(self) -> None:
        """SSN pattern should be detected with high confidence."""
        text = "Patient SSN is 123-45-6789 for identification."
        result = detect_phi(text, use_llm=False)
        assert result["phi_detected"] is True
        entity_types = [e["type"] for e in result["entities"]]
        assert "ssn" in entity_types

    def test_detect_email(self) -> None:
        """Email addresses should be detected."""
        text = "Send records to john.doe@hospital.com please."
        result = detect_phi(text, use_llm=False)
        assert result["phi_detected"] is True
        entity_types = [e["type"] for e in result["entities"]]
        assert "email" in entity_types

    def test_detect_phone(self) -> None:
        """Phone numbers should be detected."""
        text = "Call the patient at (555) 123-4567 for follow-up."
        result = detect_phi(text, use_llm=False)
        assert result["phi_detected"] is True
        entity_types = [e["type"] for e in result["entities"]]
        assert "phone" in entity_types

    def test_detect_dob(self) -> None:
        """Date of birth patterns should be detected."""
        text = "Patient DOB: 03/15/1985."
        result = detect_phi(text, use_llm=False)
        assert result["phi_detected"] is True
        entity_types = [e["type"] for e in result["entities"]]
        assert "dob" in entity_types

    def test_detect_mrn(self) -> None:
        """Medical Record Numbers should be detected."""
        text = "See record MRN: 12345678 for details."
        result = detect_phi(text, use_llm=False)
        assert result["phi_detected"] is True
        entity_types = [e["type"] for e in result["entities"]]
        assert "medical_record_number" in entity_types

    def test_detect_ip_address(self) -> None:
        """IP addresses should be detected."""
        text = "Patient accessed portal from 192.168.1.100."
        result = detect_phi(text, use_llm=False)
        assert result["phi_detected"] is True
        entity_types = [e["type"] for e in result["entities"]]
        assert "ip_address" in entity_types

    def test_no_phi_in_clean_text(self) -> None:
        """Clean text with no PHI should return empty results."""
        text = "What is the recommended dosage for ibuprofen?"
        result = detect_phi(text, use_llm=False)
        assert result["phi_detected"] is False
        assert result["entity_count"] == 0
        assert result["entities"] == []

    def test_empty_text(self) -> None:
        """Empty text should return empty results."""
        result = detect_phi("", use_llm=False)
        assert result["phi_detected"] is False
        assert result["entity_count"] == 0

    def test_multiple_phi_entities(self) -> None:
        """Text with multiple PHI types should detect all of them."""
        text = (
            "Patient John Smith (SSN: 123-45-6789) born on 01/15/1990, "
            "email: john@example.com, phone: (555) 987-6543."
        )
        result = detect_phi(text, use_llm=False)
        assert result["phi_detected"] is True
        assert result["entity_count"] >= 3  # SSN, email, phone at minimum

    def test_detection_method_without_llm(self) -> None:
        """Without LLM, method should be 'regex'."""
        text = "SSN: 111-22-3333"
        result = detect_phi(text, use_llm=False)
        assert result["method"] == "regex"

    def test_query_hash_generated(self) -> None:
        """Query hash should be generated for every detection."""
        text = "Test query"
        result = detect_phi(text, use_llm=False)
        assert "query_hash" in result
        assert len(result["query_hash"]) == 64  # SHA-256 hex digest length

    def test_contextual_patient_name(self) -> None:
        """Contextual patterns should detect patient names."""
        text = "Patient name: Robert Wilson was admitted yesterday."
        result = detect_phi(text, use_llm=False)
        assert result["phi_detected"] is True
        entity_types = [e["type"] for e in result["entities"]]
        assert "patient_name" in entity_types

    def test_contextual_doctor_name(self) -> None:
        """Contextual patterns should detect doctor names."""
        text = "Dr. Emily Chen performed the examination."
        result = detect_phi(text, use_llm=False)
        assert result["phi_detected"] is True
        entity_types = [e["type"] for e in result["entities"]]
        assert "doctor_name" in entity_types or "patient_name" in entity_types


class TestPHIEntity:
    """Tests for the PHIEntity dataclass."""

    def test_to_dict(self) -> None:
        """PHIEntity.to_dict() should return complete dict representation."""
        entity = PHIEntity(
            entity_type="ssn",
            value="123-45-6789",
            start=10,
            end=21,
            method="regex",
            confidence=0.95,
        )
        d = entity.to_dict()
        assert d["type"] == "ssn"
        assert d["value"] == "123-45-6789"
        assert d["start"] == 10
        assert d["end"] == 21
        assert d["method"] == "regex"
        assert d["confidence"] == 0.95
