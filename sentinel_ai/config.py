# sentinel_ai/config.py
# Configuration loader for Sentinel AI.
# Reads environment variables and provides typed access to all settings.

import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

from dotenv import load_dotenv

# Load .env file if present
load_dotenv()


class SentinelConfig:
    """Central configuration for Sentinel AI and the Prime agent."""

    def __init__(self) -> None:
        """Initialize configuration from environment variables and policy file."""
        self.groq_api_key: str = os.getenv("GROQ_API_KEY", "")
        self.hindsight_api_key: str = os.getenv("HINDSIGHT_API_KEY", "")
        self.hindsight_enabled: bool = os.getenv("HINDSIGHT_ENABLED", "true").lower() == "true"
        self.policy_file: str = os.getenv("POLICY_FILE", "policies/hipaa.json")
        self.audit_log_path: str = os.getenv("AUDIT_LOG_PATH", "audit.log")
        self.log_level: str = os.getenv("LOG_LEVEL", "INFO")
        self.agent_name: str = os.getenv("AGENT_NAME", "Prime")
        self.project_name: str = os.getenv("PROJECT_NAME", "Sentinel AI")
        self.host: str = os.getenv("HOST", "0.0.0.0")
        self.port: int = int(os.getenv("PORT", "8000"))

        # Load policy
        self.policy: Dict[str, Any] = self._load_policy()

    def _load_policy(self) -> Dict[str, Any]:
        """Load the compliance policy from the JSON file.

        Returns:
            Dict containing the full policy configuration.
            Falls back to a minimal default if the file is not found.
        """
        policy_path = Path(self.policy_file)
        if not policy_path.is_absolute():
            # Resolve relative to project root
            project_root = Path(__file__).parent.parent
            policy_path = project_root / policy_path

        try:
            with open(policy_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except FileNotFoundError:
            print(f"[WARNING] Policy file not found at {policy_path}. Using minimal defaults.")
            return self._default_policy()
        except json.JSONDecodeError as e:
            print(f"[WARNING] Invalid JSON in policy file: {e}. Using minimal defaults.")
            return self._default_policy()

    @staticmethod
    def _default_policy() -> Dict[str, Any]:
        """Return a minimal fallback policy when the policy file is unavailable.

        Returns:
            Dict with default HIPAA policy settings.
        """
        return {
            "framework": "HIPAA",
            "phi_identifiers": ["patient_name", "ssn", "dob", "phone", "email"],
            "approved_models": ["groq/openai-gpt-oss-120b", "ollama/llama3.1"],
            "blocked_models": ["openai/gpt-4", "anthropic/claude-3-opus", "openai/gpt-4o"],
            "redaction_strategy": "mask",
            "redaction_placeholder": "[REDACTED-{TYPE}]",
            "audit_required": True,
            "enable_hindsight_memory": True,
            "agent_name": "Prime",
            "project_name": "Sentinel AI",
        }

    @property
    def approved_models(self) -> List[str]:
        """Get list of approved models from policy."""
        return self.policy.get("approved_models", [])

    @property
    def blocked_models(self) -> List[str]:
        """Get list of blocked models from policy."""
        return self.policy.get("blocked_models", [])

    @property
    def phi_identifiers(self) -> List[str]:
        """Get list of PHI identifier categories from policy."""
        return self.policy.get("phi_identifiers", [])

    @property
    def redaction_strategy(self) -> str:
        """Get the redaction strategy from policy."""
        return self.policy.get("redaction_strategy", "mask")

    @property
    def confidence_threshold(self) -> float:
        """Get confidence threshold for PHI detection."""
        return float(self.policy.get("confidence_threshold", 0.7))

    @property
    def default_model(self) -> str:
        """Get the default model to use for routing."""
        return self.policy.get("default_model", "groq/openai-gpt-oss-120b")

    @property
    def fallback_model(self) -> str:
        """Get the fallback model."""
        return self.policy.get("fallback_model", "ollama/llama3.1")


# Global singleton
config = SentinelConfig()
