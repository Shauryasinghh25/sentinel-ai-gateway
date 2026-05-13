"""
policy/engine.py — YAML-based Policy Engine

Loads, validates, and evaluates security policies.
Supports:
- Multiple named policies
- YAML configuration files
- Runtime policy updates
- Policy inheritance
"""
import yaml
import os
from pathlib import Path
from typing import Dict, Optional, List, Any
from loguru import logger

from backend.models.schemas import PolicyConfig


DEFAULT_POLICY_YAML = """
policies:
  default:
    name: "Default Security Policy"
    version: "1.0"
    toxicity_threshold: 0.8
    injection_confidence_threshold: 0.7
    risk_score_block_threshold: 0.85
    block_pii: true
    redact_pii: true
    block_financial_advice: false
    block_medical_advice: false
    block_code_execution: false
    block_political_content: false
    allowed_tools:
      - weather_api
      - calculator
      - currency_converter
      - text_formatter
    blocked_tools:
      - shell
      - exec
      - bash
      - delete_file
    allowed_topics: []
    blocked_topics:
      - illegal drugs
      - weapons manufacturing
    rate_limit_requests: 100
    rate_limit_window_seconds: 60
    preferred_model: "gpt-4o-mini"
    fallback_model: "gpt-3.5-turbo"
    allowed_providers:
      - openai
      - anthropic
      - google

  strict:
    name: "Strict Security Policy"
    version: "1.0"
    toxicity_threshold: 0.5
    injection_confidence_threshold: 0.5
    risk_score_block_threshold: 0.65
    block_pii: true
    redact_pii: true
    block_financial_advice: true
    block_medical_advice: true
    block_code_execution: true
    block_political_content: true
    allowed_tools:
      - calculator
      - weather_api
    blocked_tools: []
    allowed_topics: []
    blocked_topics: []
    rate_limit_requests: 50
    rate_limit_window_seconds: 60

  permissive:
    name: "Permissive Policy (Dev/Test)"
    version: "1.0"
    toxicity_threshold: 0.95
    injection_confidence_threshold: 0.90
    risk_score_block_threshold: 0.98
    block_pii: false
    redact_pii: true
    block_financial_advice: false
    block_medical_advice: false
    block_code_execution: false
    block_political_content: false
    allowed_tools: []
    blocked_tools:
      - shell
      - exec
    allowed_topics: []
    blocked_topics: []
    rate_limit_requests: 1000
    rate_limit_window_seconds: 60
"""


class PolicyEngine:
    """
    Policy evaluation and management engine.

    Loads policies from YAML files and evaluates them at runtime.
    """

    def __init__(self, policy_file: Optional[str] = None):
        self._policies: Dict[str, PolicyConfig] = {}
        self._raw_config: Dict[str, Any] = {}

        # Load default policies
        self._load_from_string(DEFAULT_POLICY_YAML)

        # Load custom policy file if provided
        if policy_file and Path(policy_file).exists():
            self.load_from_file(policy_file)
            logger.info(f"Loaded custom policy from {policy_file}")

    def _load_from_string(self, yaml_string: str):
        """Load policies from a YAML string."""
        try:
            config = yaml.safe_load(yaml_string)
            self._raw_config.update(config.get("policies", {}))
            self._parse_policies(config.get("policies", {}))
        except yaml.YAMLError as e:
            logger.error(f"Failed to parse policy YAML: {e}")

    def load_from_file(self, filepath: str):
        """Load policies from a YAML file."""
        try:
            with open(filepath, "r") as f:
                config = yaml.safe_load(f)
            if "policies" in config:
                self._raw_config.update(config["policies"])
                self._parse_policies(config["policies"])
                logger.info(f"Loaded {len(config['policies'])} policies from {filepath}")
        except (IOError, yaml.YAMLError) as e:
            logger.error(f"Failed to load policy file {filepath}: {e}")

    def _parse_policies(self, policies_dict: Dict[str, Any]):
        """Parse raw policy dict into PolicyConfig objects."""
        for policy_id, policy_data in policies_dict.items():
            if not isinstance(policy_data, dict):
                continue
            try:
                policy = PolicyConfig(
                    policy_id=policy_id,
                    **{k: v for k, v in policy_data.items()
                       if k in PolicyConfig.model_fields}
                )
                self._policies[policy_id] = policy
                logger.debug(f"Loaded policy: {policy_id}")
            except Exception as e:
                logger.error(f"Failed to parse policy '{policy_id}': {e}")

    def get_policy(self, policy_id: str = "default") -> PolicyConfig:
        """Get a policy by ID. Falls back to 'default' if not found."""
        if policy_id in self._policies:
            return self._policies[policy_id]
        logger.warning(f"Policy '{policy_id}' not found, using default")
        return self._policies.get("default", PolicyConfig())

    def list_policies(self) -> List[Dict[str, str]]:
        """List all available policies."""
        return [
            {
                "policy_id": p.policy_id,
                "name": p.name,
                "version": p.version,
            }
            for p in self._policies.values()
        ]

    def update_policy(self, policy_id: str, updates: Dict[str, Any]) -> PolicyConfig:
        """Update a policy's configuration at runtime."""
        existing = self.get_policy(policy_id)
        updated_data = existing.model_dump()
        updated_data.update(updates)
        updated = PolicyConfig(**updated_data)
        self._policies[policy_id] = updated
        logger.info(f"Updated policy '{policy_id}'")
        return updated

    def create_policy(self, policy_id: str, config: PolicyConfig) -> PolicyConfig:
        """Create a new policy."""
        config.policy_id = policy_id
        self._policies[policy_id] = config
        logger.info(f"Created new policy '{policy_id}'")
        return config

    def export_to_yaml(self) -> str:
        """Export all policies to YAML string."""
        data = {"policies": {}}
        for pid, policy in self._policies.items():
            data["policies"][pid] = policy.model_dump(
                exclude={"policy_id"}
            )
        return yaml.dump(data, default_flow_style=False, allow_unicode=True)

    def get_raw_config(self, policy_id: str) -> Dict[str, Any]:
        return self._raw_config.get(policy_id, {})
