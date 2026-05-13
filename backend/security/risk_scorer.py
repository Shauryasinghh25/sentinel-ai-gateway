"""
security/risk_scorer.py — Unified Risk Scoring System

Aggregates all security signals into a single risk score [0.0, 1.0]
and determines the appropriate action (allow / sanitize / block).

Risk score interpretation:
  0.00 - 0.30: NONE   → Allow
  0.30 - 0.60: LOW    → Allow with logging
  0.60 - 0.75: MEDIUM → Flag / Sanitize
  0.75 - 0.90: HIGH   → Block (configurable)
  0.90 - 1.00: CRITICAL → Block always
"""
from typing import List, Optional, Dict, Tuple
from dataclasses import dataclass, field

from backend.models.schemas import (
    RiskLevel, AttackType, GatewayAction,
    SecurityResult, SecurityViolation
)


@dataclass
class RiskSignal:
    """An individual security signal contributing to the final risk score."""
    source: str           # injection / toxicity / pii / rag / mcp / policy
    attack_type: str
    confidence: float     # 0.0 – 1.0
    severity: str         # critical / high / medium / low
    weight: float = 1.0   # relative importance in aggregation
    metadata: Dict = field(default_factory=dict)


class RiskScorer:
    """
    Aggregates multiple security signals into a final risk score and action decision.

    Design principles:
    - Critical signals always result in blocking
    - Multiple medium signals can escalate the risk level
    - Configurable thresholds via policy
    """

    SEVERITY_WEIGHTS = {
        "critical": 1.0,
        "high": 0.85,
        "medium": 0.65,
        "low": 0.35,
    }

    RISK_THRESHOLDS = {
        RiskLevel.CRITICAL: 0.90,
        RiskLevel.HIGH: 0.75,
        RiskLevel.MEDIUM: 0.60,
        RiskLevel.LOW: 0.30,
        RiskLevel.NONE: 0.0,
    }

    def __init__(
        self,
        block_threshold: float = 0.85,
        flag_threshold: float = 0.60,
    ):
        self.block_threshold = block_threshold
        self.flag_threshold = flag_threshold

    def compute(self, signals: List[RiskSignal]) -> Tuple[float, RiskLevel, GatewayAction]:
        """
        Compute aggregated risk score from multiple signals.

        Algorithm:
        1. If any critical signal → score = max(existing, 0.95)
        2. Weighted average of all signals
        3. Add multi-signal bonus (more signals = higher risk)
        4. Clamp to [0, 1]

        Returns:
            (risk_score, risk_level, recommended_action)
        """
        if not signals:
            return 0.0, RiskLevel.NONE, GatewayAction.ALLOWED

        # Check for critical signals
        has_critical = any(s.severity == "critical" for s in signals)

        # Weighted score
        total_weight = sum(s.weight * self.SEVERITY_WEIGHTS.get(s.severity, 0.5) for s in signals)
        weighted_conf = sum(
            s.confidence * s.weight * self.SEVERITY_WEIGHTS.get(s.severity, 0.5)
            for s in signals
        )

        base_score = weighted_conf / total_weight if total_weight > 0 else 0.0

        # Multi-signal escalation bonus
        multi_bonus = min(0.15, (len(signals) - 1) * 0.03)
        score = min(1.0, base_score + multi_bonus)

        # Critical floor
        if has_critical:
            score = max(score, 0.92)

        # Map to risk level
        risk_level = self._score_to_level(score)

        # Determine action
        action = self._score_to_action(score, has_critical)

        return round(score, 4), risk_level, action

    def _score_to_level(self, score: float) -> RiskLevel:
        if score >= self.RISK_THRESHOLDS[RiskLevel.CRITICAL]:
            return RiskLevel.CRITICAL
        elif score >= self.RISK_THRESHOLDS[RiskLevel.HIGH]:
            return RiskLevel.HIGH
        elif score >= self.RISK_THRESHOLDS[RiskLevel.MEDIUM]:
            return RiskLevel.MEDIUM
        elif score >= self.RISK_THRESHOLDS[RiskLevel.LOW]:
            return RiskLevel.LOW
        return RiskLevel.NONE

    def _score_to_action(self, score: float, has_critical: bool) -> GatewayAction:
        if has_critical or score >= self.block_threshold:
            return GatewayAction.BLOCKED
        elif score >= self.flag_threshold:
            return GatewayAction.FLAGGED
        return GatewayAction.ALLOWED

    def signals_to_violations(
        self,
        signals: List[RiskSignal],
        request_id: str = ""
    ) -> List[SecurityViolation]:
        """Convert raw signals into SecurityViolation objects."""
        violations = []
        for s in signals:
            try:
                attack_type = AttackType(s.attack_type)
            except ValueError:
                attack_type = AttackType.UNKNOWN

            violations.append(SecurityViolation(
                guard=s.source,
                attack_type=attack_type,
                risk_level=RiskLevel(
                    self._score_to_level(s.confidence * self.SEVERITY_WEIGHTS.get(s.severity, 0.5))
                ),
                message=f"{s.source}: {s.attack_type} detected",
                confidence=s.confidence,
                matched_pattern=s.metadata.get("pattern"),
                metadata=s.metadata,
            ))
        return violations
