"""
security/engine.py — Main Security Engine Orchestrator

Ties together all security components:
- Prompt injection detection
- PII detection & redaction
- Toxicity analysis
- Policy evaluation
- Risk scoring

This is the single entry point for all security checks.
"""
import time
import uuid
from typing import Optional, Dict, Any

from backend.security.injection import PromptInjectionEngine
from backend.security.pii import PIIEngine
from backend.security.toxicity import ToxicityEngine
from backend.security.risk_scorer import RiskScorer, RiskSignal
from backend.models.schemas import (
    SecurityResult, SecurityViolation, GatewayAction,
    AttackType, RiskLevel, PolicyConfig
)
POLICY_PATTERNS = {
    "financial_advice": [
        "stocks",
        "investment",
        "portfolio",
        "crypto",
        "trading",
        "buy shares",
        "market prediction",
        "financial advice",
    ],

    "medical_advice": [
        "diagnose",
        "treatment",
        "medicine",
        "symptoms",
        "dosage",
        "prescription",
        "disease",
    ],

    "code_execution": [
        "execute code",
        "run shell",
        "bash script",
        "powershell",
        "subprocess",
        "exec(",
        "terminal command",
    ],

    "political_content": [
        "vote for",
        "election campaign",
        "political propaganda",
        "party manifesto",
        "political strategy",
    ],
}

class SecurityEngine:
    """
    Central security orchestrator for SentinelAI Gateway.

    Usage:
        engine = SecurityEngine()
        result = await engine.analyze_input(text, policy)
        if result.is_blocked:
            return blocked_response()
    """

    def __init__(self, policy: Optional[PolicyConfig] = None):
        self.policy = policy or PolicyConfig()
        self.injection_engine = PromptInjectionEngine()
        self.pii_engine = PIIEngine()
        self.toxicity_engine = ToxicityEngine()
        self.risk_scorer = RiskScorer(
            block_threshold=self.policy.risk_score_block_threshold,
            flag_threshold=0.60,
        )

    def update_policy(self, policy: PolicyConfig):
        self.policy = policy
        self.risk_scorer = RiskScorer(
            block_threshold=policy.risk_score_block_threshold,
        )

    def analyze_input(
        self,
        text: str,
        context: Optional[Dict[str, Any]] = None,
        policy_override: Optional[PolicyConfig] = None,
    ) -> SecurityResult:
        """
        Full security analysis on user input.

        Steps:
        1. Prompt injection detection
        2. PII detection/redaction
        3. Toxicity analysis
        4. Topic policy check
        5. Risk aggregation → action decision

        Returns SecurityResult with risk score, action, and violations.
        """
        active_policy = policy_override or self.policy
        active_scorer = RiskScorer(block_threshold=active_policy.risk_score_block_threshold, flag_threshold=0.60) if policy_override else self.risk_scorer

        t0 = time.perf_counter()
        request_id = str(uuid.uuid4())
        signals: list[RiskSignal] = []
        sanitized_text = text

        # ── 1. Prompt Injection ───────────────────────────────────────────────
        inj_matches, inj_score, inj_attack_type = self.injection_engine.analyze(text)

        if inj_matches:
            primary_match = max(inj_matches, key=lambda m: m.confidence)
            signals.append(RiskSignal(
                source="prompt_injection",
                attack_type=inj_attack_type,
                confidence=inj_score,
                severity=primary_match.severity,
                weight=1.5,  # Injection is weighted higher
                metadata={
                    "pattern": primary_match.pattern,
                    "matched_text": primary_match.matched_text,
                    "match_count": len(inj_matches),
                }
            ))

        # ── 2. PII Detection ──────────────────────────────────────────────────
        has_pii, pii_matches, redacted_text = self.pii_engine.detect(text)
        if has_pii:
            pii_types = self.pii_engine.get_unique_types(pii_matches)
            is_block = active_policy.block_pii
            signals.append(RiskSignal(
                source="pii_detection",
                attack_type="pii_leakage",
                confidence=max(m.confidence for m in pii_matches),
                severity="high" if is_block else "medium",
                weight=1.2,
                metadata={
                    "pii_types": list(pii_types),
                    "match_count": len(pii_matches),
                    "redacted": True,
                }
            ))
            if active_policy.redact_pii:
                sanitized_text = redacted_text

        # ── 3. Toxicity ───────────────────────────────────────────────────────
        tox_matches, tox_score = self.toxicity_engine.analyze(text)
        if tox_matches and tox_score >= active_policy.toxicity_threshold:
            primary_tox = max(tox_matches, key=lambda m: m.confidence)
            signals.append(RiskSignal(
                source="toxicity",
                attack_type="toxicity",
                confidence=tox_score,
                severity=primary_tox.severity,
                weight=1.4,
                metadata={
                    "category": primary_tox.category,
                    "matched_text": primary_tox.matched_text,
                }
            ))

      
        # ── 4. Policy-Based Topic Detection ──────────────────────────────────
        lower = text.lower()

        policy_checks = [ 
            ("financial_advice", active_policy.block_financial_advice), 
            ("medical_advice", active_policy.block_medical_advice),
            ("code_execution", active_policy.block_code_execution), 
            ("political_content", active_policy.block_political_content), 
            ]

        for topic_name, enabled in policy_checks:
             if not enabled:
                 continue

             patterns = POLICY_PATTERNS.get(topic_name, [])

             for pattern in patterns:
                 if pattern.lower() in lower:
                    signals.append(
                        RiskSignal(
                            source="policy_topic",
                            attack_type="unknown",
                            confidence=0.95,
                            severity="high",
                             weight=1.3,
                            metadata={
                                    "policy_topic": topic_name,
                                    "matched_pattern": pattern,
                        
                                  }
                        )
                    )
                    break


        # ── 5. Aggregate Risk Score ───────────────────────────────────────────
        risk_score, risk_level, action = active_scorer.compute(signals)

        # Override: if PII detected and policy says block → force block
        if has_pii and active_policy.block_pii and action != GatewayAction.BLOCKED:
            action = GatewayAction.BLOCKED

        # Override: if sanitized, mark as sanitized instead of allowed
        if sanitized_text != text and action == GatewayAction.ALLOWED:
            action = GatewayAction.SANITIZED

        violations = active_scorer.signals_to_violations(signals, request_id)

        latency_ms = (time.perf_counter() - t0) * 1000

        return SecurityResult(
            request_id=request_id,
            action=action,
            risk_score=risk_score,
            risk_level=risk_level,
            violations=violations,
            original_text=text,
            sanitized_text=sanitized_text if sanitized_text != text else None,
            latency_ms=round(latency_ms, 3),
        )

    def analyze_output(
        self,
        output: str,
        original_input: str = "",
        context: Optional[Dict[str, Any]] = None,
        policy_override: Optional[PolicyConfig] = None,
    ) -> SecurityResult:
        """
        Security analysis on LLM output (response validation).

        Checks:
        - PII in output (data leakage prevention)
        - Toxicity in response
        - Hallucination indicators (basic)
        """
        # Resolve active policy and scorer — mirrors analyze_input pattern
        active_policy = policy_override or self.policy
        active_scorer = (
            RiskScorer(
                block_threshold=active_policy.risk_score_block_threshold,
                flag_threshold=0.60,
            )
            if policy_override
            else self.risk_scorer
        )

        t0 = time.perf_counter()
        request_id = str(uuid.uuid4())
        signals: list[RiskSignal] = []
        sanitized_text = output

        # PII in output
        has_pii, pii_matches, redacted_output = self.pii_engine.detect(output)
        if has_pii:
            pii_types = self.pii_engine.get_unique_types(pii_matches)
            signals.append(RiskSignal(
                source="pii_output",
                attack_type="pii_leakage",
                confidence=max(m.confidence for m in pii_matches),
                severity="high",
                weight=1.2,
                metadata={"pii_types": list(pii_types)}
            ))
            if active_policy.redact_pii:
                sanitized_text = redacted_output

        # Toxicity in output
        tox_matches, tox_score = self.toxicity_engine.analyze(output)
        if tox_matches and tox_score >= active_policy.toxicity_threshold:
            primary = max(tox_matches, key=lambda m: m.confidence)
            signals.append(RiskSignal(
                source="toxicity_output",
                attack_type="toxicity",
                confidence=tox_score,
                severity=primary.severity,
                weight=1.4,
                metadata={"category": primary.category}
            ))
        # ── Policy-Based Topic Detection ────────────────────────────────────
        lower = output.lower()

        policy_checks = [
             ("financial_advice", active_policy.block_financial_advice),
             ("medical_advice", active_policy.block_medical_advice),
             ("code_execution", active_policy.block_code_execution),
             ("political_content", active_policy.block_political_content),
        ]

        for topic_name, enabled in policy_checks:
          if not enabled:
             continue

          patterns = POLICY_PATTERNS.get(topic_name, [])

          for pattern in patterns:
            if pattern.lower() in lower:
                signals.append(
                    RiskSignal(
                        source="policy_topic_output",
                        attack_type="policy_violation",
                        confidence=0.95,
                        severity="high",
                        weight=1.3,
                        metadata={
                            "policy_topic": topic_name,
                            "matched_pattern": pattern,
                        }
                    )
                )
                break



        risk_score, risk_level, action = active_scorer.compute(signals)
        violations = active_scorer.signals_to_violations(signals, request_id)

        if sanitized_text != output and action == GatewayAction.ALLOWED:
            action = GatewayAction.SANITIZED

        latency_ms = (time.perf_counter() - t0) * 1000

        return SecurityResult(
            request_id=request_id,
            action=action,
            risk_score=risk_score,
            risk_level=risk_level,
            violations=violations,
            original_text=output,
            sanitized_text=sanitized_text if sanitized_text != output else None,
            latency_ms=round(latency_ms, 3),
        )
        
    