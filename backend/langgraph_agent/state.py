"""
langgraph_agent/state.py — Shared state type for the SentinelAI security graph.

The AgentState dict is passed between every node in the graph.
Each node reads what it needs and writes its results back.

Architecture — three conceptual layers
────────────────────────────────────────
  Layer 1 │ CORE DETECTION       analyze_input_node
           │                     Populated fields: request_id, risk_score, risk_level,
           │                     action, should_block, violations, sanitized_text
           │
  Layer 2  │ EVALUATION PIPELINE (pluggable, ordered — see graph.py)
           │                     Future nodes write into pipeline_findings[<node_name>]
           │                     and may escalate action / should_block.
           │                     Examples: rag_validation_node, tool_governance_node,
           │                               memory_validation_node, human_approval_node
           │
  Layer 3  │ EXPLAINER           explain_decision
           │                     Consumes violations + pipeline_findings to produce
           │                     a human-readable explanation + recommendations.
"""
from __future__ import annotations
from typing import TypedDict, List, Optional, Any, Dict, Annotated


def merge_dicts(a: Dict, b: Dict) -> Dict:
    """LangGraph reducer: merge two dicts, right value wins on key collision."""
    res = (a or {}).copy()
    res.update(b or {})
    return res


# ── Violation format stored in state ─────────────────────────────────────────
# Mirrors SecurityViolation but as a plain TypedDict so the graph state
# remains JSON-serialisable without depending on Pydantic models at runtime.

class ViolationDict(TypedDict):
    guard: str                  # source engine: prompt_injection / pii_detection / toxicity / …
    attack_type: str            # AttackType enum value string
    confidence: float
    message: str
    risk_level: str             # RiskLevel enum value string
    metadata: Dict[str, Any]    # rich signal metadata forwarded from SecurityEngine


# ── Main graph state ──────────────────────────────────────────────────────────

class AgentState(TypedDict):

    # ── Input ─────────────────────────────────────────────────────────────────
    input_text: str                      # Original user text to analyse
    context: Optional[Dict[str, Any]]   # Extra metadata (user_id, session_id, policy_id, …)

    # ── Layer 1: Core engine results (populated by analyze_input_node) ────────
    request_id: Optional[str]            # Correlation ID from SecurityEngine
    risk_score: float                    # 0.0 – 1.0
    risk_level: str                      # none / low / medium / high / critical
    action: str                          # allowed / blocked / sanitized / flagged
    should_block: bool
    violations: List[ViolationDict]      # Standardised signals from SecurityEngine
    sanitized_text: Optional[str]        # Redacted version (if PII found + redact_pii=True)

    # ── Layer 2: Extension pipeline results (populated by evaluation nodes) ───
    # Each evaluation node in EVALUATION_PIPELINE writes its findings under its
    # own key so they are independently inspectable and don't clobber each other.
    #
    # Convention:  pipeline_findings["<node_name>"] = { ... node-specific dict ... }
    #
    # Examples of future node outputs:
    #   pipeline_findings["rag_validation"]   = {"poisoned_docs": [...], "escalated": True}
    #   pipeline_findings["tool_governance"]  = {"blocked_tools": [...]}
    #   pipeline_findings["memory_validation"]= {"replay_detected": False}
    #   pipeline_findings["human_approval"]   = {"approved": True, "reviewer": "alice"}
    pipeline_findings: Annotated[Dict[str, Any], merge_dicts]

    # ── Layer 3: Explanation (populated by explain_decision) ──────────────────
    explanation: str                     # Human-readable reasoning
    recommendations: List[str]           # Suggested mitigations

    # ── Timing ────────────────────────────────────────────────────────────────
    node_latencies: Annotated[Dict[str, float], merge_dicts]   # Per-node timing (ms)
    total_latency_ms: float
