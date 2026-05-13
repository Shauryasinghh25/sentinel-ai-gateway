
from __future__ import annotations
import time
from typing import Any, Dict, List

from backend.langgraph_agent.state import AgentState
from backend.dependencies import get_security_engine


# ── Helper ────────────────────────────────────────────────────────────────────

def _timer(state: AgentState, key: str, t0: float) -> Dict:
    """Return a node_latencies update dict for a single node."""
    latencies = dict(state.get("node_latencies") or {})
    latencies[key] = round((time.perf_counter() - t0) * 1000, 2)
    return {"node_latencies": latencies}


# ─────────────────────────────────────────────────────────────────────────────
# LAYER 1 — Core Detection
# ─────────────────────────────────────────────────────────────────────────────

def analyze_input_node(state: AgentState) -> Dict[str, Any]:
    """
    Delegates to the shared SecurityEngine singleton for the active policy.

    SecurityEngine is the single source of truth for:
      • Prompt injection detection
      • PII detection & redaction
      • Toxicity analysis
      • Topic policy enforcement
      • Risk aggregation → action decision

    The engine instance is retrieved from the shared cache in dependencies.py,
    ensuring that policy updates via PUT /policy/{id} take effect immediately.

    Populates:
        request_id, risk_score, risk_level, action, should_block,
        violations (serialised dicts with metadata), sanitized_text
    """
    t0 = time.perf_counter()
    text = state["input_text"]
    policy_id = (state.get("context") or {}).get("policy_id", "default")

    # Retrieve the per-policy singleton — same cache used by all other routers
    engine = get_security_engine(policy_id)
    result = engine.analyze_input(text)

    # Serialise SecurityViolation objects to plain dicts.
    # metadata is forwarded so Layer 3 (explain_decision) and any future
    # evaluation nodes can inspect full signal details.
    violations: List[Dict[str, Any]] = [
        {
            "guard":       v.guard,
            "attack_type": v.attack_type.value if hasattr(v.attack_type, "value") else v.attack_type,
            "confidence":  v.confidence,
            "message":     v.message,
            "risk_level":  v.risk_level.value if hasattr(v.risk_level, "value") else v.risk_level,
            "metadata":    v.metadata or {},
        }
        for v in result.violations
    ]

    update: Dict[str, Any] = {
        "request_id":     result.request_id,
        "risk_score":     result.risk_score,
        "risk_level":     result.risk_level.value if hasattr(result.risk_level, "value") else result.risk_level,
        "action":         result.action.value if hasattr(result.action, "value") else result.action,
        "should_block":   result.is_blocked,
        "violations":     violations,
        "sanitized_text": result.sanitized_text,
    }
    update.update(_timer(state, "analyze_input", t0))
    return update


# ─────────────────────────────────────────────────────────────────────────────
# LAYER 2 — Evaluation Pipeline  (future pluggable nodes)
# ─────────────────────────────────────────────────────────────────────────────
#
# Copy one of the stubs below, implement the body, then register the function
# in the EVALUATION_PIPELINE list inside graph.py — no other wiring needed.
#
# Contract every evaluation node must honour:
#   • Input  : AgentState  (read any existing field)
#   • Output : Dict[str, Any]  (partial state update)
#              MUST write:  pipeline_findings[<your_node_name>] = { ... }
#              MAY write:   action, should_block, risk_score  (to escalate)
#              MUST write:  node_latencies update via _timer()
# ─────────────────────────────────────────────────────────────────────────────

# ── Stub: RAG Validation ─────────────────────────────────────────────────────
# def rag_validation_node(state: AgentState) -> Dict[str, Any]:
#     """
#     Detect prompt injections hidden inside retrieved RAG documents.
#
#     Checks whether any retrieved context chunks contain adversarial instructions
#     that could override the LLM's behaviour (indirect prompt injection via RAG).
#
#     Writes into pipeline_findings["rag_validation"]:
#         poisoned_chunks : List[str]  — chunks that triggered injection patterns
#         escalated       : bool       — True if action was upgraded to "blocked"
#     """
#     t0 = time.perf_counter()
#     # TODO: implement
#     findings = {"poisoned_chunks": [], "escalated": False}
#     update: Dict[str, Any] = {"pipeline_findings": {"rag_validation": findings}}
#     update.update(_timer(state, "rag_validation", t0))
#     return update


# ── Stub: Tool Governance ─────────────────────────────────────────────────────
# def tool_governance_node(state: AgentState) -> Dict[str, Any]:
#     """
#     Validate that any tool calls requested in the input comply with the active
#     policy's allowed_tools / blocked_tools lists.
#
#     Writes into pipeline_findings["tool_governance"]:
#         blocked_tools   : List[str]  — tools denied by policy
#         escalated       : bool
#     """
#     t0 = time.perf_counter()
#     # TODO: implement
#     findings = {"blocked_tools": [], "escalated": False}
#     update: Dict[str, Any] = {"pipeline_findings": {"tool_governance": findings}}
#     update.update(_timer(state, "tool_governance", t0))
#     return update


# ── Stub: Memory Validation ───────────────────────────────────────────────────
# def memory_validation_node(state: AgentState) -> Dict[str, Any]:
#     """
#     Detect session-level replay attacks and memory poisoning.
#     Compares the current input against session history stored in context.
#
#     Writes into pipeline_findings["memory_validation"]:
#         replay_detected : bool
#         similar_inputs  : List[str]
#     """
#     t0 = time.perf_counter()
#     # TODO: implement
#     findings = {"replay_detected": False, "similar_inputs": []}
#     update: Dict[str, Any] = {"pipeline_findings": {"memory_validation": findings}}
#     update.update(_timer(state, "memory_validation", t0))
#     return update


# ── Stub: Human Approval (LangGraph interrupt-based) ─────────────────────────
# def human_approval_node(state: AgentState) -> Dict[str, Any]:
#     """
#     Pause graph execution and wait for a human reviewer to approve or reject.
#     Uses LangGraph's interrupt() primitive — requires a checkpointer backend.
#
#     Only insert this node for high-risk actions; use a conditional edge
#     from analyze_input_node that routes here only when risk_level == "critical".
#
#     Writes into pipeline_findings["human_approval"]:
#         approved  : bool
#         reviewer  : str
#         notes     : str
#     """
#     from langgraph.types import interrupt
#     t0 = time.perf_counter()
#     # TODO: implement
#     decision = interrupt({"question": "Approve this request?", "state": state})
#     findings = {"approved": decision.get("approved", False), "reviewer": decision.get("reviewer", "")}
#     if not findings["approved"]:
#         # escalate
#         update: Dict[str, Any] = {"action": "blocked", "should_block": True,
#                                    "pipeline_findings": {"human_approval": findings}}
#     else:
#         update = {"pipeline_findings": {"human_approval": findings}}
#     update.update(_timer(state, "human_approval", t0))
#     return update


# ─────────────────────────────────────────────────────────────────────────────
# LAYER 3 — Explainer
# ─────────────────────────────────────────────────────────────────────────────

def explain_decision(state: AgentState) -> Dict[str, Any]:
    """
    Synthesises ALL signals into a human-readable explanation and concrete
    remediation recommendations — this is the agentic value-add.

    Sources:
      • state["violations"]        — standardised SecurityEngine findings
      • state["pipeline_findings"] — augmentations from evaluation pipeline nodes
      • state["action"], ["risk_score"], ["risk_level"]

    Consumes violations by guard name so new violation sources added to
    SecurityEngine surface automatically without changes here.
    In a future version this node can call an LLM for richer, context-aware
    explanations (just replace the rule-based blocks below).
    """
    t0 = time.perf_counter()

    action      = state.get("action", "allowed")
    risk_score  = state.get("risk_score", 0.0)
    risk_level  = state.get("risk_level", "none")
    violations  = state.get("violations") or []
    pipeline    = state.get("pipeline_findings") or {}

    # ── Group violations by guard for targeted explanation ────────────────────
    def _by_guard(guard: str) -> List[Dict]:
        return [v for v in violations if v.get("guard") == guard]

    inj_violations    = _by_guard("prompt_injection")
    pii_violations    = _by_guard("pii_detection")
    tox_violations    = _by_guard("toxicity")
    policy_violations = _by_guard("policy_topic")
    # Future guards surface here automatically — no code change needed.
    other_violations  = [
        v for v in violations
        if v.get("guard") not in {"prompt_injection", "pii_detection", "toxicity", "policy_topic"}
    ]

    # ── Build explanation ─────────────────────────────────────────────────────
    parts: List[str] = []

    action_label = {
        "blocked":   f"Request BLOCKED (risk score {risk_score:.2f} — {risk_level}). "
                     "The content was identified as a security threat.",
        "flagged":   f"Request FLAGGED for review (risk score {risk_score:.2f} — {risk_level}). "
                     "Suspicious signals detected but below hard-block threshold.",
        "sanitized": f"Request SANITIZED (risk score {risk_score:.2f}). "
                     "PII was redacted before forwarding.",
    }.get(action, f"Request ALLOWED (risk score {risk_score:.2f} — {risk_level}). "
                  "No significant threats detected.")
    parts.append(action_label)

    # Injection detail
    if inj_violations:
        primary = max(inj_violations, key=lambda v: v["confidence"])
        matched = primary.get("metadata", {}).get("matched_text", "")
        snippet = f' (matched: "{matched[:40]}")' if matched else ""
        parts.append(
            f"Injection detection: '{primary['attack_type']}' pattern matched "
            f"with {primary['confidence']:.0%} confidence{snippet}."
        )

    # PII detail
    if pii_violations:
        pii_types: List[str] = []
        for v in pii_violations:
            pii_types.extend(v.get("metadata", {}).get("pii_types", []))
        unique_types = list(dict.fromkeys(pii_types))  # deduplicate, preserve order
        label = ", ".join(unique_types[:4]) if unique_types else "sensitive data"
        parts.append(
            f"PII detected: {label}. "
            "Sensitive data has been redacted in the sanitized version."
        )

    # Toxicity detail
    if tox_violations:
        categories: List[str] = [
            v.get("metadata", {}).get("category", v["attack_type"])
            for v in tox_violations
        ]
        parts.append(f"Toxicity signals: {', '.join(dict.fromkeys(categories))[:3]}.")

    # Policy topic detail
    if policy_violations:
        topics = [v.get("metadata", {}).get("policy_topic", "") for v in policy_violations]
        parts.append(f"Policy violation: topic(s) blocked by active policy — {', '.join(t for t in topics if t)}.")

    # Other / future guard detail
    for v in other_violations:
        parts.append(f"Security signal from guard '{v['guard']}': {v['message']}.")

    # Pipeline findings from evaluation nodes
    for node_name, findings in pipeline.items():
        if isinstance(findings, dict):
            if findings.get("escalated") or findings.get("approved") is False:
                parts.append(f"Evaluation node '{node_name}' escalated the verdict.")

    explanation = " ".join(parts)

    # ── Build recommendations ─────────────────────────────────────────────────
    recommendations: List[str] = []

    if action == "blocked":
        recommendations.append("Do not forward this request to the LLM.")
        recommendations.append("Log the event and notify your security team.")
        if any(v["attack_type"] == "jailbreak" for v in inj_violations):
            recommendations.append(
                "Consider rate-limiting or banning this user session — "
                "jailbreaks are intentional abuse."
            )
        if policy_violations:
            recommendations.append(
                "Review your active policy's blocked topic list to confirm this "
                "restriction is intentional."
            )

    elif action == "flagged":
        recommendations.append("Queue for human review before allowing LLM processing.")
        recommendations.append(
            f"Consider lowering the block threshold below {risk_score:.2f} "
            "if this pattern recurs frequently."
        )

    elif action == "sanitized":
        recommendations.append("Forward sanitized_text (not the original) to the LLM.")
        pii_list = []
        for v in pii_violations:
            pii_list.extend(v.get("metadata", {}).get("pii_types", []))
        if pii_list:
            recommendations.append(
                f"Audit why users are sending {', '.join(dict.fromkeys(pii_list))} — "
                "consider UX changes to prevent accidental PII exposure."
            )

    else:
        recommendations.append("Request is safe to forward to the LLM.")

    # Evaluation-pipeline recommendations
    for node_name, findings in pipeline.items():
        if isinstance(findings, dict):
            if findings.get("poisoned_chunks"):
                recommendations.append(
                    f"RAG validation flagged {len(findings['poisoned_chunks'])} "
                    "potentially poisoned context chunk(s). Inspect your retrieval pipeline."
                )
            if findings.get("blocked_tools"):
                recommendations.append(
                    f"Tool governance blocked: {', '.join(findings['blocked_tools'])}. "
                    "Update the policy allowlist if this was unintended."
                )
            if findings.get("replay_detected"):
                recommendations.append(
                    "Memory validation detected a repeated/replay input pattern. "
                    "Consider invalidating this session."
                )

    # ── Compute total latency ─────────────────────────────────────────────────
    node_latencies = dict(state.get("node_latencies") or {})
    node_latencies["explain_decision"] = round((time.perf_counter() - t0) * 1000, 2)
    total_ms = round(sum(node_latencies.values()), 2)

    return {
        "explanation":      explanation,
        "recommendations":  recommendations,
        "node_latencies":   node_latencies,
        "total_latency_ms": total_ms,
    }
