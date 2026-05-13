"""
langgraph_agent/graph.py — SentinelAI Security StateGraph

Current topology:

    START
      │
      ▼
  analyze_input      ← SecurityEngine delegation (single source of truth)
      │
     [evaluation pipeline — zero or more pluggable nodes]
      │
      ▼
  explain_decision   ← synthesises violations + pipeline findings
      │
      ▼
     END

Adding a future evaluation node
────────────────────────────────
1. Implement your node function in nodes.py following the Layer 2 contract.
2. Import it here.
3. Append it to EVALUATION_PIPELINE:
       EVALUATION_PIPELINE = [
           ("rag_validation", rag_validation_node),
       ]
That's it — graph wiring, state threading, and explain_decision consumption
are all automatic.

For human-in-the-loop nodes that require LangGraph interrupts, pass a
checkpointer to builder.compile(checkpointer=...) and use interrupt() inside
the node.  Conditional routing (e.g. only run human_approval when
risk_level=="critical") can be added via builder.add_conditional_edges().
"""
from __future__ import annotations
from typing import Callable, List, Tuple

from langgraph.graph import StateGraph, START, END

from backend.langgraph_agent.state import AgentState
from backend.langgraph_agent.nodes import (
    analyze_input_node,
    explain_decision,
    # ── Future evaluation nodes — uncomment as you implement them ─────────────
    # rag_validation_node,
    # tool_governance_node,
    # memory_validation_node,
    # human_approval_node,
    # multi_agent_review_node,
)


# ── Evaluation pipeline registry ──────────────────────────────────────────────
# Ordered list of (node_id, node_fn) tuples that run between
# analyze_input and explain_decision.
#
# Rules:
#   • Nodes execute sequentially in list order (preserves causal reasoning).
#   • Each node may read all prior state, including other nodes' pipeline_findings.
#   • Add parallel branches via builder.add_conditional_edges() for independent
#     nodes that don't need each other's output.
#
EVALUATION_PIPELINE: List[Tuple[str, Callable]] = [
    # ("rag_validation",    rag_validation_node),
    # ("tool_governance",   tool_governance_node),
    # ("memory_validation", memory_validation_node),
    # ("human_approval",    human_approval_node),
]


# ── Graph builder ─────────────────────────────────────────────────────────────

def _build_graph() -> StateGraph:
    """
    Construct and compile the security evaluation graph.

    The topology is driven by EVALUATION_PIPELINE, so the graph automatically
    adapts when nodes are added or removed from that list.
    """
    builder = StateGraph(AgentState)

    # ── Layer 1: Core detection ───────────────────────────────────────────────
    builder.add_node("analyze_input", analyze_input_node)
    builder.add_edge(START, "analyze_input")

    # ── Layer 2: Evaluation pipeline (dynamic, ordered) ───────────────────────
    prev_node = "analyze_input"
    for node_id, node_fn in EVALUATION_PIPELINE:
        builder.add_node(node_id, node_fn)
        builder.add_edge(prev_node, node_id)
        prev_node = node_id

    # ── Layer 3: Explainer ───────────────────────────────────────────────────
    builder.add_node("explain_decision", explain_decision)
    builder.add_edge(prev_node, "explain_decision")
    builder.add_edge("explain_decision", END)

    return builder.compile()


# ── Graph singleton ───────────────────────────────────────────────────────────
# A module-level singleton so compilation (which validates the graph structure)
# only happens once.  Call _reset_graph() in tests to force a rebuild.

_graph: StateGraph | None = None


def get_security_graph() -> StateGraph:
    """Return the compiled graph singleton, building it on first call."""
    global _graph
    if _graph is None:
        _graph = _build_graph()
    return _graph


def _reset_graph() -> None:
    """Force the graph to be rebuilt on the next call to get_security_graph().
    Useful in tests when EVALUATION_PIPELINE is mutated between test cases."""
    global _graph
    _graph = None


# ── Graph topology introspection ──────────────────────────────────────────────

def get_graph_topology() -> dict:
    """
    Return a machine-readable description of the current graph topology.
    Consumed by GET /agent/graph/info so the dashboard always reflects reality.
    """
    nodes = [
        {
            "id":          "analyze_input",
            "type":        "core_detection",
            "layer":       1,
            "description": (
                "Delegates to SecurityEngine.analyze_input() — the single source of truth. "
                "Runs prompt injection, PII, toxicity, and topic policy checks."
            ),
        }
    ]
    edges = [{"from": "START", "to": "analyze_input"}]

    prev = "analyze_input"
    for node_id, _ in EVALUATION_PIPELINE:
        nodes.append({
            "id":          node_id,
            "type":        "evaluation",
            "layer":       2,
            "description": f"Evaluation pipeline node: {node_id}",
        })
        edges.append({"from": prev, "to": node_id})
        prev = node_id

    nodes.append({
        "id":          "explain_decision",
        "type":        "explainer",
        "layer":       3,
        "description": (
            "Synthesises violations and pipeline findings into a human-readable "
            "explanation with remediation recommendations."
        ),
    })
    edges.append({"from": prev, "to": "explain_decision"})
    edges.append({"from": "explain_decision", "to": "END"})

    return {
        "graph_name":        "SentinelAI Security Graph",
        "version":           "2.0",
        "architecture":      "layered-pipeline",
        "layers": {
            "1_core_detection":    ["analyze_input"],
            "2_evaluation":        [n for n, _ in EVALUATION_PIPELINE],
            "3_explainer":         ["explain_decision"],
        },
        "nodes":             nodes,
        "edges":             edges,
        "evaluation_pipeline_active": [n for n, _ in EVALUATION_PIPELINE],
        "description": (
            "A LangGraph StateGraph where SecurityEngine is the single source of truth "
            "for all detection. Optional evaluation nodes (Layer 2) can be registered in "
            "EVALUATION_PIPELINE to extend the pipeline without modifying core detection."
        ),
    }


# ── Public entrypoint ─────────────────────────────────────────────────────────

async def run_security_analysis(
    text: str,
    context: dict | None = None,
    policy_id: str = "default",
) -> AgentState:
    """
    Run the full agentic security analysis pipeline on a piece of text.

    Args:
        text:       The user input / LLM output to analyse.
        context:    Optional metadata dict (user_id, session_id, …).
                    policy_id inside context takes precedence over the
                    top-level policy_id argument.
        policy_id:  Active policy to apply.  Resolved via the shared
                    SecurityEngine cache in dependencies.py.

    Returns:
        Final AgentState with all fields populated.
    """
    graph = get_security_graph()

    # Merge policy_id into context so analyze_input_node can read it
    merged_context: dict = dict(context or {})
    merged_context.setdefault("policy_id", policy_id)

    initial_state: AgentState = {
        # Input
        "input_text":       text,
        "context":          merged_context,
        # Layer 1 — populated by analyze_input_node
        "request_id":       None,
        "risk_score":       0.0,
        "risk_level":       "none",
        "action":           "allowed",
        "should_block":     False,
        "violations":       [],
        "sanitized_text":   None,
        # Layer 2 — populated by evaluation pipeline nodes
        "pipeline_findings": {},
        # Layer 3 — populated by explain_decision
        "explanation":      "",
        "recommendations":  [],
        # Timing
        "node_latencies":   {},
        "total_latency_ms": 0.0,
    }

    final_state: AgentState = await graph.ainvoke(initial_state)
    return final_state
