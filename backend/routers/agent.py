"""
routers/agent.py — LangGraph Agentic Security Analysis Endpoints

POST /agent/analyze          - Full agentic analysis with explanation
POST /agent/analyze/batch    - Analyse multiple texts in one call
GET  /agent/graph/info       - Returns live graph topology metadata
"""
from __future__ import annotations
import asyncio
from typing import List, Optional, Dict, Any

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from backend.gateway.auth import get_current_user, TokenData
from backend.langgraph_agent import run_security_analysis
from backend.langgraph_agent.graph import get_graph_topology
from backend.observability.metrics import metrics


router = APIRouter(prefix="/agent", tags=["LangGraph Agent"])


# ── Request / Response schemas ────────────────────────────────────────────────

class AnalyzeRequest(BaseModel):
    text: str
    policy_id: Optional[str] = "default"
    context: Optional[Dict[str, Any]] = None


class BatchAnalyzeRequest(BaseModel):
    texts: List[str]
    policy_id: Optional[str] = "default"
    context: Optional[Dict[str, Any]] = None


class ViolationOut(BaseModel):
    guard: str
    attack_type: str
    confidence: float
    message: str
    risk_level: str
    metadata: Dict[str, Any] = {}


class AnalyzeResponse(BaseModel):
    # Correlation
    request_id: Optional[str] = None

    # Decision (from SecurityEngine via analyze_input_node)
    action: str
    risk_score: float
    risk_level: str
    should_block: bool

    # Standardised violations (replaces legacy match arrays)
    violations: List[ViolationOut]

    # Sanitized content
    sanitized_text: Optional[str]

    # Evaluation pipeline augmentations
    # Keys are node names; values are node-specific finding dicts.
    # Empty when no evaluation pipeline nodes are active.
    pipeline_findings: Dict[str, Any] = {}

    # Agent explanation (the value-add vs the simple /security/check endpoint)
    explanation: str
    recommendations: List[str]

    # Performance — keyed by node name, so new pipeline nodes appear automatically
    node_latencies: Dict[str, float]
    total_latency_ms: float


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.post("/analyze", response_model=AnalyzeResponse)
async def analyze(
    request: AnalyzeRequest,
    current_user: TokenData = Depends(get_current_user),
):
    """
    Run the full LangGraph agentic security pipeline on a single text.

    Compared to /security/check/input, this endpoint:
    - Delegates detection to SecurityEngine (single source of truth)
    - Returns per-node timing breakdown (latency for each pipeline stage)
    - Surfaces raw violation metadata for deep inspection
    - Provides a human-readable explanation of WHY the decision was made
    - Gives concrete remediation recommendations
    - Exposes pipeline_findings from any active evaluation nodes
    """
    state = await run_security_analysis(
        text=request.text,
        context=request.context,
        policy_id=request.policy_id or "default",
    )
    
    # Instrumentation
    metrics.record_security_check(
        latency_ms=state.get("total_latency_ms", 0.0),
        violations=len(state.get("violations") or []),
        risk_score=state.get("risk_score", 0.0),
        attack_types=[
            v.get("attack_type") if isinstance(v, dict) else v.attack_type.value
            for v in (state.get("violations") or [])
        ]
    )

    return _state_to_response(state)


@router.post("/analyze/batch", response_model=List[AnalyzeResponse])
async def analyze_batch(
    request: BatchAnalyzeRequest,
    current_user: TokenData = Depends(get_current_user),
):
    """
    Analyse multiple texts concurrently using asyncio.gather.
    Useful for red-team bulk evaluation or pipeline scanning.
    Capped at 20 inputs per call to prevent abuse.
    """
    tasks = [
        run_security_analysis(
            text=text,
            context=request.context,
            policy_id=request.policy_id or "default",
        )
        for text in request.texts[:20]
    ]
    states = await asyncio.gather(*tasks)
    return [_state_to_response(s) for s in states]


@router.get("/graph/info")
async def graph_info(
    current_user: TokenData = Depends(get_current_user),
):
    """
    Returns live metadata about the current LangGraph security graph topology.

    The response is generated from graph.py's EVALUATION_PIPELINE list, so it
    always reflects the actual running topology — no manual syncing required.
    Useful for dashboard visualisation and API documentation.
    """
    return get_graph_topology()


# ── Helper ────────────────────────────────────────────────────────────────────

def _state_to_response(state) -> AnalyzeResponse:
    violations = [
        ViolationOut(
            guard=v.get("guard", ""),
            attack_type=v.get("attack_type", "unknown"),
            confidence=v.get("confidence", 0.0),
            message=v.get("message", ""),
            risk_level=v.get("risk_level", "none"),
            metadata=v.get("metadata", {}),
        )
        for v in (state.get("violations") or [])
    ]

    return AnalyzeResponse(
        request_id=state.get("request_id"),
        action=state.get("action", "allowed"),
        risk_score=state.get("risk_score", 0.0),
        risk_level=state.get("risk_level", "none"),
        should_block=state.get("should_block", False),
        violations=violations,
        sanitized_text=state.get("sanitized_text"),
        pipeline_findings=state.get("pipeline_findings") or {},
        explanation=state.get("explanation", ""),
        recommendations=state.get("recommendations") or [],
        node_latencies=state.get("node_latencies") or {},
        total_latency_ms=state.get("total_latency_ms", 0.0),
    )
