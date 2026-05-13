"""
routers/gateway.py — Main Gateway Proxy Endpoints

POST /gateway/chat    - Main LLM gateway with security checks
POST /gateway/analyze - Security-only analysis (no LLM call)
GET  /gateway/health  - Provider health check
"""
import time
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from loguru import logger

from backend.config import settings
from backend.models.schemas import (
    GatewayRequest, GatewayResponse, GatewayAction, RequestEvent
)
from backend.gateway.auth import get_current_user, TokenData
from backend.gateway.rate_limiter import rate_limiter
from backend.gateway.proxy import LLMProxy
from backend.observability.metrics import metrics
from backend.observability.storage import event_store
# Shared singletons — UI policy changes are visible here immediately
from backend.dependencies import policy_engine, get_security_engine


router = APIRouter(prefix="/gateway", tags=["Gateway"])
proxy = LLMProxy()


def _record_event(
    request: GatewayRequest,
    response: GatewayResponse,
):
    """Background task to persist the request event."""
    action = GatewayAction.ALLOWED
    if response.security:
        action = response.security.action
    attack_types = []
    if response.security and response.security.violations:
        attack_types = [v.attack_type.value for v in response.security.violations]
    usage = response.usage or {}

    event = RequestEvent(
        request_id=request.request_id,
        user_id=request.user_id,
        session_id=request.session_id,
        provider=request.provider.value,
        model=request.model,
        action=action,
        risk_score=response.security.risk_score if response.security else 0.0,
        attack_types=attack_types,
        latency_ms=response.latency_ms,
        input_tokens=usage.get("prompt_tokens", 0),
        output_tokens=usage.get("completion_tokens", 0),
        policy_id=request.policy_id or "default",
    )
    event_store.store(event)
    metrics.record_request(
        provider=request.provider.value,
        model=request.model,
        action=action.value,
        risk_score=event.risk_score,
        latency_ms=response.latency_ms,
        attack_types=attack_types,
        policy_id=event.policy_id,
        input_tokens=event.input_tokens,
        output_tokens=event.output_tokens,
    )


@router.post("/chat", response_model=GatewayResponse)
async def gateway_chat(
    request: GatewayRequest,
    background_tasks: BackgroundTasks,
    current_user: TokenData = Depends(get_current_user),
):
    """
    Main AI gateway endpoint.

    Flow:
    1. Rate limiting check
    2. Input security analysis
    3. If blocked → return blocked response
    4. Route to LLM provider
    5. Output security analysis
    6. Return response
    """
    t0 = time.perf_counter()

    # Rate limiting
    identity = current_user.sub
    policy = policy_engine.get_policy(request.policy_id or "default")
    allowed, retry_after = rate_limiter.check(
        identity,
        capacity=policy.rate_limit_requests,
        window=policy.rate_limit_window_seconds,
    )
    if not allowed:
        raise HTTPException(
            status_code=429,
            detail={"error": "Rate limit exceeded", "retry_after": retry_after},
            headers={"Retry-After": str(int(retry_after) + 1)},
        )

    # Security engine
    engine = get_security_engine(request.policy_id or "default")

    # Extract user message for analysis
    user_messages = [m for m in request.messages if m.role == "user"]
    input_text = user_messages[-1].content if user_messages else ""

    # Input security check
    input_security = engine.analyze_input(input_text)

    if input_security.is_blocked:
        response = GatewayResponse(
            request_id=request.request_id,
            status="blocked",
            security=input_security,
            error=f"Request blocked: {input_security.risk_level.value} risk detected",
            latency_ms=round((time.perf_counter() - t0) * 1000, 2),
        )
        background_tasks.add_task(_record_event, request, response)
        return response

    # Use sanitized text if available
    effective_input = input_security.sanitized_text or input_text

    # Call LLM provider
    try:
        llm_result = await proxy.call(request, input_text=effective_input)
    except Exception as e:
        logger.error(f"LLM call failed: {e}")
        raise HTTPException(status_code=502, detail=f"LLM provider error: {str(e)}")

    # Output security check
    output_text = llm_result.get("content", "")
    output_security = engine.analyze_output(output_text, original_input=input_text)

    # If output is blocked, return error
    if output_security.is_blocked:
        response = GatewayResponse(
            request_id=request.request_id,
            status="blocked",
            output_security=output_security,
            error="LLM response blocked by output security policy",
            latency_ms=round((time.perf_counter() - t0) * 1000, 2),
        )
        background_tasks.add_task(_record_event, request, response)
        return response

    final_content = output_security.sanitized_text or output_text

    response = GatewayResponse(
        request_id=request.request_id,
        status="success",
        content=final_content,
        model=llm_result.get("model"),
        provider=llm_result.get("provider"),
        security=input_security,
        output_security=output_security,
        usage=llm_result.get("usage"),
        latency_ms=round((time.perf_counter() - t0) * 1000, 2),
    )
    background_tasks.add_task(_record_event, request, response)
    return response


@router.post("/analyze")
async def analyze_only(
    request: GatewayRequest,
    current_user: TokenData = Depends(get_current_user),
):
    """
    Security-only analysis endpoint (no LLM call).
    Returns security assessment for a given input.
    """
    engine = get_security_engine(request.policy_id or "default")
    user_messages = [m for m in request.messages if m.role == "user"]
    input_text = user_messages[-1].content if user_messages else ""

    result = engine.analyze_input(input_text)
    
    metrics.record_security_check(
        latency_ms=result.latency_ms,
        violations=len(result.violations),
        risk_score=result.risk_score,
        attack_types=[
            v.attack_type.value
            for v in result.violations
        ]
    )

    return {
        "request_id": request.request_id,
        "action": result.action.value,
        "risk_score": result.risk_score,
        "risk_level": result.risk_level.value,
        "violations": [
            {
                "guard": v.guard,
                "attack_type": v.attack_type.value,
                "risk_level": v.risk_level.value,
                "confidence": v.confidence,
                "message": v.message,
            }
            for v in result.violations
        ],
        "sanitized_text": result.sanitized_text,
        "latency_ms": result.latency_ms,
    }


@router.get("/health")
async def gateway_health():
    """Health check including provider status."""
    provider_health = proxy.get_provider_health()
    return {
        "status": "healthy",
        "version": settings.APP_VERSION,
        "providers": provider_health,
        "security_engine": "active",
        "policy_engine": "active",
    }
@router.get("/providers")
async def get_provider_status():
    """Return configured provider status."""

    return {
        "openai": bool(settings.OPENAI_API_KEY),
        "anthropic": bool(settings.ANTHROPIC_API_KEY),
        "google": bool(settings.GOOGLE_API_KEY),
        "ollama": bool(settings.OLLAMA_BASE_URL),
    }



