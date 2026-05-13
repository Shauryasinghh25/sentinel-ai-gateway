"""
routers/analytics.py — Analytics & Observability API

GET /analytics/stats     - Aggregated dashboard stats
GET /analytics/events    - Recent request events
GET /analytics/threats   - Threat timeline
GET /metrics             - Prometheus metrics endpoint
"""
from fastapi import APIRouter, Depends, Query
from fastapi.responses import PlainTextResponse

from backend.gateway.auth import get_current_user, TokenData
from backend.observability.storage import event_store
from backend.observability.metrics import metrics

router = APIRouter(tags=["Analytics"])


@router.get("/analytics/stats")
async def get_stats(
    hours: int = Query(24, ge=1, le=168),
    current_user: TokenData = Depends(get_current_user),
):
    """Get aggregated dashboard statistics."""
    stats = event_store.get_stats(hours=hours)
    runtime_stats = metrics.get_dashboard_stats()
    return {
        **stats.model_dump(),
        "runtime_metrics": runtime_stats,
    }


@router.get("/analytics/events")
async def get_events(
    limit: int = Query(50, ge=1, le=500),
    current_user: TokenData = Depends(get_current_user),
):
    """Get recent request events."""
    events = event_store.get_recent(limit=limit)
    return {
        "total": len(events),
        "events": [
            {
                "event_id": e.event_id,
                "timestamp": e.timestamp.isoformat(),
                "request_id": e.request_id,
                "provider": e.provider,
                "model": e.model,
                "action": e.action.value,
                "risk_score": e.risk_score,
                "attack_types": e.attack_types,
                "latency_ms": e.latency_ms,
                "tokens": e.input_tokens + e.output_tokens,
                "policy_id": e.policy_id,
            }
            for e in events
        ]
    }


@router.get("/analytics/threats")
async def get_threats(
    hours: int = Query(24, ge=1, le=168),
    current_user: TokenData = Depends(get_current_user),
):
    """Get threat timeline for heatmap visualization."""
    threats = event_store.get_threat_timeline(hours=hours)
    return {
        "hours": hours,
        "total_threats": len(threats),
        "timeline": threats,
    }


@router.get("/metrics", response_class=PlainTextResponse)
async def prometheus_metrics():
    """Prometheus metrics endpoint."""
    output = metrics.get_prometheus_output()
    if output is None:
        return PlainTextResponse("# Prometheus not available\n", status_code=503)
    return PlainTextResponse(output, media_type="text/plain; version=0.0.4")
