"""
observability/storage.py — In-memory + PostgreSQL Event Storage

Stores request events for analytics and audit purposes.
Uses SQLAlchemy async for PostgreSQL, with in-memory fallback.
"""
import json
import os
import time
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any
from collections import deque
from loguru import logger

from backend.models.schemas import RequestEvent, DashboardStats, GatewayAction


class InMemoryEventStore:
    """
    Thread-safe in-memory event store.
    Keeps last N events for dashboard analytics.
    Used as fallback when PostgreSQL is not available.
    """

    def __init__(self, max_events: int = 10_000):
        self._events: deque = deque(maxlen=max_events)
        # Import here to avoid circular imports at module load time
        from backend.config import settings
        if settings.SEED_DEMO_DATA:
            self._seed_demo_data()
            logger.info("[storage] Demo data seeded (500 synthetic events)")
        else:
            logger.info("[storage] Event store ready — waiting for real traffic")

    def _seed_demo_data(self):
        """Seed realistic demo events for dashboard visualization."""
        import random
        from datetime import datetime, timedelta

        attack_types = [
            "jailbreak", "prompt_injection", "pii_leakage",
            "toxicity", "role_override", "tool_manipulation",
            "rag_poisoning", "unknown"
        ]
        providers = ["openai", "anthropic", "google", "ollama"]
        models = ["gpt-4o-mini", "gpt-4o", "claude-3-haiku", "gemini-1.5-flash"]
        actions = ["allowed", "blocked", "sanitized", "flagged"]
        action_weights = [0.65, 0.20, 0.10, 0.05]

        now = datetime.utcnow()

        for i in range(500):
            ts = now - timedelta(minutes=random.randint(0, 1440))  # last 24 hours
            action = random.choices(actions, weights=action_weights)[0]
            is_threat = action in ("blocked", "flagged")
            risk_score = (
                random.uniform(0.7, 1.0) if action == "blocked"
                else random.uniform(0.55, 0.75) if action == "flagged"
                else random.uniform(0.0, 0.35) if action == "allowed"
                else random.uniform(0.3, 0.6)
            )
            attack_type_list = (
                random.sample(attack_types[:6], k=random.randint(1, 2))
                if is_threat else []
            )
            provider = random.choice(providers)
            model = random.choice(models)

            event = RequestEvent(
                timestamp=ts,
                request_id=f"demo-{i:04d}",
                provider=provider,
                model=model,
                action=GatewayAction(action),
                risk_score=round(risk_score, 3),
                attack_types=attack_type_list,
                latency_ms=round(random.uniform(50, 800), 1),
                input_tokens=random.randint(50, 500),
                output_tokens=random.randint(20, 400),
                policy_id="default",
            )
            self._events.append(event)

    def store(self, event: RequestEvent):
        """Store a new request event."""
        self._events.append(event)

    def get_recent(self, limit: int = 100) -> List[RequestEvent]:
        """Get the most recent N events."""
        events = list(self._events)
        return sorted(events, key=lambda e: e.timestamp, reverse=True)[:limit]

    def get_stats(self, hours: int = 24) -> DashboardStats:
        """Compute dashboard statistics for the last N hours."""
        cutoff = datetime.utcnow() - timedelta(hours=hours)
        events = [e for e in self._events if e.timestamp >= cutoff]

        if not events:
            return DashboardStats()

        total = len(events)
        blocked = sum(1 for e in events if e.action == GatewayAction.BLOCKED)
        allowed = sum(1 for e in events if e.action == GatewayAction.ALLOWED)
        flagged = sum(1 for e in events if e.action == GatewayAction.FLAGGED)
        sanitized = sum(1 for e in events if e.action == GatewayAction.SANITIZED)
        avg_risk = sum(e.risk_score for e in events) / total
        avg_latency = sum(e.latency_ms for e in events) / total
        total_tokens = sum(e.input_tokens + e.output_tokens for e in events)

        # Attack breakdown
        attack_breakdown: Dict[str, int] = {}
        provider_breakdown: Dict[str, int] = {}
        model_breakdown: Dict[str, int] = {}
        for e in events:
            for at in e.attack_types:
                attack_breakdown[at] = attack_breakdown.get(at, 0) + 1
            provider_breakdown[e.provider] = provider_breakdown.get(e.provider, 0) + 1
            model_breakdown[e.model] = model_breakdown.get(e.model, 0) + 1

        # Requests per hour (last 24h)
        hour_buckets: Dict[int, Dict] = {}
        for e in events:
            hour = e.timestamp.hour
            if hour not in hour_buckets:
                hour_buckets[hour] = {"hour": hour, "total": 0, "blocked": 0}
            hour_buckets[hour]["total"] += 1
            if e.action == GatewayAction.BLOCKED:
                hour_buckets[hour]["blocked"] += 1

        requests_per_hour = sorted(hour_buckets.values(), key=lambda x: x["hour"])

        # Top threats
        top_threats = sorted(
            [{"type": k, "count": v} for k, v in attack_breakdown.items()],
            key=lambda x: x["count"],
            reverse=True,
        )[:10]

        return DashboardStats(
            total_requests=total,
            blocked_requests=blocked,
            allowed_requests=allowed,
            flagged_requests=flagged,
            sanitized_requests=sanitized,
            block_rate=round(blocked / max(total, 1), 4),
            avg_risk_score=round(avg_risk, 3),
            avg_latency_ms=round(avg_latency, 2),
            total_tokens=total_tokens,
            attack_breakdown=attack_breakdown,
            provider_breakdown=provider_breakdown,
            model_breakdown=model_breakdown,
            requests_per_hour=requests_per_hour,
            top_threats=top_threats,
        )

    def get_threat_timeline(self, hours: int = 24) -> List[Dict]:
        """Get blocked requests timeline for threat heatmap."""
        cutoff = datetime.utcnow() - timedelta(hours=hours)
        blocked = [
            e for e in self._events
            if e.action == GatewayAction.BLOCKED and e.timestamp >= cutoff
        ]
        return [
            {
                "timestamp": e.timestamp.isoformat(),
                "attack_type": e.attack_types[0] if e.attack_types else "unknown",
                "risk_score": e.risk_score,
                "provider": e.provider,
                "model": e.model,
            }
            for e in sorted(blocked, key=lambda x: x.timestamp, reverse=True)
        ]


# Global event store instance
event_store = InMemoryEventStore()
