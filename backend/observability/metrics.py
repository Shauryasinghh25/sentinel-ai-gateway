"""
observability/metrics.py — Prometheus Metrics & Structured Logging

Tracks:
- Request counts by action/provider/model
- Risk score distribution
- Latency histograms
- Token usage
- Attack type frequencies
- Active connections
"""
import time
from typing import Optional
from loguru import logger
import json
import sys

try:
    from prometheus_client import (
        Counter, Histogram, Gauge, Summary,
        generate_latest, CONTENT_TYPE_LATEST,
        CollectorRegistry
    )
    PROMETHEUS_AVAILABLE = True
except ImportError:
    PROMETHEUS_AVAILABLE = False
    logger.warning("prometheus_client not installed. Metrics endpoint disabled.")


if PROMETHEUS_AVAILABLE:
    # ── Prometheus Metrics ────────────────────────────────────────────────────
    REQUEST_COUNT = Counter(
        "sentinel_requests_total",
        "Total gateway requests",
        ["provider", "model", "action", "policy_id"]
    )

    BLOCKED_COUNT = Counter(
        "sentinel_blocked_total",
        "Total blocked requests",
        ["attack_type", "risk_level", "policy_id"]
    )

    ATTACK_TYPE_COUNT = Counter(
        "sentinel_attack_types_total",
        "Attack types detected",
        ["attack_type"]
    )

    REQUEST_LATENCY = Histogram(
        "sentinel_request_latency_ms",
        "Gateway request latency in milliseconds",
        ["provider", "action"],
        buckets=[10, 25, 50, 100, 200, 500, 1000, 2000, 5000]
    )

    SECURITY_LATENCY = Histogram(
        "sentinel_security_check_latency_ms",
        "Security check latency in milliseconds",
        buckets=[1, 2, 5, 10, 20, 50, 100, 200]
    )

    RISK_SCORE = Histogram(
        "sentinel_risk_scores",
        "Distribution of risk scores",
        buckets=[0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0]
    )

    TOKEN_USAGE = Counter(
        "sentinel_tokens_total",
        "Total tokens processed",
        ["provider", "model", "direction"]  # direction: input/output
    )

    ACTIVE_REQUESTS = Gauge(
        "sentinel_active_requests",
        "Currently processing requests"
    )

    PII_DETECTIONS = Counter(
        "sentinel_pii_detections_total",
        "PII detections",
        ["pii_type"]
    )


class MetricsCollector:
    """
    Centralized metrics collection and structured logging.
    """

    def __init__(self):
        self._enabled = PROMETHEUS_AVAILABLE
        # In-memory counters for dashboard (always active)
        self._counters = {
            "total_requests": 0,
            "blocked": 0,
            "allowed": 0,
            "flagged": 0,
            "sanitized": 0,
            "rate_limited": 0,
            "total_tokens": 0,
            "attack_types": {},
            "providers": {},
            "models": {},
            "risk_scores": [],
            "latencies": [],
            "pii_types": {},
        }

    def record_request(
        self,
        provider: str,
        model: str,
        action: str,
        risk_score: float,
        latency_ms: float,
        attack_types: list[str] = None,
        policy_id: str = "default",
        input_tokens: int = 0,
        output_tokens: int = 0,
        pii_types: list[str] = None,
    ):
        """Record a completed gateway request."""
        # In-memory
        self._counters["total_requests"] += 1
        self._counters[action] = self._counters.get(action, 0) + 1
        self._counters["total_tokens"] += input_tokens + output_tokens
        self._counters["risk_scores"].append(risk_score)
        self._counters["latencies"].append(latency_ms)

        # Provider stats
        self._counters["providers"][provider] = self._counters["providers"].get(provider, 0) + 1
        self._counters["models"][model] = self._counters["models"].get(model, 0) + 1

        # Attack types
        for at in (attack_types or []):
            self._counters["attack_types"][at] = self._counters["attack_types"].get(at, 0) + 1

        # PII types
        for pt in (pii_types or []):
            self._counters["pii_types"][pt] = self._counters["pii_types"].get(pt, 0) + 1

        # Prometheus
        if self._enabled:
            REQUEST_COUNT.labels(
                provider=provider, model=model, action=action, policy_id=policy_id
            ).inc()
            REQUEST_LATENCY.labels(provider=provider, action=action).observe(latency_ms)
            RISK_SCORE.observe(risk_score)
            TOKEN_USAGE.labels(provider=provider, model=model, direction="input").inc(input_tokens)
            TOKEN_USAGE.labels(provider=provider, model=model, direction="output").inc(output_tokens)

            if action == "blocked":
                risk_level = "high" if risk_score > 0.8 else "medium"
                for at in (attack_types or ["unknown"]):
                    BLOCKED_COUNT.labels(
                        attack_type=at, risk_level=risk_level, policy_id=policy_id
                    ).inc()
                    ATTACK_TYPE_COUNT.labels(attack_type=at).inc()

        # Structured log
        logger.info(json.dumps({
            "event": "gateway_request",
            "provider": provider,
            "model": model,
            "action": action,
            "risk_score": risk_score,
            "latency_ms": latency_ms,
            "attack_types": attack_types or [],
            "tokens": input_tokens + output_tokens,
            "policy_id": policy_id,
        }))

    def record_security_check(
        self,
        latency_ms: float,
        violations: int,
        risk_score: float = 0.0,
        attack_types: list[str] = None,
    ):
        """Record security check performance."""

        if self._enabled:
            SECURITY_LATENCY.observe(latency_ms)

            RISK_SCORE.observe(risk_score)

            for attack_type in (attack_types or []):
                ATTACK_TYPE_COUNT.labels(
                    attack_type=attack_type
                ).inc()

    def get_dashboard_stats(self) -> dict:
        """Get aggregated stats for the dashboard."""
        total = self._counters["total_requests"]
        blocked = self._counters.get("blocked", 0)
        risk_scores = self._counters["risk_scores"]
        latencies = self._counters["latencies"]

        return {
            "total_requests": total,
            "blocked_requests": blocked,
            "allowed_requests": self._counters.get("allowed", 0),
            "flagged_requests": self._counters.get("flagged", 0),
            "sanitized_requests": self._counters.get("sanitized", 0),
            "block_rate": round(blocked / max(total, 1), 4),
            "avg_risk_score": round(sum(risk_scores) / max(len(risk_scores), 1), 3),
            "avg_latency_ms": round(sum(latencies) / max(len(latencies), 1), 2),
            "total_tokens": self._counters["total_tokens"],
            "attack_breakdown": self._counters["attack_types"],
            "provider_breakdown": self._counters["providers"],
            "model_breakdown": self._counters["models"],
            "pii_breakdown": self._counters["pii_types"],
        }

    def get_prometheus_output(self) -> Optional[bytes]:
        """Generate Prometheus metrics output."""
        if not self._enabled:
            return None
        return generate_latest()


# Global singleton
metrics = MetricsCollector()


def setup_logging():
    """Configure structured JSON logging."""
    logger.remove()
    logger.add(
        sys.stdout,
        format="{message}",
        level="INFO",
        serialize=False,
    )
    logger.add(
        "logs/sentinel-ai.log",
        rotation="100 MB",
        retention="30 days",
        compression="gz",
        level="INFO",
        serialize=True,
    )
