"""
backend/dependencies.py — Shared singleton dependencies

This module is the SINGLE source of truth for the PolicyEngine and
SecurityEngine instances used across the entire application.

Every router and agent node must import from here so that runtime
policy updates (via PUT /policy/{id}) are immediately visible to
the live analyser (/security/check/*) and the LangGraph agent (/agent/analyze).

Import pattern:
    from backend.dependencies import policy_engine, get_security_engine, rag_layer, mcp_layer
"""
from __future__ import annotations

from backend.policy.engine import PolicyEngine
from backend.security.engine import SecurityEngine
from backend.security.rag_security import RAGSecurityLayer
from backend.security.mcp_security import MCPSecurityLayer
from backend.models.schemas import PolicyConfig

# ── Shared policy engine (one instance for the entire process) ────────────────
# All writes via PUT /policy/{id} update this object.
# All reads in security checks, agent nodes, and gateway proxy use this object.
policy_engine = PolicyEngine()

# ── Shared auxiliary layers ───────────────────────────────────────────────────
rag_layer = RAGSecurityLayer()
mcp_layer = MCPSecurityLayer()

# ── Per-policy SecurityEngine cache ──────────────────────────────────────────
# SecurityEngine is stateless after construction except for the policy it holds.
# We cache one engine per policy_id and invalidate the cache whenever a policy
# is updated so the new thresholds take effect on the very next request.
_engine_cache: dict[str, SecurityEngine] = {}


def get_security_engine(policy_id: str = "default") -> SecurityEngine:
    """
    Return a SecurityEngine configured with the current policy.

    The engine is cached by policy_id. Calling `invalidate_engine(policy_id)`
    (done automatically by `update_policy_and_invalidate`) flushes the entry
    so the next call rebuilds with fresh thresholds.
    """
    if policy_id not in _engine_cache:
        active_policy = policy_engine.get_policy(policy_id)
        _engine_cache[policy_id] = SecurityEngine(policy=active_policy)
    return _engine_cache[policy_id]


def invalidate_engine(policy_id: str) -> None:
    """Remove a cached engine so it is rebuilt on the next request."""
    _engine_cache.pop(policy_id, None)


def update_policy_and_invalidate(policy_id: str, updates: dict) -> PolicyConfig:
    """
    Convenience wrapper used by the policy router:
    1. Updates the policy in the shared PolicyEngine.
    2. Invalidates the SecurityEngine cache for that policy_id
       so live analysis immediately picks up the new thresholds.
    """
    updated = policy_engine.update_policy(policy_id, updates)
    invalidate_engine(policy_id)
    return updated
