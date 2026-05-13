"""
routers/policy.py — Policy Management Endpoints

GET    /policy/list          - List all policies
GET    /policy/{id}          - Get a specific policy
PUT    /policy/{id}          - Update a policy
POST   /policy               - Create a new policy
GET    /policy/export        - Export all policies as YAML
"""
from typing import Dict, Any
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from backend.gateway.auth import get_current_user, require_permission, TokenData
from backend.models.schemas import PolicyConfig

# ── Shared singleton — all routers/agents use the SAME policy engine instance ─
from backend.dependencies import (
    policy_engine,
    update_policy_and_invalidate,
    invalidate_engine,
)

router = APIRouter(prefix="/policy", tags=["Policy"])


class PolicyUpdateRequest(BaseModel):
    updates: Dict[str, Any]


@router.get("/list")
async def list_policies(current_user: TokenData = Depends(get_current_user)):
    """List all available policies."""
    return {"policies": policy_engine.list_policies()}


@router.get("/export")
async def export_policies(current_user: TokenData = Depends(get_current_user)):
    """Export all policies as YAML."""
    return {"yaml": policy_engine.export_to_yaml()}


@router.get("/{policy_id}")
async def get_policy(
    policy_id: str,
    current_user: TokenData = Depends(get_current_user),
):
    """Get a specific policy configuration."""
    policy = policy_engine.get_policy(policy_id)
    return policy.model_dump()


@router.put("/{policy_id}")
async def update_policy(
    policy_id: str,
    request: PolicyUpdateRequest,
    current_user: TokenData = Depends(require_permission("admin")),
):
    """
    Update an existing policy (admin only).

    After updating, the SecurityEngine cache for this policy_id is
    invalidated so every subsequent analysis request immediately
    uses the new thresholds.
    """
    updated = update_policy_and_invalidate(policy_id, request.updates)
    return {
        "message": f"Policy '{policy_id}' updated — live analysis updated immediately",
        "policy": updated.model_dump(),
    }


@router.post("")
async def create_policy(
    policy: PolicyConfig,
    current_user: TokenData = Depends(require_permission("admin")),
):
    """Create a new policy (admin only)."""
    created = policy_engine.create_policy(policy.policy_id, policy)
    # Pre-warm the engine cache for the new policy
    invalidate_engine(policy.policy_id)
    return {
        "message": f"Policy '{policy.policy_id}' created",
        "policy": created.model_dump(),
    }

