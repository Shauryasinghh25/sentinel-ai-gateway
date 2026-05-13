"""
models/schemas.py — Shared Pydantic data models for SentinelAI Gateway
"""
from __future__ import annotations
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any, Literal
from datetime import datetime
from enum import Enum
import uuid


# ── Enums ────────────────────────────────────────────────────────────────────

class RiskLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NONE = "none"


class AttackType(str, Enum):
    JAILBREAK = "jailbreak"
    PROMPT_INJECTION = "prompt_injection"
    ROLE_OVERRIDE = "role_override"
    INDIRECT_INJECTION = "indirect_injection"
    UNICODE_OBFUSCATION = "unicode_obfuscation"
    HIDDEN_INSTRUCTION = "hidden_instruction"
    TOOL_MANIPULATION = "tool_manipulation"
    PROMPT_LEAKAGE = "prompt_leakage"
    PII_LEAKAGE = "pii_leakage"
    TOXICITY = "toxicity"
    RAG_POISONING = "rag_poisoning"
    MCP_ABUSE = "mcp_abuse"
    UNKNOWN = "unknown"


class GatewayAction(str, Enum):
    ALLOWED = "allowed"
    BLOCKED = "blocked"
    SANITIZED = "sanitized"
    FLAGGED = "flagged"
    RATE_LIMITED = "rate_limited"


class LLMProvider(str, Enum):
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    GOOGLE = "google"
    OLLAMA = "ollama"


# ── Security Violation ────────────────────────────────────────────────────────

class SecurityViolation(BaseModel):
    violation_id: str = Field(default_factory=lambda: str(uuid.uuid4())[:8])
    guard: str
    attack_type: AttackType = AttackType.UNKNOWN
    risk_level: RiskLevel = RiskLevel.MEDIUM
    message: str
    confidence: float = Field(ge=0.0, le=1.0)
    matched_pattern: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


# ── Security Result ───────────────────────────────────────────────────────────

class SecurityResult(BaseModel):
    request_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=datetime.utcnow)

    # Decision
    action: GatewayAction = GatewayAction.ALLOWED
    risk_score: float = Field(ge=0.0, le=1.0, default=0.0)
    risk_level: RiskLevel = RiskLevel.NONE

    # Violations
    violations: List[SecurityViolation] = Field(default_factory=list)

    # Content
    original_text: str = ""
    sanitized_text: Optional[str] = None

    # Performance
    latency_ms: float = 0.0

    @property
    def is_blocked(self) -> bool:
        return self.action == GatewayAction.BLOCKED

    @property
    def has_violations(self) -> bool:
        return len(self.violations) > 0

    def primary_attack_type(self) -> Optional[AttackType]:
        if not self.violations:
            return None
        # Return highest confidence violation's attack type
        return max(self.violations, key=lambda v: v.confidence).attack_type


# ── Gateway Request / Response ────────────────────────────────────────────────

class Message(BaseModel):
    role: Literal["system", "user", "assistant"] = "user"
    content: str


class GatewayRequest(BaseModel):
    request_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    messages: List[Message]
    model: str = "gpt-4o-mini"
    provider: LLMProvider = LLMProvider.OPENAI
    max_tokens: int = 1000
    temperature: float = 0.7
    stream: bool = False
    metadata: Dict[str, Any] = Field(default_factory=dict)

    # Security context
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    policy_id: Optional[str] = "default"


class GatewayResponse(BaseModel):
    request_id: str
    status: str  # "success" | "blocked" | "error"
    content: Optional[str] = None
    model: Optional[str] = None
    provider: Optional[str] = None

    # Security metadata
    security: Optional[SecurityResult] = None
    output_security: Optional[SecurityResult] = None

    # Usage
    usage: Optional[Dict[str, int]] = None
    latency_ms: float = 0.0

    # Error
    error: Optional[str] = None


# ── Analytics Models ──────────────────────────────────────────────────────────

class RequestEvent(BaseModel):
    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    request_id: str
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    provider: str
    model: str
    action: GatewayAction
    risk_score: float
    attack_types: List[str] = Field(default_factory=list)
    latency_ms: float
    input_tokens: int = 0
    output_tokens: int = 0
    policy_id: str = "default"


class DashboardStats(BaseModel):
    total_requests: int = 0
    blocked_requests: int = 0
    allowed_requests: int = 0
    flagged_requests: int = 0
    sanitized_requests: int = 0
    block_rate: float = 0.0
    avg_risk_score: float = 0.0
    avg_latency_ms: float = 0.0
    total_tokens: int = 0
    attack_breakdown: Dict[str, int] = Field(default_factory=dict)
    provider_breakdown: Dict[str, int] = Field(default_factory=dict)
    model_breakdown: Dict[str, int] = Field(default_factory=dict)
    requests_per_hour: List[Dict[str, Any]] = Field(default_factory=list)
    top_threats: List[Dict[str, Any]] = Field(default_factory=list)


# ── Auth Models ───────────────────────────────────────────────────────────────

class APIKey(BaseModel):
    key_id: str = Field(default_factory=lambda: str(uuid.uuid4())[:12])
    name: str
    key_hash: str
    permissions: List[str] = Field(default_factory=lambda: ["read", "write"])
    rate_limit: int = 100
    created_at: datetime = Field(default_factory=datetime.utcnow)
    is_active: bool = True


class TokenData(BaseModel):
    sub: str
    permissions: List[str] = Field(default_factory=list)
    exp: Optional[int] = None


# ── Tool Security Models ──────────────────────────────────────────────────────

class ToolCallRequest(BaseModel):
    tool_name: str
    tool_args: Dict[str, Any] = Field(default_factory=dict)
    agent_id: Optional[str] = None
    context: Dict[str, Any] = Field(default_factory=dict)


class ToolCallResult(BaseModel):
    tool_name: str
    allowed: bool
    reason: Optional[str] = None
    sanitized_args: Optional[Dict[str, Any]] = None
    risk_level: RiskLevel = RiskLevel.NONE


# ── Policy Models ─────────────────────────────────────────────────────────────

class PolicyConfig(BaseModel):
    policy_id: str = "default"
    name: str = "Default Policy"
    version: str = "1.0"

    # Thresholds
    toxicity_threshold: float = 0.8
    injection_confidence_threshold: float = 0.7
    risk_score_block_threshold: float = 0.85

    # Toggles
    block_pii: bool = True
    redact_pii: bool = True
    block_financial_advice: bool = False
    block_medical_advice: bool = False
    block_code_execution: bool = False
    block_political_content: bool = False

    # Tool permissions
    allowed_tools: List[str] = Field(default_factory=list)
    blocked_tools: List[str] = Field(default_factory=list)

    # Topic control
    allowed_topics: List[str] = Field(default_factory=list)
    blocked_topics: List[str] = Field(default_factory=list)

    # Rate limiting
    rate_limit_requests: int = 100
    rate_limit_window_seconds: int = 60

    # Model routing
    preferred_model: str = "gpt-4o-mini"
    fallback_model: str = "gpt-3.5-turbo"
    allowed_providers: List[str] = Field(default_factory=lambda: ["openai", "anthropic", "google"])
