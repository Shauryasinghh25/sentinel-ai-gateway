"""
security/mcp_security.py — MCP (Model Context Protocol) Security Layer

Secures tool calls made by AI agents through MCP:
- Tool allow/deny policies
- Argument sanitization
- Credential leak prevention
- Sandboxed execution validation
- Permission enforcement
"""
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field

# Type alias for _sanitize_args return
Tuple_like = Tuple[Dict, List]

from backend.models.schemas import PolicyConfig, ToolCallRequest, ToolCallResult, RiskLevel
from backend.security.pii import PIIEngine


# ── High-risk tool categories ─────────────────────────────────────────────────

DANGEROUS_TOOLS: Set[str] = {
    # Code execution
    "execute_code", "run_code", "eval_code", "exec", "shell",
    "bash", "cmd", "terminal", "subprocess", "os_command",
    # File system (destructive)
    "delete_file", "remove_file", "format_disk", "overwrite_file",
    "write_file", "create_file",  # can be allowed per policy
    # Network (exfiltration risk)
    "http_post", "send_email", "send_webhook", "upload_file",
    "send_request",  # can be allowed per policy
    # Database (write operations)
    "sql_execute", "db_write", "db_delete", "drop_table",
    "db_update", "truncate_table",
    # Credential access
    "get_credentials", "get_api_key", "get_password", "get_secret",
    "read_env", "get_env_var",
}

MEDIUM_RISK_TOOLS: Set[str] = {
    "read_file", "list_files", "search_web", "http_get",
    "sql_query", "db_read", "read_env",
}

SAFE_TOOLS: Set[str] = {
    "calculator", "weather_api", "currency_converter",
    "text_formatter", "base64_encode", "base64_decode",
    "uuid_generator", "timestamp", "json_formatter",
    "math_eval", "unit_converter",
}

# Arguments that might carry credentials
SENSITIVE_ARG_NAMES: Set[str] = {
    "password", "passwd", "pwd", "secret", "token", "api_key", "apikey",
    "auth", "credential", "private_key", "access_key", "secret_key",
    "bearer", "jwt", "authorization",
}

# Argument values that look like injections
INJECTION_IN_ARGS_PATTERNS = [
    r'(?:ignore|forget|override)\s+(?:previous|all|your)\s+instructions',
    r'\bsystem\s+prompt\b',
    r'\bjailbreak\b',
    r';\s*(?:rm|del|format|drop|truncate)\s+',  # command chaining
    r'(?:--|\|\|)\s*\w+',  # shell flag injection
    r'\x00|\x1b|\x08',  # control characters
]


@dataclass
class ToolRiskProfile:
    tool_name: str
    base_risk: str  # critical / high / medium / low / safe
    requires_approval: bool
    blocked_by_default: bool
    sensitive_args: List[str] = field(default_factory=list)


class MCPSecurityLayer:
    """
    Security enforcement for MCP tool calls.

    Integrates with any MCP server to validate tool invocations
    before they are executed by the agent.
    """

    def __init__(self, policy: Optional[PolicyConfig] = None):
        self.policy = policy or PolicyConfig()
        self.pii_engine = PIIEngine()
        self._allowed_tools: Set[str] = set(policy.allowed_tools) if policy else set()
        self._blocked_tools: Set[str] = set(policy.blocked_tools) if policy else set()

        import re
        self._injection_patterns = [
            re.compile(p, re.IGNORECASE)
            for p in INJECTION_IN_ARGS_PATTERNS
        ]

    def update_policy(self, policy: PolicyConfig):
        self.policy = policy
        self._allowed_tools = set(policy.allowed_tools)
        self._blocked_tools = set(policy.blocked_tools)

    def get_tool_risk_profile(self, tool_name: str) -> ToolRiskProfile:
        """Classify tool risk level."""
        name_lower = tool_name.lower()

        if name_lower in DANGEROUS_TOOLS or any(d in name_lower for d in ["exec", "shell", "delete", "drop"]):
            return ToolRiskProfile(
                tool_name=tool_name,
                base_risk="critical",
                requires_approval=True,
                blocked_by_default=True,
            )
        elif name_lower in MEDIUM_RISK_TOOLS:
            return ToolRiskProfile(
                tool_name=tool_name,
                base_risk="medium",
                requires_approval=False,
                blocked_by_default=False,
            )
        elif name_lower in SAFE_TOOLS:
            return ToolRiskProfile(
                tool_name=tool_name,
                base_risk="safe",
                requires_approval=False,
                blocked_by_default=False,
            )
        else:
            # Unknown tool → treat as medium risk
            return ToolRiskProfile(
                tool_name=tool_name,
                base_risk="medium",
                requires_approval=False,
                blocked_by_default=False,
            )

    def _sanitize_args(self, args: Dict[str, Any]) -> Tuple_like:
        """Sanitize tool arguments, removing PII and injections."""
        sanitized = dict(args)
        issues = []

        for key, value in args.items():
            # Check for sensitive arg names
            if any(s in key.lower() for s in SENSITIVE_ARG_NAMES):
                sanitized[key] = "[REDACTED]"
                issues.append(f"Sensitive arg '{key}' redacted")
                continue

            if not isinstance(value, str):
                continue

            # Check for injection in arg values
            for pattern in self._injection_patterns:
                if pattern.search(str(value)):
                    sanitized[key] = "[BLOCKED_INJECTION]"
                    issues.append(f"Injection detected in arg '{key}'")
                    break

            # Check for PII in arg values
            has_pii, _, redacted = self.pii_engine.detect(str(value))
            if has_pii:
                sanitized[key] = redacted
                issues.append(f"PII redacted from arg '{key}'")

        return sanitized, issues

    def validate_tool_call(self, request: ToolCallRequest) -> ToolCallResult:
        """
        Validate a tool call request before execution.

        Decision logic:
        1. Check explicit allow/deny lists from policy
        2. Check tool risk profile
        3. Sanitize arguments
        4. Return allow/deny decision
        """
        tool_name = request.tool_name
        name_lower = tool_name.lower()

        # Explicit deny list
        if tool_name in self._blocked_tools or name_lower in DANGEROUS_TOOLS:
            return ToolCallResult(
                tool_name=tool_name,
                allowed=False,
                reason=f"Tool '{tool_name}' is blocked by security policy",
                risk_level=RiskLevel.CRITICAL,
            )

        # Explicit allow list (if configured, only allow listed tools)
        if self._allowed_tools and tool_name not in self._allowed_tools:
            return ToolCallResult(
                tool_name=tool_name,
                allowed=False,
                reason=f"Tool '{tool_name}' is not in the allowed tools list",
                risk_level=RiskLevel.HIGH,
            )

        # Risk profile check
        profile = self.get_tool_risk_profile(tool_name)
        if profile.blocked_by_default and tool_name not in self._allowed_tools:
            return ToolCallResult(
                tool_name=tool_name,
                allowed=False,
                reason=f"High-risk tool '{tool_name}' blocked by default. Explicitly allow in policy.",
                risk_level=RiskLevel.HIGH,
            )

        # Sanitize arguments
        sanitized_args, arg_issues = self._sanitize_args(request.tool_args)

        risk_level = {
            "critical": RiskLevel.CRITICAL,
            "high": RiskLevel.HIGH,
            "medium": RiskLevel.MEDIUM,
            "low": RiskLevel.LOW,
            "safe": RiskLevel.NONE,
        }.get(profile.base_risk, RiskLevel.MEDIUM)

        return ToolCallResult(
            tool_name=tool_name,
            allowed=True,
            reason=None if not arg_issues else f"Args sanitized: {'; '.join(arg_issues)}",
            sanitized_args=sanitized_args,
            risk_level=risk_level,
        )


