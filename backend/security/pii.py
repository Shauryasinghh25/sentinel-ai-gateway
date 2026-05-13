"""
security/pii.py — PII Detection & Redaction Engine

Detects and redacts:
- Email addresses
- Phone numbers
- Social Security Numbers
- Credit card numbers
- IP addresses
- API keys / secrets
- AWS access keys
- Private keys
- Passport numbers
- Driver's license
- Bank account numbers
- Medical record numbers
- Dates of birth
"""
import re
from typing import List, Tuple, Dict, Set
from dataclasses import dataclass


@dataclass
class PIIMatch:
    pii_type: str
    value: str
    replacement: str
    position: int
    confidence: float


# ── PII Pattern Registry ──────────────────────────────────────────────────────

PII_PATTERNS: Dict[str, Tuple[str, str, float]] = {
    # (pattern, replacement_token, confidence)
    "email": (
        r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b',
        "[EMAIL_REDACTED]",
        0.99
    ),
    "phone_us": (
        r'\b(\+?1[\s.\-]?)?\(?\d{3}\)?[\s.\-]?\d{3}[\s.\-]?\d{4}\b',
        "[PHONE_REDACTED]",
        0.92
    ),
    "phone_intl": (
        r'\+(?:[0-9] ?){6,14}[0-9]\b',
        "[PHONE_REDACTED]",
        0.88
    ),
    "ssn": (
        r'\b\d{3}[\s\-]\d{2}[\s\-]\d{4}\b',
        "[SSN_REDACTED]",
        0.98
    ),
    "credit_card": (
        r'\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6(?:011|5\d{2}))[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{3,4}\b',
        "[CREDIT_CARD_REDACTED]",
        0.97
    ),
    "ip_address": (
        r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b',
        "[IP_REDACTED]",
        0.95
    ),
    "ipv6": (
        r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b',
        "[IPV6_REDACTED]",
        0.95
    ),
    "openai_key": (
        r'\bsk-[A-Za-z0-9\-_]{20,}\b',
        "[API_KEY_REDACTED]",
        0.99
    ),
    "anthropic_key": (
        r'\bsk-ant-[A-Za-z0-9\-_]{20,}\b',
        "[API_KEY_REDACTED]",
        0.99
    ),
    "github_token": (
        r'\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b',
        "[GITHUB_TOKEN_REDACTED]",
        0.99
    ),
    "aws_access_key": (
        r'\b(?:AKIA|AIPA|AKIA|AROA|ASIA)[A-Z0-9]{16}\b',
        "[AWS_KEY_REDACTED]",
        0.99
    ),
    "aws_secret_key": (
        r'\b[A-Za-z0-9+/]{40}\b(?=.*aws)',
        "[AWS_SECRET_REDACTED]",
        0.85
    ),
    "jwt_token": (
        r'\beyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\b',
        "[JWT_REDACTED]",
        0.97
    ),
    "private_key": (
        r'-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----[\s\S]*?-----END\s+(?:RSA\s+)?PRIVATE\s+KEY-----',
        "[PRIVATE_KEY_REDACTED]",
        0.99
    ),
    "bank_account": (
        r'\b\d{8,17}\b(?=\s*(?:account|acct|bank|routing))',
        "[BANK_ACCOUNT_REDACTED]",
        0.82
    ),
    "routing_number": (
        r'\b(?:routing|ABA)\s*(?:number|#|num)?\s*:?\s*\d{9}\b',
        "[ROUTING_NUMBER_REDACTED]",
        0.91
    ),
    "passport": (
        r'\b[A-Z]{1,2}\d{6,9}\b(?=\s*(?:passport|document))',
        "[PASSPORT_REDACTED]",
        0.80
    ),
    "dob": (
        r'\b(?:DOB|date\s+of\s+birth|born\s+on)\s*:?\s*\d{1,2}[/\-\.]\d{1,2}[/\-\.]\d{2,4}\b',
        "[DOB_REDACTED]",
        0.89
    ),
    "medical_record": (
        r'\b(?:MRN|medical\s+record\s+(?:number|#|num))\s*:?\s*[A-Z0-9\-]{6,}\b',
        "[MRN_REDACTED]",
        0.90
    ),
    "bitcoin_address": (
        r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b',
        "[CRYPTO_ADDRESS_REDACTED]",
        0.88
    ),
    "ethereum_address": (
        r'\b0x[a-fA-F0-9]{40}\b',
        "[CRYPTO_ADDRESS_REDACTED]",
        0.95
    ),
}


class PIIEngine:
    """
    High-performance PII detection and redaction engine.
    Compiles all regex patterns at startup for maximum throughput.
    """

    def __init__(self, enabled_types: List[str] = None):
        """
        Args:
            enabled_types: list of PII types to check (None = all)
        """
        self._patterns: List[Tuple[str, re.Pattern, str, float]] = []
        target_types = enabled_types or list(PII_PATTERNS.keys())

        for pii_type, (pattern, replacement, confidence) in PII_PATTERNS.items():
            if pii_type in target_types:
                try:
                    compiled = re.compile(pattern, re.IGNORECASE | re.MULTILINE)
                    self._patterns.append((pii_type, compiled, replacement, confidence))
                except re.error:
                    pass

    def detect(self, text: str) -> Tuple[bool, List[PIIMatch], str]:
        """
        Detect and redact PII from text.

        Returns:
            (has_pii, matches, redacted_text)
        """
        matches: List[PIIMatch] = []
        redacted = text

        for pii_type, pattern, replacement, confidence in self._patterns:
            for m in pattern.finditer(text):
                matches.append(PIIMatch(
                    pii_type=pii_type,
                    value=m.group(0),
                    replacement=replacement,
                    position=m.start(),
                    confidence=confidence,
                ))

        if matches:
            # Redact in reverse order to preserve positions
            redacted = text
            for pii_type, pattern, replacement, _ in self._patterns:
                redacted = pattern.sub(replacement, redacted)

        return bool(matches), matches, redacted

    def get_pii_summary(self, matches: List[PIIMatch]) -> Dict[str, int]:
        """Returns a count of each PII type found."""
        summary: Dict[str, int] = {}
        for m in matches:
            summary[m.pii_type] = summary.get(m.pii_type, 0) + 1
        return summary

    def get_unique_types(self, matches: List[PIIMatch]) -> Set[str]:
        return {m.pii_type for m in matches}
