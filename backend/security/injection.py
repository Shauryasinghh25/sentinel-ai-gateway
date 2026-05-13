"""
security/injection.py — Advanced Prompt Injection Detection Engine

Detects:
- Jailbreak attempts (DAN, role override, etc.)
- Indirect prompt injection
- Unicode obfuscation
- Hidden instructions
- Tool manipulation attacks
- Prompt leakage attempts
- Role override attacks

Uses a multi-layer approach:
1. Rule-based pattern matching (fast, <1ms)
2. Semantic heuristics (character analysis)
3. Risk score aggregation
"""
import re
import unicodedata
from typing import List, Tuple, Optional, Dict
from dataclasses import dataclass, field


@dataclass
class InjectionMatch:
    """A single matched injection pattern."""
    attack_type: str
    pattern: str
    confidence: float
    matched_text: str
    severity: str  # critical / high / medium / low


# ── Injection Pattern Library ────────────────────────────────────────────────

JAILBREAK_PATTERNS: List[Tuple[str, float, str]] = [
    # (regex pattern, confidence, severity)
    # DAN / Do Anything Now
    (r'\bdan\s+mode\b', 0.98, "critical"),
    (r'\bdo anything now\b', 0.97, "critical"),
    (r'\byou are now\s+(?:dan|jailbroken|freed|unrestricted)', 0.98, "critical"),

    # Role override
    (r'\bact as\s+(?:a |an )?(?:jailbroken|unrestricted|evil|hacked|uncensored|DAN)\b', 0.97, "critical"),
    (r'\bpretend\s+(?:you are|to be)\s+(?:a |an )?(?:different|evil|uncensored|unrestricted)', 0.92, "critical"),
    (r'\byou are no longer\s+(?:an ai|a language model|restricted)', 0.95, "critical"),
    (r'\byou have no\s+(?:restrictions|limits|guidelines|rules)', 0.93, "critical"),
    (r'\byour\s+(?:true self|real|actual)\s+(?:is|has no)', 0.88, "high"),

    # Instruction override
    (r'ignore\s+(?:all\s+)?(?:previous|prior|above|your)\s+instructions', 0.99, "critical"),
    (r'disregard\s+(?:all\s+)?(?:previous|prior|above|your)\s+instructions', 0.99, "critical"),
    (r'forget\s+(?:everything|what|your|all)\s+(?:you|instructions|were)', 0.96, "critical"),
    (r'override\s+(?:your\s+)?(?:instructions|safety|guidelines|training)', 0.97, "critical"),
    (r'bypass\s+(?:your\s+)?(?:safety|filters|guardrails|restrictions|content\s+policy)', 0.97, "critical"),
    (r'new\s+(?:primary\s+)?instructions?\s*:', 0.90, "high"),
    (r'updated?\s+(?:system\s+)?instructions?\s*:', 0.88, "high"),

    # System prompt attacks
    (r'\[system\]', 0.85, "high"),
    (r'<system>', 0.85, "high"),
    (r'system\s+prompt\s*:', 0.87, "high"),
    (r'your\s+(?:actual\s+)?system\s+prompt\s+(?:is|says|contains)', 0.89, "high"),
    (r'reveal\s+(?:your\s+)?(?:system|original|base)\s+prompt', 0.94, "critical"),
    (r'print\s+(?:your\s+)?(?:system|original|base)\s+prompt', 0.94, "critical"),
    (r'show\s+(?:me\s+)?(?:your\s+)?(?:system|hidden)\s+(?:prompt|instructions)', 0.92, "critical"),

    # Jailbreak keywords
    (r'\bjailbreak\b', 0.95, "critical"),
    (r'\bunrestricted\s+mode\b', 0.93, "critical"),
    (r'\bgrandma\s+(?:trick|exploit|jailbreak)\b', 0.90, "high"),
    (r'\bhypothetically\s+speaking.*(?:how to|instructions|steps)', 0.82, "high"),
    (r'\bfor\s+(?:educational|research|fictional)\s+purposes.*(?:how to|instructions)', 0.80, "high"),
    (r'\bin\s+(?:a|this)\s+story.*(?:how to|instructions|steps\s+to)', 0.78, "medium"),

    # Developer/debug mode tricks
    (r'\bdeveloper\s+mode\s+(?:enabled|activated|on)\b', 0.91, "high"),
    (r'\bdebug\s+mode\s+(?:enabled|activated|on)\b', 0.88, "high"),
    (r'\bgod\s+mode\s+(?:enabled|activated|on)\b', 0.93, "high"),
    (r'\bsudo\s+(?:mode|command)\b', 0.85, "high"),
    (r'\badmin\s+override\b', 0.87, "high"),

    # Manipulation patterns
    (r'when\s+(?:you\s+)?(?:say|respond|reply)\s+\w+\s+it\s+(?:actually\s+)?means', 0.83, "high"),
    (r'from\s+now\s+on\s+(?:you\s+(?:are|will|must|should))', 0.88, "high"),
    (r'your\s+(?:new\s+)?role\s+is\s+to\b', 0.86, "high"),
    (r'translate\s+(?:everything|your\s+response)\s+to\b.*\bbase64\b', 0.91, "high"),
]

INDIRECT_INJECTION_PATTERNS: List[Tuple[str, float, str]] = [
    # Patterns that might appear in documents/RAG content
    (r'<injection>', 0.99, "critical"),
    (r'\[\[inject\]\]', 0.99, "critical"),
    (r'<!--.*instructions.*-->', 0.90, "high"),
    (r'STOP\.\s+IGNORE\s+(?:THE\s+)?(?:ABOVE|PREVIOUS)', 0.97, "critical"),
    (r'ASSISTANT\s*:\s*(?:Sure|Of course|I will)', 0.88, "high"),
    (r'Human:\s*(?:ignore|disregard)', 0.87, "high"),
    (r'\bNEW\s+TASK\b.*\bFORGET\b', 0.93, "critical"),
    (r'\bINSTRUCTION\s+OVERRIDE\b', 0.97, "critical"),
    (r'END\s+OF\s+(?:DOCUMENT|TEXT)\.\s*NEW\s+INSTRUCTIONS', 0.98, "critical"),
]

HIDDEN_INSTRUCTION_PATTERNS: List[Tuple[str, float, str]] = [
    # Zero-width characters
    (r'[\u200b\u200c\u200d\u2060\ufeff]', 0.92, "high"),
    # Excessive whitespace for hiding
    (r'\S\s{20,}\S', 0.75, "medium"),
    # Homoglyph patterns (look-alike characters)
    (r'[аеоuіoа]\s*(?:ignore|system|prompt)', 0.85, "high"),  # Cyrillic lookalikes
]

TOOL_MANIPULATION_PATTERNS: List[Tuple[str, float, str]] = [
    (r'\bcall\s+(?:the\s+)?(?:delete|drop|exec|execute|shell|bash|cmd)\s+(?:tool|function|api)', 0.94, "critical"),
    (r'\bexecute\s+(?:this\s+)?(?:code|command|script|shell)\s+(?:for|as|using)\b', 0.88, "high"),
    (r'\buse\s+(?:the\s+)?(?:file|filesystem|shell|terminal|bash)\s+(?:tool|api|function)\b', 0.85, "high"),
    (r'\baccess\s+(?:the\s+)?(?:database|db|filesystem|network)\s+(?:directly|tool|api)', 0.87, "high"),
    (r'\bsend\s+(?:my|the)\s+(?:data|information|credentials)\s+to\b', 0.90, "high"),
    (r'\bexfiltrate\b', 0.98, "critical"),
]

PROMPT_LEAKAGE_PATTERNS: List[Tuple[str, float, str]] = [
    (r'what\s+(?:are\s+)?(?:your\s+)?(?:initial|original|starting|system)\s+instructions', 0.90, "high"),
    (r'what\s+(?:was\s+)?(?:your\s+)?prompt', 0.85, "high"),
    (r'repeat\s+(?:your\s+)?(?:system|original|base|first)\s+(?:prompt|message|instruction)', 0.93, "critical"),
    (r'output\s+(?:your\s+)?(?:system|original|base)\s+prompt', 0.93, "critical"),
    (r'can\s+you\s+(?:tell|show|reveal)\s+(?:me\s+)?(?:your\s+)?(?:prompt|instructions)', 0.88, "high"),
]


class PromptInjectionEngine:
    """
    Multi-layer prompt injection detection engine.

    Returns a list of matched injection patterns with confidence scores
    and a final aggregated risk score.
    """

    def __init__(self):
        # Compile all patterns for performance
        self._jailbreak = self._compile(JAILBREAK_PATTERNS, "jailbreak")
        self._indirect = self._compile(INDIRECT_INJECTION_PATTERNS, "indirect_injection")
        self._hidden = self._compile(HIDDEN_INSTRUCTION_PATTERNS, "hidden_instruction")
        self._tool = self._compile(TOOL_MANIPULATION_PATTERNS, "tool_manipulation")
        self._leakage = self._compile(PROMPT_LEAKAGE_PATTERNS, "prompt_leakage")

    def _compile(
        self,
        patterns: List[Tuple[str, float, str]],
        attack_type: str
    ) -> List[Tuple[re.Pattern, float, str, str]]:
        compiled = []
        for pattern, confidence, severity in patterns:
            try:
                compiled.append((re.compile(pattern, re.IGNORECASE | re.DOTALL), confidence, severity, attack_type))
            except re.error:
                pass
        return compiled

    def _scan_group(
        self,
        text: str,
        pattern_group: List[Tuple[re.Pattern, float, str, str]]
    ) -> List[InjectionMatch]:
        matches = []
        for compiled_pattern, confidence, severity, attack_type in pattern_group:
            m = compiled_pattern.search(text)
            if m:
                matches.append(InjectionMatch(
                    attack_type=attack_type,
                    pattern=compiled_pattern.pattern,
                    confidence=confidence,
                    matched_text=m.group(0)[:100],
                    severity=severity,
                ))
        return matches

    def _check_unicode_obfuscation(self, text: str) -> List[InjectionMatch]:
        """Detect Unicode-based obfuscation and homoglyph attacks."""
        matches = []

        # Check for excessive non-ASCII characters that might be homoglyphs
        suspicious_chars = 0
        for char in text:
            cat = unicodedata.category(char)
            if cat in ('Cf', 'Mn') or (ord(char) > 127 and cat.startswith('L')):
                suspicious_chars += 1

        if suspicious_chars > 5:
            confidence = min(0.95, 0.6 + (suspicious_chars * 0.03))
            matches.append(InjectionMatch(
                attack_type="unicode_obfuscation",
                pattern="non-ascii-character-density",
                confidence=confidence,
                matched_text=f"{suspicious_chars} suspicious unicode chars",
                severity="high" if suspicious_chars > 15 else "medium",
            ))

        # Check for zero-width characters
        zero_width = [c for c in text if ord(c) in (0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF)]
        if zero_width:
            matches.append(InjectionMatch(
                attack_type="hidden_instruction",
                pattern="zero-width-character",
                confidence=0.93,
                matched_text=f"{len(zero_width)} zero-width chars",
                severity="high",
            ))

        return matches

    def _check_role_override(self, text: str) -> List[InjectionMatch]:
        """Detect role-switch attempts that don't match exact patterns."""
        matches = []
        lower = text.lower()

        # Check for "you are now X" variations
        you_are_patterns = [
            r'you\s+(?:are|should\s+be|will\s+be|must\s+be|can\s+be)\s+(?:now\s+)?(?:a |an )?(\w+)',
        ]
        for pat in you_are_patterns:
            for m in re.finditer(pat, lower):
                role = m.group(1) if m.lastindex else ""
                malicious_roles = {
                    'hacker', 'criminal', 'unrestricted', 'villain', 'evil', 'bad',
                    'uncensored', 'unfiltered', 'unmoderated', 'free', 'dangerous'
                }
                if role in malicious_roles:
                    matches.append(InjectionMatch(
                        attack_type="role_override",
                        pattern=pat,
                        confidence=0.94,
                        matched_text=m.group(0)[:80],
                        severity="critical",
                    ))

        return matches

    def analyze(self, text: str) -> Tuple[List[InjectionMatch], float, str]:
        """
        Full injection analysis.

        Returns:
            (matches, risk_score, primary_attack_type)
        """
        all_matches: List[InjectionMatch] = []

        # Run all detection layers
        all_matches.extend(self._scan_group(text, self._jailbreak))
        all_matches.extend(self._scan_group(text, self._indirect))
        all_matches.extend(self._scan_group(text, self._hidden))
        all_matches.extend(self._scan_group(text, self._tool))
        all_matches.extend(self._scan_group(text, self._leakage))
        all_matches.extend(self._check_unicode_obfuscation(text))
        all_matches.extend(self._check_role_override(text))

        if not all_matches:
            return [], 0.0, "none"

        # Aggregate risk score (max confidence + bonus for multiple matches)
        max_conf = max(m.confidence for m in all_matches)
        multi_bonus = min(0.1, (len(all_matches) - 1) * 0.02)
        risk_score = min(1.0, max_conf + multi_bonus)

        # Primary attack type = highest confidence match
        primary = max(all_matches, key=lambda m: m.confidence)

        return all_matches, risk_score, primary.attack_type
