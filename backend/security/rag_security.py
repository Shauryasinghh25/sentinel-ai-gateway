"""
security/rag_security.py — RAG Pipeline Security Layer

Protects vector database retrievals and document ingestion against:
- Document poisoning attacks
- Malicious chunk injection
- Prompt injection embedded in documents
- PII in retrieved context
- Context manipulation attacks
"""
import re
from typing import List, Tuple, Dict, Optional
from dataclasses import dataclass, field

from backend.security.injection import PromptInjectionEngine
from backend.security.pii import PIIEngine
from backend.models.schemas import RiskLevel


@dataclass
class ChunkSecurityResult:
    """Security analysis result for a single retrieved document chunk."""
    chunk_id: str
    is_safe: bool
    risk_score: float
    risk_level: RiskLevel
    issues: List[str] = field(default_factory=list)
    sanitized_content: Optional[str] = None
    original_content: str = ""


@dataclass
class RAGSecurityResult:
    """Security analysis for an entire RAG retrieval batch."""
    total_chunks: int
    safe_chunks: int
    blocked_chunks: int
    sanitized_chunks: int
    chunk_results: List[ChunkSecurityResult] = field(default_factory=list)
    safe_context: str = ""
    overall_risk_score: float = 0.0


# ── Suspicious document patterns (embedded injections in docs) ────────────────

DOCUMENT_INJECTION_PATTERNS = [
    # Direct instruction overrides in documents
    r'IGNORE\s+(?:THE\s+)?(?:ABOVE|PREVIOUS|ALL)\s+INSTRUCTIONS',
    r'NEW\s+INSTRUCTION\s*:',
    r'SYSTEM\s*:\s*(?:ignore|forget|override)',
    r'<\|im_start\|>',
    r'<\|im_end\|>',
    r'\[\[SYSTEM\]\]',
    r'END\s+OF\s+(?:DOCUMENT|TEXT)\s*\.\s*(?:NEW|UPDATED)\s+INSTRUCTIONS',
    r'STOP\s+(?:READING|PROCESSING)\s+(?:AND|THEN)\s+(?:INSTEAD|DO)',
    # Fake conversation turns embedded in docs
    r'^User\s*:\s*(?:ignore|forget|disregard)',
    r'^Human\s*:\s*(?:ignore|forget|disregard)',
    r'^Assistant\s*:\s*(?:I will|Sure|Of course|Certainly)',
]

MALICIOUS_METADATA_PATTERNS = [
    r'(?:system|instruction)\s*:\s*(?:ignore|override|forget)',
    r'<metadata>.*?(?:inject|override).*?</metadata>',
]

PII_SENSITIVE_PATTERNS = [
    r'\b\d{3}[-\s]\d{2}[-\s]\d{4}\b',  # SSN
    r'\b(?:patient|medical)\s+(?:record|id)\s*:?\s*\w+\b',
    r'\b(?:HIPAA|PHI|PII)\b',
]


class RAGSecurityLayer:
    """
    Security layer for RAG (Retrieval Augmented Generation) pipelines.

    Integrates with:
    - ChromaDB
    - Pinecone  
    - FAISS
    - Qdrant
    """

    def __init__(self):
        self.injection_engine = PromptInjectionEngine()
        self.pii_engine = PIIEngine()
        self._doc_patterns = [
            re.compile(p, re.IGNORECASE | re.MULTILINE)
            for p in DOCUMENT_INJECTION_PATTERNS
        ]

    def sanitize_document(self, content: str, doc_id: str = "") -> Tuple[str, List[str]]:
        """
        Sanitize a document before ingestion into the vector store.

        Returns (sanitized_content, list_of_issues)
        """
        issues = []
        sanitized = content

        # Check for embedded injection patterns
        for pattern in self._doc_patterns:
            if pattern.search(content):
                issues.append(f"Embedded injection pattern detected: {pattern.pattern[:50]}")
                # Remove the malicious instruction
                sanitized = pattern.sub("[REMOVED]", sanitized)

        # Check for PII in documents
        has_pii, pii_matches, redacted = self.pii_engine.detect(content)
        if has_pii:
            pii_types = self.pii_engine.get_unique_types(pii_matches)
            issues.append(f"PII detected in document: {', '.join(pii_types)}")
            sanitized = redacted

        return sanitized, issues

    def validate_chunk(self, chunk: str, chunk_id: str = "") -> ChunkSecurityResult:
        """
        Validate a single retrieved chunk before inclusion in the LLM context.
        """
        issues = []
        risk_score = 0.0
        sanitized = chunk

        # 1. Check for prompt injection in chunk
        inj_matches, inj_score, attack_type = self.injection_engine.analyze(chunk)
        if inj_matches:
            issues.append(f"Prompt injection in retrieved chunk: {attack_type}")
            risk_score = max(risk_score, inj_score)

        # 2. Check for embedded instructions
        for pattern in self._doc_patterns:
            if pattern.search(chunk):
                issues.append("Malicious instruction embedded in chunk")
                risk_score = max(risk_score, 0.90)
                sanitized = pattern.sub("[BLOCKED_CONTENT]", sanitized)

        # 3. PII in retrieved context
        has_pii, pii_matches, redacted = self.pii_engine.detect(chunk)
        if has_pii:
            pii_types = self.pii_engine.get_unique_types(pii_matches)
            issues.append(f"PII in retrieved context: {', '.join(pii_types)}")
            risk_score = max(risk_score, 0.75)
            sanitized = redacted

        # 4. Anomaly detection: very short chunks that only contain commands
        if len(chunk.split()) < 10 and issues:
            risk_score = min(1.0, risk_score + 0.1)

        is_safe = risk_score < 0.6
        risk_level = self._score_to_level(risk_score)

        return ChunkSecurityResult(
            chunk_id=chunk_id or f"chunk_{hash(chunk[:20]):08x}",
            is_safe=is_safe,
            risk_score=round(risk_score, 3),
            risk_level=risk_level,
            issues=issues,
            sanitized_content=sanitized if sanitized != chunk else None,
            original_content=chunk,
        )

    def validate_retrieval_batch(
        self,
        chunks: List[str],
        max_risk_score: float = 0.6,
    ) -> RAGSecurityResult:
        """
        Validate a batch of retrieved chunks.

        Filters out poisoned/malicious chunks and builds a safe context window.
        """
        chunk_results = []
        safe_parts = []
        blocked = 0
        sanitized_count = 0

        for i, chunk in enumerate(chunks):
            result = self.validate_chunk(chunk, f"chunk_{i}")
            chunk_results.append(result)

            if not result.is_safe:
                blocked += 1
            else:
                content = result.sanitized_content or result.original_content
                if result.sanitized_content:
                    sanitized_count += 1
                safe_parts.append(content)

        overall_risk = max((r.risk_score for r in chunk_results), default=0.0)

        return RAGSecurityResult(
            total_chunks=len(chunks),
            safe_chunks=len(chunks) - blocked,
            blocked_chunks=blocked,
            sanitized_chunks=sanitized_count,
            chunk_results=chunk_results,
            safe_context="\n\n".join(safe_parts),
            overall_risk_score=round(overall_risk, 3),
        )

    def _score_to_level(self, score: float) -> RiskLevel:
        if score >= 0.90:
            return RiskLevel.CRITICAL
        elif score >= 0.75:
            return RiskLevel.HIGH
        elif score >= 0.60:
            return RiskLevel.MEDIUM
        elif score >= 0.30:
            return RiskLevel.LOW
        return RiskLevel.NONE
