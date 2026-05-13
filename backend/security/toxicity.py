"""
security/toxicity.py — Multi-Category Toxicity & Harm Detection

Categories:
- Violence / weapons
- Self-harm / suicide
- CSAM indicators
- Illegal activity facilitation
- Hate speech / discrimination
- Cybersecurity attacks
- Financial fraud / scams
- Drug facilitation
- Bioweapons / CBRN
"""
import re
from typing import List, Tuple, Optional, Dict
from dataclasses import dataclass


@dataclass
class ToxicityMatch:
    category: str
    matched_text: str
    pattern: str
    severity: str
    confidence: float


# ── Category Pattern Definitions ──────────────────────────────────────────────

TOXICITY_CATEGORIES: Dict[str, Tuple[List[str], str, float]] = {
    "violence": (
        [
            r'\bhow\s+to\s+(?:kill|murder|hurt|attack|harm)\s+(?:someone|a person|people)\b',
            r'\b(?:make|build|create|construct)\s+(?:a\s+)?(?:bomb|explosive|weapon|IED)\b',
            r'\b(?:instructions|steps|guide|tutorial)\s+(?:for|to|on)\s+(?:killing|murdering|harming)\b',
            r'\b(?:mass\s+shooting|mass\s+murder|massacre)\s+(?:how|plan|guide)\b',
            r'\b(?:stab|shoot|strangle|poison)\s+(?:someone|a person|them)\b',
        ],
        "critical",
        0.94
    ),
    "self_harm": (
        [
            r'\bhow\s+to\s+(?:commit\s+suicide|kill\s+myself|end\s+my\s+life)\b',
            r'\b(?:methods|ways|steps)\s+(?:of|to)\s+(?:suicide|self.harm|self-harm)\b',
            r'\bwhat(?:\'s| is)\s+(?:the\s+)?(?:most\s+)?(?:effective|painless)\s+(?:way|method)\s+to\s+(?:die|kill\s+myself)\b',
            r'\b(?:cutting|burning|hurting)\s+myself\s+(?:instructions|how\s+to|steps)\b',
        ],
        "critical",
        0.96
    ),
    "cyberattack": (
        [
            r'\b(?:how\s+to|steps\s+to|guide\s+to)\s+(?:hack|compromise|infiltrate|breach)\s+(?:a\s+)?(?:system|network|website|database|server)\b',
            r'\b(?:create|write|build|develop|make)\s+(?:a\s+)?(?:virus|malware|ransomware|keylogger|trojan|worm|rootkit|backdoor)\b',
            r'\b(?:SQL|command|code)\s+injection\s+(?:tutorial|how\s+to|example)\b',
            r'\b(?:DDoS|denial.of.service)\s+(?:attack|tool|script|instructions)\b',
            r'\bbrute\s+force\s+(?:attack|password|login)\s+(?:tool|script|code)\b',
            r'\b(?:phishing|spear.phishing)\s+(?:email|template|kit|page)\s+(?:create|build|make)\b',
            r'\b(?:exploit|vulnerability)\s+(?:code|script|payload|CVE-\d{4}-\d+)\b',
        ],
        "high",
        0.89
    ),
    "hate_speech": (
        [
            r'\b(?:all|most|those)\s+\w+(?:\s+\w+)?\s+(?:are|should be)\s+(?:killed|exterminated|eliminated|inferior|subhuman)\b',
            r'\b(?:white|black|Jewish|Muslim|Christian|Asian|Hispanic)\s+(?:supremacy|genocide|extermination)\b',
            r'\b(?:slur|racial epithet|offensive term)\s+(?:against|for)\b',
            r'\bgenerate\s+(?:racist|antisemitic|islamophobic|homophobic)\s+(?:content|jokes|memes|propaganda)\b',
        ],
        "high",
        0.87
    ),
    "illegal_drugs": (
        [
            r'\bhow\s+to\s+(?:make|synthesize|produce|manufacture|cook)\s+(?:meth|methamphetamine|heroin|cocaine|fentanyl|MDMA|ecstasy)\b',
            r'\b(?:drug|narcotics)\s+(?:synthesis|manufacturing|production)\s+(?:instructions|guide|steps)\b',
            r'\b(?:acquire|buy|purchase|get)\s+(?:drugs|narcotics|controlled\s+substances)\s+(?:illegally|online|darkweb)\b',
        ],
        "high",
        0.91
    ),
    "financial_fraud": (
        [
            r'\bhow\s+to\s+(?:commit|run|execute)\s+(?:fraud|scam|ponzi|money\s+laundering)\b',
            r'\b(?:fake|counterfeit|forge)\s+(?:identity|documents|checks|currency)\b',
            r'\b(?:launder|wash)\s+(?:money|funds|cash)\s+(?:how\s+to|guide|steps|methods)\b',
            r'\b(?:credit\s+card|identity)\s+(?:fraud|theft)\s+(?:how\s+to|guide|steps|methods)\b',
            r'\bpump\s+and\s+dump\s+(?:scheme|scam|manipulation)\b',
        ],
        "high",
        0.88
    ),
    "bioweapons": (
        [
            r'\b(?:how\s+to|steps\s+to|guide\s+to)\s+(?:create|make|synthesize|weaponize)\s+(?:anthrax|botulinum|ricin|sarin|VX|novichok)\b',
            r'\b(?:biological|chemical)\s+(?:weapon|agent|warfare)\s+(?:synthesis|production|creation|guide)\b',
            r'\bCBRN\s+(?:weapon|attack|synthesis)\b',
            r'\bweaponize\s+(?:pathogen|bacteria|virus|toxin)\b',
        ],
        "critical",
        0.99
    ),
    "csam": (
        [
            r'\b(?:child|minor|underage|teen|juvenile)\s+(?:sexual|erotic|nude|naked|explicit)\s+(?:content|material|image|video|photo)\b',
            r'\b(?:CSAM|CP|child\s+porn(?:ography)?)\b',
            r'\bsexual\s+(?:content|material)\s+(?:involving|with|of)\s+(?:minor|child|underage|teen)\b',
        ],
        "critical",
        0.99
    ),
}


class ToxicityEngine:
    """
    Rule-based toxicity and harmful content detector.
    Fast, deterministic, no API calls required.
    """

    def __init__(self, enabled_categories: List[str] = None):
        self._compiled: Dict[str, Tuple[List[re.Pattern], str, float]] = {}
        target = enabled_categories or list(TOXICITY_CATEGORIES.keys())

        for category, (patterns, severity, confidence) in TOXICITY_CATEGORIES.items():
            if category in target:
                compiled_patterns = []
                for p in patterns:
                    try:
                        compiled_patterns.append(re.compile(p, re.IGNORECASE | re.DOTALL))
                    except re.error:
                        pass
                self._compiled[category] = (compiled_patterns, severity, confidence)

    def analyze(self, text: str) -> Tuple[List[ToxicityMatch], float]:
        """
        Analyze text for toxic/harmful content.

        Returns:
            (matches, max_severity_score)
        """
        matches: List[ToxicityMatch] = []

        for category, (patterns, severity, confidence) in self._compiled.items():
            for pattern in patterns:
                m = pattern.search(text)
                if m:
                    matches.append(ToxicityMatch(
                        category=category,
                        matched_text=m.group(0)[:100],
                        pattern=pattern.pattern[:80],
                        severity=severity,
                        confidence=confidence,
                    ))
                    break  # One match per category is enough

        if not matches:
            return [], 0.0

        # Score is max confidence
        max_score = max(m.confidence for m in matches)
        return matches, max_score

    def get_severity_score(self, severity: str) -> float:
        return {"critical": 1.0, "high": 0.85, "medium": 0.65, "low": 0.40}.get(severity, 0.5)
