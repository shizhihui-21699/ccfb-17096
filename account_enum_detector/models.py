"""Data models for account-enumeration detection."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class ProbeRecord:
    seq: int
    round_index: int
    klass: str  # existing | nonexisting | warmup
    account: str
    account_masked: str
    requested_at: str
    status: int | None = None
    ok: bool = False
    error: str | None = None
    ttfb_ms: float | None = None
    total_ms: float | None = None
    body_length: int = 0
    body_sha256: str | None = None
    body_excerpt: str = ""
    normalized_body: str = ""
    normalized_sha256: str | None = None
    header_signature: str | None = None
    headers_normalized: dict[str, str] = field(default_factory=dict)
    defense_reasons: list[str] = field(default_factory=list)

    def to_dict(self, include_accounts: bool = False) -> dict[str, Any]:
        data = asdict(self)
        if not include_accounts:
            data.pop("account", None)
        return data


@dataclass
class Finding:
    kind: str
    verdict_weight: str  # strong | moderate | info
    title: str
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class AnalysisResult:
    verdict: str
    confidence: str
    summary: str
    sample_counts: dict[str, int]
    successful_counts: dict[str, int]
    defense: dict[str, Any]
    timing: dict[str, Any]
    findings: list[Finding]

    def to_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict,
            "confidence": self.confidence,
            "summary": self.summary,
            "sample_counts": self.sample_counts,
            "successful_counts": self.successful_counts,
            "defense": self.defense,
            "timing": self.timing,
            "findings": [f.to_dict() for f in self.findings],
        }
