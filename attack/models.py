from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class HTTPResponseEvidence:
    status_code: int
    url: str
    content_length: int
    content_type: str
    body_hash: str
    body_preview: str = ""


@dataclass
class IDORFinding:
    attack_type: str
    target: str
    endpoint: str
    parameter: str
    object_a: str
    object_b: str

    status: str
    confidence: str
    severity: str

    baseline: HTTPResponseEvidence | None = None
    cross_context: HTTPResponseEvidence | None = None

    evidence: list[str] = field(default_factory=list)
    ai_analysis: Any = None

    def to_dict(self) -> dict:
        return {
            "attack_type": self.attack_type,
            "target": self.target,
            "endpoint": self.endpoint,
            "parameter": self.parameter,
            "object_a": self.object_a,
            "object_b": self.object_b,
            "status": self.status,
            "confidence": self.confidence,
            "severity": self.severity,
            "baseline": (
                self.baseline.__dict__
                if self.baseline
                else None
            ),
            "cross_context": (
                self.cross_context.__dict__
                if self.cross_context
                else None
            ),
            "evidence": self.evidence,
            "ai_analysis": self.ai_analysis,
        }