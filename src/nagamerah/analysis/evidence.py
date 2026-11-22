
"""Normalized evidence model for NAGAMERAH."""

from dataclasses import dataclass, field
from typing import Any


@dataclass
class Evidence:
    source: str
    category: str
    evidence_type: str
    value: Any
    description: str
    severity: str = "unknown"
    confidence: str = "unknown"
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert evidence into a JSON-serializable dictionary."""
        return {
            "source": self.source,
            "category": self.category,
            "evidence_type": self.evidence_type,
            "value": self.value,
            "description": self.description,
            "severity": self.severity,
            "confidence": self.confidence,
            "metadata": self.metadata,
        }
