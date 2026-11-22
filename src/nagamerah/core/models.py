
from typing import Any

from pydantic import BaseModel, Field


class ProviderResult(BaseModel):
    provider: str
    status: str
    score: float | None = None
    summary: dict[str, Any] = Field(default_factory=dict)
    queried_at: str | None = None
    from_cache: bool = False
    error: str | None = None


class AnalysisResult(BaseModel):
    ioc: dict
    providers: list[ProviderResult] = Field(default_factory=list)

    # Threat assessment
    score: float | None = None
    verdict: str = "Unknown"

    # Confidence level retained for compatibility
    confidence: str = "LOW"

    # Detailed confidence assessment
    confidence_assessment: dict[str, Any] | None = None

    # Coverage of applicable provider checks
    coverage: dict[str, Any] | None = None

    labels: list[str] = Field(default_factory=list)

    # Legacy classifier output retained for compatibility
    evidence: list[str] = Field(default_factory=list)

    # Structured evidence from the v2 normalizer
    evidence_details: list[dict[str, Any]] = Field(default_factory=list)
