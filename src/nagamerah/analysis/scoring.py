
"""Evidence-driven threat scoring for NAGAMERAH v2.

Threat Score is an explainable threat intensity index, not a probability.
"""

from __future__ import annotations

import math
from typing import Any

from .evidence import Evidence


MAX_PRIMARY_SCORE = 85
MAX_CORROBORATION = 15
MAX_THREAT_SCORE = 100


def _valid_number(value: Any) -> float | None:
    """Return a valid finite numeric value, excluding booleans."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None

    value = float(value)

    if not math.isfinite(value):
        return None

    return value


def _valid_percentage(value: Any) -> float | None:
    """Validate percentage values within the 0-100 range."""
    number = _valid_number(value)

    if number is None or not 0 <= number <= 100:
        return None

    return number


def _valid_count(value: Any) -> int | None:
    """Validate non-negative integer counters."""
    if isinstance(value, bool) or not isinstance(value, int):
        return None

    if value < 0:
        return None

    return value


def _tier(value: float, thresholds: tuple[tuple[float, int], ...]) -> int:
    """Convert a validated percentage into a bounded score."""
    for threshold, points in thresholds:
        if value < threshold:
            return points

    return thresholds[-1][1]


def _vt_malicious_score(ratio: float) -> int:
    """Map VT malicious detection ratio into a threat score."""
    return _tier(
        ratio,
        (
            (1, 0),
            (5, 10),
            (10, 20),
            (20, 35),
            (35, 50),
            (50, 65),
            (70, 75),
            (101, 85),
        ),
    )


def _vt_suspicious_score(ratio: float) -> int:
    """Map suspicious-only detections into a bounded supporting score."""
    return _tier(
        ratio,
        (
            (1, 0),
            (5, 5),
            (10, 10),
            (20, 15),
            (101, 25),
        ),
    )


def _abuseipdb_score(value: float) -> int:
    """Map AbuseIPDB confidence into a threat score."""
    return _tier(
        value,
        (
            (1, 0),
            (10, 10),
            (25, 20),
            (40, 35),
            (60, 50),
            (75, 65),
            (90, 75),
            (101, 85),
        ),
    )


def _get_vt_malicious(evidence: Evidence) -> int | None:
    """Return a validated VirusTotal malicious signal."""
    ratio = _valid_percentage(evidence.metadata.get("ratio"))
    engine_count = _valid_count(evidence.metadata.get("engine_count"))
    detection_count = _valid_count(evidence.value)

    if ratio is None or engine_count is None or detection_count is None:
        return None

    if engine_count == 0 or detection_count == 0:
        return None

    if detection_count > engine_count:
        return None

    # Ensure the normalized ratio is consistent with its raw counts.
    expected_ratio = detection_count / engine_count * 100

    if not math.isclose(ratio, expected_ratio, abs_tol=0.1):
        return None

    score = _vt_malicious_score(ratio)

    # Insufficient engine sample sizes must not produce a strong score.
    if engine_count < 5:
        score = min(score, 20)
    elif engine_count < 10:
        score = min(score, 40)

    return score


def _get_vt_suspicious(evidence: Evidence) -> int | None:
    """Return a validated, bounded VirusTotal suspicious signal."""
    ratio = _valid_percentage(evidence.metadata.get("ratio"))
    engine_count = _valid_count(evidence.metadata.get("engine_count"))
    detection_count = _valid_count(evidence.value)

    if ratio is None or engine_count is None or detection_count is None:
        return None

    if engine_count == 0 or detection_count == 0:
        return None

    if detection_count > engine_count:
        return None

    expected_ratio = detection_count / engine_count * 100

    if not math.isclose(ratio, expected_ratio, abs_tol=0.1):
        return None

    score = _vt_suspicious_score(ratio)

    if engine_count < 5:
        score = min(score, 10)
    elif engine_count < 10:
        score = min(score, 15)

    return score


def _get_abuseipdb(evidence: Evidence) -> int | None:
    """Return a validated AbuseIPDB confidence signal."""
    confidence = _valid_percentage(evidence.value)

    if confidence is None:
        return None

    return _abuseipdb_score(confidence)


def score_evidence(evidence: list[Evidence] | None) -> float | None:
    """Calculate a Threat Score from normalized evidence.

    Primary signals:
        VirusTotal malicious detection
        AbuseIPDB abuse confidence

    Supporting signal:
        VirusTotal suspicious detection

    Contextual evidence is deliberately excluded.

    Independent-provider corroboration is capped at 15 points.
    """
    if not evidence:
        return None

    vt_malicious = []
    vt_suspicious = []
    abuse_scores = []

    for item in evidence:
        if not isinstance(item, Evidence):
            continue

        if item.category != "threat":
            continue

        if item.source == "virustotal":
            if item.evidence_type == "malicious_detection":
                value = _get_vt_malicious(item)

                if value is not None:
                    vt_malicious.append(value)

            elif item.evidence_type == "suspicious_detection":
                value = _get_vt_suspicious(item)

                if value is not None:
                    vt_suspicious.append(value)

        elif item.source == "abuseipdb":
            if item.evidence_type == "abuse_confidence":
                value = _get_abuseipdb(item)

                if value is not None:
                    abuse_scores.append(value)

    # Deduplicate provider signals by retaining the strongest
    # valid signal from each provider.
    vt_primary = max(vt_malicious, default=None)
    abuse_primary = max(abuse_scores, default=None)
    vt_secondary = max(vt_suspicious, default=0)

    primary_signals = [
        value
        for value in (vt_primary, abuse_primary)
        if value is not None
    ]

    # Suspicious-only evidence cannot independently create
    # a high threat score.
    if not primary_signals:
        if vt_secondary == 0:
            return None

        return float(min(vt_secondary, 25))

    primary = max(primary_signals)

    # Corroboration is awarded only when both independent
    # providers have valid positive threat signals.
    corroboration = 0

    if (
        vt_primary is not None
        and abuse_primary is not None
        and vt_primary > 0
        and abuse_primary > 0
    ):
        corroboration = round(
            MAX_CORROBORATION * min(abuse_primary, vt_primary)
            / MAX_PRIMARY_SCORE,
            1,
        )

    final_score = min(
        MAX_THREAT_SCORE,
        primary + corroboration,
    )

    return round(float(final_score), 1)


def verdict(value: float | None) -> str:
    """Legacy score-to-verdict mapping.

    Full v2 verdict guardrails will be implemented separately
    in verdict.py.
    """
    if value is None:
        return "Unknown"

    if value < 40:
        return "No Detection"

    if value < 80:
        return "Suspicious"

    return "Malicious"



def score(results, weights=None):
    """Temporary legacy scoring for the existing engine.

    This function will be removed during engine migration.
    New v2 code must use score_evidence().
    """
    weights = weights or {"virustotal": 1.0, "abuseipdb": 1.0}

    valid = [
        result
        for result in results
        if result.status == "ok" and result.score is not None
    ]

    if not valid:
        return None

    weighted = []

    for result in valid:
        weight = float(weights.get(result.provider, 1.0))

        if weight > 0:
            weighted.append((float(result.score), weight))

    denominator = sum(weight for _, weight in weighted)

    if not denominator:
        return None

    return round(
        sum(value * weight for value, weight in weighted) / denominator,
        1,
    )
