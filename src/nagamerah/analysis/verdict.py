
"""Evidence-based verdict engine for NAGAMERAH."""

import math
from typing import Any


MALICIOUS_THRESHOLD = 80
SUSPICIOUS_THRESHOLD = 40
VT_MINIMUM_ENGINES = 10
VT_MALICIOUS_RATIO_THRESHOLD = 50.0
ABUSE_CONFIDENCE_THRESHOLD = 90.0


def _get(evidence: Any, key: str, default: Any = None) -> Any:
    """Read evidence fields from either a dictionary or an object."""
    if isinstance(evidence, dict):
        return evidence.get(key, default)
    return getattr(evidence, key, default)


def _valid_number(value: Any) -> float | None:
    """Return a finite numeric value, excluding booleans."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None

    if not math.isfinite(value):
        return None

    return float(value)


def _valid_ratio(value: Any) -> float | None:
    number = _valid_number(value)

    if number is None or not 0 <= number <= 100:
        return None

    return number


def _valid_engine_count(value: Any) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int):
        return None

    if value <= 0:
        return None

    return value


def _has_strong_vt_evidence(evidence: Any) -> bool:
    """Check whether VT malicious evidence meets minimum quality requirements."""
    if (
        _get(evidence, "source") != "virustotal"
        or _get(evidence, "category") != "threat"
        or _get(evidence, "evidence_type") != "malicious_detection"
    ):
        return False

    detections = _valid_number(_get(evidence, "value"))
    metadata = _get(evidence, "metadata", {})

    if not isinstance(metadata, dict) or detections is None:
        return False

    engines = _valid_engine_count(metadata.get("engine_count"))
    ratio = _valid_ratio(metadata.get("ratio"))

    if engines is None or ratio is None:
        return False

    if engines < VT_MINIMUM_ENGINES:
        return False

    if detections <= 0 or ratio < VT_MALICIOUS_RATIO_THRESHOLD:
        return False

    # Ensure the reported ratio is consistent with detection count.
    calculated_ratio = detections / engines * 100

    if not math.isclose(ratio, calculated_ratio, abs_tol=1.0):
        return False

    return True


def _has_strong_abuseipdb_evidence(evidence: Any) -> bool:
    """Check whether AbuseIPDB confidence meets the malicious threshold."""
    if (
        _get(evidence, "source") != "abuseipdb"
        or _get(evidence, "category") != "threat"
        or _get(evidence, "evidence_type") != "abuse_confidence"
    ):
        return False

    confidence = _valid_ratio(_get(evidence, "value"))

    return (
        confidence is not None
        and confidence >= ABUSE_CONFIDENCE_THRESHOLD
    )


def _has_primary_threat_evidence(evidence: list) -> bool:
    """Check for recognized primary threat evidence."""
    for item in evidence:
        if _has_strong_vt_evidence(item):
            return True

        if _has_strong_abuseipdb_evidence(item):
            return True

    return False



def _has_valid_threat_signal(evidence: list) -> bool:
    """Check for recognized and valid threat evidence, including valid zero results."""
    for item in evidence:
        source = _get(item, "source")
        category = _get(item, "category")
        evidence_type = _get(item, "evidence_type")
        value = _valid_number(_get(item, "value"))

        if category != "threat" or value is None or value < 0:
            continue

        if source == "virustotal" and evidence_type in {
            "malicious_detection",
            "suspicious_detection",
        }:
            metadata = _get(item, "metadata", {})

            if not isinstance(metadata, dict):
                continue

            engines = _valid_engine_count(metadata.get("engine_count"))
            ratio = _valid_ratio(metadata.get("ratio"))

            if engines is None or ratio is None:
                continue

            if value > engines:
                continue

            calculated_ratio = value / engines * 100

            if math.isclose(ratio, calculated_ratio, abs_tol=1.0):
                return True

        elif source == "abuseipdb" and evidence_type == "abuse_confidence":
            if _valid_ratio(value) is not None:
                return True

    return False

def verdict(threat_score: Any, evidence: list | None = None) -> str:
    """Determine verdict using score and validated evidence."""
    evidence = evidence or []

    score = _valid_number(threat_score)

    if score is None or not 0 <= score <= 100:
        return "INCONCLUSIVE"

    if not evidence:
        return "INCONCLUSIVE"

    if not _has_valid_threat_signal(evidence):
        return "INCONCLUSIVE"

    if score >= MALICIOUS_THRESHOLD and _has_primary_threat_evidence(evidence):
        return "MALICIOUS"

    if score >= SUSPICIOUS_THRESHOLD:
        return "SUSPICIOUS"

    return "NO DETECTION"
