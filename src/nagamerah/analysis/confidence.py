"""Evidence-based confidence evaluation for NAGAMERAH."""

from dataclasses import dataclass
from datetime import datetime, timezone
import math
from typing import Any


@dataclass(frozen=True)
class ConfidenceResult:
    score: int
    level: str
    reasons: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "score": self.score,
            "level": self.level,
            "reasons": list(self.reasons),
        }


def _get(item: Any, key: str, default: Any = None) -> Any:
    """Read a field from either a dictionary or an object."""
    if isinstance(item, dict):
        return item.get(key, default)

    return getattr(item, key, default)


def _number(value: Any) -> float | None:
    """Return a finite number, excluding booleans."""
    if isinstance(value, bool):
        return None

    if not isinstance(value, (int, float)):
        return None

    if not math.isfinite(value):
        return None

    return float(value)


def _timestamp(metadata: dict) -> datetime | None:
    """Extract the best available evidence timestamp."""

    keys = (
        "last_analysis_date",
        "last_reported_at",
        "timestamp",
        "last_seen",
        "updated_at",
        "queried_at",
    )

    for key in keys:
        value = metadata.get(key)

        if isinstance(value, bool):
            continue

        # Unix timestamp.
        if isinstance(value, (int, float)):
            try:
                return datetime.fromtimestamp(
                    value,
                    tz=timezone.utc,
                )
            except (ValueError, OverflowError, OSError):
                continue

        # ISO 8601 timestamp.
        if isinstance(value, str):
            try:
                parsed = datetime.fromisoformat(
                    value.replace("Z", "+00:00")
                )

                if parsed.tzinfo is None:
                    parsed = parsed.replace(tzinfo=timezone.utc)

                return parsed.astimezone(timezone.utc)

            except ValueError:
                continue

    return None


def _freshness_adjustment(
    metadata: dict,
    now: datetime,
) -> tuple[int, str]:
    """Adjust confidence according to evidence age."""

    timestamp = _timestamp(metadata)

    if timestamp is None:
        return -8, "Evidence timestamp unavailable (-8)"

    age_days = (now - timestamp).total_seconds() / 86400

    if age_days < -1:
        return -10, "Evidence timestamp is in the future (-10)"

    if age_days <= 30:
        return 5, "Evidence is recent (+5)"

    if age_days <= 90:
        return 0, "Evidence is 31–90 days old (+0)"

    return -15, "Evidence is older than 90 days (-15)"


def _evaluate_virustotal(item: Any, metadata: dict) -> int | None:
    """Evaluate VirusTotal evidence quality."""

    evidence_type = _get(item, "evidence_type")
    raw_value = _get(item, "value")

    if evidence_type not in {
        "malicious_detection",
        "suspicious_detection",
    }:
        return None

    if isinstance(raw_value, bool) or not isinstance(raw_value, int):
        return None

    engines = metadata.get("engine_count")
    ratio = _number(metadata.get("ratio"))

    if (
        isinstance(engines, bool)
        or not isinstance(engines, int)
        or engines <= 0
        or raw_value < 0
        or raw_value > engines
        or ratio is None
        or not 0 <= ratio <= 100
    ):
        return None

    actual_ratio = raw_value / engines * 100

    if not math.isclose(
        ratio,
        actual_ratio,
        abs_tol=1.0,
    ):
        return None

    quality = 50

    if engines >= 10:
        quality += 15

    if engines >= 20:
        quality += 10

    if engines >= 50:
        quality += 10

    if evidence_type == "suspicious_detection":
        quality -= 10

    return min(quality, 90)


def _evaluate_abuseipdb(item: Any, metadata: dict) -> int | None:
    """Evaluate AbuseIPDB evidence quality."""

    value = _number(_get(item, "value"))

    if value is None or not 0 <= value <= 100:
        return None

    reports = metadata.get("total_reports")

    if (
        isinstance(reports, bool)
        or not isinstance(reports, int)
        or reports < 0
    ):
        reports = 0

    quality = 50

    if reports >= 20:
        quality += 25
    elif reports >= 5:
        quality += 15
    elif reports >= 1:
        quality += 5

    return min(quality, 85)


def _evaluate_item(item: Any) -> tuple[int, str] | None:
    """Evaluate one threat evidence item."""

    source = _get(item, "source")
    category = _get(item, "category")
    evidence_type = _get(item, "evidence_type")
    value = _number(_get(item, "value"))
    metadata = _get(item, "metadata", {})

    if not isinstance(metadata, dict):
        return None

    if category != "threat" or value is None or value < 0:
        return None

    if source == "virustotal":
        quality = _evaluate_virustotal(item, metadata)

        if quality is not None:
            return quality, source

    elif source == "abuseipdb":
        if evidence_type == "abuse_confidence":
            quality = _evaluate_abuseipdb(item, metadata)

            if quality is not None:
                return quality, source

    return None


def _find(
    evidence: list,
    source: str,
    evidence_type: str,
) -> Any:
    """Find a specific threat evidence item."""

    for item in evidence:
        if (
            _get(item, "source") == source
            and _get(item, "category") == "threat"
            and _get(item, "evidence_type") == evidence_type
        ):
            return item

    return None


def evaluate_confidence(
    evidence: list,
    now: datetime | None = None,
) -> ConfidenceResult:
    """Evaluate confidence from evidence quality, freshness and corroboration."""

    if now is None:
        now = datetime.now(timezone.utc)

    elif now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)

    else:
        now = now.astimezone(timezone.utc)

    evaluated = []

    for item in evidence or []:
        result = _evaluate_item(item)

        if result is None:
            continue

        quality, source = result
        metadata = _get(item, "metadata", {})

        adjustment, freshness_reason = _freshness_adjustment(
            metadata,
            now,
        )

        evaluated.append({
            "quality": quality,
            "source": source,
            "adjustment": adjustment,
            "freshness_reason": freshness_reason,
        })

    if not evaluated:
        return ConfidenceResult(
            score=0,
            level="LOW",
            reasons=("No valid threat evidence available",),
        )

    # Select the strongest evidence by quality.
    strongest = max(
        evaluated,
        key=lambda item: item["quality"],
    )

    score = strongest["quality"] + strongest["adjustment"]

    reasons = [
        f"Strongest evidence source: {strongest['source']}",
        f"Evidence quality score: {strongest['quality']}",
        strongest["freshness_reason"],
    ]

    # Independent provider corroboration.
    sources = {
        item["source"]
        for item in evaluated
    }

    if {"virustotal", "abuseipdb"}.issubset(sources):
        score += 10

        reasons.append(
            "Independent provider corroboration (+10)"
        )

        vt_item = _find(
            evidence,
            "virustotal",
            "malicious_detection",
        )

        abuse_item = _find(
            evidence,
            "abuseipdb",
            "abuse_confidence",
        )

        if vt_item is not None and abuse_item is not None:
            vt_metadata = _get(vt_item, "metadata", {})

            vt_ratio = _number(
                vt_metadata.get("ratio")
            )

            abuse_value = _number(
                _get(abuse_item, "value")
            )

            if vt_ratio is not None and abuse_value is not None:
                if vt_ratio <= 5 and abuse_value >= 75:
                    score -= 15

                    reasons.append(
                        "Significant provider disagreement (-15)"
                    )

    score = max(
        0,
        min(100, int(round(score))),
    )

    if score >= 70:
        level = "HIGH"

    elif score >= 40:
        level = "MEDIUM"

    else:
        level = "LOW"

    return ConfidenceResult(
        score=score,
        level=level,
        reasons=tuple(reasons),
    )