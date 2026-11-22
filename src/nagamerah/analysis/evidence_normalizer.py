
"""Normalize provider results into structured evidence."""

import math
from typing import Any

from .evidence import Evidence


def _get(result: Any, key: str, default: Any = None) -> Any:
    """Read a field from either a dict or an object."""
    if isinstance(result, dict):
        return result.get(key, default)

    return getattr(result, key, default)


def _valid_count(value: Any) -> int | None:
    """Return a valid non-negative integer counter."""
    if isinstance(value, bool):
        return None

    if isinstance(value, int) and value >= 0:
        return value

    return None


def _valid_engine_count(value: Any) -> int | None:
    """Return a valid positive engine count."""
    if isinstance(value, bool):
        return None

    if isinstance(value, int) and value > 0:
        return value

    return None


def _valid_number(value: Any) -> int | float | None:
    """Return a finite numeric value, excluding booleans."""
    if isinstance(value, bool):
        return None

    if isinstance(value, (int, float)) and math.isfinite(value):
        return value

    return None


def _valid_score(value: Any) -> float | None:
    """Return a valid finite score in the 0-100 range."""
    number = _valid_number(value)

    if number is None or not 0 <= number <= 100:
        return None

    return float(number)


def _stats_are_consistent(stats: dict, engine_count: int) -> bool:
    """Validate VT statistics against the total engine count."""
    keys = ("malicious", "suspicious", "harmless", "undetected")
    counts = [_valid_count(stats.get(key)) for key in keys]

    if any(count is None for count in counts):
        return False

    return sum(counts) <= engine_count


def _normalize_virustotal(
    summary: dict,
    queried_at: str | None = None,
) -> list[Evidence]:
    """Normalize VirusTotal results into evidence."""
    evidence = []

    stats = summary.get("stats")

    if not isinstance(stats, dict):
        return evidence

    malicious = _valid_count(stats.get("malicious"))
    suspicious = _valid_count(stats.get("suspicious"))
    harmless = _valid_count(stats.get("harmless"))
    undetected = _valid_count(stats.get("undetected"))

    engine_count = _valid_engine_count(summary.get("engine_count"))

    common_metadata = {
        "queried_at": queried_at,
        "last_analysis_date": summary.get("last_analysis_date"),
    }

    stats_complete = all(
        value is not None
        for value in (malicious, suspicious, harmless, undetected)
    )

    stats_consistent = (
        stats_complete
        and engine_count is not None
        and _stats_are_consistent(stats, engine_count)
    )

    # Calculate ratios only when statistics are complete and consistent.
    malicious_ratio = (
        round(malicious / engine_count * 100, 2)
        if stats_consistent
        else None
    )

    suspicious_ratio = (
        round(suspicious / engine_count * 100, 2)
        if stats_consistent
        else None
    )

    # Malicious detection evidence.
    if malicious is not None and malicious > 0:
        evidence.append(
            Evidence(
                source="virustotal",
                category="threat",
                evidence_type="malicious_detection",
                value=malicious,
                description=(
                    f"{malicious} engines classified the IOC as malicious"
                ),
                metadata={
                    **common_metadata,
                    "engine_count": engine_count,
                    "ratio": malicious_ratio,
                },
            )
        )

    # Suspicious detection evidence.
    if suspicious is not None and suspicious > 0:
        evidence.append(
            Evidence(
                source="virustotal",
                category="threat",
                evidence_type="suspicious_detection",
                value=suspicious,
                description=(
                    f"{suspicious} engines classified the IOC as suspicious"
                ),
                metadata={
                    **common_metadata,
                    "engine_count": engine_count,
                    "ratio": suspicious_ratio,
                },
            )
        )

    # Harmless results are contextual, not threat evidence.
    if harmless is not None and harmless > 0:
        evidence.append(
            Evidence(
                source="virustotal",
                category="context",
                evidence_type="harmless_detection",
                value=harmless,
                description=(
                    f"{harmless} engines classified the IOC as harmless"
                ),
                metadata={
                    **common_metadata,
                    "engine_count": engine_count,
                },
            )
        )

    # Undetected results are not proof of safety.
    if undetected is not None and undetected > 0:
        evidence.append(
            Evidence(
                source="virustotal",
                category="context",
                evidence_type="undetected",
                value=undetected,
                description=(
                    f"{undetected} engines did not detect the IOC"
                ),
                metadata={
                    **common_metadata,
                    "engine_count": engine_count,
                },
            )
        )

    # VirusTotal reputation must be a finite numeric value.
    reputation = _valid_number(summary.get("reputation"))

    if reputation is not None:
        evidence.append(
            Evidence(
                source="virustotal",
                category="context",
                evidence_type="reputation",
                value=reputation,
                description=f"VirusTotal reputation: {reputation}",
                metadata=common_metadata.copy(),
            )
        )

    return evidence


def _normalize_abuseipdb(
    summary: dict,
    queried_at: str | None = None,
) -> list[Evidence]:
    """Normalize AbuseIPDB results into evidence."""
    evidence = []

    reports = _valid_count(summary.get("totalReports"))
    last_reported = summary.get("lastReportedAt")

    common_metadata = {
        "queried_at": queried_at,
        "last_reported_at": last_reported,
    }

    score = _valid_score(summary.get("abuseConfidenceScore"))

    if score is not None:
        evidence.append(
            Evidence(
                source="abuseipdb",
                category="threat",
                evidence_type="abuse_confidence",
                value=score,
                description=(
                    f"AbuseIPDB abuse confidence score: {score}/100"
                ),
                metadata={
                    **common_metadata,
                    "total_reports": reports,
                },
            )
        )

    if reports is not None and reports > 0:
        evidence.append(
            Evidence(
                source="abuseipdb",
                category="context",
                evidence_type="abuse_report_count",
                value=reports,
                description=(
                    f"AbuseIPDB has recorded {reports} reports"
                ),
                metadata=common_metadata.copy(),
            )
        )

    return evidence


def _normalize_local_dns(summary: dict) -> list[Evidence]:
    """Normalize local DNS results into contextual evidence."""
    evidence = []

    records = summary.get("records")
    domain = summary.get("domain")

    if not isinstance(records, dict):
        return evidence

    valid_records = {
        str(record_type): values
        for record_type, values in records.items()
        if isinstance(values, list)
    }

    populated_records = {
        record_type: values
        for record_type, values in valid_records.items()
        if values
    }

    if populated_records:
        evidence.append(
            Evidence(
                source="local_dns",
                category="context",
                evidence_type="dns_resolution",
                value=True,
                description="Domain successfully returned DNS records",
                severity="informational",
                metadata={
                    "domain": domain,
                    "record_types": list(populated_records.keys()),
                },
            )
        )

        evidence.append(
            Evidence(
                source="local_dns",
                category="context",
                evidence_type="dns_records",
                value=populated_records,
                description="DNS records retrieved",
                severity="informational",
                metadata={
                    "domain": domain,
                },
            )
        )

    return evidence


def normalize(results: list) -> list[Evidence]:
    """Normalize successful provider results into structured evidence."""
    normalized = []

    for result in results or []:
        status = _get(result, "status")

        if status != "ok":
            continue

        provider = _get(result, "provider")
        summary = _get(result, "summary", {})
        queried_at = _get(result, "queried_at")

        if not isinstance(summary, dict):
            continue

        if provider == "virustotal":
            normalized.extend(
                _normalize_virustotal(summary, queried_at)
            )

        elif provider == "abuseipdb":
            normalized.extend(
                _normalize_abuseipdb(summary, queried_at)
            )

        elif provider == "local_dns":
            normalized.extend(
                _normalize_local_dns(summary)
            )

    return normalized
