
from datetime import datetime, timezone, timedelta

from nagamerah.analysis.evidence import Evidence
from nagamerah.analysis.confidence import evaluate_confidence


NOW = datetime(2026, 11, 22, 12, 0, tzinfo=timezone.utc)


def make_evidence(
    source,
    evidence_type,
    value,
    metadata=None,
    category="threat",
):
    return Evidence(
        source=source,
        category=category,
        evidence_type=evidence_type,
        value=value,
        description="Test evidence",
        metadata=metadata or {},
    )


def test_empty_evidence_returns_low_confidence():
    result = evaluate_confidence([], now=NOW)

    assert result.score == 0
    assert result.level == "LOW"


def test_context_only_evidence_returns_low_confidence():
    evidence = [
        make_evidence(
            "localdns",
            "dns_resolution",
            "resolved",
            category="context",
        )
    ]

    result = evaluate_confidence(evidence, now=NOW)

    assert result.score == 0
    assert result.level == "LOW"


def test_invalid_evidence_is_ignored():
    evidence = [
        make_evidence(
            "virustotal",
            "malicious_detection",
            5,
            {"engine_count": 50, "ratio": 1},
        )
    ]

    result = evaluate_confidence(evidence, now=NOW)

    assert result.score == 0
    assert result.level == "LOW"


def test_vt_low_engine_count_produces_medium_confidence():
    evidence = [
        make_evidence(
            "virustotal",
            "malicious_detection",
            5,
            {"engine_count": 10, "ratio": 50},
        )
    ]

    result = evaluate_confidence(evidence, now=NOW)

    assert result.score == 57
    assert result.level == "MEDIUM"


def test_vt_adequate_engine_count_produces_high_confidence():
    evidence = [
        make_evidence(
            "virustotal",
            "malicious_detection",
            35,
            {"engine_count": 50, "ratio": 70},
        )
    ]

    result = evaluate_confidence(evidence, now=NOW)

    assert result.score == 77
    assert result.level == "HIGH"


def test_recent_vt_evidence_increases_confidence():
    evidence = [
        make_evidence(
            "virustotal",
            "malicious_detection",
            35,
            {
                "engine_count": 50,
                "ratio": 70,
                "timestamp": NOW.timestamp(),
            },
        )
    ]

    result = evaluate_confidence(evidence, now=NOW)

    assert result.score == 90
    assert result.level == "HIGH"


def test_old_evidence_reduces_confidence():
    old_timestamp = (NOW - timedelta(days=120)).timestamp()

    evidence = [
        make_evidence(
            "virustotal",
            "malicious_detection",
            35,
            {
                "engine_count": 50,
                "ratio": 70,
                "timestamp": old_timestamp,
            },
        )
    ]

    result = evaluate_confidence(evidence, now=NOW)

    assert result.score == 70
    assert result.level == "HIGH"
    assert "older than 90 days" in result.reasons[2]


def test_abuseipdb_reports_improve_evidence_quality():
    evidence = [
        make_evidence(
            "abuseipdb",
            "abuse_confidence",
            95,
            {"total_reports": 25},
        )
    ]

    result = evaluate_confidence(evidence, now=NOW)

    assert result.score == 67
    assert result.level == "MEDIUM"


def test_independent_sources_add_corroboration():
    evidence = [
        make_evidence(
            "virustotal",
            "malicious_detection",
            40,
            {
                "engine_count": 50,
                "ratio": 80,
                "timestamp": NOW.timestamp(),
            },
        ),
        make_evidence(
            "abuseipdb",
            "abuse_confidence",
            95,
            {
                "report_count": 25,
                "timestamp": NOW.timestamp(),
            },
        ),
    ]

    result = evaluate_confidence(evidence, now=NOW)

    assert result.score == 100
    assert result.level == "HIGH"
    assert any(
        "corroboration" in reason
        for reason in result.reasons
    )


def test_provider_disagreement_reduces_confidence():
    evidence = [
        make_evidence(
            "virustotal",
            "malicious_detection",
            0,
            {
                "engine_count": 50,
                "ratio": 0,
                "timestamp": NOW.timestamp(),
            },
        ),
        make_evidence(
            "abuseipdb",
            "abuse_confidence",
            95,
            {
                "report_count": 25,
                "timestamp": NOW.timestamp(),
            },
        ),
    ]

    result = evaluate_confidence(evidence, now=NOW)

    assert result.score == 85
    assert result.level == "HIGH"
    assert any(
        "disagreement" in reason
        for reason in result.reasons
    )


def test_result_can_be_serialized():
    result = evaluate_confidence([], now=NOW)

    data = result.to_dict()

    assert data["score"] == 0
    assert data["level"] == "LOW"
    assert isinstance(data["reasons"], list)
