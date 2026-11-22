
from nagamerah.analysis.evidence_normalizer import normalize
from nagamerah.core.models import ProviderResult


def test_virustotal_malicious_detection():
    results = [
        ProviderResult(
            provider="virustotal",
            status="ok",
            summary={
                "stats": {
                    "malicious": 65,
                    "suspicious": 0,
                    "harmless": 0,
                    "undetected": 9,
                },
                "engine_count": 74,
            },
        )
    ]

    evidence = normalize(results)

    malicious = [
        item for item in evidence
        if item.evidence_type == "malicious_detection"
    ]

    assert len(malicious) == 1
    assert malicious[0].value == 65
    assert malicious[0].category == "threat"
    assert malicious[0].metadata["engine_count"] == 74
    assert malicious[0].metadata["ratio"] == 87.84


def test_virustotal_suspicious_detection():
    results = [
        ProviderResult(
            provider="virustotal",
            status="ok",
            summary={
                "stats": {
                    "malicious": 0,
                    "suspicious": 4,
                    "harmless": 20,
                    "undetected": 10,
                },
                "engine_count": 34,
            },
        )
    ]

    evidence = normalize(results)

    suspicious = [
        item for item in evidence
        if item.evidence_type == "suspicious_detection"
    ]

    assert len(suspicious) == 1
    assert suspicious[0].value == 4
    assert suspicious[0].category == "threat"
    assert suspicious[0].metadata["ratio"] == 11.76


def test_virustotal_harmless_and_undetected_are_context():
    results = [
        ProviderResult(
            provider="virustotal",
            status="ok",
            summary={
                "stats": {
                    "malicious": 0,
                    "suspicious": 0,
                    "harmless": 59,
                    "undetected": 33,
                },
                "engine_count": 92,
            },
        )
    ]

    evidence = normalize(results)

    assert evidence
    assert all(item.category == "context" for item in evidence)
    assert not any(item.category == "threat" for item in evidence)


def test_virustotal_zero_detection_does_not_mean_safe():
    results = [
        ProviderResult(
            provider="virustotal",
            status="ok",
            summary={
                "stats": {
                    "malicious": 0,
                    "suspicious": 0,
                    "harmless": 59,
                    "undetected": 33,
                },
                "engine_count": 92,
            },
        )
    ]

    evidence = normalize(results)

    assert not any(
        item.evidence_type == "malicious_detection"
        for item in evidence
    )


def test_virustotal_invalid_stats_do_not_crash():
    results = [
        ProviderResult(
            provider="virustotal",
            status="ok",
            summary={
                "stats": {
                    "malicious": "invalid",
                    "suspicious": -5,
                    "harmless": None,
                    "undetected": True,
                },
                "engine_count": "invalid",
            },
        )
    ]

    evidence = normalize(results)

    assert not any(
        item.category == "threat"
        for item in evidence
    )


def test_virustotal_invalid_engine_count_ratio_is_none():
    results = [
        ProviderResult(
            provider="virustotal",
            status="ok",
            summary={
                "stats": {
                    "malicious": 10,
                    "suspicious": 0,
                    "harmless": 0,
                    "undetected": 0,
                },
                "engine_count": 5,
            },
        )
    ]

    evidence = normalize(results)

    malicious = next(
        item for item in evidence
        if item.evidence_type == "malicious_detection"
    )

    assert malicious.value == 10
    assert malicious.metadata["ratio"] is None


def test_abuseipdb_score():
    results = [
        ProviderResult(
            provider="abuseipdb",
            status="ok",
            summary={
                "abuseConfidenceScore": 95,
                "totalReports": 120,
                "lastReportedAt": "2026-11-20T10:00:00Z",
            },
        )
    ]

    evidence = normalize(results)

    abuse = next(
        item for item in evidence
        if item.evidence_type == "abuse_confidence"
    )

    assert abuse.value == 95
    assert abuse.category == "threat"
    assert abuse.metadata["total_reports"] == 120


def test_abuseipdb_zero_is_preserved():
    results = [
        ProviderResult(
            provider="abuseipdb",
            status="ok",
            summary={
                "abuseConfidenceScore": 0,
                "totalReports": 0,
            },
        )
    ]

    evidence = normalize(results)

    abuse = [
        item for item in evidence
        if item.evidence_type == "abuse_confidence"
    ]

    assert len(abuse) == 1
    assert abuse[0].value == 0


def test_abuseipdb_missing_score_is_not_zero():
    results = [
        ProviderResult(
            provider="abuseipdb",
            status="ok",
            summary={
                "totalReports": 10,
            },
        )
    ]

    evidence = normalize(results)

    assert not any(
        item.evidence_type == "abuse_confidence"
        for item in evidence
    )


def test_abuseipdb_invalid_score_is_ignored():
    results = [
        ProviderResult(
            provider="abuseipdb",
            status="ok",
            summary={
                "abuseConfidenceScore": 101,
                "totalReports": 10,
            },
        )
    ]

    evidence = normalize(results)

    assert not any(
        item.evidence_type == "abuse_confidence"
        for item in evidence
    )


def test_abuseipdb_report_count_context():
    results = [
        ProviderResult(
            provider="abuseipdb",
            status="ok",
            summary={
                "abuseConfidenceScore": 80,
                "totalReports": 50,
                "lastReportedAt": "2026-11-20T10:00:00Z",
            },
        )
    ]

    evidence = normalize(results)

    reports = next(
        item for item in evidence
        if item.evidence_type == "abuse_report_count"
    )

    assert reports.value == 50
    assert reports.category == "context"


def test_local_dns_is_context_only():
    results = [
        ProviderResult(
            provider="local_dns",
            status="ok",
            score=None,
            summary={
                "domain": "example.com",
                "records": {
                    "A": ["1.2.3.4"],
                    "AAAA": [],
                    "MX": ["mail.example.com"],
                    "NS": ["ns.example.com"],
                    "TXT": [],
                },
            },
        )
    ]

    evidence = normalize(results)

    assert evidence
    assert all(item.category == "context" for item in evidence)

    assert any(
        item.evidence_type == "dns_resolution"
        for item in evidence
    )

    assert any(
        item.evidence_type == "dns_records"
        for item in evidence
    )


def test_local_dns_empty_records_produce_no_evidence():
    results = [
        ProviderResult(
            provider="local_dns",
            status="ok",
            score=None,
            summary={
                "domain": "example.com",
                "records": {
                    "A": [],
                    "AAAA": [],
                    "MX": [],
                    "NS": [],
                    "TXT": [],
                },
            },
        )
    ]

    evidence = normalize(results)

    assert evidence == []


def test_failed_provider_produces_no_evidence():
    results = [
        ProviderResult(
            provider="virustotal",
            status="error",
            summary={
                "stats": {
                    "malicious": 65,
                    "suspicious": 0,
                },
            },
        ),
        ProviderResult(
            provider="abuseipdb",
            status="rate_limited",
            summary={
                "abuseConfidenceScore": 95,
            },
        ),
        ProviderResult(
            provider="local_dns",
            status="skipped",
            summary={
                "records": {
                    "A": ["1.2.3.4"],
                },
            },
        ),
    ]

    assert normalize(results) == []


def test_unknown_provider_is_ignored():
    results = [
        ProviderResult(
            provider="unknown_provider",
            status="ok",
            score=99,
            summary={
                "score": 99,
            },
        )
    ]

    assert normalize(results) == []


def test_empty_input():
    assert normalize([]) == []
    assert normalize(None) == []
