
from nagamerah.analysis.evidence import Evidence
from nagamerah.analysis.verdict import verdict


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


def test_empty_evidence_is_inconclusive():
    assert verdict(0, []) == "INCONCLUSIVE"


def test_context_only_is_inconclusive():
    evidence = [
        make_evidence(
            "local_dns",
            "dns_resolution",
            True,
            category="context",
        )
    ]
    assert verdict(0, evidence) == "INCONCLUSIVE"


def test_low_score_with_valid_coverage_is_no_detection():
    evidence = [
        make_evidence(
            "virustotal",
            "malicious_detection",
            0,
            {"engine_count": 50, "ratio": 0},
        )
    ]
    assert verdict(0, evidence) == "NO DETECTION"


def test_moderate_score_is_suspicious():
    evidence = [
        make_evidence(
            "abuseipdb",
            "abuse_confidence",
            50,
        )
    ]
    assert verdict(50, evidence) == "SUSPICIOUS"


def test_strong_vt_evidence_can_be_malicious():
    evidence = [
        make_evidence(
            "virustotal",
            "malicious_detection",
            40,
            {"engine_count": 60, "ratio": 66.67},
        )
    ]
    assert verdict(85, evidence) == "MALICIOUS"


def test_vt_low_engine_count_cannot_be_malicious():
    evidence = [
        make_evidence(
            "virustotal",
            "malicious_detection",
            3,
            {"engine_count": 4, "ratio": 75},
        )
    ]
    assert verdict(85, evidence) == "SUSPICIOUS"


def test_suspicious_only_cannot_be_malicious():
    evidence = [
        make_evidence(
            "virustotal",
            "suspicious_detection",
            30,
            {"engine_count": 50, "ratio": 60},
        )
    ]
    assert verdict(85, evidence) == "SUSPICIOUS"


def test_abuseipdb_strong_signal_can_be_malicious():
    evidence = [
        make_evidence(
            "abuseipdb",
            "abuse_confidence",
            95,
            {"total_reports": 100},
        )
    ]
    assert verdict(85, evidence) == "MALICIOUS"


def test_context_does_not_qualify_for_malicious():
    evidence = [
        make_evidence(
            "local_dns",
            "dns_records",
            {"A": ["192.0.2.1"]},
            category="context",
        )
    ]
    assert verdict(90, evidence) == "INCONCLUSIVE"


def test_high_score_without_primary_evidence_is_inconclusive():
    evidence = [
        make_evidence(
            "virustotal",
            "reputation",
            -10,
            category="context",
        )
    ]
    assert verdict(90, evidence) == "INCONCLUSIVE"


def test_zero_abuse_score_is_no_detection():
    evidence = [
        make_evidence(
            "abuseipdb",
            "abuse_confidence",
            0,
            {"total_reports": 0},
        )
    ]
    assert verdict(0, evidence) == "NO DETECTION"


def test_invalid_score_is_inconclusive():
    evidence = [
        make_evidence(
            "virustotal",
            "malicious_detection",
            10,
            {"engine_count": 50, "ratio": 20},
        )
    ]
    assert verdict(float("nan"), evidence) == "INCONCLUSIVE"


def test_high_vt_ratio_below_malicious_threshold_is_suspicious():
    evidence = [
        make_evidence(
            "virustotal",
            "malicious_detection",
            20,
            {"engine_count": 50, "ratio": 40},
        )
    ]
    assert verdict(70, evidence) == "SUSPICIOUS"
