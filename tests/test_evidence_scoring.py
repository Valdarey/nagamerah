
from nagamerah.analysis.evidence import Evidence
from nagamerah.analysis.scoring import score_evidence


def vt_malicious(count, engines, ratio=None):
    if ratio is None:
        ratio = count / engines * 100

    return Evidence(
        source="virustotal",
        category="threat",
        evidence_type="malicious_detection",
        value=count,
        description="VT malicious detections",
        metadata={
            "engine_count": engines,
            "ratio": ratio,
        },
    )


def vt_suspicious(count, engines, ratio=None):
    if ratio is None:
        ratio = count / engines * 100

    return Evidence(
        source="virustotal",
        category="threat",
        evidence_type="suspicious_detection",
        value=count,
        description="VT suspicious detections",
        metadata={
            "engine_count": engines,
            "ratio": ratio,
        },
    )


def abuse_score(value):
    return Evidence(
        source="abuseipdb",
        category="threat",
        evidence_type="abuse_confidence",
        value=value,
        description="AbuseIPDB confidence",
    )


def context_evidence():
    return Evidence(
        source="local_dns",
        category="context",
        evidence_type="dns_resolution",
        value=True,
        description="DNS resolution successful",
    )


def test_vt_malicious_mapping():
    assert score_evidence([vt_malicious(1, 100)]) == 10
    assert score_evidence([vt_malicious(5, 100)]) == 20
    assert score_evidence([vt_malicious(15, 100)]) == 35
    assert score_evidence([vt_malicious(25, 100)]) == 50
    assert score_evidence([vt_malicious(40, 100)]) == 65
    assert score_evidence([vt_malicious(60, 100)]) == 75
    assert score_evidence([vt_malicious(75, 100)]) == 85


def test_abuseipdb_mapping():
    assert score_evidence([abuse_score(5)]) == 10
    assert score_evidence([abuse_score(15)]) == 20
    assert score_evidence([abuse_score(30)]) == 35
    assert score_evidence([abuse_score(50)]) == 50
    assert score_evidence([abuse_score(65)]) == 65
    assert score_evidence([abuse_score(80)]) == 75
    assert score_evidence([abuse_score(95)]) == 85


def test_vt_low_engine_count_is_capped():
    # 50% detection but only 4 engines.
    assert score_evidence([vt_malicious(2, 4)]) == 20


def test_vt_malicious_ratio_mismatch_is_rejected():
    evidence = vt_malicious(50, 100, ratio=10)

    assert score_evidence([evidence]) is None


def test_vt_suspicious_only_is_bounded():
    result = score_evidence([vt_suspicious(50, 100)])

    assert result == 25
    assert result <= 25


def test_contextual_evidence_does_not_increase_score():
    assert score_evidence([context_evidence()]) is None


def test_independent_provider_corroboration():
    result = score_evidence([
        vt_malicious(60, 100),
        abuse_score(80),
    ])

    # VT = 75, AbuseIPDB = 75
    # Corroboration = 15 * 75 / 85 = 13.2
    assert result == 88.2


def test_duplicate_evidence_does_not_increase_score():
    evidence = vt_malicious(60, 100)

    assert score_evidence([evidence, evidence, evidence]) == 75


def test_invalid_abuse_score_is_rejected():
    assert score_evidence([abuse_score(150)]) is None
    assert score_evidence([abuse_score(float("nan"))]) is None
    assert score_evidence([abuse_score(float("inf"))]) is None


def test_zero_abuse_confidence_is_valid():
    assert score_evidence([abuse_score(0)]) == 0


def test_empty_evidence():
    assert score_evidence([]) is None
    assert score_evidence(None) is None
