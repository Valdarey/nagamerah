from nagamerah.analysis.coverage import evaluate_coverage


def test_ipv4_all_providers_completed():
    result = evaluate_coverage(
        "IPv4",
        [
            {"provider": "virustotal", "status": "success"},
            {"provider": "abuseipdb", "status": "success"},
        ],
    )

    assert result.score == 100
    assert result.level == "FULL"
    assert result.applicable == 2
    assert result.completed == 2
    assert result.missing == ()


def test_ipv4_partial_coverage():
    result = evaluate_coverage(
        "IPv4",
        [
            {"provider": "virustotal", "status": "success"},
            {"provider": "abuseipdb", "status": "failed"},
        ],
    )

    assert result.score == 50
    assert result.level == "PARTIAL"
    assert result.completed == 1
    assert result.missing == ("abuseipdb",)


def test_no_data_counts_as_completed():
    result = evaluate_coverage(
        "IPv4",
        [
            {"provider": "virustotal", "status": "no_data"},
            {"provider": "abuseipdb", "status": "success"},
        ],
    )

    assert result.score == 100
    assert result.level == "FULL"
    assert result.completed == 2
    assert result.missing == ()


def test_provider_not_returned_counts_as_unknown():
    result = evaluate_coverage(
        "IPv4",
        [
            {"provider": "virustotal", "status": "success"},
        ],
    )

    assert result.score == 50
    assert result.statuses["unknown"] == 1
    assert result.missing == ("abuseipdb",)


def test_failed_provider_does_not_count_as_completed():
    result = evaluate_coverage(
        "IPv4",
        [
            {"provider": "virustotal", "status": "failed"},
            {"provider": "abuseipdb", "status": "failed"},
        ],
    )

    assert result.score == 0
    assert result.level == "LOW"
    assert result.completed == 0
    assert result.missing == ("abuseipdb", "virustotal")


def test_domain_applicability():
    result = evaluate_coverage(
        "DOMAIN",
        [
            {"provider": "virustotal", "status": "success"},
            {"provider": "localdns", "status": "success"},
            {"provider": "abuseipdb", "status": "success"},
        ],
    )

    assert result.applicable == 2
    assert result.completed == 2
    assert result.score == 100
    assert result.level == "FULL"


def test_hash_only_uses_virustotal():
    result = evaluate_coverage(
        "SHA256",
        [
            {"provider": "virustotal", "status": "success"},
            {"provider": "abuseipdb", "status": "success"},
            {"provider": "localdns", "status": "success"},
        ],
    )

    assert result.applicable == 1
    assert result.completed == 1
    assert result.score == 100
    assert result.level == "FULL"


def test_skipped_provider_is_incomplete():
    result = evaluate_coverage(
        "IPv4",
        [
            {"provider": "virustotal", "status": "success"},
            {"provider": "abuseipdb", "status": "skipped"},
        ],
    )

    assert result.score == 50
    assert result.statuses["skipped"] == 1
    assert result.missing == ("abuseipdb",)


def test_unsupported_provider_is_incomplete():
    result = evaluate_coverage(
        "IPv4",
        [
            {"provider": "virustotal", "status": "success"},
            {"provider": "abuseipdb", "status": "unsupported"},
        ],
    )

    assert result.score == 50
    assert result.statuses["unsupported"] == 1
    assert result.missing == ("abuseipdb",)


def test_status_aliases_are_normalized():
    result = evaluate_coverage(
        "IPv4",
        [
            {"provider": "VT", "status": "ok"},
            {"provider": "AbuseIPDB", "status": "not_found"},
        ],
    )

    assert result.score == 100
    assert result.statuses["success"] == 1
    assert result.statuses["no_data"] == 1
    assert result.level == "FULL"


def test_unknown_status_is_counted_as_unknown():
    result = evaluate_coverage(
        "IPv4",
        [
            {"provider": "virustotal", "status": "weird_status"},
            {"provider": "abuseipdb", "status": "success"},
        ],
    )

    assert result.score == 50
    assert result.statuses["unknown"] == 1
    assert result.missing == ("virustotal",)


def test_duplicate_provider_does_not_increase_coverage():
    result = evaluate_coverage(
        "IPv4",
        [
            {"provider": "virustotal", "status": "success"},
            {"provider": "virustotal", "status": "success"},
            {"provider": "abuseipdb", "status": "failed"},
        ],
    )

    assert result.applicable == 2
    assert result.completed == 1
    assert result.score == 50


def test_custom_applicable_providers():
    result = evaluate_coverage(
        "IPv4",
        [
            {"provider": "virustotal", "status": "success"},
        ],
        applicable_providers={"virustotal"},
    )

    assert result.applicable == 1
    assert result.completed == 1
    assert result.score == 100
    assert result.level == "FULL"


def test_no_applicable_providers():
    result = evaluate_coverage(
        "UNKNOWN_TYPE",
        [],
    )

    assert result.score == 0
    assert result.level == "NONE"
    assert result.applicable == 0
    assert result.completed == 0


def test_coverage_result_to_dict():
    result = evaluate_coverage(
        "IPv4",
        [
            {"provider": "virustotal", "status": "success"},
            {"provider": "abuseipdb", "status": "failed"},
        ],
    )

    data = result.to_dict()

    assert isinstance(data, dict)
    assert data["score"] == 50
    assert data["level"] == "PARTIAL"
    assert data["applicable"] == 2
    assert data["completed"] == 1
    assert data["missing"] == ["abuseipdb"]
    assert isinstance(data["statuses"], dict)
    assert isinstance(data["reasons"], list)