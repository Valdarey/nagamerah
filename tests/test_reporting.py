
import csv
import io
import json

import pytest

from nagamerah.reporting.generator import render


@pytest.fixture
def sample_report():
    return {
        "ioc": {
            "value": "example.com",
            "type": "DOMAIN",
            "defanged": False,
            "private_or_reserved": False,
        },
        "score": 75,
        "verdict": "SUSPICIOUS",
        "confidence": "HIGH",
        "confidence_assessment": {
            "score": 80,
            "level": "HIGH",
            "reasons": [
                "Strongest evidence source: virustotal",
                "Evidence is recent (+5)",
            ],
        },
        "coverage": {
            "score": 100,
            "level": "FULL",
            "applicable": 2,
            "completed": 2,
            "statuses": {
                "success": 2,
                "no_data": 0,
                "failed": 0,
                "skipped": 0,
                "unsupported": 0,
                "not_applicable": 0,
                "unknown": 0,
            },
            "missing": [],
            "reasons": [
                "All applicable provider checks completed",
            ],
        },
        "evidence_details": [
            {
                "source": "virustotal",
                "category": "threat",
                "evidence_type": "malicious_detection",
                "value": 15,
                "description": "Malicious detections found",
                "severity": "high",
                "confidence": "high",
                "metadata": {
                    "engine_count": 70,
                    "ratio": 21.43,
                },
            },
        ],
        "evidence": ["Legacy evidence"],
        "labels": ["malicious"],
        "providers": [
            {
                "provider": "virustotal",
                "status": "ok",
                "score": 75,
                "summary": {
                    "stats": {
                        "malicious": 15,
                        "suspicious": 2,
                        "undetected": 40,
                        "harmless": 13,
                    },
                    "engine_count": 70,
                },
                "queried_at": "2026-11-22T10:00:00Z",
                "from_cache": False,
                "error": None,
            },
        ],
    }


def test_render_json(sample_report):
    result = render(sample_report, "json")
    parsed = json.loads(result)

    assert parsed["score"] == 75
    assert parsed["confidence_assessment"]["score"] == 80
    assert parsed["coverage"]["level"] == "FULL"
    assert len(parsed["evidence_details"]) == 1


def test_render_txt(sample_report):
    result = render(sample_report, "txt")

    assert "THREAT ASSESSMENT" in result
    assert "CONFIDENCE ASSESSMENT" in result
    assert "PROVIDER COVERAGE" in result
    assert "STRUCTURED EVIDENCE" in result
    assert "malicious_detection" in result


def test_render_csv(sample_report):
    result = render(sample_report, "csv")
    rows = list(csv.DictReader(io.StringIO(result)))

    assert len(rows) == 1
    assert rows[0]["Threat Score"] == "75"
    assert rows[0]["Confidence Score"] == "80"
    assert rows[0]["Coverage Level"] == "FULL"


def test_render_html(sample_report):
    result = render(sample_report, "html")

    assert "<table" in result
    assert "example.com" in result
    assert "SUSPICIOUS" in result
    assert "FULL" in result


def test_render_multiple_reports(sample_report):
    result = render([sample_report, sample_report], "csv")
    rows = list(csv.DictReader(io.StringIO(result)))

    assert len(rows) == 2


def test_render_unsupported_format(sample_report):
    with pytest.raises(ValueError):
        render(sample_report, "xml")


def test_render_txt_without_optional_data():
    report = {
        "ioc": {"value": "example.com", "type": "DOMAIN"},
        "providers": [],
    }

    result = render(report, "txt")

    assert "example.com" in result
    assert "No structured evidence available." in result
