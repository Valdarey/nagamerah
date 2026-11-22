
"""Render NAGAMERAH analysis results to TXT, JSON, CSV, or HTML."""

import csv
import html
import io
import json


LABEL_WIDTH = 20


def safe_csv(value):
    """Prevent spreadsheet formula injection."""
    text = str(value)
    return (
        "'" + text
        if text.startswith(("=", "+", "-", "@", "\t", "\r"))
        else text
    )


def _rows(data):
    return data if isinstance(data, list) else [data]


def _kv(label, value):
    return f"{label:<{LABEL_WIDTH}}: {value}"


def _provider_lines(provider):
    summary = provider.get("summary") or {}

    lines = [
        _kv("Provider", provider.get("provider", "unknown")),
        _kv("Status", str(provider.get("status", "unknown")).upper()),
    ]

    if provider.get("score") is not None:
        lines.append(_kv("Provider Score", f"{provider['score']}/100"))

    lines.append(
        _kv("Cache", "HIT" if provider.get("from_cache") else "MISS")
    )

    if provider.get("error"):
        lines.append(_kv("Error", provider["error"]))

    if summary.get("reason"):
        lines.append(_kv("Reason", summary["reason"]))

    stats = summary.get("stats") or {}

    if stats:
        names = ("malicious", "suspicious", "undetected", "harmless")
        counts = {
            name: int(stats.get(name) or 0)
            for name in names
        }

        total = int(
            summary.get("engine_count")
            or sum(int(value or 0) for value in stats.values())
        )

        lines.append(
            _kv(
                "Detection",
                f"{counts['malicious']}/{total} engines malicious",
            )
        )

        for name in names:
            lines.append(_kv(name.capitalize(), counts[name]))

    reputation = summary.get("reputation")

    if reputation is not None:
        lines.append(_kv("Reputation", reputation))

    abuse_score = summary.get("abuseConfidenceScore")

    if abuse_score is not None:
        lines.append(_kv("Abuse Score", f"{abuse_score}/100"))

    total_reports = summary.get("totalReports")

    if total_reports is not None:
        lines.append(_kv("Total Reports", total_reports))

    return lines


def _confidence_lines(report):
    assessment = report.get("confidence_assessment") or {}

    lines = [
        "CONFIDENCE ASSESSMENT",
        "-" * 48,
        _kv("Level", report.get("confidence", "N/A")),
        _kv("Score", f"{assessment.get('score', 'N/A')}/100"),
    ]

    reasons = assessment.get("reasons") or []

    lines.append(_kv("Reasons", ""))

    if reasons:
        lines.extend(f"  - {reason}" for reason in reasons)
    else:
        lines.append("  No confidence reasons available.")

    return lines


def _coverage_lines(report):
    coverage = report.get("coverage") or {}

    lines = [
        "PROVIDER COVERAGE",
        "-" * 48,
        _kv("Score", f"{coverage.get('score', 'N/A')}%"),
        _kv("Level", coverage.get("level", "N/A")),
        _kv(
            "Completed",
            f"{coverage.get('completed', 'N/A')}/"
            f"{coverage.get('applicable', 'N/A')}",
        ),
    ]

    missing = coverage.get("missing") or []

    lines.append(
        _kv("Missing Providers", ", ".join(missing) if missing else "None")
    )

    statuses = coverage.get("statuses") or {}

    for status, count in statuses.items():
        lines.append(_kv(status.capitalize(), count))

    reasons = coverage.get("reasons") or []

    for reason in reasons:
        lines.append(_kv("Coverage Reason", reason))

    return lines


def _evidence_lines(report):
    evidence = report.get("evidence_details") or []

    lines = [
        "STRUCTURED EVIDENCE",
        "-" * 48,
    ]

    if not evidence:
        lines.append("No structured evidence available.")
        return lines

    for index, item in enumerate(evidence, start=1):
        lines.extend([
            f"Evidence #{index}",
            _kv("Source", item.get("source", "N/A")),
            _kv("Category", item.get("category", "N/A")),
            _kv("Type", item.get("evidence_type", "N/A")),
            _kv("Value", item.get("value", "N/A")),
            _kv("Severity", item.get("severity", "N/A")),
            _kv("Confidence", item.get("confidence", "N/A")),
            _kv("Description", item.get("description", "N/A")),
        ])

        metadata = item.get("metadata") or {}

        if metadata:
            lines.append(_kv("Metadata", json.dumps(metadata, default=str)))

        lines.append("")

    return lines


def _txt(report):
    ioc = report.get("ioc") or {}
    providers = report.get("providers") or []

    lines = [
        "NAGAMERAH — THREAT INTELLIGENCE REPORT",
        "=" * 48,
        "IOC INFORMATION",
        "-" * 48,
        _kv("IOC", ioc.get("value", ioc.get("original", "N/A"))),
        _kv("Type", ioc.get("type", "N/A")),
        _kv("Defanged", "Yes" if ioc.get("defanged") else "No"),
        _kv(
            "Private/Reserved",
            "Yes" if ioc.get("private_or_reserved") else "No",
        ),
        "",
        "THREAT ASSESSMENT",
        "-" * 48,
        _kv("Threat Score", f"{report.get('score', 'N/A')}/100"),
        _kv("Verdict", report.get("verdict", "Unknown")),
        "",
    ]

    lines.extend(_confidence_lines(report))
    lines.extend(["", *_coverage_lines(report)])
    lines.extend(["", *_evidence_lines(report)])

    legacy_evidence = report.get("evidence") or []

    if legacy_evidence:
        lines.extend(["LEGACY CLASSIFICATION", "-" * 48])
        lines.extend(f"[+] {item}" for item in legacy_evidence)

    labels = report.get("labels") or []

    lines.extend([
        "",
        "LABELS",
        "-" * 48,
        ", ".join(labels) if labels else "None",
        "",
        "PROVIDER RESULTS",
        "-" * 48,
    ])

    for provider in providers:
        lines.extend(_provider_lines(provider))
        lines.append("-" * 48)

    lines.extend([
        "",
        "Report generated by NAGAMERAH",
        "",
    ])

    return "\n".join(lines)


def _csv(data):
    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow([
        "IOC",
        "Type",
        "Threat Score",
        "Verdict",
        "Confidence",
        "Confidence Score",
        "Coverage Score",
        "Coverage Level",
        "Completed Providers",
        "Applicable Providers",
        "Missing Providers",
        "Evidence Count",
        "Provider Count",
        "Labels",
    ])

    for row in _rows(data):
        ioc = row.get("ioc") or {}
        coverage = row.get("coverage") or {}
        confidence = row.get("confidence_assessment") or {}

        writer.writerow([
            safe_csv(ioc.get("value", "")),
            ioc.get("type"),
            row.get("score"),
            row.get("verdict"),
            row.get("confidence"),
            confidence.get("score"),
            coverage.get("score"),
            coverage.get("level"),
            coverage.get("completed"),
            coverage.get("applicable"),
            safe_csv(", ".join(coverage.get("missing") or [])),
            len(row.get("evidence_details") or []),
            len(row.get("providers") or []),
            safe_csv(", ".join(row.get("labels") or [])),
        ])

    return output.getvalue()


def _html(data):
    rows = []

    for row in _rows(data):
        ioc = row.get("ioc") or {}
        coverage = row.get("coverage") or {}
        confidence = row.get("confidence_assessment") or {}

        values = [
            ioc.get("value", ""),
            ioc.get("type", ""),
            row.get("score", "N/A"),
            row.get("verdict", "Unknown"),
            row.get("confidence", "N/A"),
            confidence.get("score", "N/A"),
            coverage.get("score", "N/A"),
            coverage.get("level", "N/A"),
        ]

        cells = "".join(
            f"<td>{html.escape(str(value))}</td>"
            for value in values
        )

        rows.append(f"<tr>{cells}</tr>")

    table = "".join(rows)

    return (
        "<!doctype html>"
        "<html lang='en'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width, initial-scale=1'>"
        "<title>NAGAMERAH Report</title></head><body>"
        "<h1>NAGAMERAH IOC Report</h1>"
        "<table border='1' cellpadding='8'>"
        "<thead><tr>"
        "<th>IOC</th><th>Type</th><th>Threat Score</th>"
        "<th>Verdict</th><th>Confidence</th>"
        "<th>Confidence Score</th><th>Coverage</th>"
        "<th>Coverage Level</th>"
        "</tr></thead><tbody>"
        f"{table}</tbody></table>"
        "</body></html>"
    )


def render(data, fmt):
    fmt = str(fmt).lower()

    if fmt == "json":
        return json.dumps(
            data,
            indent=2,
            ensure_ascii=False,
            default=str,
        )

    if fmt == "txt":
        return "\n\n".join(_txt(row) for row in _rows(data))

    if fmt == "csv":
        return _csv(data)

    if fmt == "html":
        return _html(data)

    raise ValueError(
        "Format tidak didukung: gunakan txt, json, csv, atau html"
    )
