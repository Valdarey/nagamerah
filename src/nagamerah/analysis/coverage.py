
"""IOC-aware provider coverage evaluation for NAGAMERAH."""

from dataclasses import dataclass
from typing import Any


PROVIDER_APPLICABILITY = {
    "IPv4": {"virustotal", "abuseipdb"},
    "IPv6": {"virustotal", "abuseipdb"},
    "DOMAIN": {"virustotal", "localdns"},
    "URL": {"virustotal"},
    "MD5": {"virustotal"},
    "SHA1": {"virustotal"},
    "SHA256": {"virustotal"},
}

COMPLETED_STATUSES = {"success", "no_data"}

KNOWN_STATUSES = {
    "success",
    "no_data",
    "failed",
    "skipped",
    "unsupported",
    "not_applicable",
}


@dataclass(frozen=True)
class CoverageResult:
    score: int
    level: str
    applicable: int
    completed: int
    statuses: dict[str, int]
    missing: tuple[str, ...]
    reasons: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "score": self.score,
            "level": self.level,
            "applicable": self.applicable,
            "completed": self.completed,
            "statuses": dict(self.statuses),
            "missing": list(self.missing),
            "reasons": list(self.reasons),
        }


def _get(item: Any, key: str, default: Any = None) -> Any:
    if isinstance(item, dict):
        return item.get(key, default)
    return getattr(item, key, default)


def _normalize_ioc_type(ioc_type: str) -> str:
    value = str(ioc_type).strip().upper()

    aliases = {
        "IP": "IPv4",
        "IPV4": "IPv4",
        "IPV6": "IPv6",
        "DOMAIN": "DOMAIN",
        "FQDN": "DOMAIN",
        "URL": "URL",
        "MD5": "MD5",
        "SHA1": "SHA1",
        "SHA-1": "SHA1",
        "SHA256": "SHA256",
        "SHA-256": "SHA256",
    }

    return aliases.get(value, value)


def _normalize_provider(provider: Any) -> str:
    value = str(provider or "").strip().lower().replace("-", "").replace("_", "")

    aliases = {
        "virustotal": "virustotal",
        "vt": "virustotal",
        "abuseipdb": "abuseipdb",
        "localdns": "localdns",
        "dns": "localdns",
    }

    return aliases.get(value, value)


def _normalize_status(status: Any) -> str:
    value = str(status or "").strip().lower().replace("-", "_").replace(" ", "_")

    aliases = {
        "ok": "success",
        "completed": "success",
        "complete": "success",
        "success": "success",
        "no_data": "no_data",
        "empty": "no_data",
        "not_found": "no_data",
        "error": "failed",
        "failure": "failed",
        "failed": "failed",
        "skip": "skipped",
        "skipped": "skipped",
        "not_supported": "unsupported",
        "unsupported": "unsupported",
        "not_applicable": "not_applicable",
        "n_a": "not_applicable",
    }

    return aliases.get(value, value)


def evaluate_coverage(
    ioc_type: str,
    provider_results: list,
    applicable_providers: set[str] | None = None,
) -> CoverageResult:
    """Calculate IOC-aware provider coverage."""

    normalized_type = _normalize_ioc_type(ioc_type)

    if applicable_providers is None:
        applicable_providers = PROVIDER_APPLICABILITY.get(
            normalized_type, set()
        )

    applicable_providers = {
        _normalize_provider(provider)
        for provider in applicable_providers
    }

    statuses = {
        status: 0
        for status in (
            "success",
            "no_data",
            "failed",
            "skipped",
            "unsupported",
            "not_applicable",
            "unknown",
        )
    }

    results_by_provider = {}

    for result in provider_results or []:
        provider = _normalize_provider(
            _get(result, "provider", _get(result, "name", ""))
        )

        if provider not in applicable_providers:
            continue

        status = _normalize_status(_get(result, "status", ""))

        if status not in KNOWN_STATUSES:
            status = "unknown"

        # Keep the last result for a provider to avoid duplicate counting.
        results_by_provider[provider] = status

    missing = []

    for provider in sorted(applicable_providers):
        status = results_by_provider.get(provider, "unknown")

        statuses[status] += 1

        if status not in COMPLETED_STATUSES:
            missing.append(provider)

    total = len(applicable_providers)
    completed = sum(
        statuses[status]
        for status in COMPLETED_STATUSES
    )

    score = round(completed / total * 100) if total else 0

    if total == 0:
        level = "NONE"
        reasons = ("No applicable providers defined for this IOC type",)
    elif score == 100:
        level = "FULL"
        reasons = ("All applicable providers completed their checks",)
    elif score >= 80:
        level = "HIGH"
        reasons = ("Most applicable provider checks completed",)
    elif score >= 50:
        level = "PARTIAL"
        reasons = ("Some applicable provider checks are incomplete",)
    else:
        level = "LOW"
        reasons = ("Most applicable provider checks are incomplete",)

    return CoverageResult(
        score=score,
        level=level,
        applicable=total,
        completed=completed,
        statuses=statuses,
        missing=tuple(missing),
        reasons=reasons,
    )
