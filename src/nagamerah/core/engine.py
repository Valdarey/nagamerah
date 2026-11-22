
"""IOC analysis orchestration for NAGAMERAH."""

from datetime import datetime, timezone

from ..ioc.parser import parse
from ..providers.virustotal import VirusTotal
from ..providers.abuseipdb import AbuseIPDB
from ..providers.local_dns import LocalDNS
from ..config import get_key

from ..analysis.evidence_normalizer import normalize
from ..analysis.scoring import score_evidence
from ..analysis.verdict import verdict
from ..analysis.confidence import evaluate_confidence
from ..analysis.classifier import classify
from ..analysis.coverage import evaluate_coverage

from .models import ProviderResult, AnalysisResult
from .cache import get, put



# Provider compatibility uses uppercase IOC types consistently.
_EXTERNAL_IP_TYPES = {"IPV4", "IPV6", "IP"}

_VT_TYPES = {
    "IPV4",
    "IPV6",
    "IP",
    "DOMAIN",
    "URL",
    "MD5",
    "SHA1",
    "SHA256",
}


def _supports(provider_name: str, ioc_type: str) -> bool:
    """Check whether a provider supports the IOC type."""
    kind = str(ioc_type).strip().upper()

    if provider_name == "virustotal":
        return kind in _VT_TYPES

    if provider_name == "abuseipdb":
        return kind in _EXTERNAL_IP_TYPES

    return True



def _coverage_status(status: str) -> str:
    """Normalize provider statuses for coverage evaluation."""
    value = str(status or "").strip().lower()

    if value in {"ok", "success", "completed"}:
        return "success"

    if value in {"no_data", "not_found"}:
        return "no_data"

    if value in {
        "error",
        "auth_error",
        "rate_limited",
        "failed",
        "failure",
    }:
        return "failed"

    if value in {"skipped", "skip"}:
        return "skipped"

    if value in {"unsupported", "not_supported"}:
        return "unsupported"

    return "unknown"


async def analyze(
    raw,
    provider_filter=None,
    offline=False,
    no_cache=False,
    refresh=False,
):
    """Analyze an IOC using the evidence-driven v2 pipeline."""

    ioc = parse(raw)
    results = []

    if ioc.get("private_or_reserved"):
        results.append(
            ProviderResult(
                provider="external",
                status="skipped",
                summary={
                    "reason": (
                        "private/loopback/reserved IP "
                        "not sent to external provider"
                    )
                },
            )
        )

    providers = [
        VirusTotal(get_key("vt_key")),
        AbuseIPDB(get_key("abuseipdb_key")),
        LocalDNS(),
    ]

    # Determine applicable providers before executing lookups.
    # This keeps provider filtering separate from coverage.
    applicable_providers = set()

    for provider in providers:
        if provider_filter and provider.name not in provider_filter:
            continue

        supported = getattr(provider, "supported_types", None)

        if (
            provider.name == "local_dns"
            and supported is not None
            and ioc["type"] not in supported
        ):
            continue

        if not _supports(provider.name, ioc["type"]):
            continue

        applicable_providers.add(provider.name)

    # Execute applicable provider lookups.
    for provider in providers:
        if provider_filter and provider.name not in provider_filter:
            continue

        supported = getattr(provider, "supported_types", None)

        if (
            provider.name == "local_dns"
            and supported is not None
            and ioc["type"] not in supported
        ):
            results.append(
                ProviderResult(
                    provider=provider.name,
                    status="skipped",
                    summary={
                        "reason": f"Unsupported IOC type: {ioc['type']}"
                    },
                )
            )
            continue

        if not _supports(provider.name, ioc["type"]):
            results.append(
                ProviderResult(
                    provider=provider.name,
                    status="skipped",
                    summary={
                        "reason": f"Unsupported IOC type: {ioc['type']}"
                    },
                )
            )
            continue

        if (
            provider.name != "local_dns"
            and (offline or ioc.get("private_or_reserved"))
        ):
            results.append(
                ProviderResult(
                    provider=provider.name,
                    status="skipped",
                    summary={
                        "reason": (
                            "Offline mode"
                            if offline
                            else "Private/reserved IOC"
                        )
                    },
                )
            )
            continue

        if (
            provider.name != "local_dns"
            and not provider.is_configured()
        ):
            results.append(
                ProviderResult(
                    provider=provider.name,
                    status="skipped",
                    summary={"reason": "API key not configured"},
                )
            )
            continue

       
        # Cache lookup.
        cached_result = None

        if not no_cache and not refresh:
            try:
                cached = get(
                    provider.name,
                    ioc["type"],
                    ioc["value"],
                )

                # Only successful, structurally valid cache
                # entries may be reused.
                if isinstance(cached, dict) and cached.get("status") == "ok":
                    payload = dict(cached)
                    payload.pop("provider", None)
                    payload.pop("from_cache", None)

                    cached_result = ProviderResult(
                        provider=provider.name,
                        **payload,
                        from_cache=True,
                    )

            except Exception:
                # Cache failure must not interrupt live lookup.
                cached_result = None

        if cached_result is not None:
            results.append(cached_result)
            continue


        # Live provider lookup.
        try:
            data = await provider.lookup(ioc)
            data["queried_at"] = datetime.now(
                timezone.utc
            ).isoformat()

            result = ProviderResult(
                provider=provider.name,
                **data,
            )

            results.append(result)

            if result.status == "ok":
                put(
                    provider.name,
                    ioc["type"],
                    ioc["value"],
                    result.model_dump(),
                )

        except Exception as exc:
            response = getattr(exc, "response", None)
            code = getattr(response, "status_code", None)

            status = (
                "auth_error"
                if code in (401, 403)
                else "rate_limited"
                if code == 429
                else "error"
            )

            results.append(
                ProviderResult(
                    provider=provider.name,
                    status=status,
                    error=str(exc)[:250],
                )
            )

    # Normalize provider results into structured evidence.
    evidence = normalize(results)

    # Evidence-driven threat assessment.
    final_score = score_evidence(evidence)
    final_verdict = verdict(final_score, evidence)

    # Confidence is evaluated from normalized evidence,
    # not raw provider results.
    confidence_result = evaluate_confidence(evidence)
    final_confidence = confidence_result.level

    # Preserve existing classification behavior.
    labels, classified_evidence = classify(results)

    # Evaluate provider coverage independently.
    coverage_inputs = [
        {
            "provider": result.provider,
            "status": _coverage_status(result.status),
        }
        for result in results
    ]

    coverage_result = evaluate_coverage(
        ioc_type=ioc["type"],
        provider_results=coverage_inputs,
        applicable_providers=applicable_providers,
    )

    # Build final analysis result.
    out = AnalysisResult(
    ioc=ioc,
    providers=results,
    score=final_score,
    verdict=final_verdict,
    confidence=final_confidence,
    confidence_assessment=confidence_result.to_dict(),
    coverage=coverage_result.to_dict(),
    labels=labels,
    evidence=classified_evidence,
    evidence_details=[
        item.to_dict() for item in evidence
    ],
)

    from .database import save_history

    save_history(out)

    return out
