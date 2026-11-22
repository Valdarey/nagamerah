"""IOC analysis orchestration for NAGAMERAH."""
from datetime import datetime, timezone



from ..ioc.parser import parse
from ..providers.virustotal import VirusTotal
from ..providers.abuseipdb import AbuseIPDB
from ..providers.local_dns import LocalDNS
from ..config import get_key
from .models import ProviderResult, AnalysisResult
from .cache import get, put
from ..analysis.scoring import score, verdict
from ..analysis.confidence import calculate
from ..analysis.classifier import classify



# IOC compatibility is explicit so unsupported providers do not receive invalid requests.
_EXTERNAL_IP_TYPES = {"IPv4", "IPv6", "IP"}
_VT_TYPES = {"IPv4", "IPv6", "IP", "DOMAIN", "URL", "MD5", "SHA1", "SHA256"}


def _supports(provider_name: str, ioc_type: str) -> bool:
    kind = str(ioc_type).upper()
    if provider_name == "virustotal":
        return kind in _VT_TYPES
    if provider_name == "abuseipdb":
        return kind in _EXTERNAL_IP_TYPES
    # LocalDNS declares its own supported_types when available.
    return True



async def analyze(raw, provider_filter=None, offline=False, no_cache=False, refresh=False):
    ioc = parse(raw)
    results = []
    if ioc.get("private_or_reserved"):
        results.append(ProviderResult(
            provider="external", status="skipped",
            summary={"reason": "private/loopback/reserved IP not sent to external provider"},
        ))

    providers = [VirusTotal(get_key("vt_key")), AbuseIPDB(get_key("abuseipdb_key")), LocalDNS()]
    for p in providers:
        if provider_filter and p.name not in provider_filter:
            continue
        supported = getattr(p, "supported_types", None)
        if p.name == "local_dns" and supported is not None and ioc["type"] not in supported:
            results.append(ProviderResult(provider=p.name, status="skipped", summary={"reason": f"Unsupported IOC type: {ioc['type']}"}))
            continue
        if not _supports(p.name, ioc["type"]):
            results.append(ProviderResult(provider=p.name, status="skipped", summary={"reason": f"Unsupported IOC type: {ioc['type']}"}))
            continue
        if p.name != "local_dns" and (offline or ioc.get("private_or_reserved")):
            results.append(ProviderResult(provider=p.name, status="skipped", summary={"reason": "Offline mode" if offline else "Private/reserved IOC"}))
            continue
        if p.name != "local_dns" and not p.is_configured():
            results.append(ProviderResult(provider=p.name, status="skipped", summary={"reason": "API key not configured"}))
            continue
        if not no_cache and not refresh:
            cached = get(p.name, ioc["type"], ioc["value"])
            if cached:
                payload = dict(cached)
                payload.pop("provider", None)
                payload.pop("from_cache", None)
                results.append(ProviderResult(provider=p.name, **payload, from_cache=True))
                continue
        try:
            data = await p.lookup(ioc)
            data["queried_at"] = datetime.now(timezone.utc).isoformat()
            result = ProviderResult(provider=p.name, **data)
            results.append(result)
            if result.status == "ok":
                put(p.name, ioc["type"], ioc["value"], result.model_dump())
        except Exception as exc:
            response = getattr(exc, "response", None)
            code = getattr(response, "status_code", None)
            status = "auth_error" if code in (401, 403) else "rate_limited" if code == 429 else "error"
            results.append(ProviderResult(provider=p.name, status=status, error=str(exc)[:250]))

    final_score = score(results)
    final_verdict = verdict(final_score)
    labels, evidence = classify(results)
    out = AnalysisResult(
        ioc=ioc, providers=results, score=final_score, verdict=final_verdict,
        confidence=calculate(results), labels=labels, evidence=evidence,
    )
    from .database import save_history
    save_history(out)
    return out
