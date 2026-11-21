from datetime import datetime,timezone
from ..ioc.parser import parse
from ..providers.virustotal import VirusTotal
from ..providers.abuseipdb import AbuseIPDB
from ..providers.local_dns import LocalDNS
from ..config import get_key
from .models import ProviderResult,AnalysisResult
from .cache import get,put
from ..analysis.scoring import score,verdict
from ..analysis.confidence import calculate
from ..analysis.classifier import classify
async def analyze(raw,provider_filter=None,offline=False,no_cache=False,refresh=False):
    ioc=parse(raw); results=[]
    if ioc['private_or_reserved']:
        results.append(ProviderResult(provider='external',status='skipped',summary={'reason':'private/loopback/reserved IP not sent to external provider'}))
    providers=[VirusTotal(get_key('vt_key')),AbuseIPDB(get_key('abuseipdb_key')),LocalDNS()]
    for p in providers:
        if provider_filter and p.name not in provider_filter: continue
        if p.name=='local_dns' and ioc['type'] not in p.supported_types: continue
        if p.name!='local_dns' and (offline or ioc['private_or_reserved']): continue
        if p.name!='local_dns' and not p.is_configured():
            results.append(ProviderResult(provider=p.name,status='skipped',summary={'reason':'API key not configured'})); continue
        if not no_cache and not refresh:
            cached=get(p.name,ioc['type'],ioc['value'])
            if cached:
                # Cache payloads may already contain model fields such as
                # 'provider' and 'from_cache'. Remove them before supplying
                # authoritative values for the current cache lookup.
                cached_payload=dict(cached)
                cached_payload.pop('provider',None)
                cached_payload.pop('from_cache',None)
                results.append(ProviderResult(provider=p.name,**cached_payload,from_cache=True))
                continue
        try:
            d=await p.lookup(ioc); d['queried_at']=datetime.now(timezone.utc).isoformat(); r=ProviderResult(provider=p.name,**d); results.append(r)
            if r.status=='ok': put(p.name,ioc['type'],ioc['value'],r.model_dump())
        except Exception as e:
            status='auth_error' if getattr(e,'response',None) is not None and e.response.status_code in (401,403) else 'rate_limited' if getattr(e,'response',None) is not None and e.response.status_code==429 else 'error'
            results.append(ProviderResult(provider=p.name,status=status,error=str(e)[:250]))
    final=score(results); v=verdict(final); labels,evidence=classify(results)
    out=AnalysisResult(ioc=ioc,providers=results,score=final,verdict=v,confidence=calculate(results),labels=labels,evidence=evidence)
    from .database import save_history
    save_history(out); return out