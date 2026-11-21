from ..core.http_client import request
from .base import Provider
class AbuseIPDB(Provider):
    name="abuseipdb"; supported_types={"IPv4","IPv6"}
    def __init__(self,key): self.key=key
    def is_configured(self): return bool(self.key)
    async def lookup(self,ioc):
        r=await request('GET','https://api.abuseipdb.com/api/v2/check',params={'ipAddress':ioc['value'],'maxAgeInDays':90,'verbose':True},headers={'Key':self.key,'Accept':'application/json'})
        d=r.json().get('data',{}); return {'status':'ok','score':float(d.get('abuseConfidenceScore',0)),'summary':{k:d.get(k) for k in ('abuseConfidenceScore','totalReports','lastReportedAt','countryCode','isp','usageType','reports')}}
