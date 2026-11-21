from ..core.http_client import request
from .base import Provider
import base64
class VirusTotal(Provider):
    name="virustotal"; supported_types={"IPv4","IPv6","Domain","URL","MD5","SHA1","SHA256"}
    def __init__(self,key): self.key=key
    def is_configured(self): return bool(self.key)
    async def lookup(self,ioc):
        value=ioc['value']; typ=ioc['type']; endpoint={'IPv4':'ip_addresses','IPv6':'ip_addresses','Domain':'domains','URL':'urls','MD5':'files','SHA1':'files','SHA256':'files'}[typ]
        item=base64.urlsafe_b64encode(value.encode()).decode().rstrip('=') if typ=='URL' else value
        r=await request('GET',f'https://www.virustotal.com/api/v3/{endpoint}/{item}',headers={'x-apikey':self.key})
        d=r.json().get('data',{}).get('attributes',{}); s=d.get('last_analysis_stats',{}); total=sum(s.values()); flagged=s.get('malicious',0)+s.get('suspicious',0)
        score=round(flagged/total*100,1) if total else None
        return {'status':'ok','score':score,'summary':{'stats':s,'engine_count':total,'flagged':flagged,'reputation':d.get('reputation'),'last_analysis_date':d.get('last_analysis_date')}}
