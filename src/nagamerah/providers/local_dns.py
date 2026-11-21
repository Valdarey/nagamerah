import dns.resolver
from .base import Provider
class LocalDNS(Provider):
    name="local_dns"; supported_types={"Domain","URL"}
    async def lookup(self,ioc):
        domain=ioc["value"] if ioc["type"]=="Domain" else __import__('urllib.parse',fromlist=['urlsplit']).urlsplit(ioc['value']).hostname
        records={}
        for typ in ("A","AAAA","MX","NS","TXT"):
            try: records[typ]=[str(x) for x in dns.resolver.resolve(domain,typ, lifetime=4)]
            except Exception: records[typ]=[]
        return {"status":"ok","score":None,"summary":{"records":records,"domain":domain}}
