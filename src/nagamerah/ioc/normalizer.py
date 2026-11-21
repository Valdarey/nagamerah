from urllib.parse import urlsplit, urlunsplit
def normalize(value: str, kind: str) -> str:
    if kind in ("Domain","MD5","SHA1","SHA256"): return value.lower().rstrip(".")
    if kind=="URL":
        p=urlsplit(value); host=(p.hostname or "").lower(); netloc=host
        if p.port: netloc+=f":{p.port}"
        return urlunsplit((p.scheme.lower(),netloc,p.path or "/",p.query,p.fragment))
    return value
