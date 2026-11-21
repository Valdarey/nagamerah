def score(results,weights=None):
    weights=weights or {"virustotal":1.0,"abuseipdb":1.0}; valid=[r for r in results if r.status=="ok" and r.score is not None]
    if not valid: return None
    total=sum(weights.get(r.provider,1.0) for r in valid)
    return round(sum(r.score*weights.get(r.provider,1.0) for r in valid)/total,1) if total else None
def verdict(value):
    if value is None: return "Unknown"
    if value<20: return "No Detection"
    if value<60: return "Suspicious"
    return "Malicious"
