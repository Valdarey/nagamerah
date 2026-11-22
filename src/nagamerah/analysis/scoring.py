"""Aggregate provider scores and map them to a verdict."""

def score(results, weights=None):
    weights = weights or {"virustotal": 1.0, "abuseipdb": 1.0}
    valid = [r for r in results if r.status == "ok" and r.score is not None]
    if not valid:
        return None
    weighted = []
    for result in valid:
        weight = float(weights.get(result.provider, 1.0))
        if weight > 0:
            weighted.append((float(result.score), weight))
    denominator = sum(weight for _, weight in weighted)
    if not denominator:
        return None
    return round(sum(value * weight for value, weight in weighted) / denominator, 1)


def verdict(value):
    if value is None:
        return "Unknown"
    if value < 20:
        return "No Detection"
    if value < 60:
        return "Suspicious"
    return "Malicious"
