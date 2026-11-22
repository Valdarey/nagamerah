"""Estimate confidence from successful, independent provider results."""

def calculate(results):
    successful = [r for r in results if r.status == "ok"]
    providers = {r.provider for r in successful}
    if len(providers) >= 2:
        return "HIGH"
    if len(providers) == 1:
        return "MEDIUM"
    return "LOW"
