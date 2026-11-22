"""Derive cautious threat labels and evidence from provider output."""

def classify(results):
    labels = []
    evidence = []
    for result in results:
        if result.status != "ok":
            continue
        summary = result.summary or {}
        if result.provider == "virustotal":
            stats = summary.get("stats") or {}
            malicious = int(stats.get("malicious") or 0)
            suspicious = int(stats.get("suspicious") or 0)
            total = int(summary.get("engine_count") or sum(int(v or 0) for v in stats.values()))
            if malicious:
                labels.append("Malware" if malicious >= 3 else "Malicious Detection")
                evidence.append(f"VirusTotal: {malicious} engine(s) classified this IOC as malicious" + (f" out of {total} engines" if total else ""))
            if suspicious:
                labels.append("Suspicious")
                evidence.append(f"VirusTotal: {suspicious} engine(s) classified this IOC as suspicious")
            reputation = summary.get("reputation")
            if reputation is not None:
                evidence.append(f"VirusTotal reputation: {reputation}")
            for category in (summary.get("categories") or []):
                if category:
                    labels.append(str(category))
                    evidence.append(f"VirusTotal category: {category}")
        elif result.provider == "abuseipdb":
            confidence = summary.get("abuseConfidenceScore")
            if confidence is not None and int(confidence) > 0:
                labels.append("Abusive IP")
                evidence.append(f"AbuseIPDB abuse confidence score: {confidence}/100")
            for report in (summary.get("reports") or []):
                category = report.get("category")
                if category:
                    labels.append(str(category))
                    evidence.append(f"AbuseIPDB category: {category}")
    return list(dict.fromkeys(labels)) or ["Unknown"], list(dict.fromkeys(evidence))
