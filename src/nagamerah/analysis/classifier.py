def classify(results):
    labels=[]; evidence=[]
    for r in results:
        s=r.summary or {}
        if r.provider=="abuseipdb":
            for cat in (s.get("reports") or []):
                c=cat.get("category")
                if c: labels.append(str(c)); evidence.append(f"AbuseIPDB category: {c}")
        if r.provider=="virustotal":
            for cat in (s.get("categories") or []):
                if cat: labels.append(str(cat)); evidence.append(f"VirusTotal category: {cat}")
    return list(dict.fromkeys(labels)) or ["Unknown"],evidence
