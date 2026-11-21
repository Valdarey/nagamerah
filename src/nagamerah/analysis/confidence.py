def calculate(results):
    count=sum(r.status=="ok" for r in results)
    return "HIGH" if count>=2 else "MEDIUM" if count==1 else "LOW"
