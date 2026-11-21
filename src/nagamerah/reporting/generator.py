import json, csv, html
def safe_csv(v):
    s=str(v); return "'"+s if s.startswith(('=','+','-','@','\t','\r')) else s
def render(data,fmt):
    if fmt=='json': return json.dumps(data,indent=2,ensure_ascii=False,default=str)
    rows=data if isinstance(data,list) else [data]
    if fmt=='txt': return '\n'.join(f"{r.get('ioc',{}).get('value','')} | {r.get('score')} | {r.get('verdict')}" for r in rows)
    if fmt=='csv':
        import io; o=io.StringIO(); w=csv.writer(o); w.writerow(['IOC','Type','Score','Verdict','Confidence']);
        for r in rows: w.writerow([safe_csv(r.get('ioc',{}).get('value','')),r.get('ioc',{}).get('type'),r.get('score'),r.get('verdict'),r.get('confidence')])
        return o.getvalue()
    if fmt=='html':
        body=''.join(f"<tr><td>{html.escape(str(r.get('ioc',{}).get('value','')))}</td><td>{html.escape(str(r.get('ioc',{}).get('type','')))}</td><td>{html.escape(str(r.get('score')))}</td><td>{html.escape(str(r.get('verdict')))}</td></tr>" for r in rows)
        return '<!doctype html><meta charset=utf-8><title>NAGAMERAH Report</title><h1>NAGAMERAH IOC Report</h1><table><thead><tr><th>IOC</th><th>Type</th><th>Score</th><th>Verdict</th></tr></thead><tbody>'+body+'</tbody></table>'
    raise ValueError('Format tidak didukung')
