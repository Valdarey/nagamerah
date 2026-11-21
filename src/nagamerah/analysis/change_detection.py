import json
def compare(old,new):
    a=json.load(open(old,encoding='utf-8')); b=json.load(open(new,encoding='utf-8'))
    def map_items(x):
        rows=x if isinstance(x,list) else x.get('results',x.get('items',[]))
        return {i.get('ioc',{}).get('value',i.get('ioc',i.get('value'))):i for i in rows if isinstance(i,dict)}
    x,y=map_items(a),map_items(b); changed=[]; added=[]; removed=[]; same=[]
    for k in y.keys()-x.keys(): added.append(k)
    for k in x.keys()-y.keys(): removed.append(k)
    for k in x.keys()&y.keys():
        xv=x[k].get('verdict'); yv=y[k].get('verdict')
        (same if xv==yv and x[k].get('score')==y[k].get('score') else changed).append((k,xv,yv,x[k].get('score'),y[k].get('score')))
    return {'changed':changed,'new':added,'removed':removed,'unchanged':same}
