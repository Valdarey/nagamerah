import json, time, hashlib
from .database import connect
def key(provider,kind,ioc): return hashlib.sha256(f"{provider}|{kind}|{ioc}".encode()).hexdigest()
def get(provider,kind,ioc):
    k=key(provider,kind,ioc)
    with connect() as db: row=db.execute("SELECT payload,expires FROM cache WHERE cache_key=?",(k,)).fetchone()
    if not row or row[1]<time.time(): return None
    return json.loads(row[0])
def put(provider,kind,ioc,payload,ttl=86400):
    with connect() as db: db.execute("INSERT OR REPLACE INTO cache VALUES(?,?,?)",(key(provider,kind,ioc),json.dumps(payload),time.time()+ttl))
def clear():
    with connect() as db: db.execute("DELETE FROM cache")
def stats():
    with connect() as db: return db.execute("SELECT count(*) FROM cache").fetchone()[0]
