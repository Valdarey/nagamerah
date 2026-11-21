import sqlite3, json
from pathlib import Path
from datetime import datetime, timezone
from ..config import data_dir
def connect():
    p=data_dir()/"nagamerah.db"; p.parent.mkdir(parents=True,exist_ok=True)
    db=sqlite3.connect(p); db.execute("PRAGMA foreign_keys=ON")
    db.execute("CREATE TABLE IF NOT EXISTS history (id INTEGER PRIMARY KEY, timestamp TEXT NOT NULL, ioc TEXT NOT NULL, kind TEXT NOT NULL, score REAL, verdict TEXT NOT NULL, data TEXT NOT NULL)")
    db.execute("CREATE TABLE IF NOT EXISTS cache (cache_key TEXT PRIMARY KEY, payload TEXT NOT NULL, expires REAL NOT NULL)")
    db.execute("CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY,value TEXT)")
    db.execute("INSERT OR IGNORE INTO meta(key,value) VALUES('schema_version','1')")
    return db
def save_history(result):
    with connect() as db: db.execute("INSERT INTO history(timestamp,ioc,kind,score,verdict,data) VALUES(?,?,?,?,?,?)",(datetime.now(timezone.utc).isoformat(),result.ioc['value'],result.ioc['type'],result.score,result.verdict,result.model_dump_json()))
def history(limit=50):
    with connect() as db: return db.execute("SELECT timestamp,ioc,kind,score,verdict FROM history ORDER BY id DESC LIMIT ?",(limit,)).fetchall()
