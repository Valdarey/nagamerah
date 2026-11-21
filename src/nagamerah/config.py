import os, stat
from pathlib import Path
try: import tomllib
except ImportError: import tomli as tomllib
import tomli_w
def config_dir(): return Path(os.getenv('XDG_CONFIG_HOME',Path.home()/'.config'))/'nagamerah'
def data_dir(): return Path(os.getenv('XDG_DATA_HOME',Path.home()/'.local/share'))/'nagamerah'
def state_dir(): return Path(os.getenv('XDG_STATE_HOME',Path.home()/'.local/state'))/'nagamerah'
def path(): return config_dir()/'config.toml'
def read():
    try: return tomllib.loads(path().read_text())
    except (FileNotFoundError,ValueError): return {}
def set_key(name,value):
    p=path(); p.parent.mkdir(parents=True,exist_ok=True,mode=0o700); cfg=read(); cfg[name]=value; p.write_text(tomli_w.dumps(cfg)); os.chmod(p,0o600); os.chmod(p.parent,0o700)
def unset(name):
    cfg=read(); cfg.pop(name,None); p=path(); p.parent.mkdir(parents=True,exist_ok=True,mode=0o700); p.write_text(tomli_w.dumps(cfg)); os.chmod(p,0o600)
def get_key(name):
    env={'vt_key':'VT_API_KEY','abuseipdb_key':'ABUSEIPDB_API_KEY'}.get(name); return os.getenv(env) or read().get(name)
def masked(value): return (value[:4]+'…'+value[-4:]) if value and len(value)>8 else ('configured' if value else 'not configured')
