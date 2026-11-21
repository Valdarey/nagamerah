import typer, asyncio, json, sys, os, csv, pathlib, time
from rich.console import Console
from rich.table import Table
from rich.progress import Progress,SpinnerColumn,TextColumn
from . import __version__
from .core.engine import analyze
from .config import path,read,set_key,unset,get_key,masked
from .core.database import history,connect
from .core.cache import clear,stats
from .analysis.change_detection import compare
from .reporting.generator import render
from .utils.banner import show
app=typer.Typer(no_args_is_help=True,help='Threat Intelligence Aggregator & IOC Enrichment CLI Tool')
config_app=typer.Typer(); cache_app=typer.Typer(); database_app=typer.Typer(); app.add_typer(config_app,name='config'); app.add_typer(cache_app,name='cache'); app.add_typer(database_app,name='database')
@app.callback()
def main(ctx:typer.Context,version:bool=typer.Option(False,'--version',help='Show version')):
    if version: typer.echo(__version__); raise typer.Exit()
@app.command()
def lookup(ioc:str,format:str=typer.Option('txt','--format'),output:str=typer.Option(None,'--output'),provider:list[str]=typer.Option(None,'--provider'),no_cache:bool=typer.Option(False,'--no-cache'),refresh:bool=typer.Option(False,'--refresh'),offline:bool=typer.Option(False,'--offline'),quiet:bool=typer.Option(False,'--quiet'),no_banner:bool=typer.Option(False,'--no-banner'),verbose:bool=typer.Option(False,'--verbose')):
    show(ioc,'auto-detected',','.join(provider or ['virustotal','abuseipdb','local_dns']),quiet,no_banner)
    try: result=asyncio.run(analyze(ioc,provider,no_cache,refresh,offline))
    except ValueError as e: typer.echo(f'Invalid IOC: {e}',err=True); raise typer.Exit(2)
    data=result.model_dump(); text=render(data,format);
    if output: pathlib.Path(output).write_text(text,encoding='utf-8'); typer.echo(f'Report saved: {output}')
    else: typer.echo(text)
    if result.verdict=='Unknown': raise typer.Exit(3)
@app.command()
def bulk(source:str,format:str=typer.Option('txt','--format'),output:str=typer.Option(None,'--output'),column:str=typer.Option('ioc','--column'),quiet:bool=typer.Option(False,'--quiet'),no_banner:bool=typer.Option(False,'--no-banner'),offline:bool=typer.Option(False,'--offline')):
    show(source,'bulk','configured providers',quiet,no_banner)
    if source=='-': raw=sys.stdin.read()
    else:
        p=pathlib.Path(source)
        if p.stat().st_size>10*1024*1024: typer.echo('Input melebihi 10 MB',err=True); raise typer.Exit(2)
        raw=p.read_text(encoding='utf-8')
    lines=[x.strip() for x in raw.splitlines() if x.strip() and not x.strip().startswith('#')]; unique=list(dict.fromkeys(lines)); results=[]; invalid=[]
    for item in unique:
        try: results.append(asyncio.run(analyze(item,offline=offline)))
        except Exception as e: invalid.append({'ioc':item,'error':str(e)})
    data=[r.model_dump() for r in results]; text=render(data,format)
    if output: pathlib.Path(output).write_text(text,encoding='utf-8'); typer.echo(f'Report saved: {output}')
    else: typer.echo(text)
    typer.echo(f'Total {len(lines)} | Unique {len(unique)} | Invalid {len(invalid)}')
    if invalid: typer.echo(json.dumps(invalid,indent=2))
@app.command()
def doctor(quiet:bool=typer.Option(False,'--quiet'),no_banner:bool=typer.Option(False,'--no-banner')):
    show('environment','system','local_dns, virustotal, abuseipdb',quiet,no_banner); import platform, importlib.util
    t=Table(title='NAGAMERAH DOCTOR'); t.add_column('Check'); t.add_column('Status')
    t.add_row('Python',platform.python_version()); t.add_row('Config',str(path())); t.add_row('VirusTotal',masked(get_key('vt_key'))); t.add_row('AbuseIPDB',masked(get_key('abuseipdb_key'))); t.add_row('Database','writable')
    Console().print(t); typer.echo('Active provider: local_dns'+(', virustotal' if get_key('vt_key') else '')+(', abuseipdb' if get_key('abuseipdb_key') else ''))
@app.command()
def history_cmd(verdict:str=typer.Option(None,'--verdict'),limit:int=typer.Option(50,'--limit')):
    rows=history(limit); t=Table(title='Lookup History'); [t.add_column(c) for c in ['Timestamp','IOC','Type','Score','Verdict']]
    for r in rows:
        if not verdict or r[4].lower()==verdict.lower(): t.add_row(*map(str,r))
    Console().print(t)
app.command('history')(history_cmd)
@app.command()
def diff(old:str,new:str):
    typer.echo(json.dumps(compare(old,new),indent=2))
@app.command()
def report(source:str,format:str=typer.Option('html','--format'),output:str=typer.Option(None,'--output')):
    data=json.loads(pathlib.Path(source).read_text(encoding='utf-8')); text=render(data,format)
    if output: pathlib.Path(output).write_text(text,encoding='utf-8'); typer.echo(f'Saved {output}')
    else: typer.echo(text)
@config_app.command('set')
def config_set(key:str):
    if key not in ('vt_key','abuseipdb_key'): typer.echo('Key harus vt_key atau abuseipdb_key'); raise typer.Exit(2)
    import getpass; value=getpass.getpass(f'Enter {key}: '); set_key(key,value); typer.echo('Saved securely.')
@config_app.command('unset')
def config_unset(key:str): unset(key); typer.echo('Removed.')
@config_app.command('show')
def config_show(): typer.echo(f'Config path: {path()}'); typer.echo('vt_key: '+masked(get_key('vt_key'))); typer.echo('abuseipdb_key: '+masked(get_key('abuseipdb_key')))
@config_app.command('path')
def config_path(): typer.echo(path())
@cache_app.command('stats')
def cache_stats(): typer.echo(f'Cache entries: {stats()}')
@cache_app.command('clear')
def cache_clear(): clear(); typer.echo('Cache cleared.')
@database_app.command('clear-history')
def db_clear_history(confirm:bool=typer.Option(False,'--yes')):
    if not confirm: typer.confirm('Delete all history?',abort=True)
    with connect() as db: db.execute('DELETE FROM history')
    typer.echo('History deleted.')
@database_app.command('path')
def db_path(): from .config import data_dir; typer.echo(data_dir()/'nagamerah.db')
