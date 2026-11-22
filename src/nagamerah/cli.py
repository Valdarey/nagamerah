"""Command-line interface for NAGAMERAH."""

import asyncio
import csv
import getpass
import io
import json
import os
import pathlib
import platform
import sys

import typer
from rich.console import Console
from rich.markup import escape
from rich.progress import BarColumn, MofNCompleteColumn, Progress, SpinnerColumn, TextColumn
from rich.table import Table

from . import __version__
from .analysis.change_detection import compare
from .config import data_dir, get_key, masked, path, set_key, unset
from .core.cache import clear, stats
from .core.database import connect, history
from .core.engine import analyze
from .reporting.generator import render
from .utils.banner import show
from .utils.help import CobraCommand, CobraGroup

MAX_INPUT_BYTES = 10 * 1024 * 1024
DEFAULT_PROVIDERS = ("virustotal", "abuseipdb", "local_dns")
KEY_NAMES = ("vt_key", "abuseipdb_key")

# Help panels: the section titles shown in --help (Dalfox-style grouping).
INPUT = "Input"
CACHE = "Cache"
OUTPUT = "Output"
FILTER = "Filter"
FORMATS = "Report format: txt, json, csv or html"

ROOT_HELP = """\
NAGAMERAH is a threat intelligence aggregator and IOC enrichment tool.
It looks up IPs, domains, URLs and file hashes in VirusTotal and AbuseIPDB,
combines the results into one reputation score, and writes TXT, JSON, CSV
or HTML reports. API keys are yours: store them with "nagamerah config set"."""

ROOT_EXAMPLES = """\
nagamerah lookup 8.8.8.8
nagamerah bulk iocs.txt --format csv --output report.csv
nagamerah config set vt_key"""

LOOKUP_EXAMPLES = """\
nagamerah lookup 8.8.8.8
nagamerah lookup hxxp://evil[.]example.com/login --format json
nagamerah lookup 44d88612fea8a8f36de82e1278abb02f --provider virustotal
nagamerah lookup 203.0.113.10 --offline"""

BULK_EXAMPLES = """\
nagamerah bulk iocs.txt
nagamerah bulk iocs.txt --format csv --output report.csv
nagamerah bulk feed.csv --column indicator
cat iocs.txt | nagamerah bulk - --format json"""


def _group(help_text: str, epilog: str | None = None) -> typer.Typer:
    return typer.Typer(
        cls=CobraGroup,
        help=help_text,
        epilog=epilog,
        no_args_is_help=True,
        add_completion=False,
        context_settings={"help_option_names": ["-h", "--help"]},
    )


def _command(target: typer.Typer, name: str | None = None, examples: str | None = None):
    """Register a command that renders its --help in the plain grouped style."""
    return target.command(name, cls=CobraCommand, epilog=examples)


app = _group(ROOT_HELP, ROOT_EXAMPLES)
config_app = _group("Manage configuration and API keys")
cache_app = _group("Manage the local cache")
database_app = _group("Manage the local database")
app.add_typer(config_app, name="config")
app.add_typer(cache_app, name="cache")
app.add_typer(database_app, name="database")


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(__version__)
        raise typer.Exit()


@app.callback()
def main(
    version: bool = typer.Option(
        False, "--version", callback=_version_callback, is_eager=True, help="Show version"
    ),
) -> None:
    pass


def _emit(text: str, output: str | None) -> None:
    """Print a report to stdout, or write it to a file (status goes to stderr)."""
    if not output:
        typer.echo(text)
        return
    try:
        pathlib.Path(output).write_text(text, encoding="utf-8")
    except OSError as exc:
        typer.echo(f"Cannot write {output}: {exc}", err=True)
        raise typer.Exit(1) from exc
    typer.echo(f"Report saved: {output}", err=True)


@_command(app, examples=LOOKUP_EXAMPLES)
def lookup(
    ioc: str = typer.Argument(..., help="IP, domain, URL or file hash (defanged is accepted)"),
    provider: list[str] = typer.Option(
        None, "--provider", help="Use only this provider, repeatable", rich_help_panel=INPUT
    ),
    offline: bool = typer.Option(
        False, "--offline", help="Use cached and local data only", rich_help_panel=INPUT
    ),
    no_cache: bool = typer.Option(
        False, "--no-cache", help="Do not read or write the cache", rich_help_panel=CACHE
    ),
    refresh: bool = typer.Option(
        False, "--refresh", help="Ignore cached data and update it", rich_help_panel=CACHE
    ),
    fmt: str = typer.Option("txt", "--format", help=FORMATS, rich_help_panel=OUTPUT),
    output: str = typer.Option(
        None, "--output", help="Write the report to a file", rich_help_panel=OUTPUT
    ),
    quiet: bool = typer.Option(False, "--quiet", help="Hide the banner", rich_help_panel=OUTPUT),
    no_banner: bool = typer.Option(
        False, "--no-banner", help="Hide the banner", rich_help_panel=OUTPUT
    ),
    verbose: bool = typer.Option(
        False, "--verbose", help="Show technical errors", rich_help_panel=OUTPUT
    ),
) -> None:
    """Look up a single IOC (IP, domain, URL or hash)"""
    show(ioc, "auto-detected", ", ".join(provider or DEFAULT_PROVIDERS), quiet, no_banner)
    try:
        result = asyncio.run(analyze(
            ioc,
            provider_filter=provider,
            offline=offline,
            no_cache=no_cache,
            refresh=refresh,
        ))
    except ValueError as exc:
        typer.echo(f"Invalid IOC: {exc}", err=True)
        raise typer.Exit(2) from exc
    except Exception as exc:
        if verbose:
            raise
        typer.echo(f"Lookup failed: {exc}", err=True)
        raise typer.Exit(1) from exc
    _emit(render(result.model_dump(), fmt), output)
    if result.verdict == "Unknown":
        raise typer.Exit(3)


def _read_source(source: str) -> str:
    if source == "-":
        return sys.stdin.read()
    file = pathlib.Path(source)
    if not file.is_file():
        typer.echo(f"File not found: {source}", err=True)
        raise typer.Exit(2)
    if file.stat().st_size > MAX_INPUT_BYTES:
        typer.echo("Input melebihi 10 MB", err=True)
        raise typer.Exit(2)
    return file.read_text(encoding="utf-8")


def _extract_iocs(raw: str, source: str, column: str) -> list[str]:
    """One IOC per line, or one CSV column; blank lines and # comments are skipped."""
    if source.lower().endswith(".csv"):
        reader = csv.DictReader(io.StringIO(raw))
        if not reader.fieldnames or column not in reader.fieldnames:
            typer.echo(f"CSV column '{column}' not found. Use --column.", err=True)
            raise typer.Exit(2)
        values = [(row.get(column) or "").strip() for row in reader]
    else:
        values = [line.strip() for line in raw.splitlines()]
    return [v for v in values if v and not v.startswith("#")]


async def _analyze_many(
    items: list[str],
    results: list,
    invalid: list,
    provider: list[str] | None,
    no_cache: bool,
    refresh: bool,
    offline: bool,
) -> None:
    """Fill ``results``/``invalid`` in place so partial work survives Ctrl+C."""
    progress = Progress(
        SpinnerColumn(),
        TextColumn("{task.description}"),
        BarColumn(),
        MofNCompleteColumn(),
        console=Console(stderr=True),
        transient=True,
    )
    with progress:
        task = progress.add_task("Analyzing", total=len(items))
        for item in items:
            try:
                results.append(await analyze(
                    item,
                    provider_filter=provider,
                    offline=offline,
                    no_cache=no_cache,
                    refresh=refresh,
                ))
            except Exception as exc:  # noqa: BLE001 - one bad IOC must not stop the run
                invalid.append({"ioc": item, "error": str(exc)})
            progress.advance(task)


@_command(app, examples=BULK_EXAMPLES)
def bulk(
    source: str = typer.Argument(
        ..., metavar="FILE", help="TXT or CSV file with one IOC per line, or - for stdin"
    ),
    column: str = typer.Option(
        "ioc", "--column", help="IOC column name for CSV input", rich_help_panel=INPUT
    ),
    provider: list[str] = typer.Option(
        None, "--provider", help="Use only this provider, repeatable", rich_help_panel=INPUT
    ),
    offline: bool = typer.Option(
        False, "--offline", help="Use cached and local data only", rich_help_panel=INPUT
    ),
    no_cache: bool = typer.Option(
        False, "--no-cache", help="Do not read or write the cache", rich_help_panel=CACHE
    ),
    refresh: bool = typer.Option(
        False, "--refresh", help="Ignore cached data and update it", rich_help_panel=CACHE
    ),
    fmt: str = typer.Option("txt", "--format", help=FORMATS, rich_help_panel=OUTPUT),
    output: str = typer.Option(
        None, "--output", help="Write the report to a file", rich_help_panel=OUTPUT
    ),
    quiet: bool = typer.Option(False, "--quiet", help="Hide the banner", rich_help_panel=OUTPUT),
    no_banner: bool = typer.Option(
        False, "--no-banner", help="Hide the banner", rich_help_panel=OUTPUT
    ),
) -> None:
    """Analyze many IOCs from a file, a CSV, or stdin"""
    show(source, "bulk", ", ".join(provider or DEFAULT_PROVIDERS), quiet, no_banner)
    lines = _extract_iocs(_read_source(source), source, column)
    unique = list(dict.fromkeys(lines))
    results: list = []
    invalid: list = []
    try:
        asyncio.run(_analyze_many(unique, results, invalid, provider, no_cache, refresh, offline))
    except KeyboardInterrupt:
        typer.echo("Interrupted. Writing partial results.", err=True)
    _emit(render([r.model_dump() for r in results], fmt), output)
    # Summary goes to stderr so JSON/CSV on stdout stays valid when piped.
    typer.echo(f"Total {len(lines)} | Unique {len(unique)} | Invalid {len(invalid)}", err=True)
    if invalid:
        typer.echo(json.dumps(invalid, indent=2), err=True)


def _database_status() -> str:
    try:
        with connect() as db:
            db.execute("SELECT 1")
        directory = data_dir()
        if not os.access(directory, os.W_OK):
            return f"not writable ({directory})"
    except Exception as exc:  # noqa: BLE001 - report any failure as a status
        return f"error: {exc}"
    return "writable"


@_command(app, examples="nagamerah doctor")
def doctor(
    quiet: bool = typer.Option(False, "--quiet", help="Hide the banner", rich_help_panel=OUTPUT),
    no_banner: bool = typer.Option(
        False, "--no-banner", help="Hide the banner", rich_help_panel=OUTPUT
    ),
) -> None:
    """Check configuration and environment readiness"""
    active = ["local_dns"]
    if get_key("vt_key"):
        active.append("virustotal")
    if get_key("abuseipdb_key"):
        active.append("abuseipdb")
    show("environment", "system", ", ".join(active), quiet, no_banner)
    table = Table(title="NAGAMERAH DOCTOR")
    table.add_column("Check")
    table.add_column("Status")
    table.add_row("Python", platform.python_version())
    table.add_row("Config", escape(str(path())))
    table.add_row("VirusTotal", masked(get_key("vt_key")))
    table.add_row("AbuseIPDB", masked(get_key("abuseipdb_key")))
    table.add_row("Database", escape(_database_status()))
    Console().print(table)
    typer.echo("Active providers: " + ", ".join(active))


@_command(app, "history", examples="nagamerah history --verdict malicious --limit 20")
def history_cmd(
    verdict: str = typer.Option(
        None, "--verdict", help="Only show this verdict", rich_help_panel=FILTER
    ),
    limit: int = typer.Option(
        50, "--limit", help="Maximum rows to show", rich_help_panel=FILTER
    ),
) -> None:
    """Show previous lookups"""
    table = Table(title="Lookup History")
    for name in ("Timestamp", "IOC", "Type", "Score", "Verdict"):
        table.add_column(name)
    for row in history(limit):
        if not verdict or str(row[4]).lower() == verdict.lower():
            table.add_row(*(escape(str(cell)) for cell in row))
    Console().print(table)


@_command(app, examples="nagamerah diff old.json new.json")
def diff(
    old: str = typer.Argument(..., metavar="OLD", help="Earlier result file (JSON)"),
    new: str = typer.Argument(..., metavar="NEW", help="Later result file (JSON)"),
) -> None:
    """Compare two result files"""
    typer.echo(json.dumps(compare(old, new), indent=2))


@_command(app, examples="nagamerah report result.json --format html --output report.html")
def report(
    source: str = typer.Argument(..., metavar="FILE", help="Saved JSON result file"),
    fmt: str = typer.Option("html", "--format", help=FORMATS, rich_help_panel=OUTPUT),
    output: str = typer.Option(
        None, "--output", help="Write the report to a file", rich_help_panel=OUTPUT
    ),
) -> None:
    """Generate a report from a saved JSON result"""
    data = json.loads(pathlib.Path(source).read_text(encoding="utf-8"))
    _emit(render(data, fmt), output)


def _check_key_name(key: str) -> None:
    if key not in KEY_NAMES:
        typer.echo("Key harus vt_key atau abuseipdb_key", err=True)
        raise typer.Exit(2)


@_command(config_app, "set", examples="nagamerah config set vt_key")
def config_set(
    key: str = typer.Argument(..., metavar="KEY", help="vt_key or abuseipdb_key"),
) -> None:
    """Store an API key through a hidden prompt"""
    _check_key_name(key)
    value = getpass.getpass(f"Enter {key}: ").strip()
    if not value:
        typer.echo("No key entered.", err=True)
        raise typer.Exit(2)
    set_key(key, value)
    typer.echo("Saved securely.")


@_command(config_app, "unset", examples="nagamerah config unset vt_key")
def config_unset(
    key: str = typer.Argument(..., metavar="KEY", help="vt_key or abuseipdb_key"),
) -> None:
    """Remove a stored API key"""
    _check_key_name(key)
    unset(key)
    typer.echo("Removed.")


@_command(config_app, "show")
def config_show() -> None:
    """Show configuration (keys are masked)"""
    typer.echo(f"Config path: {path()}")
    typer.echo("vt_key: " + masked(get_key("vt_key")))
    typer.echo("abuseipdb_key: " + masked(get_key("abuseipdb_key")))


@_command(config_app, "path")
def config_path() -> None:
    """Print the configuration file path"""
    typer.echo(path())


@_command(cache_app, "stats")
def cache_stats() -> None:
    """Show cache statistics"""
    typer.echo(f"Cache entries: {stats()}")


@_command(cache_app, "clear")
def cache_clear() -> None:
    """Delete all cached results"""
    clear()
    typer.echo("Cache cleared.")


@_command(database_app, "clear-history")
def db_clear_history(
    confirm: bool = typer.Option(False, "--yes", help="Do not ask for confirmation"),
) -> None:
    """Delete all lookup history"""
    if not confirm:
        typer.confirm("Delete all history?", abort=True)
    with connect() as db:
        db.execute("DELETE FROM history")
    typer.echo("History deleted.")


@_command(database_app, "path")
def db_path() -> None:
    """Print the database file path"""
    typer.echo(data_dir() / "nagamerah.db")


@_command(app, "version")
def version_cmd() -> None:
    """Show version"""
    typer.echo(f"NAGAMERAH v{__version__}")