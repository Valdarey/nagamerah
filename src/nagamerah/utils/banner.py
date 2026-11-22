"""Startup banner for NAGAMERAH (src/nagamerah/utils/banner.py).

Printed to stderr so that machine-readable output on stdout (``--format json | jq``)
stays clean. Skipped when stderr is not a terminal, with ``--quiet`` / ``--no-banner``,
or when the ``NAGAMERAH_NO_BANNER`` environment variable is set.
"""

import os
from datetime import datetime

from rich.console import Console
from rich.table import Table
from rich.text import Text

from .. import __version__

LOGO = """\
███╗   ██╗ █████╗  ██████╗  █████╗ ███╗   ███╗███████╗██████╗  █████╗ ██╗  ██╗
████╗  ██║██╔══██╗██╔════╝ ██╔══██╗████╗ ████║██╔════╝██╔══██╗██╔══██╗██║  ██║
██╔██╗ ██║███████║██║  ███╗███████║██╔████╔██║█████╗  ██████╔╝███████║███████║
██║╚██╗██║██╔══██║██║   ██║██╔══██║██║╚██╔╝██║██╔══╝  ██╔══██╗██╔══██║██╔══██║
██║ ╚████║██║  ██║╚██████╔╝██║  ██║██║ ╚═╝ ██║███████╗██║  ██║██║  ██║██║  ██║
╚═╝  ╚═══╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝"""

LOGO_LINES = LOGO.splitlines()
LOGO_WIDTH = max(len(line) for line in LOGO_LINES)
COMPACT_TITLE = "N A G A M E R A H"
TAGLINE = (
    "Threat Intelligence Aggregator & IOC Enrichment CLI Tool.",
    "Focused on automation, evidence, and honest scoring.",
)

def _title_lines(width: int) -> list[Text]:
    """Large logo on wide terminals, compact title on narrow ones."""
    if width >= LOGO_WIDTH:
        lines = [Text(row, style="bold red") for row in LOGO_LINES]
        pad = LOGO_WIDTH
    else:
        lines = [Text(COMPACT_TITLE, style="bold red")]
        pad = len(COMPACT_TITLE)
    lines += [Text(""), Text(f"NagaMerah v{__version__}".center(pad), style="bold white")]
    lines.append(Text(""))
    lines += [Text(line.center(pad), style="white") for line in TAGLINE]
    return lines


def _info_table(target: str, kind: str, providers: str) -> Table:
    cache = Text("true", style="bold green")
    cache.append(" (TTL 24h)", style="default")
    started = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    rows = [
        ("Target", Text(target, style="cyan")),
        ("Type", Text(kind, style="cyan")),
        ("Providers", Text(providers, style="cyan")),
        ("Cache", cache),
        ("Timeout", Text("15", style="cyan")),
        ("Retries", Text("3", style="cyan")),
        ("Concurrency", Text("3", style="cyan")),
        ("Started at", Text(started, style="cyan")),
    ]
    grid = Table.grid(padding=(0, 3))
    grid.add_column(no_wrap=True)
    grid.add_column()
    for label, value in rows:
        grid.add_row(Text(label, style="bold"), value)
    return grid


def show(target="-", kind="-", providers="-", quiet=False, no_banner=False) -> None:
    """Print the banner and the info block (no-op when it should be hidden)."""
    console = Console(stderr=True, highlight=False)
    if quiet or no_banner or os.environ.get("NAGAMERAH_NO_BANNER") or not console.is_terminal:
        return
    console.print()
    for line in _title_lines(console.width):
        console.print(line)
    console.print()
    console.print(_info_table(str(target), str(kind), str(providers)))
    console.print()