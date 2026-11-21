import os,sys
from rich.console import Console
from rich.text import Text
LOGO='███╗   ██╗ █████╗  ██████╗  █████╗ ███╗   ███╗███████╗██████╗  █████╗ ██╗  ██╗\n████╗  ██║██╔══██╗██╔════╝ ██╔══██╗████╗ ████║██╔════╝██╔══██╗██╔══██╗██║  ██║\n██╔██╗ ██║███████║██║  ███╗███████║██╔████╔██║█████╗  ██████╔╝███████║███████║\n██║╚██╗██║██╔══██║██║   ██║██╔══██║██║╚██╔╝██║██╔══╝  ██╔══██╗██╔══██║██╔══██║\n██║ ╚████║██║  ██║╚██████╔╝██║  ██║██║ ╚═╝ ██║███████╗██║  ██║██║  ██║██║  ██║\n╚═╝  ╚═══╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝'

def show(target='-',kind='-',providers='-',quiet=False,no_banner=False):
    c=Console(stderr=True); env=os.getenv('NAGAMERAH_NO_BANNER')
    if quiet or no_banner or env or not c.is_terminal: return
    width=c.width; logo=LOGO.splitlines() if width>=78 else ['N A G A M E R A H']
    for line in logo: c.print(line,style='bold red')
    c.print(f"NagaMerah v1.0.0",style='bold white'); c.print("Threat Intelligence Aggregator & IOC Enrichment CLI Tool.\nFocused on automation, evidence, and honest scoring.",style='white')
    c.print(f"🎯 Target     {target}\n🔎 Type       {kind}\n🧩 Providers  {providers}\n💾 Cache      true (TTL 24h)\n⏳ Timeout    15\n🔁 Retries   3\n🚦 Concurrency 3",style='cyan')
