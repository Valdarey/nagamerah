import os,sys
from rich.console import Console
from rich.text import Text
LOGO='\n███╗   ██╗ █████╗  ██████╗  █████╗ ███╗   ███╗███████╗██████╗  █████╗ ██╗  ██╗\n████╗  ██║██╔══██╗██╔════╝ ██╔══██╗████╗ ████║██╔════╝██╔══██╗██╔══██╗██║  ██║\n██╔██╗ ██║███████║██║  ███╗███████║██╔████╔██║█████╗  ██████╔╝███████║███████║\n██║╚██╗██║██╔══██║██║   ██║██╔══██║██║╚██╔╝██║██╔══╝  ██╔══██╗██╔══██║██╔══██║\n██║ ╚████║██║  ██║╚██████╔╝██║  ██║██║ ╚═╝ ██║███████╗██║  ██║██║  ██║██║  ██║\n╚═╝  ╚═══╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝'

def show(target='-',kind='-',providers='-',quiet=False,no_banner=False):
    c=Console(stderr=True); env=os.getenv('NAGAMERAH_NO_BANNER')
    if quiet or no_banner or env or not c.is_terminal: return
    width=c.width; logo=LOGO.splitlines() if width>=78 else ['N A G A M E R A H']
    for line in logo: c.print(line,style='bold red')
    c.print("Threat Intelligence Aggregator & IOC Enrichment CLI Tool.\nFocused on automation, evidence, and honest scoring.\n",style='white')
    c.print(f"Target : {target}\nType : {kind}\nProviders : {providers}\nCache : true (TTL 24h)\nTimeout : 15\nRetries : 3\nConcurrency : 3\n",style='cyan')
