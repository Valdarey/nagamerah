from .defang import refang
from .detector import detect
from .normalizer import normalize
import ipaddress
def parse(raw: str) -> dict:
    if not isinstance(raw,str) or not raw.strip(): raise ValueError("IOC kosong")
    if len(raw)>2048: raise ValueError("IOC melebihi 2048 karakter")
    if any(ord(c)<32 and c not in "\t\r\n" for c in raw): raise ValueError("IOC mengandung karakter kontrol")
    clean, was_defanged=refang(raw.strip()); kind=detect(clean); clean=normalize(clean,kind)
    private=False
    if kind in ("IPv4","IPv6"):
        ip=ipaddress.ip_address(clean); private=not ip.is_global
    return {"original":raw.strip(),"value":clean,"type":kind,"defanged":was_defanged,"private_or_reserved":private}
