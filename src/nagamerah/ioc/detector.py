import ipaddress, re
def detect(value: str) -> str:
    try:
        ip=ipaddress.ip_address(value)
        return "IPv4" if ip.version==4 else "IPv6"
    except ValueError: pass
    if re.fullmatch(r"[a-fA-F0-9]{32}", value): return "MD5"
    if re.fullmatch(r"[a-fA-F0-9]{40}", value): return "SHA1"
    if re.fullmatch(r"[a-fA-F0-9]{64}", value): return "SHA256"
    if value.startswith(("http://","https://")): return "URL"
    if re.fullmatch(r"(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}", value.rstrip(".")): return "Domain"
    raise ValueError("IOC tidak valid atau jenis IOC tidak didukung")
