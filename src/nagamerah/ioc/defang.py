import re
def refang(value: str) -> tuple[str, bool]:
    original=value
    value=re.sub(r"(?i)hxxps", "https", value)
    value=re.sub(r"(?i)hxxp", "http", value)
    value=value.replace("[.]", ".").replace("(.)", ".").replace("[://]", "://")
    return value, value != original
def defang(value: str) -> str:
    value=value.replace("https://", "hxxps://").replace("http://", "hxxp://")
    return value.replace(".", "[.]", 1) if "://" not in value else value.replace(".", "[.]", 1)
