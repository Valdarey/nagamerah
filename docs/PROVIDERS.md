# Providers
VirusTotal: obtain API key from the official VirusTotal account portal. Uses GET report endpoints only (does not upload files or submit URLs for scanning).
AbuseIPDB: create an API key at the official AbuseIPDB website. This implementation reads IP check reputation; it never submits reports.
Local DNS: locally resolves domain/URL host A, AAAA, MX, NS, TXT records; informational and not scored. Provider quota limits vary; review official provider documentation. Add providers by implementing `Provider` interface and registering it in the engine.
