
import pytest

import nagamerah.core.engine as engine
import nagamerah.core.database as database


class FakeProvider:
    def __init__(self, name, result=None, supported_types=None):
        self.name = name
        self.result = result or {
            "status": "no_data",
            "score": None,
            "summary": {},
        }
        self.supported_types = supported_types
        self.lookup_count = 0

    def is_configured(self):
        return True

    async def lookup(self, ioc):
        self.lookup_count += 1
        return self.result


def install_providers(monkeypatch, vt=None, abuse=None, dns=None):
    vt = vt or FakeProvider("virustotal")
    abuse = abuse or FakeProvider("abuseipdb")
    dns = dns or FakeProvider(
        "local_dns",
        supported_types={"Domain", "URL"},
    )

    monkeypatch.setattr(engine, "VirusTotal", lambda key: vt)
    monkeypatch.setattr(engine, "AbuseIPDB", lambda key: abuse)
    monkeypatch.setattr(engine, "LocalDNS", lambda: dns)

    monkeypatch.setattr(engine, "get_key", lambda key: "fake-key")
    monkeypatch.setattr(engine, "get", lambda *args: None)
    monkeypatch.setattr(engine, "put", lambda *args: None)

    monkeypatch.setattr(
        engine,
        "classify",
        lambda results: (["Unknown"], []),
    )

    monkeypatch.setattr(
        database,
        "save_history",
        lambda result: None,
    )

    return vt, abuse, dns


@pytest.mark.anyio
async def test_offline_ipv4_skips_external_providers(monkeypatch):
    vt, abuse, dns = install_providers(monkeypatch)

    result = await engine.analyze(
        "8.8.8.8",
        offline=True,
    )

    assert vt.lookup_count == 0
    assert abuse.lookup_count == 0
    assert dns.lookup_count == 0

    assert result.coverage["applicable"] == 2
    assert result.coverage["completed"] == 0
    assert result.coverage["level"] == "LOW"

    assert result.score is None
    assert result.verdict == "INCONCLUSIVE"


@pytest.mark.anyio
async def test_provider_filter_excludes_unselected_providers(
    monkeypatch,
):
    vt, abuse, dns = install_providers(monkeypatch)

    result = await engine.analyze(
        "8.8.8.8",
        provider_filter=["virustotal"],
    )

    assert vt.lookup_count == 1
    assert abuse.lookup_count == 0
    assert dns.lookup_count == 0

    assert result.coverage["applicable"] == 1
    assert result.coverage["completed"] == 1
    assert result.coverage["level"] == "FULL"


@pytest.mark.anyio
async def test_no_data_counts_as_completed_without_threat_score(
    monkeypatch,
):
    vt, abuse, dns = install_providers(monkeypatch)

    result = await engine.analyze(
        "8.8.8.8",
        provider_filter=["virustotal"],
    )

    assert vt.lookup_count == 1

    assert result.providers[0].status == "no_data"
    assert result.coverage["applicable"] == 1
    assert result.coverage["completed"] == 1

    assert result.score is None
    assert result.verdict == "INCONCLUSIVE"


@pytest.mark.anyio
async def test_valid_cache_is_used_without_live_lookup(monkeypatch):
    vt, abuse, dns = install_providers(monkeypatch)

    cached_payload = {
        "status": "ok",
        "score": None,
        "summary": {},
        "queried_at": "2026-11-22T00:00:00+00:00",
    }

    monkeypatch.setattr(
        engine,
        "get",
        lambda provider, kind, ioc: (
            cached_payload if provider == "virustotal" else None
        ),
    )

    result = await engine.analyze(
        "8.8.8.8",
        provider_filter=["virustotal"],
    )

    assert vt.lookup_count == 0
    assert result.providers[0].from_cache is True
    assert result.providers[0].status == "ok"

    assert result.coverage["applicable"] == 1
    assert result.coverage["completed"] == 1


@pytest.mark.anyio
async def test_provider_exception_counts_as_failed(monkeypatch):
    vt, abuse, dns = install_providers(monkeypatch)

    async def failing_lookup(ioc):
        raise RuntimeError("Simulated provider failure")

    monkeypatch.setattr(vt, "lookup", failing_lookup)

    result = await engine.analyze(
        "8.8.8.8",
        provider_filter=["virustotal"],
    )

    assert result.providers[0].status == "error"
    assert result.coverage["applicable"] == 1
    assert result.coverage["completed"] == 0
    assert result.coverage["statuses"]["failed"] == 1
    assert result.score is None


@pytest.mark.anyio
async def test_corrupt_cache_falls_back_to_live_lookup(monkeypatch):
    vt, abuse, dns = install_providers(monkeypatch)

    def corrupt_cache(*args):
        raise ValueError("Invalid cache payload")

    monkeypatch.setattr(engine, "get", corrupt_cache)

    result = await engine.analyze(
        "8.8.8.8",
        provider_filter=["virustotal"],
    )

    assert vt.lookup_count == 1
    assert result.providers[0].status == "no_data"
    assert result.providers[0].from_cache is False
