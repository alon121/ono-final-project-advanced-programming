import asyncio

from webtech_inspector.api_client import LocalVulnerabilityClient
from webtech_inspector.async_processing import discover_endpoints_concurrent, discover_endpoints_sequential
from webtech_inspector.models import ScanTarget
from webtech_inspector.repository import load_signatures, load_insights


def make_client():
    return LocalVulnerabilityClient(load_insights())


def test_concurrent_vs_sequential_endpoints_identical():
    signatures = load_signatures()
    concurrent = asyncio.run(discover_endpoints_concurrent(
        ScanTarget("T1", "https://a.example.test"), make_client(), signatures))
    sequential = discover_endpoints_sequential(ScanTarget("T2", "https://a.example.test"), make_client(), signatures)

    assert len(concurrent) == 3
    assert len(sequential) == 3
    for first, second in zip(concurrent, sequential):
        assert type(first) is type(second)
        assert first.endpoint_id == second.endpoint_id
        assert first.vulnerabilities == second.vulnerabilities


def test_discovery_finds_local_vulnerabilities():
    target = ScanTarget("T1", "https://a.example.test")
    home, robots, package = discover_endpoints_sequential(target, make_client(), load_signatures())

    assert [vuln["cve_id"] for vuln in home.vulnerabilities] == ["I001"]
    assert robots.vulnerabilities == []
    assert [vuln["cve_id"] for vuln in package.vulnerabilities] == ["CVE-0000-0001"]


def test_discovery_adds_endpoints_to_target():
    target = ScanTarget("T1", "https://a.example.test")
    asyncio.run(discover_endpoints_concurrent(target, make_client(), load_signatures()))
    assert len(target) == 3


def test_local_client_no_match():
    client = make_client()
    assert client.fetch_cves_sync("jQuery", "9.9.9") == []
    assert client.fetch_cves_sync("Angular", "1.0.0") == []
