import asyncio
from unittest.mock import Mock, patch

import requests

from webtech_inspector.api_client import LocalVulnerabilityClient
from webtech_inspector.async_processing import (discover_endpoints_concurrent, discover_endpoints_sequential,
                                                scan_real_site)
from webtech_inspector.models import ScanTarget
from webtech_inspector.repository import load_signatures, load_insights

GET = "webtech_inspector.async_processing.requests.get"


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


def make_page(status_code, text, headers=None):
    page = Mock()
    page.status_code = status_code
    page.text = text
    page.headers = headers or {}
    return page


def fake_site(pages):
    # answers each url from the dict, like a small fake website
    def get(url, timeout, headers):
        if isinstance(pages[url], Exception):
            raise pages[url]
        return pages[url]
    return get


def test_scan_real_site_reads_home_and_headers():
    pages = {
        "https://a.example.test/": make_page(200, "<script src='jquery-3.4.1.min.js'></script>",
                                             {"Server": "nginx/1.18.0"}),
        "https://a.example.test/package.json": make_page(404, "not found"),
    }
    target = ScanTarget("LIVE", "https://a.example.test/")
    with patch(GET, side_effect=fake_site(pages)):
        endpoints = asyncio.run(scan_real_site(target, make_client(), load_signatures()))

    assert [endpoint.endpoint_id for endpoint in endpoints] == ["live-home", "live-headers"]
    assert endpoints[1].raw_content == "Server: nginx/1.18.0"
    assert [vuln["cve_id"] for vuln in endpoints[0].vulnerabilities] == ["I001"]
    assert len(target) == 2


def test_scan_real_site_reads_package_json():
    pages = {
        "https://a.example.test/": make_page(200, "<p>hello</p>"),
        "https://a.example.test/package.json": make_page(200, '{"dependencies": {"lodash": "4.17.15"}}'),
    }
    with patch(GET, side_effect=fake_site(pages)):
        endpoints = asyncio.run(scan_real_site(ScanTarget("LIVE", "https://a.example.test"),
                                               make_client(), load_signatures()))

    package = endpoints[2]
    assert package.content_type == "JSON"
    assert [vuln["cve_id"] for vuln in package.vulnerabilities] == ["CVE-0000-0001"]


def test_scan_real_site_skips_html_package_json():
    # some sites return their home page for every path
    pages = {
        "https://a.example.test/": make_page(200, "<p>hello</p>"),
        "https://a.example.test/package.json": make_page(200, "<html>home page</html>"),
    }
    with patch(GET, side_effect=fake_site(pages)):
        endpoints = asyncio.run(scan_real_site(ScanTarget("LIVE", "https://a.example.test"),
                                               make_client(), load_signatures()))

    assert len(endpoints) == 2


def test_scan_real_site_not_reachable():
    error = requests.exceptions.ConnectionError("no network")
    pages = {"https://a.example.test/": error, "https://a.example.test/package.json": error}
    with patch(GET, side_effect=fake_site(pages)):
        endpoints = asyncio.run(scan_real_site(ScanTarget("LIVE", "https://a.example.test"),
                                               make_client(), load_signatures()))

    assert endpoints == []
