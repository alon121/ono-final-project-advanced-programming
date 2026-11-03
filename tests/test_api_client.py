import asyncio
from unittest.mock import Mock, patch

import pytest
import requests

from webtech_inspector.api_client import VulnerabilityApiClient

POST = "webtech_inspector.api_client.requests.post"


def make_response(status_code, data=None):
    response = Mock()
    response.status_code = status_code
    response.json.return_value = data
    if status_code >= 400:
        response.raise_for_status.side_effect = requests.exceptions.HTTPError(f"HTTP {status_code}")
    return response


def make_client():
    # no waiting between retries, so the tests stay fast
    return VulnerabilityApiClient(base_url="http://test.local", timeout=1, max_retries=3, retry_delay=0)


def test_api_client_success(mock_api_success_response):
    with patch(POST, return_value=make_response(200, mock_api_success_response)):
        result = make_client().fetch_cves_sync("Lodash", "4.17.15")

    assert result == [{"cve_id": "CVE-0000-0001", "summary": "Synthetic example vulnerability", "severity": 2}]


def test_api_client_no_vulnerabilities():
    with patch(POST, return_value=make_response(200, {})):
        assert make_client().fetch_cves_sync("React", "18.2.0") == []


def test_api_client_timeout_retry(mock_api_success_response):
    timeout = requests.exceptions.Timeout("too slow")
    answers = [timeout, timeout, make_response(200, mock_api_success_response)]

    with patch(POST, side_effect=answers) as fake_post:
        result = make_client().fetch_cves_sync("Lodash", "4.17.15")

    assert fake_post.call_count == 3
    assert len(result) == 1


def test_api_client_max_retries_exceeded():
    with patch(POST, side_effect=requests.exceptions.Timeout("too slow")) as fake_post:
        with pytest.raises(requests.exceptions.Timeout):
            make_client().fetch_cves_sync("Lodash", "4.17.15")

    assert fake_post.call_count == 3


def test_api_client_connection_error_retry(mock_api_success_response):
    answers = [requests.exceptions.ConnectionError("no network"), make_response(200, mock_api_success_response)]

    with patch(POST, side_effect=answers) as fake_post:
        make_client().fetch_cves_sync("Lodash", "4.17.15")

    assert fake_post.call_count == 2


def test_api_client_http_404_empty_list():
    with patch(POST, return_value=make_response(404)) as fake_post:
        assert make_client().fetch_cves_sync("Lodash", "4.17.15") == []

    assert fake_post.call_count == 1


def test_api_client_http_500_no_retry():
    with patch(POST, return_value=make_response(500)) as fake_post:
        with pytest.raises(requests.exceptions.HTTPError):
            make_client().fetch_cves_sync("Lodash", "4.17.15")

    assert fake_post.call_count == 1


def test_api_client_unknown_severity():
    data = {"vulns": [{"id": "OSV-1", "summary": "no level"}]}
    with patch(POST, return_value=make_response(200, data)):
        result = make_client().fetch_cves_sync("Lodash", "4.17.15")

    assert result[0]["cve_id"] == "OSV-1"
    assert result[0]["severity"] is None


def test_api_client_async(mock_api_success_response):
    with patch(POST, return_value=make_response(200, mock_api_success_response)):
        result = asyncio.run(make_client().fetch_cves_async("Lodash", "4.17.15"))

    assert result[0]["cve_id"] == "CVE-0000-0001"
