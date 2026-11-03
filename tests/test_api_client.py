import asyncio
from unittest.mock import Mock, patch

import pytest
import requests

from webtech_inspector.api_client import VulnerabilityApiClient

GET = "webtech_inspector.api_client.requests.get"


def make_response(status_code, data=None):
    response = Mock()
    response.status_code = status_code
    response.json.return_value = data
    if status_code >= 400:
        response.raise_for_status.side_effect = requests.exceptions.HTTPError(f"HTTP {status_code}")
    return response


def make_client(api_key=""):
    # no waiting between retries, so the tests stay fast
    return VulnerabilityApiClient(base_url="http://test.local", timeout=1, max_retries=3,
                                  retry_delay=0, api_key=api_key)


def make_cve(cve_id, metrics):
    return {"cve": {"id": cve_id, "descriptions": [{"lang": "en", "value": "text"}], "metrics": metrics}}


def test_api_client_success(mock_api_success_response):
    with patch(GET, return_value=make_response(200, mock_api_success_response)):
        result = make_client().fetch_cves_sync("Lodash", "4.17.15")

    assert result == [{"cve_id": "CVE-0000-0001", "summary": "Synthetic example vulnerability", "severity": 2}]


def test_api_client_sends_cpe_name(mock_api_success_response):
    with patch(GET, return_value=make_response(200, mock_api_success_response)) as fake_get:
        make_client().fetch_cves_sync("Lodash", "4.17.15")

    params = fake_get.call_args.kwargs["params"]
    assert params == {"virtualMatchString": "cpe:2.3:a:lodash:lodash:4.17.15"}


def test_api_client_sends_api_key(mock_api_success_response):
    with patch(GET, return_value=make_response(200, mock_api_success_response)) as fake_get:
        make_client(api_key="secret").fetch_cves_sync("Lodash", "4.17.15")
        make_client().fetch_cves_sync("Lodash", "4.17.15")

    first_call, second_call = fake_get.call_args_list
    assert first_call.kwargs["headers"] == {"apiKey": "secret"}
    assert second_call.kwargs["headers"] == {}


def test_api_client_unknown_technology_no_request():
    with patch(GET) as fake_get:
        assert make_client().fetch_cves_sync("Angular", "1.0.0") == []

    assert fake_get.call_count == 0


def test_api_client_no_vulnerabilities():
    with patch(GET, return_value=make_response(200, {"totalResults": 0, "vulnerabilities": []})):
        assert make_client().fetch_cves_sync("jQuery", "3.6.0") == []


def test_api_client_timeout_retry(mock_api_success_response):
    timeout = requests.exceptions.Timeout("too slow")
    answers = [timeout, timeout, make_response(200, mock_api_success_response)]

    with patch(GET, side_effect=answers) as fake_get:
        result = make_client().fetch_cves_sync("Lodash", "4.17.15")

    assert fake_get.call_count == 3
    assert len(result) == 1


def test_api_client_max_retries_exceeded():
    with patch(GET, side_effect=requests.exceptions.Timeout("too slow")) as fake_get:
        with pytest.raises(requests.exceptions.Timeout):
            make_client().fetch_cves_sync("Lodash", "4.17.15")

    assert fake_get.call_count == 3


def test_api_client_connection_error_retry(mock_api_success_response):
    answers = [requests.exceptions.ConnectionError("no network"), make_response(200, mock_api_success_response)]

    with patch(GET, side_effect=answers) as fake_get:
        make_client().fetch_cves_sync("Lodash", "4.17.15")

    assert fake_get.call_count == 2


def test_api_client_http_404_empty_list():
    with patch(GET, return_value=make_response(404)) as fake_get:
        assert make_client().fetch_cves_sync("Lodash", "4.17.15") == []

    assert fake_get.call_count == 1


def test_api_client_http_403_no_retry():
    # NVD answers 403 when we send too many requests without a key
    with patch(GET, return_value=make_response(403)) as fake_get:
        with pytest.raises(requests.exceptions.HTTPError):
            make_client().fetch_cves_sync("Lodash", "4.17.15")

    assert fake_get.call_count == 1


@pytest.mark.parametrize("metrics, expected", [
    ({"cvssMetricV31": [{"cvssData": {"baseSeverity": "CRITICAL"}}]}, 1),
    ({"cvssMetricV30": [{"cvssData": {"baseSeverity": "MEDIUM"}}]}, 3),
    ({"cvssMetricV2": [{"baseSeverity": "LOW"}]}, 4),
    ({}, None),
])
def test_api_client_severity_versions(metrics, expected):
    data = {"vulnerabilities": [make_cve("CVE-0000-0002", metrics)]}
    with patch(GET, return_value=make_response(200, data)):
        result = make_client().fetch_cves_sync("Lodash", "4.17.15")

    assert result[0]["severity"] == expected


def test_api_client_async(mock_api_success_response):
    with patch(GET, return_value=make_response(200, mock_api_success_response)):
        result = asyncio.run(make_client().fetch_cves_async("Lodash", "4.17.15"))

    assert result[0]["cve_id"] == "CVE-0000-0001"
