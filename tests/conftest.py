import pytest

from webtech_inspector.models import ContentEndpoint, MetaDataEndpoint


@pytest.fixture
def mock_api_success_response():
    # a short answer in the same format NVD returns
    return {
        "totalResults": 1,
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-0000-0001",
                    "descriptions": [{"lang": "en", "value": "Synthetic example vulnerability"}],
                    "metrics": {"cvssMetricV31": [{"cvssData": {"baseSeverity": "HIGH"}}]},
                }
            }
        ],
    }


@pytest.fixture
def sample_content_endpoint():
    return ContentEndpoint("E1", "<script src='jquery-3.4.1.min.js'></script>", "homepage", "/", 200, "HTML")


@pytest.fixture
def sample_metadata_endpoint():
    return MetaDataEndpoint("E2", "X-Powered-By: Express", "headers", "headers")
