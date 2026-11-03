import pytest

from webtech_inspector.models import ContentEndpoint, MetaDataEndpoint


@pytest.fixture
def mock_api_success_response():
    # a short answer in the same format OSV returns
    return {
        "vulns": [
            {
                "id": "GHSA-0000-0000-0001",
                "aliases": ["CVE-0000-0001"],
                "summary": "Synthetic example vulnerability",
                "database_specific": {"severity": "HIGH"},
            }
        ]
    }


@pytest.fixture
def sample_content_endpoint():
    return ContentEndpoint("E1", "<script src='jquery-3.4.1.min.js'></script>", "homepage", "/", 200, "HTML")


@pytest.fixture
def sample_metadata_endpoint():
    return MetaDataEndpoint("E2", "X-Powered-By: Express", "headers", "headers")
