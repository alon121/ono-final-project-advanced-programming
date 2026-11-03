import pytest


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
