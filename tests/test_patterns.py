import pytest

from webtech_inspector.factories import EndpointFactory
from webtech_inspector.models import ContentEndpoint, MetaDataEndpoint
from webtech_inspector.services import (RiskScoringService, RiskScoringStrategy, SeverityFirstStrategy,
                                        ExposureWeightedStrategy)

CONTENT_RECORD = {"endpoint_type": "content", "endpoint_id": "E1", "raw_content": "<html></html>",
                  "source_name": "homepage", "path": "/", "status_code": 200, "content_type": "HTML"}
METADATA_RECORD = {"endpoint_type": "metadata", "endpoint_id": "E2", "raw_content": "Server: nginx",
                   "source_name": "headers", "metadata_type": "headers"}


def test_endpoint_factory_content():
    endpoint = EndpointFactory.create_endpoint(CONTENT_RECORD)
    assert isinstance(endpoint, ContentEndpoint)
    assert endpoint.endpoint_type == "content"


def test_endpoint_factory_metadata():
    endpoint = EndpointFactory.create_endpoint(METADATA_RECORD)
    assert isinstance(endpoint, MetaDataEndpoint)
    assert endpoint.endpoint_type == "metadata"


def test_endpoint_factory_invalid_type():
    with pytest.raises(ValueError, match="video"):
        EndpointFactory.create_endpoint({"endpoint_type": "video"}, line_number=7)


def test_risk_strategy_severity_first():
    strategy = SeverityFirstStrategy()
    assert strategy.calculate_score(1, "content") == 100.0
    assert strategy.calculate_score(1, "metadata") == 100.0


def test_risk_strategy_exposure_weighted():
    strategy = ExposureWeightedStrategy()
    assert strategy.calculate_score(2, "content") == 75.0 * 1.5
    assert strategy.calculate_score(2, "metadata") == 75.0


@pytest.mark.parametrize("severity, expected", [(1, 100.0), (2, 75.0), (3, 50.0), (4, 25.0), (None, 0.0)])
def test_risk_strategy_parametrized(severity, expected):
    assert SeverityFirstStrategy().calculate_score(severity, "metadata") == expected


def test_strategy_base_cannot_be_created():
    with pytest.raises(TypeError):
        RiskScoringStrategy()


def test_service_uses_given_strategy(sample_content_endpoint, sample_metadata_endpoint):
    sample_content_endpoint.vulnerabilities = [{"cve_id": "CVE-0000-0001", "summary": "", "severity": 1}]
    sample_metadata_endpoint.vulnerabilities = [{"cve_id": "CVE-0000-0002", "summary": "", "severity": 3}]
    endpoints = [sample_content_endpoint, sample_metadata_endpoint]

    # same data, two strategies, two different totals
    assert RiskScoringService(SeverityFirstStrategy()).evaluate_target_risk(endpoints) == 150.0
    assert RiskScoringService(ExposureWeightedStrategy()).evaluate_target_risk(endpoints) == 200.0


def test_service_no_vulnerabilities(sample_content_endpoint):
    assert RiskScoringService(SeverityFirstStrategy()).evaluate_target_risk([sample_content_endpoint]) == 0.0
    assert RiskScoringService(SeverityFirstStrategy()).evaluate_target_risk([]) == 0.0
