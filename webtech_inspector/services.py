from abc import ABC, abstractmethod

# 1 = critical. An unknown severity (None) gives 0 points.
SEVERITY_SCORES = {1: 100.0, 2: 75.0, 3: 50.0, 4: 25.0}


class RiskScoringStrategy(ABC):
    @abstractmethod
    def calculate_score(self, severity, endpoint_type):
        pass


class SeverityFirstStrategy(RiskScoringStrategy):
    def calculate_score(self, severity, endpoint_type):
        return SEVERITY_SCORES.get(severity, 0.0)


class ExposureWeightedStrategy(RiskScoringStrategy):
    def calculate_score(self, severity, endpoint_type):
        score = SEVERITY_SCORES.get(severity, 0.0)
        # content (pages and files) is open to visitors, so it counts more than metadata
        if endpoint_type == "content":
            return score * 1.5
        return score


class RiskScoringService:
    def __init__(self, strategy):
        # the strategy is passed in from outside, so we can switch it without changing this class
        self.strategy = strategy

    def evaluate_target_risk(self, endpoints):
        total = 0.0
        for endpoint in endpoints:
            for vulnerability in endpoint.vulnerabilities:
                total += self.strategy.calculate_score(vulnerability["severity"], endpoint.endpoint_type)
        return total


def filter_cves_by_min_severity(vulns, min_severity):
    # 1 is the most severe, so "severe enough" means a number <= min_severity.
    # A vulnerability with unknown severity (None) is skipped.
    result = []
    for vuln in vulns:
        severity = vuln["severity"]
        if severity is not None and severity <= min_severity:
            result.append(vuln)
    return result
