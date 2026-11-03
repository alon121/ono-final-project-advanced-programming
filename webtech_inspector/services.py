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
    result = []
    for vuln in vulns:
        if vuln["severity"] is not None:
            if vuln["severity"] <= min_severity:
                result.append(vuln)
    return result
