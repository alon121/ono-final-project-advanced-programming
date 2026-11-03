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
