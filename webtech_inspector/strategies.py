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
        base = SeverityFirstStrategy().calculate_score(severity, endpoint_type)
        # content (pages and files) is open to visitors, so it counts more than metadata
        if endpoint_type == "content":
            return base * 1.5
        return base
