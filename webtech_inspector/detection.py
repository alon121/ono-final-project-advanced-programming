from webtech_inspector.models import RiskFinding


def match_insights(detections, insights):
    findings = []
    for detection in detections:
        for insight in insights:
            if insight.applies_to(detection):
                findings.append(RiskFinding(detection, insight))
    return findings


def find_manual_checks(detections, insights):
    # the version is unknown, but we have rules for this technology - a person should check it
    tech_names_with_rules = set()
    for insight in insights:
        tech_names_with_rules.add(insight.tech_name)

    manual_checks = []
    for detection in detections:
        if detection.version is None and detection.tech_name in tech_names_with_rules:
            manual_checks.append(detection)
    return manual_checks
