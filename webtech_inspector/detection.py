from webtech_inspector.models import Detection, RiskFinding


def detect_technologies(target, signatures):
    detections = []
    warnings = []
    seen = set()

    for endpoint in target.endpoints:
        for signature in signatures:
            # a broken file should not stop the whole scan, so we save a warning and move on
            try:
                if not signature.match(endpoint):
                    continue
                version = signature.extract_version(endpoint)
            except ValueError as error:
                warnings.append(f"{signature.signature_id} on {endpoint.endpoint_id}: {error}")
                continue

            key = (endpoint.endpoint_id, signature.signature_id, version)
            if key in seen:
                continue
            seen.add(key)

            detection_id = f"{target.target_id}-{endpoint.endpoint_id}-{signature.signature_id}"
            detection = Detection(detection_id, target.target_id, endpoint.endpoint_id,
                                  signature.signature_id, signature.tech_name, signature.category, version)
            detections.append(detection)

    return detections, warnings


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
