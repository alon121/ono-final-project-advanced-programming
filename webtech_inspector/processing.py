import heapq
from collections import deque

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
                if str(error) not in warnings:
                    warnings.append(str(error))
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


def count_by_tech(detections):
    tech_counts = {}
    for detection in detections:
        tech_counts[detection.tech_name] = tech_counts.get(detection.tech_name, 0) + 1
    return tech_counts


def group_by_category(detections):
    categories = {}
    for detection in detections:
        if detection.category not in categories:
            categories[detection.category] = []
        categories[detection.category].append(detection)
    return categories


def finding_rows(findings):
    rows = []
    for finding in findings:
        row = (finding.detection.tech_name, finding.detection.version, finding.severity)
        rows.append(row)
    return rows


def split_first(items):
    if len(items) == 0:
        return None, []
    first, *remaining = items
    return first, remaining


def known_version_detections(detections):
    return [detection for detection in detections if detection.version is not None]


def tech_names_of_target(detections, target_id):
    return {detection.tech_name for detection in detections if detection.target_id == target_id}


def endpoint_index(target):
    return {endpoint.endpoint_id: endpoint for endpoint in target.endpoints}


def compare_targets(tech_names_a, tech_names_b):
    common = tech_names_a & tech_names_b
    only_in_a = tech_names_a - tech_names_b
    return common, only_in_a


def build_endpoint_queue(target):
    queue = deque()
    for endpoint in target.endpoints:
        queue.append(endpoint)
    return queue


def next_endpoint(queue):
    if len(queue) == 0:
        return None
    return queue.popleft()


def build_priority_queue(findings):
    # severity 1 comes out first; the counter keeps the original order when severity is equal,
    # so Python never needs to compare two RiskFinding objects
    heap = []
    counter = 0
    for finding in findings:
        heapq.heappush(heap, (finding.severity, counter, finding))
        counter += 1
    return heap


def next_finding(heap):
    if len(heap) == 0:
        return None
    severity, counter, finding = heapq.heappop(heap)
    return finding


def severity_key(finding):
    return finding.severity


def sort_by_severity(findings):
    return sorted(findings, key=severity_key)


def sort_targets_by_size(targets):
    return sorted(targets, key=lambda target: len(target), reverse=True)


def sort_by_severity_and_name(findings):
    # lower() so "jQuery" and "PHP" are sorted like a person would expect
    return sorted(findings, key=lambda finding: (finding.severity, finding.detection.tech_name.lower()))


SEVERITY_NAMES = {1: "critical", 2: "high", 3: "medium", 4: "low"}


def count_by_severity(findings):
    counts = {}
    for severity in SEVERITY_NAMES:
        counts[severity] = 0
    for finding in findings:
        counts[finding.severity] += 1
    return counts


def tech_stack_by_target(detections):
    # target_id -> list of "name version" texts, without repeats
    stack = {}
    for detection in detections:
        version_text = detection.version if detection.version is not None else "?"
        text = f"{detection.tech_name} {version_text}"
        if detection.target_id not in stack:
            stack[detection.target_id] = []
        if text not in stack[detection.target_id]:
            stack[detection.target_id].append(text)
    return stack


def top_findings(findings, how_many):
    heap = build_priority_queue(findings)
    result = []
    while len(result) < how_many:
        finding = next_finding(heap)
        if finding is None:
            break
        result.append(finding)
    return result
