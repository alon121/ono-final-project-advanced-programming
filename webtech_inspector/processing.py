import heapq
from collections import deque


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
    return sorted(findings, key=lambda finding: (finding.severity, finding.detection.tech_name))
