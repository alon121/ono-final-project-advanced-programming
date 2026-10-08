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
