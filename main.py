from webtech_inspector.models import ScanTarget, ContentEndpoint, MetaDataEndpoint
from webtech_inspector.models import RegexSignature, PackageSignature
from webtech_inspector.repository import load_targets, load_signatures, load_insights
from webtech_inspector.detection import detect_technologies, match_insights, find_manual_checks
from webtech_inspector import processing


def demo_models():
    print("=== Models demo ===")
    target = ScanTarget("T001", "https://demo.example.test")

    homepage = ContentEndpoint("E001", "<script src='jquery-3.4.1.min.js'></script>", "homepage", "/", 200, "HTML")
    headers = MetaDataEndpoint("E002", "X-Powered-By: Express", "headers", "headers")
    target.add_endpoint(homepage)
    target.add_endpoint(headers)

    print(target)
    print(repr(target))
    print("Endpoints:", target.endpoints)
    print("Homepage successful?", homepage.is_successful)

    print("Find E002:", target.find_endpoint("E002"))
    print("Find E999:", target.find_endpoint("E999"))

    try:
        target.add_endpoint(ContentEndpoint("E001", "", "copy", "/", 200, "HTML"))
    except ValueError as error:
        print("Error:", error)

    try:
        ContentEndpoint("E003", "", "bad", "/", 999, "HTML")
    except ValueError as error:
        print("Error:", error)

    print("Remove E002:", target.remove_endpoint("E002"))
    print("Remove E002 again:", target.remove_endpoint("E002"))
    print("Endpoints left:", len(target))


def demo_signatures():
    print("\n=== Signatures demo (polymorphism) ===")
    signatures = [
        RegexSignature("S001", "jQuery", "JavaScript Library",
                       r"jquery[-.]?[0-9]", r"jquery[-.]([0-9]+\.[0-9]+\.[0-9]+)"),
        RegexSignature("S002", "Express", "Web Server", r"x-powered-by:\s*express"),
        PackageSignature("S003", "React", "JavaScript Framework", "react"),
        PackageSignature("S004", "Express", "Web Server", "express"),
    ]

    endpoints = [
        ContentEndpoint("E001", "<script src='jquery-3.4.1.min.js'></script>", "homepage", "/", 200, "HTML"),
        ContentEndpoint("E002", '{"dependencies": {"react": "17.0.2", "express": "^4.18.2"}}',
                        "package.json", "/package.json", 200, "JSON"),
        MetaDataEndpoint("E003", "X-Powered-By: Express", "headers", "headers"),
    ]

    # one loop for all signature types - no check of which class it is
    for endpoint in endpoints:
        for signature in signatures:
            if signature.match(endpoint):
                version = signature.extract_version(endpoint)
                print(f"{endpoint.endpoint_id}: {signature.tech_name} version={version} (by {signature.signature_id})")

    try:
        RegexSignature("S999", "Broken", "Test", "jquery[")
    except ValueError as error:
        print("Error:", error)


def demo_loading():
    print("\n=== Loading local data ===")
    target_lookup = load_targets()
    signatures = load_signatures()
    insights = load_insights()

    endpoint_count = 0
    for target in target_lookup.values():
        endpoint_count += len(target)
        print(target)

    print(f"Loaded {len(target_lookup)} targets, {endpoint_count} endpoints, "
          f"{len(signatures)} signatures, {len(insights)} insights")
    print("Lookup T003:", target_lookup.get("T003"))
    print("Lookup T999:", target_lookup.get("T999"))
    return target_lookup, signatures, insights


def demo_detection(target_lookup, signatures):
    print("\n=== Detection ===")
    all_detections = []
    for target in target_lookup.values():
        detections, warnings = detect_technologies(target, signatures)
        print(f"{target.target_id}: {len(detections)} detections")
        for detection in detections:
            print("  ", detection)
        for warning in warnings:
            print("   Warning:", warning)
        all_detections.extend(detections)

    broken_target = ScanTarget("T900", "https://broken.example.test")
    broken_target.add_endpoint(ContentEndpoint("E900", '{"dependencies": ', "package.json",
                                               "/package.json", 200, "JSON"))
    detections, warnings = detect_technologies(broken_target, signatures)
    print("Broken package.json ->", len(detections), "detections,", len(warnings), "warnings")
    print("   Warning:", warnings[0])
    return all_detections


def demo_risks(detections, insights):
    print("\n=== Possible risks (local synthetic rules, not verified vulnerabilities) ===")
    findings = match_insights(detections, insights)
    for finding in findings:
        critical_text = " CRITICAL" if finding.insight.is_critical else ""
        print(f"{finding}{critical_text}")

    print("\nNeeds manual check (version unknown):")
    for detection in find_manual_checks(detections, insights):
        print("  ", detection.tech_name, "in", detection.target_id, detection.endpoint_id)

    matched_ids = set()
    for finding in findings:
        matched_ids.add(finding.detection.detection_id)

    print("\nKnown version but no matching rule (no finding):")
    for detection in detections:
        if detection.version is not None and detection.detection_id not in matched_ids:
            print("  ", detection.tech_name, detection.version)
    return findings


def demo_collections(target_lookup, detections, findings):
    print("\n=== Collections ===")

    tech_counts = processing.count_by_tech(detections)
    print("Detections per technology:")
    for tech_name, count in tech_counts.items():
        print(f"   {tech_name}: {count}")
    print("Angular count (missing key):", tech_counts.get("Angular", 0))

    rows = processing.finding_rows(findings)
    print("First finding row (tuple):", rows[0])
    first, remaining = processing.split_first(rows)
    print(f"First: {first}, remaining rows: {len(remaining)}")
    print("split_first on empty list:", processing.split_first([]))

    known = processing.known_version_detections(detections)
    print(f"Known versions: {len(known)} of {len(detections)}")

    demo_tech = processing.tech_names_of_target(detections, "T001")
    portal_tech = processing.tech_names_of_target(detections, "T002")
    common, only_demo = processing.compare_targets(demo_tech, portal_tech)
    print("T001 tech:", sorted(demo_tech))
    print("T002 tech:", sorted(portal_tech))
    print("Common:", sorted(common), "| only in T001:", sorted(only_demo))

    demo_tech.add("React")
    print("After add('React') again, size is still:", len(demo_tech))
    demo_tech.discard("Angular")
    print("discard('Angular') on a missing item works without error")
    print("'jQuery' in T001?", "jQuery" in demo_tech)

    index = processing.endpoint_index(target_lookup["T001"])
    print("T001 endpoint index keys:", list(index.keys()))

    print("Detections by category:")
    for category, category_detections in processing.group_by_category(detections).items():
        print(f"   {category}: {len(category_detections)}")


def demo_queues_and_sorting(target_lookup, findings):
    print("\n=== FIFO queue (deque) ===")
    queue = processing.build_endpoint_queue(target_lookup["T001"])
    print("Endpoints in queue:", len(queue))
    endpoint = processing.next_endpoint(queue)
    while endpoint is not None:
        print("   Processing", endpoint)
        endpoint = processing.next_endpoint(queue)
    print("Queue is empty, next_endpoint returns:", processing.next_endpoint(queue))

    print("\n=== Priority queue (heapq) ===")
    heap = processing.build_priority_queue(findings)
    finding = processing.next_finding(heap)
    while finding is not None:
        print("   Handle:", finding)
        finding = processing.next_finding(heap)
    print("Heap is empty, next_finding returns:", processing.next_finding(heap))

    print("\n=== Sorting ===")
    print("By severity (named function):")
    for finding in processing.sort_by_severity(findings)[:3]:
        print("  ", finding)

    print("Targets by number of endpoints (lambda):")
    for target in processing.sort_targets_by_size(target_lookup.values()):
        print(f"   {target.target_id}: {len(target)}")

    print("By severity, then tech name (two fields):")
    for finding in processing.sort_by_severity_and_name(findings):
        print("  ", finding)


def main():
    print("WebTech Inspector - Stage 1 (local synthetic data only)")
    demo_models()
    demo_signatures()
    target_lookup, signatures, insights = demo_loading()
    detections = demo_detection(target_lookup, signatures)
    findings = demo_risks(detections, insights)
    demo_collections(target_lookup, detections, findings)
    demo_queues_and_sorting(target_lookup, findings)


if __name__ == "__main__":
    main()
