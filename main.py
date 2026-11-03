import argparse
import asyncio
import threading
import time
from itertools import islice

import requests

from webtech_inspector.api_client import VulnerabilityApiClient, LocalVulnerabilityClient
from webtech_inspector.async_processing import (discover_endpoints_concurrent, discover_endpoints_sequential,
                                                scan_real_site)
from webtech_inspector.services import (RiskScoringService, SeverityFirstStrategy, ExposureWeightedStrategy,
                                        filter_cves_by_min_severity, sort_cves_by_severity)
from webtech_inspector.threaded_processing import (ActiveSessionRegistry, SafeThreadedSessionRunner,
                                                   TargetAlreadyProcessingError)
from webtech_inspector.models import ScanTarget, ContentEndpoint, MetaDataEndpoint
from webtech_inspector.models import RegexSignature, PackageSignature
from webtech_inspector.repository import load_targets, load_signatures, load_insights
from webtech_inspector import processing
from webtech_inspector.iterators import EndpointCollection, iter_urgent_findings, iter_with_log
from webtech_inspector.iterators import tech_version_pipeline
from webtech_inspector.context_managers import AnalysisSession


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
        RegexSignature("S002", "Express", "Web Framework", r"x-powered-by:\s*express"),
        PackageSignature("S003", "React", "JavaScript Framework", "react"),
        PackageSignature("S004", "Express", "Web Framework", "express"),
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
        with AnalysisSession(target):
            detections, warnings = processing.detect_technologies(target, signatures)
        print(f"{target.target_id}: {len(detections)} detections")
        for detection in detections:
            print("  ", detection)
        for warning in warnings:
            print("   Warning:", warning)
        all_detections.extend(detections)

    broken_target = ScanTarget("T900", "https://broken.example.test")
    broken_target.add_endpoint(ContentEndpoint("E900", '{"dependencies": ', "package.json",
                                               "/package.json", 200, "JSON"))
    detections, warnings = processing.detect_technologies(broken_target, signatures)
    print("Broken package.json ->", len(detections), "detections,", len(warnings), "warnings")
    print("   Warning:", warnings[0])
    return all_detections


def demo_risks(detections, insights):
    print("\n=== Possible risks (local synthetic rules, not verified vulnerabilities) ===")
    findings = processing.match_insights(detections, insights)
    for finding in findings:
        critical_text = " CRITICAL" if finding.insight.is_critical else ""
        print(f"{finding}{critical_text}")

    print("\nNeeds manual check (version unknown):")
    for detection in processing.find_manual_checks(detections, insights):
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
    first, remaining = processing.split_first(rows)
    print(f"First finding row (tuple): {first}, remaining rows: {len(remaining)}")
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


def demo_iterators(target_lookup):
    print("\n=== Iterable and Iterator ===")
    collection = EndpointCollection(target_lookup["T002"].endpoints)

    first_iterator = iter(collection)
    second_iterator = iter(collection)
    print("first :", next(first_iterator).endpoint_id)
    print("first :", next(first_iterator).endpoint_id)
    print("second:", next(second_iterator).endpoint_id, "(started from the beginning)")
    print("first :", next(first_iterator).endpoint_id)

    print("A for loop on the same collection:")
    for endpoint in collection:
        print("  ", endpoint)

    empty_iterator = iter(EndpointCollection([]))
    try:
        next(empty_iterator)
    except StopIteration:
        print("Empty collection -> StopIteration")


def demo_generators(detections, findings):
    print("\n=== Generator (yield) ===")
    urgent = iter_urgent_findings(findings)
    print("Generator created:", urgent)
    print("next():", next(urgent))
    print("The rest with for:")
    for finding in urgent:
        print("  ", finding)

    try:
        next(urgent)
    except StopIteration:
        print("Generator is used up -> StopIteration")
    print("Looping again on the same generator gives:", list(urgent))
    print("A new generator starts again, first item:", next(iter_urgent_findings(findings)))

    print("\n=== Lazy pipeline ===")
    pipeline = tech_version_pipeline(iter_with_log(detections), "JavaScript Library")
    print("Pipeline created, nothing was read yet")
    print("Taking only 2 results:")
    for tech_name, version in islice(pipeline, 2):
        print(f"   -> {tech_name} {version}")
    print(f"Stopped. Only part of the {len(detections)} detections were read.")


def demo_context_manager(target_lookup, signatures):
    print("\n=== Context manager ===")
    target = target_lookup["T003"]
    print("Status before:", target.status)

    with AnalysisSession(target) as session_target:
        print("Status inside with:", session_target.status)
        detections, warnings = processing.detect_technologies(session_target, signatures)
        print("Detections found inside the session:", len(detections))
    print("Status after:", target.status)

    try:
        with AnalysisSession(target):
            print("Status inside with:", target.status)
            raise ValueError("demo error inside the analysis")
    except ValueError as error:
        print("Caught outside the with block:", error)
    print("Status after the error:", target.status)


def print_report(target_lookup, signatures, detections, findings, insights):
    print("\n" + "=" * 60)
    print("REPORT")
    print("=" * 60)

    endpoint_count = 0
    for target in target_lookup.values():
        endpoint_count += len(target)
    known = processing.known_version_detections(detections)

    print(f"Targets: {len(target_lookup)} | Endpoints: {endpoint_count} | "
          f"Signatures: {len(signatures)} | Detections: {len(detections)}")
    print(f"Known version: {len(known)} | Unknown version: {len(detections) - len(known)}")

    print("\nTech stack:")
    stack = processing.tech_stack_by_target(detections)
    for target_id, tech_list in stack.items():
        print(f"   {target_id} ({target_lookup[target_id].uri}): {', '.join(tech_list)}")

    print("\nDetections by category:")
    for category, category_detections in processing.group_by_category(detections).items():
        print(f"   {category}: {len(category_detections)}")

    print("\nPossible risks by severity:")
    for severity, count in processing.count_by_severity(findings).items():
        print(f"   {severity} ({processing.SEVERITY_NAMES[severity]}): {count}")

    print("\nTop 3 to handle first:")
    for number, finding in enumerate(processing.top_findings(findings, 3), start=1):
        detection = finding.detection
        print(f"   {number}. {detection.tech_name} {detection.version} - "
              f"{detection.target_id}/{detection.endpoint_id} - rule {finding.insight.insight_id}")
        print(f"      Recommendation: {finding.insight.recommendation}")

    manual_checks = processing.find_manual_checks(detections, insights)
    print(f"\nNeeds manual check (version unknown): {len(manual_checks)}")

    print("\nNote: this report uses synthetic data and local matching rules only.")
    print("It is not a penetration test and no vulnerability was verified on a network.")


def demo_discovery(live, signatures, insights):
    print("\n=== Phase 2: discover 3 paths and check vulnerabilities ===")
    local_client = LocalVulnerabilityClient(insights)
    if live:
        client = VulnerabilityApiClient()
    else:
        client = local_client

    start = time.perf_counter()
    try:
        endpoints = asyncio.run(discover_endpoints_concurrent(
            ScanTarget("W001", "https://web.example.test"), client, signatures))
    except requests.exceptions.RequestException as error:
        # the API is not reachable, so we keep working with the local rules
        print(f"Live API failed ({error}). Falling back to local data.")
        client = local_client
        endpoints = asyncio.run(discover_endpoints_concurrent(
            ScanTarget("W001", "https://web.example.test"), client, signatures))
    concurrent_time = time.perf_counter() - start

    start = time.perf_counter()
    discover_endpoints_sequential(ScanTarget("W002", "https://web.example.test"), client, signatures)
    sequential_time = time.perf_counter() - start
    print(f"Concurrent: {concurrent_time:.3f}s | Sequential: {sequential_time:.3f}s")

    for endpoint in endpoints:
        print(f"   {endpoint.endpoint_id} ({endpoint.endpoint_type}): {len(endpoint.vulnerabilities)} vulnerabilities")
        for vuln in endpoint.vulnerabilities:
            print(f"      {vuln['cve_id']} severity={vuln['severity']}")
    return endpoints


def demo_strategies(endpoints):
    print("\n=== Phase 2: risk score with two strategies ===")
    for strategy in [SeverityFirstStrategy(), ExposureWeightedStrategy()]:
        service = RiskScoringService(strategy)
        print(f"   {type(strategy).__name__}: {service.evaluate_target_risk(endpoints):.1f}")

    all_vulns = []
    for endpoint in endpoints:
        all_vulns.extend(endpoint.vulnerabilities)
    urgent = filter_cves_by_min_severity(all_vulns, 2)
    print(f"   Critical or high (severity <= 2): {len(urgent)} of {len(all_vulns)}")


def demo_threads():
    print("\n=== Phase 2: two threads on the same target ===")
    runner = SafeThreadedSessionRunner(ActiveSessionRegistry())
    target = ScanTarget("W003", "https://web.example.test")

    def work(name):
        try:
            print(f"   {name}: {runner.run_session(target)}")
        except TargetAlreadyProcessingError as error:
            print(f"   {name}: blocked - {error}")

    threads = [threading.Thread(target=work, args=("thread-1",)),
               threading.Thread(target=work, args=("thread-2",))]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    print(f"   Status after both threads: {target.status}")


def scan_website(url, live):
    print(f"\n=== Scanning {url} ===")
    signatures = load_signatures()
    insights = load_insights()
    local_client = LocalVulnerabilityClient(insights)
    if live:
        client = VulnerabilityApiClient()
    else:
        client = local_client

    target = ScanTarget("LIVE", url)
    try:
        endpoints = asyncio.run(scan_real_site(target, client, signatures))
    except requests.exceptions.RequestException as error:
        # NVD did not answer (or blocked us for too many requests), so we use the local rules
        print(f"Vulnerability API failed ({error}). Using local rules instead.")
        target = ScanTarget("LIVE", url)
        endpoints = asyncio.run(scan_real_site(target, local_client, signatures))

    if len(endpoints) == 0:
        print("Could not read the site.")
        return

    print("Pages read:")
    for endpoint in endpoints:
        print(f"   {endpoint}")

    detections, warnings = processing.detect_technologies(target, signatures)
    print("Technologies found:")
    if len(detections) == 0:
        print("   none of our signatures matched")
    for detection in detections:
        print(f"   {detection}")

    print("Vulnerabilities (most severe first):")
    all_vulns = []
    for endpoint in endpoints:
        all_vulns.extend(endpoint.vulnerabilities)
    for vuln in sort_cves_by_severity(all_vulns):
        print(f"   {vuln['cve_id']} severity={vuln['severity']} - {vuln['summary'][:80]}")
    if len(all_vulns) == 0:
        print("   none found for the detected versions")
    score = RiskScoringService(SeverityFirstStrategy()).evaluate_target_risk(endpoints)
    print(f"Risk score: {score:.1f}")


def main():
    parser = argparse.ArgumentParser(description="WebTech Inspector demo")
    parser.add_argument("--live", action="store_true", help="check vulnerabilities with the real NVD API")
    parser.add_argument("--url", help="scan a real website, for example https://example.com")
    args = parser.parse_args()

    if args.live:
        print("[LIVE API MODE] vulnerabilities come from NVD (services.nvd.nist.gov)")
    else:
        print("[OFFLINE MODE] vulnerabilities come from local synthetic rules")

    if args.url:
        if not args.url.startswith(("http://", "https://")):
            print("The url must start with http:// or https://")
            return
        scan_website(args.url, args.live)
        return

    print("WebTech Inspector - Stage 1 (local synthetic data only)")
    demo_models()
    demo_signatures()
    target_lookup, signatures, insights = demo_loading()
    detections = demo_detection(target_lookup, signatures)
    findings = demo_risks(detections, insights)
    demo_collections(target_lookup, detections, findings)
    demo_queues_and_sorting(target_lookup, findings)
    demo_iterators(target_lookup)
    demo_generators(detections, findings)
    demo_context_manager(target_lookup, signatures)
    print_report(target_lookup, signatures, detections, findings, insights)

    discovered = demo_discovery(args.live, signatures, insights)
    demo_strategies(discovered)
    demo_threads()


if __name__ == "__main__":
    main()
