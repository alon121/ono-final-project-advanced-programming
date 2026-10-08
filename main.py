from webtech_inspector.models import ScanTarget, ContentEndpoint, MetaDataEndpoint
from webtech_inspector.models import RegexSignature, PackageSignature
from webtech_inspector.repository import load_targets, load_signatures, load_insights
from webtech_inspector.detection import detect_technologies


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


def main():
    print("WebTech Inspector - Stage 1 (local synthetic data only)")
    demo_models()
    demo_signatures()
    target_lookup, signatures, insights = demo_loading()
    demo_detection(target_lookup, signatures)


if __name__ == "__main__":
    main()
