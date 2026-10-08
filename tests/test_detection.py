import unittest

from webtech_inspector.models import ScanTarget, ContentEndpoint, MetaDataEndpoint
from webtech_inspector.repository import load_targets, load_signatures
from webtech_inspector.detection import detect_technologies


def make_target(*endpoints):
    target = ScanTarget("T1", "https://a.example.test")
    for endpoint in endpoints:
        target.add_endpoint(endpoint)
    return target


def find(detections, tech_name):
    for detection in detections:
        if detection.tech_name == tech_name:
            return detection
    return None


class TestDetection(unittest.TestCase):
    def setUp(self):
        self.signatures = load_signatures()

    def test_html(self):
        page = ContentEndpoint("E1", "<script src='jquery-3.4.1.min.js'></script>", "home", "/", 200, "HTML")
        detections, warnings = detect_technologies(make_target(page), self.signatures)
        jquery = find(detections, "jQuery")
        self.assertEqual(jquery.version, "3.4.1")
        self.assertEqual(jquery.target_id, "T1")
        self.assertEqual(jquery.endpoint_id, "E1")
        self.assertEqual(warnings, [])

    def test_js_file(self):
        bundle = ContentEndpoint("E1", "/*! jQuery v3.6.0 */", "bundle", "/app.js", 200, "JS")
        detections, _ = detect_technologies(make_target(bundle), self.signatures)
        self.assertEqual(find(detections, "jQuery").version, "3.6.0")

    def test_package_json(self):
        package = ContentEndpoint("E1", '{"dependencies": {"react": "17.0.2", "express": "^4.18.2"}}',
                                  "package.json", "/package.json", 200, "JSON")
        detections, _ = detect_technologies(make_target(package), self.signatures)
        self.assertEqual(find(detections, "React").version, "17.0.2")
        self.assertIsNone(find(detections, "Express").version)

    def test_no_match(self):
        page = ContentEndpoint("E1", "<p>hello</p>", "home", "/", 200, "HTML")
        detections, warnings = detect_technologies(make_target(page), self.signatures)
        self.assertEqual(detections, [])
        self.assertEqual(warnings, [])

    def test_many_signatures_one_endpoint(self):
        headers = MetaDataEndpoint("E1", "Server: nginx/1.18.0\nX-Powered-By: Express", "headers", "headers")
        detections, _ = detect_technologies(make_target(headers), self.signatures)
        names = [detection.tech_name for detection in detections]
        self.assertEqual(sorted(names), ["Express", "nginx"])

    def test_broken_json_gives_warning(self):
        package = ContentEndpoint("E1", '{"dependencies": ', "package.json", "/package.json", 200, "JSON")
        detections, warnings = detect_technologies(make_target(package), self.signatures)
        self.assertEqual(detections, [])
        self.assertGreater(len(warnings), 0)

    def test_no_duplicates(self):
        targets = load_targets()
        for target in targets.values():
            detections, _ = detect_technologies(target, self.signatures)
            ids = [detection.detection_id for detection in detections]
            self.assertEqual(len(ids), len(set(ids)))

    def test_similar_names_are_not_detected(self):
        page = ContentEndpoint("E1", "<script src='jquery-ui-1.12.1.js'></script>"
                                     "<script src='bootstrap-datepicker.js'></script>", "home", "/", 200, "HTML")
        detections, _ = detect_technologies(make_target(page), self.signatures)
        self.assertEqual(detections, [])

    def test_jquery_without_version(self):
        page = ContentEndpoint("E1", "<script src='/js/jquery.min.js'></script>", "home", "/", 200, "HTML")
        detections, _ = detect_technologies(make_target(page), self.signatures)
        self.assertIsNone(find(detections, "jQuery").version)

    def test_two_targets_same_tech_other_versions(self):
        old_page = ContentEndpoint("E1", "jquery-3.4.1.js", "home", "/", 200, "HTML")
        new_page = ContentEndpoint("E2", "jquery-3.6.0.js", "home", "/", 200, "HTML")
        old_detections, _ = detect_technologies(make_target(old_page), self.signatures)
        new_detections, _ = detect_technologies(make_target(new_page), self.signatures)
        self.assertEqual(find(old_detections, "jQuery").version, "3.4.1")
        self.assertEqual(find(new_detections, "jQuery").version, "3.6.0")

    def test_one_warning_per_broken_file(self):
        package = ContentEndpoint("E1", "{oops", "package.json", "/package.json", 200, "JSON")
        _, warnings = detect_technologies(make_target(package), self.signatures)
        self.assertEqual(len(warnings), 1)

    def test_empty_target(self):
        detections, warnings = detect_technologies(make_target(), self.signatures)
        self.assertEqual(detections, [])


if __name__ == "__main__":
    unittest.main()
