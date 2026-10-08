import unittest

from webtech_inspector.models import ScanTarget, ContentEndpoint, Detection, Insight, RiskFinding
from webtech_inspector import processing


def make_detection(target_id, tech_name, version, category="Library"):
    return Detection(f"{target_id}-{tech_name}", target_id, "E1", "S1", tech_name, category, version)


DETECTIONS = [
    make_detection("T1", "jQuery", "3.4.1"),
    make_detection("T1", "React", None, "Framework"),
    make_detection("T2", "jQuery", "3.6.0"),
    make_detection("T2", "Vue", "3.2.0", "Framework"),
]


class TestCollections(unittest.TestCase):
    def test_count_by_tech(self):
        counts = processing.count_by_tech(DETECTIONS)
        self.assertEqual(counts["jQuery"], 2)
        self.assertEqual(counts.get("Angular", 0), 0)
        self.assertEqual(processing.count_by_tech([]), {})

    def test_group_by_category(self):
        groups = processing.group_by_category(DETECTIONS)
        self.assertEqual(len(groups["Library"]), 2)
        self.assertEqual(len(groups["Framework"]), 2)

    def test_finding_rows(self):
        insight = Insight("I1", "jQuery", ["3.4.1"], 2, "d", "r")
        rows = processing.finding_rows([RiskFinding(DETECTIONS[0], insight)])
        self.assertEqual(rows, [("jQuery", "3.4.1", 2)])

    def test_split_first(self):
        self.assertEqual(processing.split_first([1, 2, 3]), (1, [2, 3]))
        self.assertEqual(processing.split_first([1]), (1, []))
        self.assertEqual(processing.split_first([]), (None, []))

    def test_known_versions(self):
        self.assertEqual(len(processing.known_version_detections(DETECTIONS)), 3)
        self.assertEqual(processing.known_version_detections([]), [])

    def test_compare_targets(self):
        first = processing.tech_names_of_target(DETECTIONS, "T1")
        second = processing.tech_names_of_target(DETECTIONS, "T2")
        common, only_first = processing.compare_targets(first, second)
        self.assertEqual(common, {"jQuery"})
        self.assertEqual(only_first, {"React"})
        self.assertEqual(processing.tech_names_of_target(DETECTIONS, "T9"), set())

    def test_endpoint_index(self):
        target = ScanTarget("T1", "https://a.example.test")
        target.add_endpoint(ContentEndpoint("E1", "", "home", "/", 200, "HTML"))
        index = processing.endpoint_index(target)
        self.assertEqual(list(index.keys()), ["E1"])
        self.assertEqual(processing.endpoint_index(ScanTarget("T2", "u")), {})


def make_finding(tech_name, severity):
    detection = make_detection("T1", tech_name, "1.0")
    insight = Insight(f"I-{tech_name}", tech_name, ["1.0"], severity, "d", "r")
    return RiskFinding(detection, insight)


class TestQueues(unittest.TestCase):
    def test_fifo_order(self):
        target = ScanTarget("T1", "https://a.example.test")
        for endpoint_id in ["E1", "E2", "E3"]:
            target.add_endpoint(ContentEndpoint(endpoint_id, "", "page", "/", 200, "HTML"))

        queue = processing.build_endpoint_queue(target)
        order = []
        endpoint = processing.next_endpoint(queue)
        while endpoint is not None:
            order.append(endpoint.endpoint_id)
            endpoint = processing.next_endpoint(queue)

        self.assertEqual(order, ["E1", "E2", "E3"])
        self.assertIsNone(processing.next_endpoint(queue))

    def test_heap_order_with_ties(self):
        findings = [make_finding("A", 3), make_finding("B", 1), make_finding("C", 2),
                    make_finding("D", 1), make_finding("E", 3)]
        heap = processing.build_priority_queue(findings)

        order = []
        finding = processing.next_finding(heap)
        while finding is not None:
            order.append(finding.detection.tech_name)
            finding = processing.next_finding(heap)

        # same severity keeps the order they were added (B before D, A before E)
        self.assertEqual(order, ["B", "D", "C", "A", "E"])

    def test_empty_queue(self):
        queue = processing.build_endpoint_queue(ScanTarget("T1", "u"))
        self.assertIsNone(processing.next_endpoint(queue))

    def test_empty_heap(self):
        heap = processing.build_priority_queue([])
        self.assertIsNone(processing.next_finding(heap))


class TestSorting(unittest.TestCase):
    def test_sort_by_severity(self):
        findings = [make_finding("A", 3), make_finding("B", 1), make_finding("C", 2)]
        severities = [finding.severity for finding in processing.sort_by_severity(findings)]
        self.assertEqual(severities, [1, 2, 3])

    def test_sort_by_two_fields(self):
        findings = [make_finding("Vue", 2), make_finding("Angular", 2), make_finding("React", 1)]
        names = [finding.detection.tech_name for finding in processing.sort_by_severity_and_name(findings)]
        self.assertEqual(names, ["React", "Angular", "Vue"])

    def test_sort_ignores_case(self):
        findings = [make_finding("PHP", 2), make_finding("jQuery", 2), make_finding("Express", 2)]
        names = [finding.detection.tech_name for finding in processing.sort_by_severity_and_name(findings)]
        self.assertEqual(names, ["Express", "jQuery", "PHP"])

    def test_sort_is_stable_on_ties(self):
        first = make_finding("A", 2)
        second = make_finding("B", 2)
        self.assertEqual(processing.sort_by_severity([first, second]), [first, second])

    def test_comprehensions_with_empty_input(self):
        self.assertEqual(processing.tech_names_of_target([], "T1"), set())
        self.assertEqual(processing.finding_rows([]), [])
        self.assertEqual(processing.group_by_category([]), {})

    def test_set_ignores_duplicates(self):
        detections = [make_detection("T1", "jQuery", "1"), make_detection("T1", "jQuery", "2")]
        self.assertEqual(processing.tech_names_of_target(detections, "T1"), {"jQuery"})

    def test_sort_targets_by_size(self):
        small = ScanTarget("T1", "u1")
        big = ScanTarget("T2", "u2")
        big.add_endpoint(ContentEndpoint("E1", "", "page", "/", 200, "HTML"))
        result = processing.sort_targets_by_size([small, big])
        self.assertEqual(result[0].target_id, "T2")

    def test_sort_empty(self):
        self.assertEqual(processing.sort_by_severity([]), [])


if __name__ == "__main__":
    unittest.main()
