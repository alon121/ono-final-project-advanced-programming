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


if __name__ == "__main__":
    unittest.main()
