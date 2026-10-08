import unittest

from webtech_inspector.models import Detection, Insight
from webtech_inspector.detection import match_insights, find_manual_checks

JQUERY_RULE = Insight("I1", "jQuery", ["3.4.0", "3.4.1"], 2, "old jQuery", "upgrade", " cve-0000-0001 ")
LODASH_RULE = Insight("I2", "Lodash", ["4.17.15"], 1, "old Lodash", "upgrade")


def make_detection(tech_name, version):
    return Detection("D1", "T1", "E1", "S1", tech_name, "Library", version)


class TestInsight(unittest.TestCase):
    def test_exact_match(self):
        self.assertTrue(JQUERY_RULE.applies_to(make_detection("jQuery", "3.4.1")))

    def test_other_version(self):
        self.assertFalse(JQUERY_RULE.applies_to(make_detection("jQuery", "3.6.0")))

    def test_unknown_version(self):
        self.assertFalse(JQUERY_RULE.applies_to(make_detection("jQuery", None)))

    def test_other_tech(self):
        self.assertFalse(JQUERY_RULE.applies_to(make_detection("React", "3.4.1")))

    def test_is_critical(self):
        self.assertTrue(LODASH_RULE.is_critical)
        self.assertFalse(JQUERY_RULE.is_critical)

    def test_cve_is_optional_and_normalized(self):
        self.assertIsNone(LODASH_RULE.cve_id)
        self.assertEqual(JQUERY_RULE.cve_id, "CVE-0000-0001")

    def test_severity_range(self):
        for good in [1, 2, 3, 4]:
            Insight("I9", "X", ["1.0"], good, "d", "r")
        for bad in [0, 5, "2", None]:
            with self.assertRaises(ValueError):
                Insight("I9", "X", ["1.0"], bad, "d", "r")

    def test_missing_recommendation(self):
        with self.assertRaises(ValueError):
            Insight("I9", "X", ["1.0"], 2, "d", "")


class TestMatching(unittest.TestCase):
    def test_findings(self):
        detections = [make_detection("jQuery", "3.4.1"), make_detection("jQuery", "3.6.0"),
                      make_detection("Lodash", "4.17.15"), make_detection("Vue", "3.2.0")]
        findings = match_insights(detections, [JQUERY_RULE, LODASH_RULE])
        self.assertEqual(len(findings), 2)
        self.assertEqual(findings[0].insight.insight_id, "I1")
        self.assertEqual(findings[0].target_id, "T1")
        self.assertEqual(findings[1].severity, 1)

    def test_nothing_to_match(self):
        self.assertEqual(match_insights([], [JQUERY_RULE]), [])
        self.assertEqual(match_insights([make_detection("jQuery", "3.4.1")], []), [])

    def test_manual_checks(self):
        detections = [make_detection("jQuery", None), make_detection("Vue", None),
                      make_detection("jQuery", "3.4.1")]
        manual = find_manual_checks(detections, [JQUERY_RULE])
        self.assertEqual(len(manual), 1)
        self.assertEqual(manual[0].tech_name, "jQuery")


if __name__ == "__main__":
    unittest.main()
