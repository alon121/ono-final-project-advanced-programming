import unittest

from webtech_inspector.models import ScanTarget, ContentEndpoint, MetaDataEndpoint, Detection, Insight


def make_page(endpoint_id="E1", status_code=200):
    return ContentEndpoint(endpoint_id, "<html></html>", "homepage", "/", status_code, "HTML")


class TestScanTarget(unittest.TestCase):
    def test_add_find_remove(self):
        target = ScanTarget("T1", "https://a.example.test")
        target.add_endpoint(make_page("E1"))
        target.add_endpoint(MetaDataEndpoint("E2", "X-Powered-By: Express", "headers", "headers"))

        self.assertEqual(len(target), 2)
        self.assertEqual(target.find_endpoint("E2").metadata_type, "headers")
        self.assertIsNone(target.find_endpoint("E9"))
        self.assertTrue(target.remove_endpoint("E1"))
        self.assertFalse(target.remove_endpoint("E1"))
        self.assertEqual(len(target), 1)

    def test_duplicate_endpoint(self):
        target = ScanTarget("T1", "https://a.example.test")
        target.add_endpoint(make_page("E1"))
        with self.assertRaises(ValueError):
            target.add_endpoint(make_page("E1"))

    def test_empty_target(self):
        target = ScanTarget("T1", "https://a.example.test")
        self.assertEqual(len(target), 0)
        self.assertFalse(target.remove_endpoint("E1"))

    def test_empty_id(self):
        with self.assertRaises(ValueError):
            ScanTarget("", "https://a.example.test")
        with self.assertRaises(ValueError):
            ScanTarget("T1", "   ")


class TestEndpoints(unittest.TestCase):
    def test_is_successful(self):
        self.assertTrue(make_page(status_code=200).is_successful)
        self.assertFalse(make_page(status_code=404).is_successful)

    def test_bad_status_code(self):
        with self.assertRaises(ValueError):
            make_page(status_code=999)
        with self.assertRaises(ValueError):
            make_page(status_code="200")

    def test_bad_content_type(self):
        with self.assertRaises(ValueError):
            ContentEndpoint("E1", "", "page", "/", 200, "XML")

    def test_metadata_searchable_content(self):
        endpoint = MetaDataEndpoint("E1", "X-Powered-By: Express", "headers", "headers")
        self.assertEqual(endpoint.get_searchable_content(), "headers: X-Powered-By: Express")


class TestDetectionAndInsight(unittest.TestCase):
    def test_unknown_version_is_none(self):
        detection = Detection("D1", "T1", "E1", "S1", "React", "JavaScript Framework")
        self.assertIsNone(detection.version)

    def test_bad_severity(self):
        with self.assertRaises(ValueError):
            Insight("I1", "jQuery", "3.4.1", 5, "desc", "fix")
        with self.assertRaises(ValueError):
            Insight("I1", "jQuery", "3.4.1", 0, "desc", "fix")


if __name__ == "__main__":
    unittest.main()
