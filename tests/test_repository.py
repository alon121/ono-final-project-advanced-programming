import json
import os
import tempfile
import unittest

from webtech_inspector.repository import load_targets, load_signatures, load_insights

GOOD_LINE = {"target_id": "T1", "target_uri": "https://a.example.test", "endpoint_id": "E1",
             "endpoint_type": "content", "source_name": "homepage", "path": "/",
             "status_code": 200, "content_type": "HTML", "raw_content": "<html></html>"}


def make_line(**changes):
    record = dict(GOOD_LINE)
    record.update(changes)
    return json.dumps(record)


class TempFileTestCase(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.folder.cleanup()

    def write_file(self, text, name="data.jsonl"):
        path = os.path.join(self.folder.name, name)
        with open(path, "w", encoding="utf-8") as file:
            file.write(text)
        return path


class TestRealData(unittest.TestCase):
    def test_sample_data(self):
        targets = load_targets()
        endpoint_count = 0
        for target in targets.values():
            endpoint_count += len(target)
        self.assertGreaterEqual(endpoint_count, 15)

    def test_load_twice_gives_same_result(self):
        first = load_targets()
        second = load_targets()
        self.assertEqual(len(first), len(second))
        self.assertIsNot(first["T001"], second["T001"])
        self.assertEqual(len(first["T001"]), len(second["T001"]))

    def test_signatures_and_insights(self):
        self.assertGreaterEqual(len(load_signatures()), 5)
        self.assertGreaterEqual(len(load_insights()), 5)


class TestBadJsonl(TempFileTestCase):
    def check_error(self, text, expected_words):
        path = self.write_file(text)
        with self.assertRaises(ValueError) as context:
            load_targets(path)
        for word in expected_words:
            self.assertIn(word, str(context.exception))

    def test_good_file_with_empty_line(self):
        path = self.write_file(make_line() + "\n\n" + make_line(endpoint_id="E2") + "\n")
        self.assertEqual(len(load_targets(path)["T1"]), 2)

    def test_broken_json(self):
        self.check_error(make_line() + "\n{bad json\n", ["line 2", "bad JSON"])

    def test_missing_field(self):
        record = dict(GOOD_LINE)
        del record["path"]
        self.check_error(json.dumps(record), ["line 1", "path"])

    def test_missing_target(self):
        record = dict(GOOD_LINE)
        del record["target_id"]
        self.check_error(json.dumps(record), ["line 1", "target_id"])

    def test_wrong_type(self):
        self.check_error(make_line(status_code="200"), ["line 1", "status_code"])

    def test_not_an_object(self):
        self.check_error("[1, 2, 3]\n", ["line 1"])
        self.check_error("5\n", ["line 1"])

    def test_unknown_endpoint_type(self):
        self.check_error(make_line(endpoint_type="video"), ["line 1", "video"])

    def test_duplicate_endpoint(self):
        self.check_error(make_line() + "\n" + make_line(target_id="T2", target_uri="https://b.example.test"),
                         ["line 2", "duplicate", "E1"])

    def test_same_target_other_uri(self):
        self.check_error(make_line() + "\n" + make_line(endpoint_id="E2", target_uri="https://other.example.test"),
                         ["line 2", "T1"])

    def test_file_not_found(self):
        with self.assertRaises(FileNotFoundError):
            load_targets(os.path.join(self.folder.name, "missing.jsonl"))


class TestBadJsonFiles(TempFileTestCase):
    def test_bad_signature_regex(self):
        path = self.write_file(json.dumps([{"signature_id": "S1", "kind": "regex", "tech_name": "X",
                                            "category": "Y", "match_pattern": "a["}]), "patterns.json")
        with self.assertRaises(ValueError):
            load_signatures(path)

    def test_duplicate_signature(self):
        item = {"signature_id": "S1", "kind": "package", "tech_name": "React",
                "category": "JavaScript Framework", "package_name": "react"}
        path = self.write_file(json.dumps([item, item]), "patterns.json")
        with self.assertRaises(ValueError):
            load_signatures(path)

    def test_missing_insight_field(self):
        path = self.write_file(json.dumps([{"insight_id": "I1", "tech_name": "X"}]), "insights.json")
        with self.assertRaises(ValueError) as context:
            load_insights(path)
        self.assertIn("missing field", str(context.exception))

    def test_broken_json_file(self):
        path = self.write_file("[{", "insights.json")
        with self.assertRaises(ValueError):
            load_insights(path)

    def test_not_a_list(self):
        path = self.write_file("{}", "insights.json")
        with self.assertRaises(ValueError):
            load_insights(path)


if __name__ == "__main__":
    unittest.main()
