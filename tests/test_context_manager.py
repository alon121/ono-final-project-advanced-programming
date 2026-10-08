import unittest

from webtech_inspector.models import ScanTarget
from webtech_inspector.context_managers import AnalysisSession


class TestAnalysisSession(unittest.TestCase):
    def setUp(self):
        self.target = ScanTarget("T1", "https://a.example.test")

    def test_normal_run(self):
        with AnalysisSession(self.target) as target:
            self.assertIs(target, self.target)
            self.assertEqual(target.status, "processing")
        self.assertEqual(self.target.status, "idle")

    def test_error_is_not_hidden_and_status_comes_back(self):
        with self.assertRaises(ValueError):
            with AnalysisSession(self.target):
                raise ValueError("boom")
        self.assertEqual(self.target.status, "idle")

    def test_other_previous_status(self):
        self.target.status = "done"
        with AnalysisSession(self.target):
            pass
        self.assertEqual(self.target.status, "done")

    def test_run_twice(self):
        with AnalysisSession(self.target):
            pass
        with AnalysisSession(self.target):
            self.assertEqual(self.target.status, "processing")
        self.assertEqual(self.target.status, "idle")

    def test_cannot_start_twice_at_the_same_time(self):
        with AnalysisSession(self.target):
            with self.assertRaises(RuntimeError):
                with AnalysisSession(self.target):
                    pass
            self.assertEqual(self.target.status, "processing")
        self.assertEqual(self.target.status, "idle")

    def test_bad_status(self):
        with self.assertRaises(ValueError):
            self.target.status = "running"


if __name__ == "__main__":
    unittest.main()
