import unittest

from itertools import islice

from webtech_inspector.models import ContentEndpoint, Detection, Insight, RiskFinding
from webtech_inspector.iterators import EndpointCollection, EndpointIterator
from webtech_inspector.iterators import iter_urgent_findings, tech_version_pipeline


def make_endpoints(count):
    endpoints = []
    for number in range(1, count + 1):
        endpoints.append(ContentEndpoint(f"E{number}", "", "page", "/", 200, "HTML"))
    return endpoints


class TestEndpointIterator(unittest.TestCase):
    def test_two_independent_iterators(self):
        collection = EndpointCollection(make_endpoints(3))
        first = iter(collection)
        second = iter(collection)
        self.assertIsNot(first, second)

        self.assertEqual(next(first).endpoint_id, "E1")
        self.assertEqual(next(first).endpoint_id, "E2")
        self.assertEqual(next(second).endpoint_id, "E1")
        self.assertEqual(next(first).endpoint_id, "E3")

    def test_stop_iteration_at_end(self):
        iterator = iter(EndpointCollection(make_endpoints(1)))
        self.assertEqual(next(iterator).endpoint_id, "E1")
        with self.assertRaises(StopIteration):
            next(iterator)
        with self.assertRaises(StopIteration):
            next(iterator)

    def test_empty_collection(self):
        collection = EndpointCollection([])
        self.assertEqual(len(collection), 0)
        with self.assertRaises(StopIteration):
            next(iter(collection))

    def test_loop_twice(self):
        collection = EndpointCollection(make_endpoints(2))
        first_loop = [endpoint.endpoint_id for endpoint in collection]
        second_loop = [endpoint.endpoint_id for endpoint in collection]
        self.assertEqual(first_loop, ["E1", "E2"])
        self.assertEqual(second_loop, ["E1", "E2"])

    def test_iterator_returns_itself(self):
        iterator = iter(EndpointCollection(make_endpoints(1)))
        self.assertIsInstance(iterator, EndpointIterator)
        self.assertIs(iter(iterator), iterator)


def make_detection(number, category, version):
    return Detection(f"D{number}", "T1", "E1", "S1", f"Tech{number}", category, version)


def make_finding(number, severity):
    insight = Insight(f"I{number}", f"Tech{number}", ["1.0"], severity, "d", "r")
    return RiskFinding(make_detection(number, "Library", "1.0"), insight)


class CountingList:
    # a small helper that counts how many items were really read
    def __init__(self, items):
        self.items = items
        self.read_count = 0

    def __iter__(self):
        for item in self.items:
            self.read_count += 1
            yield item


class TestGenerator(unittest.TestCase):
    def test_only_urgent(self):
        findings = [make_finding(1, 1), make_finding(2, 3), make_finding(3, 2), make_finding(4, 4)]
        severities = [finding.severity for finding in iter_urgent_findings(findings)]
        self.assertEqual(severities, [1, 2])

    def test_next_then_for_then_used_up(self):
        findings = [make_finding(1, 1), make_finding(2, 2), make_finding(3, 1)]
        urgent = iter_urgent_findings(findings)
        self.assertEqual(next(urgent).insight.insight_id, "I1")
        rest = [finding.insight.insight_id for finding in urgent]
        self.assertEqual(rest, ["I2", "I3"])
        with self.assertRaises(StopIteration):
            next(urgent)
        self.assertEqual(list(urgent), [])

    def test_new_generator_starts_again(self):
        findings = [make_finding(1, 1)]
        self.assertEqual(len(list(iter_urgent_findings(findings))), 1)
        self.assertEqual(len(list(iter_urgent_findings(findings))), 1)

    def test_empty(self):
        self.assertEqual(list(iter_urgent_findings([])), [])


class TestLazyPipeline(unittest.TestCase):
    def test_result(self):
        detections = [make_detection(1, "Library", "1.0"), make_detection(2, "Server", "2.0"),
                      make_detection(3, "Library", None), make_detection(4, "Library", "4.0")]
        result = list(tech_version_pipeline(detections, "Library"))
        self.assertEqual(result, [("Tech1", "1.0"), ("Tech4", "4.0")])

    def test_nothing_is_read_before_asking(self):
        source = CountingList([make_detection(1, "Library", "1.0")])
        tech_version_pipeline(source, "Library")
        self.assertEqual(source.read_count, 0)

    def test_stops_after_two(self):
        detections = []
        for number in range(1, 11):
            detections.append(make_detection(number, "Library", "1.0"))
        source = CountingList(detections)

        first_two = list(islice(tech_version_pipeline(source, "Library"), 2))
        self.assertEqual(len(first_two), 2)
        self.assertEqual(source.read_count, 2)

    def test_pipeline_is_a_generator_not_a_list(self):
        pipeline = tech_version_pipeline([], "Library")
        self.assertNotIsInstance(pipeline, list)
        self.assertEqual(list(pipeline), [])


if __name__ == "__main__":
    unittest.main()
