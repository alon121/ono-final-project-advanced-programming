import unittest

from webtech_inspector.models import ContentEndpoint
from webtech_inspector.iterators import EndpointCollection, EndpointIterator


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


if __name__ == "__main__":
    unittest.main()
