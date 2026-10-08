class EndpointCollection:
    def __init__(self, endpoints):
        self.endpoints = list(endpoints)

    def __iter__(self):
        # a new iterator every time, so two loops do not share the same position
        return EndpointIterator(self.endpoints)

    def __len__(self):
        return len(self.endpoints)


class EndpointIterator:
    def __init__(self, endpoints):
        self.endpoints = endpoints
        self.index = 0

    def __iter__(self):
        return self

    def __next__(self):
        if self.index >= len(self.endpoints):
            raise StopIteration
        endpoint = self.endpoints[self.index]
        self.index += 1
        return endpoint
