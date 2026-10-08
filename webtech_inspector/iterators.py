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


def iter_urgent_findings(findings):
    # urgent = severity 1 (critical) or 2 (high)
    for finding in findings:
        if finding.severity <= 2:
            yield finding


def iter_with_log(detections):
    # prints every item when it is really read, so we can see the pipeline is lazy
    for detection in detections:
        print(f"      (reading {detection.detection_id})")
        yield detection


def tech_version_pipeline(detections, category):
    # nothing runs here - each step only describes the work.
    # the work starts when someone asks for the next item (next / for / islice)
    in_category = (detection for detection in detections if detection.category == category)
    with_version = (detection for detection in in_category if detection.version is not None)
    tech_and_version = ((detection.tech_name, detection.version) for detection in with_version)
    return tech_and_version
