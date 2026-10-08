VALID_CONTENT_TYPES = ["HTML", "JSON", "JS", "CSS"]


def check_not_empty(value, field_name):
    if not isinstance(value, str) or value.strip() == "":
        raise ValueError(f"{field_name} must be a non-empty string")


class Endpoint:
    def __init__(self, endpoint_id, raw_content, source_name):
        check_not_empty(endpoint_id, "endpoint_id")
        self.endpoint_id = endpoint_id
        self.raw_content = raw_content
        self.source_name = source_name

    def get_searchable_content(self):
        return self.raw_content

    def __str__(self):
        return f"{self.endpoint_id} ({self.source_name})"

    def __repr__(self):
        return f"Endpoint('{self.endpoint_id}', '{self.source_name}')"


class ContentEndpoint(Endpoint):
    def __init__(self, endpoint_id, raw_content, source_name, path, status_code, content_type):
        super().__init__(endpoint_id, raw_content, source_name)

        if not isinstance(status_code, int) or status_code < 100 or status_code > 599:
            raise ValueError(f"status_code must be a number between 100 and 599, got {status_code!r}")
        if content_type not in VALID_CONTENT_TYPES:
            raise ValueError(f"content_type must be one of {VALID_CONTENT_TYPES}, got {content_type}")

        self.path = path
        self.status_code = status_code
        self.content_type = content_type

    @property
    def is_successful(self):
        return 200 <= self.status_code < 300

    @classmethod
    def from_dict(cls, data):
        return cls(
            data["endpoint_id"],
            data["raw_content"],
            data["source_name"],
            data["path"],
            data["status_code"],
            data["content_type"],
        )

    def __str__(self):
        return f"{self.endpoint_id} {self.path} [{self.content_type}, {self.status_code}]"

    def __repr__(self):
        return f"ContentEndpoint('{self.endpoint_id}', '{self.path}', {self.status_code})"


class MetaDataEndpoint(Endpoint):
    def __init__(self, endpoint_id, raw_content, source_name, metadata_type):
        super().__init__(endpoint_id, raw_content, source_name)
        self.metadata_type = metadata_type

    def get_searchable_content(self):
        # headers are searched together with their type, e.g. "headers: X-Powered-By: Express"
        return f"{self.metadata_type}: {self.raw_content}"

    @classmethod
    def from_dict(cls, data):
        return cls(
            data["endpoint_id"],
            data["raw_content"],
            data["source_name"],
            data["metadata_type"],
        )

    def __str__(self):
        return f"{self.endpoint_id} metadata ({self.metadata_type})"

    def __repr__(self):
        return f"MetaDataEndpoint('{self.endpoint_id}', '{self.metadata_type}')"


class ScanTarget:
    def __init__(self, target_id, uri):
        check_not_empty(target_id, "target_id")
        check_not_empty(uri, "uri")
        self.target_id = target_id
        self.uri = uri
        self.endpoints = []

    def find_endpoint(self, endpoint_id):
        for endpoint in self.endpoints:
            if endpoint.endpoint_id == endpoint_id:
                return endpoint
        return None

    def add_endpoint(self, endpoint):
        if self.find_endpoint(endpoint.endpoint_id) is not None:
            raise ValueError(f"Endpoint {endpoint.endpoint_id} already exists in target {self.target_id}")
        self.endpoints.append(endpoint)

    def remove_endpoint(self, endpoint_id):
        endpoint = self.find_endpoint(endpoint_id)
        if endpoint is None:
            return False
        self.endpoints.remove(endpoint)
        return True

    def __len__(self):
        return len(self.endpoints)

    @classmethod
    def from_dict(cls, data):
        return cls(data["target_id"], data["target_uri"])

    def __str__(self):
        return f"Target {self.target_id} - {self.uri} ({len(self)} endpoints)"

    def __repr__(self):
        return f"ScanTarget('{self.target_id}', '{self.uri}')"


class Detection:
    def __init__(self, detection_id, target_id, endpoint_id, signature_id, tech_name, category, version=None):
        self.detection_id = detection_id
        self.target_id = target_id
        self.endpoint_id = endpoint_id
        self.signature_id = signature_id
        self.tech_name = tech_name
        self.category = category
        # None means the version is unknown
        self.version = version

    def __str__(self):
        version_text = self.version if self.version is not None else "unknown version"
        return f"{self.tech_name} {version_text} (found in {self.endpoint_id})"

    def __repr__(self):
        return f"Detection('{self.detection_id}', '{self.tech_name}', {self.version!r})"


class Insight:
    def __init__(self, insight_id, tech_name, affected_version, severity, description, recommendation, cve_id=None):
        check_not_empty(insight_id, "insight_id")
        check_not_empty(tech_name, "tech_name")
        if not isinstance(severity, int) or severity < 1 or severity > 4:
            raise ValueError(f"severity must be a number between 1 and 4, got {severity!r}")

        self.insight_id = insight_id
        self.tech_name = tech_name
        self.affected_version = affected_version
        self.severity = severity
        self.description = description
        self.recommendation = recommendation
        self.cve_id = cve_id

    @classmethod
    def from_dict(cls, data):
        return cls(
            data["insight_id"],
            data["tech_name"],
            data["affected_version"],
            data["severity"],
            data["description"],
            data["recommendation"],
            data.get("cve_id"),
        )

    def __str__(self):
        return f"{self.insight_id}: {self.tech_name} {self.affected_version} (severity {self.severity})"

    def __repr__(self):
        return f"Insight('{self.insight_id}', '{self.tech_name}', {self.severity})"
