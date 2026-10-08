import json
import re
from abc import ABC, abstractmethod

VALID_CONTENT_TYPES = ["HTML", "JSON", "JS", "CSS"]
VALID_STATUSES = ["idle", "processing", "done"]


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
        self.status = "idle"

    @property
    def status(self):
        return self._status

    @status.setter
    def status(self, new_status):
        if new_status not in VALID_STATUSES:
            raise ValueError(f"status must be one of {VALID_STATUSES}, got {new_status!r}")
        self._status = new_status

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
    def __init__(self, insight_id, tech_name, affected_versions, severity, description, recommendation, cve_id=None):
        check_not_empty(insight_id, "insight_id")
        check_not_empty(tech_name, "tech_name")
        check_not_empty(recommendation, "recommendation")
        if not isinstance(severity, int) or severity < 1 or severity > 4:
            raise ValueError(f"severity must be a number between 1 and 4, got {severity!r}")
        if not isinstance(affected_versions, list) or len(affected_versions) == 0:
            raise ValueError(f"Insight {insight_id} needs a non-empty list of affected_versions")

        self.insight_id = insight_id
        self.tech_name = tech_name
        self.affected_versions = affected_versions
        self.severity = severity
        self.description = description
        self.recommendation = recommendation
        self.cve_id = Insight.normalize_cve(cve_id)

    @property
    def is_critical(self):
        return self.severity == 1

    def applies_to(self, detection):
        # only exact versions match; an unknown version (None) never creates a finding
        if detection.tech_name != self.tech_name:
            return False
        if detection.version is None:
            return False
        return detection.version in self.affected_versions

    @staticmethod
    def normalize_cve(cve_id):
        if cve_id is None:
            return None
        return cve_id.strip().upper()

    @classmethod
    def from_dict(cls, data):
        return cls(
            data["insight_id"],
            data["tech_name"],
            data["affected_versions"],
            data["severity"],
            data["description"],
            data["recommendation"],
            data.get("cve_id"),
        )

    def __str__(self):
        versions = ", ".join(self.affected_versions)
        return f"{self.insight_id}: {self.tech_name} {versions} (severity {self.severity})"

    def __repr__(self):
        return f"Insight('{self.insight_id}', '{self.tech_name}', {self.severity})"


class RiskFinding:
    # a possible risk: a detection that matched a local synthetic rule, not a verified vulnerability
    def __init__(self, detection, insight):
        self.detection = detection
        self.insight = insight
        self.target_id = detection.target_id
        self.severity = insight.severity

    def __str__(self):
        return (f"[severity {self.severity}] {self.detection.tech_name} {self.detection.version} "
                f"in {self.target_id}/{self.detection.endpoint_id} - rule {self.insight.insight_id}")

    def __repr__(self):
        return f"RiskFinding('{self.detection.detection_id}', '{self.insight.insight_id}')"


class Signature(ABC):
    def __init__(self, signature_id, tech_name, category):
        check_not_empty(signature_id, "signature_id")
        check_not_empty(tech_name, "tech_name")
        self.signature_id = signature_id
        self.tech_name = tech_name
        self.category = category

    @abstractmethod
    def match(self, endpoint):
        pass

    @abstractmethod
    def extract_version(self, endpoint):
        pass

    def __str__(self):
        return f"{self.signature_id}: {self.tech_name} ({self.category})"


class RegexSignature(Signature):
    def __init__(self, signature_id, tech_name, category, match_pattern, version_pattern=None):
        super().__init__(signature_id, tech_name, category)
        check_regex(match_pattern, signature_id)
        if version_pattern is not None:
            check_regex(version_pattern, signature_id)
        self.match_pattern = match_pattern
        self.version_pattern = version_pattern

    def match(self, endpoint):
        text = endpoint.get_searchable_content()
        return re.search(self.match_pattern, text, re.IGNORECASE) is not None

    def extract_version(self, endpoint):
        if self.version_pattern is None:
            return None
        found = re.search(self.version_pattern, endpoint.get_searchable_content(), re.IGNORECASE)
        if found is None:
            return None
        return found.group(1)

    def __repr__(self):
        return f"RegexSignature('{self.signature_id}', '{self.tech_name}')"


class PackageSignature(Signature):
    def __init__(self, signature_id, tech_name, category, package_name):
        super().__init__(signature_id, tech_name, category)
        check_not_empty(package_name, "package_name")
        self.package_name = package_name

    def read_packages(self, endpoint):
        # only JSON files are package files, HTML pages are skipped
        if getattr(endpoint, "content_type", None) != "JSON":
            return {}
        try:
            data = json.loads(endpoint.raw_content)
        except json.JSONDecodeError as error:
            raise ValueError(f"Endpoint {endpoint.endpoint_id} has broken JSON: {error}")

        packages = {}
        packages.update(data.get("dependencies", {}))
        packages.update(data.get("devDependencies", {}))
        return packages

    def match(self, endpoint):
        return self.package_name in self.read_packages(endpoint)

    def extract_version(self, endpoint):
        version_text = self.read_packages(endpoint).get(self.package_name)
        if version_text is None:
            return None
        # "^17.0.2" or "~4.18.2" is a range, not the installed version, so we treat it as unknown
        if re.fullmatch(r"[0-9]+(\.[0-9]+)*", version_text) is None:
            return None
        return version_text

    def __repr__(self):
        return f"PackageSignature('{self.signature_id}', '{self.package_name}')"


def check_regex(pattern, signature_id):
    try:
        re.compile(pattern)
    except re.error as error:
        raise ValueError(f"Signature {signature_id} has a bad regex '{pattern}': {error}")


def signature_from_dict(data):
    if data["kind"] == "regex":
        return RegexSignature(
            data["signature_id"],
            data["tech_name"],
            data["category"],
            data["match_pattern"],
            data.get("version_pattern"),
        )
    if data["kind"] == "package":
        return PackageSignature(
            data["signature_id"],
            data["tech_name"],
            data["category"],
            data["package_name"],
        )
    raise ValueError(f"Unknown signature kind: {data['kind']}")
