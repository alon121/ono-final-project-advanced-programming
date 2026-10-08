import json
from pathlib import Path

from webtech_inspector.models import ScanTarget, ContentEndpoint, MetaDataEndpoint, Insight, signature_from_dict

PROJECT_ROOT = Path(__file__).parent.parent
DATA_FOLDER = PROJECT_ROOT / "data"

SAMPLE_DATA_FILE = DATA_FOLDER / "sample_data.jsonl"
PATTERNS_FILE = DATA_FOLDER / "patterns.json"
INSIGHTS_FILE = DATA_FOLDER / "insights.json"

COMMON_FIELDS = ["target_id", "target_uri", "endpoint_id", "endpoint_type", "source_name", "raw_content"]
CONTENT_FIELDS = ["path", "status_code", "content_type"]
METADATA_FIELDS = ["metadata_type"]


def check_fields(record, fields, line_number):
    if not isinstance(record, dict):
        raise ValueError(f"Line {line_number}: expected a JSON object")
    for field in fields:
        if field not in record:
            raise ValueError(f"Line {line_number}: missing field '{field}'")


def endpoint_from_record(record, line_number):
    check_fields(record, COMMON_FIELDS, line_number)

    if record["endpoint_type"] == "content":
        check_fields(record, CONTENT_FIELDS, line_number)
        return ContentEndpoint.from_dict(record)
    if record["endpoint_type"] == "metadata":
        check_fields(record, METADATA_FIELDS, line_number)
        return MetaDataEndpoint.from_dict(record)

    raise ValueError(f"Line {line_number}: unknown endpoint_type '{record['endpoint_type']}'")


def load_targets(file_path=SAMPLE_DATA_FILE):
    # each line is one endpoint; endpoints with the same target_id go to the same ScanTarget
    target_lookup = {}
    seen_endpoint_ids = set()

    with open(file_path, encoding="utf-8") as file:
        for line_number, line in enumerate(file, start=1):
            if line.strip() == "":
                continue

            try:
                record = json.loads(line)
            except json.JSONDecodeError as error:
                raise ValueError(f"{file_path} line {line_number}: bad JSON ({error})")

            try:
                endpoint = endpoint_from_record(record, line_number)
                target = target_lookup.get(record["target_id"])
                if target is None:
                    target = ScanTarget.from_dict(record)
                    target_lookup[target.target_id] = target
            except ValueError as error:
                raise ValueError(f"{file_path} line {line_number}: {error}")

            if target.uri != record["target_uri"]:
                raise ValueError(f"{file_path} line {line_number}: target {target.target_id} "
                                 f"already has uri {target.uri}, got {record['target_uri']}")

            if endpoint.endpoint_id in seen_endpoint_ids:
                raise ValueError(f"{file_path} line {line_number}: duplicate endpoint_id {endpoint.endpoint_id}")
            seen_endpoint_ids.add(endpoint.endpoint_id)

            target.add_endpoint(endpoint)

    return target_lookup


def load_json_list(file_path):
    with open(file_path, encoding="utf-8") as file:
        try:
            data = json.load(file)
        except json.JSONDecodeError as error:
            raise ValueError(f"{file_path}: bad JSON ({error})")

    if not isinstance(data, list):
        raise ValueError(f"{file_path}: expected a list of items")
    return data


def load_signatures(file_path=PATTERNS_FILE):
    signatures = []
    seen_ids = set()
    for number, item in enumerate(load_json_list(file_path), start=1):
        try:
            signature = signature_from_dict(item)
        except KeyError as error:
            raise ValueError(f"{file_path} item {number}: missing field {error}")
        except ValueError as error:
            raise ValueError(f"{file_path} item {number}: {error}")

        if signature.signature_id in seen_ids:
            raise ValueError(f"{file_path} item {number}: duplicate signature_id {signature.signature_id}")
        seen_ids.add(signature.signature_id)
        signatures.append(signature)
    return signatures


def load_insights(file_path=INSIGHTS_FILE):
    insights = []
    seen_ids = set()
    for number, item in enumerate(load_json_list(file_path), start=1):
        try:
            insight = Insight.from_dict(item)
        except KeyError as error:
            raise ValueError(f"{file_path} item {number}: missing field {error}")
        except ValueError as error:
            raise ValueError(f"{file_path} item {number}: {error}")

        if insight.insight_id in seen_ids:
            raise ValueError(f"{file_path} item {number}: duplicate insight_id {insight.insight_id}")
        seen_ids.add(insight.insight_id)
        insights.append(insight)
    return insights
