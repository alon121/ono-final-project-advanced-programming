from webtech_inspector.models import ContentEndpoint, MetaDataEndpoint


class EndpointFactory:
    # the only place that decides which Endpoint class to create from a record
    @staticmethod
    def create_endpoint(record, line_number=0):
        endpoint_type = record.get("endpoint_type")
        if endpoint_type == "content":
            return ContentEndpoint.from_dict(record)
        if endpoint_type == "metadata":
            return MetaDataEndpoint.from_dict(record)
        raise ValueError(f"Unknown endpoint_type {endpoint_type} at line {line_number}")
