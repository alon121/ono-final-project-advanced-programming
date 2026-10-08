from webtech_inspector.models import Detection


def detect_technologies(target, signatures):
    detections = []
    warnings = []
    seen = set()

    for endpoint in target.endpoints:
        for signature in signatures:
            # a broken file should not stop the whole scan, so we save a warning and move on
            try:
                if not signature.match(endpoint):
                    continue
                version = signature.extract_version(endpoint)
            except ValueError as error:
                warnings.append(f"{signature.signature_id} on {endpoint.endpoint_id}: {error}")
                continue

            key = (endpoint.endpoint_id, signature.signature_id, version)
            if key in seen:
                continue
            seen.add(key)

            detection_id = f"{target.target_id}-{endpoint.endpoint_id}-{signature.signature_id}"
            detection = Detection(detection_id, target.target_id, endpoint.endpoint_id,
                                  signature.signature_id, signature.tech_name, signature.category, version)
            detections.append(detection)

    return detections, warnings
