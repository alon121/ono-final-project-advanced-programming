import asyncio
import time

from webtech_inspector.factories import EndpointFactory

# how long one simulated web request takes (seconds)
FETCH_DELAY = 0.05

# the 3 paths we check on every target
PATHS_CONFIG = [("/", "content"), ("/robots.txt", "metadata"), ("/package.json", "content")]

# simulated answers, so the demo works without a real website
SIMULATED_PAGES = {
    "/": {"content_type": "HTML", "raw_content": "<script src='/js/jquery-3.4.1.min.js'></script>"},
    "/robots.txt": {"metadata_type": "robots", "raw_content": "User-agent: *\nDisallow: /admin"},
    "/package.json": {"content_type": "JSON", "raw_content": '{"dependencies": {"lodash": "4.17.15"}}'},
}


def build_record(base_url, path, endpoint_type):
    record = {"endpoint_type": endpoint_type, "endpoint_id": f"web{path}",
              "source_name": base_url + path, "path": path, "status_code": 200}
    record.update(SIMULATED_PAGES[path])
    return record


def find_technologies(endpoint, signatures):
    # only technologies with a known version can be checked for vulnerabilities
    found = []
    for signature in signatures:
        if signature.match(endpoint):
            version = signature.extract_version(endpoint)
            if version is not None:
                found.append((signature.tech_name, version))
    return found


async def fetch_path_mockable(base_url, path, endpoint_type, delay=FETCH_DELAY):
    # the sleep stands for the time a real web request would take
    await asyncio.sleep(delay)
    return build_record(base_url, path, endpoint_type)


async def create_endpoint_and_enrich(base_url, path, endpoint_type, api_client, signatures):
    record = await fetch_path_mockable(base_url, path, endpoint_type)
    endpoint = EndpointFactory.create_endpoint(record)
    for tech_name, version in find_technologies(endpoint, signatures):
        endpoint.vulnerabilities.extend(await api_client.fetch_cves_async(tech_name, version))
    return endpoint


async def discover_endpoints_concurrent(target, api_client, signatures):
    tasks = []
    for path, endpoint_type in PATHS_CONFIG:
        tasks.append(create_endpoint_and_enrich(target.uri, path, endpoint_type, api_client, signatures))

    # all 3 paths run at the same time; gather keeps the results in the same order as the tasks
    endpoints = await asyncio.gather(*tasks)
    for endpoint in endpoints:
        target.add_endpoint(endpoint)
    return endpoints


def discover_endpoints_sequential(target, api_client, signatures):
    # the same work, one path after the other - used to compare with the concurrent version
    endpoints = []
    for path, endpoint_type in PATHS_CONFIG:
        time.sleep(FETCH_DELAY)
        endpoint = EndpointFactory.create_endpoint(build_record(target.uri, path, endpoint_type))
        for tech_name, version in find_technologies(endpoint, signatures):
            endpoint.vulnerabilities.extend(api_client.fetch_cves_sync(tech_name, version))
        target.add_endpoint(endpoint)
        endpoints.append(endpoint)
    return endpoints
