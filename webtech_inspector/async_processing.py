import asyncio
import json
import logging
import time

import requests

from webtech_inspector import config
from webtech_inspector.factories import EndpointFactory
from webtech_inspector.models import ContentEndpoint, MetaDataEndpoint

logger = logging.getLogger(__name__)

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


async def enrich_endpoint(endpoint, api_client, signatures):
    for tech_name, version in find_technologies(endpoint, signatures):
        endpoint.vulnerabilities.extend(await api_client.fetch_cves_async(tech_name, version))


async def create_endpoint_and_enrich(base_url, path, endpoint_type, api_client, signatures):
    record = await fetch_path_mockable(base_url, path, endpoint_type)
    endpoint = EndpointFactory.create_endpoint(record)
    await enrich_endpoint(endpoint, api_client, signatures)
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


# ---------- real website scan (used with --url) ----------

def get_page(url):
    # returns the response, or None if the site did not answer - one bad page should not stop the scan
    try:
        return requests.get(url, timeout=config.API_TIMEOUT, headers={"User-Agent": "WebTech-Inspector"})
    except requests.exceptions.RequestException as error:
        logger.warning(f"Could not read {url}: {error}")
        return None


def is_json_object(text):
    # many sites answer every path with their home page, so we check it is really a JSON file
    try:
        return isinstance(json.loads(text), dict)
    except json.JSONDecodeError:
        return False


async def scan_real_site(target, api_client, signatures):
    base_url = target.uri.rstrip("/")
    loop = asyncio.get_running_loop()

    # both pages are requested at the same time
    home, package = await asyncio.gather(
        loop.run_in_executor(None, get_page, base_url + "/"),
        loop.run_in_executor(None, get_page, base_url + "/package.json"),
    )

    endpoints = []
    if home is not None and home.status_code == 200:
        endpoints.append(ContentEndpoint("live-home", home.text, "homepage", "/", 200, "HTML"))
        # headers like "Server: nginx/1.18.0" also tell us about the technology
        headers_text = "\n".join(f"{name}: {value}" for name, value in home.headers.items())
        endpoints.append(MetaDataEndpoint("live-headers", headers_text, "headers", "headers"))
    if package is not None and package.status_code == 200 and is_json_object(package.text):
        endpoints.append(ContentEndpoint("live-package", package.text, "package.json", "/package.json", 200, "JSON"))

    for endpoint in endpoints:
        await enrich_endpoint(endpoint, api_client, signatures)
        target.add_endpoint(endpoint)
    return endpoints
