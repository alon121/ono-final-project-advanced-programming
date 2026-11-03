import asyncio
import logging
import time

import requests

from webtech_inspector import config

logger = logging.getLogger(__name__)

# NVD gives the level as text; we turn it into our scale (1 = critical)
SEVERITY_LEVELS = {"CRITICAL": 1, "HIGH": 2, "MEDIUM": 3, "LOW": 4}

# NVD searches by CPE name "vendor:product"; these were checked against NVD
NVD_PRODUCTS = {
    "jQuery": "jquery:jquery",
    "Lodash": "lodash:lodash",
    "Express": "openjsf:express",
    "Bootstrap": "getbootstrap:bootstrap",
    "nginx": "f5:nginx",
    "PHP": "php:php",
    "WordPress": "wordpress:wordpress",
}


class VulnerabilityApiClient:
    def __init__(self, base_url=config.API_BASE_URL, timeout=config.API_TIMEOUT,
                 max_retries=config.MAX_RETRIES, retry_delay=config.RETRY_DELAY, api_key=config.NVD_API_KEY):
        self.base_url = base_url
        self.timeout = timeout
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        self.api_key = api_key

    def fetch_cves_sync(self, tech_name, version):
        product = NVD_PRODUCTS.get(tech_name)
        if product is None:
            # we do not know the CPE name of this technology, so we cannot ask NVD
            return []

        params = {"virtualMatchString": f"cpe:2.3:a:{product}:{version}"}
        headers = {}
        if self.api_key:
            headers["apiKey"] = self.api_key

        for attempt in range(1, self.max_retries + 1):
            try:
                response = requests.get(self.base_url, params=params, headers=headers, timeout=self.timeout)
                if response.status_code == 404:
                    return []
                response.raise_for_status()
                return self.read_vulnerabilities(response.json())

            except (requests.exceptions.Timeout, requests.exceptions.ConnectionError) as error:
                # a network problem may pass, so we try again
                logger.warning(f"Attempt {attempt} of {self.max_retries} failed: {error}")
                if attempt == self.max_retries:
                    raise
                time.sleep(self.retry_delay)

            except requests.exceptions.RequestException as error:
                # errors like 400 or 500 will not fix themselves, so no retry
                logger.error(f"API request failed: {error}")
                raise

    def read_vulnerabilities(self, data):
        vulnerabilities = []
        for item in data.get("vulnerabilities", []):
            cve = item["cve"]
            vulnerabilities.append({
                "cve_id": cve["id"],
                "summary": self.find_summary(cve),
                "severity": self.find_severity(cve),
            })
        return vulnerabilities

    def find_summary(self, cve):
        for description in cve.get("descriptions", []):
            if description.get("lang") == "en":
                return description.get("value", "")
        return ""

    def find_severity(self, cve):
        metrics = cve.get("metrics", {})
        # newer CVSS versions first; in CVSS v2 the level sits outside "cvssData"
        if "cvssMetricV31" in metrics:
            level = metrics["cvssMetricV31"][0]["cvssData"]["baseSeverity"]
        elif "cvssMetricV30" in metrics:
            level = metrics["cvssMetricV30"][0]["cvssData"]["baseSeverity"]
        elif "cvssMetricV2" in metrics:
            level = metrics["cvssMetricV2"][0]["baseSeverity"]
        else:
            # None means NVD did not give a level
            return None
        return SEVERITY_LEVELS.get(level)

    async def fetch_cves_async(self, tech_name, version):
        # requests is blocking, so we run it in a thread and do not stop the event loop
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self.fetch_cves_sync, tech_name, version)


class LocalVulnerabilityClient:
    # offline version: answers from our local insights.json, with the same methods as the real client
    def __init__(self, insights):
        self.insights = insights

    def fetch_cves_sync(self, tech_name, version):
        vulnerabilities = []
        for insight in self.insights:
            if insight.tech_name == tech_name and version in insight.affected_versions:
                vulnerabilities.append({
                    "cve_id": insight.cve_id or insight.insight_id,
                    "summary": insight.description,
                    "severity": insight.severity,
                })
        return vulnerabilities

    async def fetch_cves_async(self, tech_name, version):
        return self.fetch_cves_sync(tech_name, version)
