import asyncio
import logging
import time

import requests

from webtech_inspector import config

logger = logging.getLogger(__name__)

# OSV gives the level as text; we turn it into our scale (1 = critical)
SEVERITY_LEVELS = {"CRITICAL": 1, "HIGH": 2, "MODERATE": 3, "MEDIUM": 3, "LOW": 4}


class VulnerabilityApiClient:
    def __init__(self, base_url=config.API_BASE_URL, timeout=config.API_TIMEOUT,
                 max_retries=config.MAX_RETRIES, retry_delay=config.RETRY_DELAY):
        self.base_url = base_url
        self.timeout = timeout
        self.max_retries = max_retries
        self.retry_delay = retry_delay

    def fetch_cves_sync(self, tech_name, version):
        # OSV query format; our technologies are npm packages with lowercase names
        query = {"version": version, "package": {"name": tech_name.lower(), "ecosystem": "npm"}}

        for attempt in range(1, self.max_retries + 1):
            try:
                response = requests.post(self.base_url, json=query, timeout=self.timeout)
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
        for vuln in data.get("vulns", []):
            vulnerabilities.append({
                "cve_id": self.find_cve_id(vuln),
                "summary": vuln.get("summary", ""),
                "severity": self.find_severity(vuln),
            })
        return vulnerabilities

    def find_cve_id(self, vuln):
        for alias in vuln.get("aliases", []):
            if alias.startswith("CVE-"):
                return alias
        return vuln.get("id")

    def find_severity(self, vuln):
        level = vuln.get("database_specific", {}).get("severity", "")
        # None means OSV did not give a level
        return SEVERITY_LEVELS.get(level.upper())

    async def fetch_cves_async(self, tech_name, version):
        # requests is blocking, so we run it in a thread and do not stop the event loop
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self.fetch_cves_sync, tech_name, version)
