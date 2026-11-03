import logging
import os

API_BASE_URL = os.getenv("API_BASE_URL", "https://services.nvd.nist.gov/rest/json/cves/2.0")
# optional; without a key NVD allows only a few requests every 30 seconds
NVD_API_KEY = os.getenv("NVD_API_KEY", "")
API_TIMEOUT = float(os.getenv("API_TIMEOUT_SECONDS", "10"))
MAX_RETRIES = int(os.getenv("MAX_RETRIES", "3"))
RETRY_DELAY = float(os.getenv("RETRY_DELAY_SECONDS", "0.5"))
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")

logging.basicConfig(level=LOG_LEVEL, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
