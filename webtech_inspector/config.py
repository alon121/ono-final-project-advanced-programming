import logging
import os

API_BASE_URL = os.getenv("API_BASE_URL", "https://api.osv.dev/v1/query")
API_TIMEOUT = float(os.getenv("API_TIMEOUT_SECONDS", "5"))
MAX_RETRIES = int(os.getenv("MAX_RETRIES", "3"))
RETRY_DELAY = float(os.getenv("RETRY_DELAY_SECONDS", "0.5"))
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")

logging.basicConfig(level=LOG_LEVEL, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
