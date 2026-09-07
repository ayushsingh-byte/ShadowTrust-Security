from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
UPLOAD_DIR = DATA_DIR / "uploads"
DB_PATH = DATA_DIR / "mobsf_history.db"

SERVICE_HOST = "127.0.0.1"
SERVICE_PORT = 5055

# Not "mobsf": inside docker-compose the proxy service is itself named `mobsf`
# and carries that network alias, so a spawned container called `mobsf` would
# be shadowed by it in DNS. Use a distinct name.
MOBSF_CONTAINER_NAME = "shadowtrust-mobsf-engine"
MOBSF_IMAGE = "opensecurity/mobile-security-framework-mobsf"
MOBSF_INTERNAL_PORT = 8000
MOBSF_PORT_RANGE_START = 8000
MOBSF_PORT_RANGE_END = 9000

# Paste your MobSF API key here after visiting http://localhost:<port>/api_docs
MOBSF_API_KEY = "30a7fd45e1029688b3c5093d05482083b8de601fa2eddb4120455b1e86db02a8"
