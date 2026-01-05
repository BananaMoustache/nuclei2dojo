import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[1]

DEFAULT_OUT_DIR = BASE_DIR / "outputs"
DEFAULT_OUT_DIR.mkdir(parents=True, exist_ok=True)

DEFECTDOJO_URL = os.environ.get("DD_URL", "http://127.0.0.1:42003/api/v2")
API_KEY = os.environ.get("DD_TOKEN", "")

PROD_TYPE_NAME = os.environ.get("DD_PROD_TYPE_NAME", "Research and Development")
PROD_TYPE_ID_ENV = os.environ.get("DD_PROD_TYPE_ID")
ALLOW_BASE_DOMAIN_FALLBACK = os.environ.get("DD_ALLOW_BASE_FALLBACK", "false").lower() == "true"


def HEADERS_AUTH(token: str) -> dict:
    return {
        "Authorization": f"Token {token}",
        "Accept": "application/json",
    }


DEFECTDOJOURL = DEFECTDOJO_URL
APIKEY = API_KEY
DEFAULTOUTDIR = DEFAULT_OUT_DIR
PRODTYPENAME = PROD_TYPE_NAME
PRODTYPEIDENV = PROD_TYPE_ID_ENV
ALLOWBASEDOMAINFALLBACK = ALLOW_BASE_DOMAIN_FALLBACK
HEADERSAUTH = HEADERS_AUTH
