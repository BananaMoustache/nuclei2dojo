import os
from typing import Any, List, Optional, Union, Tuple

import requests

from .config import HEADERS_AUTH, PROD_TYPE_NAME, PROD_TYPE_ID_ENV, ALLOW_BASE_DOMAIN_FALLBACK
from .utils import utc_today, log_warn


def _json_or_none(r: requests.Response) -> Any:
    try:
        return r.json()
    except ValueError:
        return None


def _results(data: Any) -> List[Any]:
    if isinstance(data, dict):
        res = data.get("results")
        return res if isinstance(res, list) else []
    if isinstance(data, list):
        return data
    return []


def _paged_get(dd_url: str, token: str, path: str, params: dict | None = None) -> list:
    url = f"{dd_url}{path if path.startswith('/') else '/' + path}"
    items, offset, limit = [], 0, 200

    while True:
        query = dict(params or {})
        query.update({"limit": limit, "offset": offset})

        r = requests.get(url, headers=HEADERS_AUTH(token), params=query, timeout=30)
        r.raise_for_status()

        data = _json_or_none(r) or {}
        items.extend(_results(data))

        if not data.get("next"):
            break

        offset += limit

    return items


def get_products(dd_url: str, token: str, q: Optional[str] = None) -> list:
    params = {"name__icontains": q} if q else None
    return _paged_get(dd_url, token, "/products/", params=params)


def get_product_types(dd_url: str, token: str) -> list:
    return _paged_get(dd_url, token, "/product_types/")


def choose_product_type(dd_url: str, token: str) -> Tuple[Optional[int], Optional[str]]:
    if PROD_TYPE_ID_ENV:
        try:
            return int(PROD_TYPE_ID_ENV), None
        except Exception:
            pass

    pts = get_product_types(dd_url, token)

    if PROD_TYPE_NAME:
        for pt in pts:
            name = (pt.get("name") or "").strip()
            if name.lower() == PROD_TYPE_NAME.strip().lower():
                return int(pt.get("id")), pt.get("name")

    if pts:
        first = pts[0]
        return int(first.get("id")), first.get("name")

    return None, None


def _inside_paren_lower(name: str) -> Optional[str]:
    name = name or ""
    i = name.find("(")
    j = name.find(")", i + 1) if i != -1 else -1
    if i != -1 and j != -1 and j > i + 1:
        return name[i + 1 : j].strip().lower()
    return None


def _base_domain(host: str) -> str:
    parts = host.split(".")
    if len(parts) >= 3 and parts[-1] == "id":
        return ".".join(parts[-3:])
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return host


def match_product_for_host(dd_url: str, token: str, host: str) -> Optional[str]:
    h = (host or "").lower().strip()
    if not h:
        return None

    candidates = get_products(dd_url, token, q=h)
    strict = []

    for p in candidates:
        pname = p.get("name") or ""
        low = pname.lower()
        in_paren = _inside_paren_lower(pname)
        if h in low or in_paren == h:
            strict.append(p)

    if strict:
        strict.sort(key=lambda x: len((x.get("name") or "")))
        return strict[0].get("name")

    if not ALLOW_BASE_DOMAIN_FALLBACK:
        return None

    base = _base_domain(h)
    if base and base != h:
        more = get_products(dd_url, token, q=base)
        sub = h.split(".")[0]
        good = []

        for p in more:
            pname = p.get("name") or ""
            low = pname.lower()
            in_paren = _inside_paren_lower(pname)
            if base in low and (sub in low or in_paren == h):
                good.append(p)

        if good:
            good.sort(key=lambda x: len((x.get("name") or "")))
            return good[0].get("name")

    return None


def _common_form(product_name: str, engagement_name: str, no_reactivate: bool) -> dict:
    return {
        "scan_type": "Nuclei Scan",
        "scan_date": utc_today(),
        "active": "true",
        "verified": "false",
        "minimum_severity": "Info",
        "close_old_findings": "false",
        "push_to_jira": "false",
        "auto_create_context": "true",
        "product_name": product_name,
        "engagement_name": engagement_name,
        "do_not_reactivate": "true" if no_reactivate else "false",
        "create_endpoints": "true",
    }


def _with_product_type(dd_url: str, token: str, form: dict) -> dict:
    pt_id, _ = choose_product_type(dd_url, token)
    if pt_id:
        form["product_type"] = str(pt_id)
    if PROD_TYPE_NAME:
        form["product_type_name"] = PROD_TYPE_NAME
    return form


def _reimport(dd_url: str, token: str, file_path: str, product_name: str, engagement_name: str) -> dict:
    url = f"{dd_url}/reimport-scan/"
    data = _with_product_type(dd_url, token, _common_form(product_name, engagement_name, no_reactivate=True))

    with open(file_path, "rb") as fh:
        files = {"file": (os.path.basename(file_path), fh, "application/json")}
        r = requests.post(url, headers=HEADERS_AUTH(token), files=files, data=data, timeout=180)
        r.raise_for_status()

    return _json_or_none(r) or {}


def _import(dd_url: str, token: str, file_path: str, product_name: str, engagement_name: str) -> dict:
    url = f"{dd_url}/import-scan/"
    data = _with_product_type(dd_url, token, _common_form(product_name, engagement_name, no_reactivate=False))

    with open(file_path, "rb") as fh:
        files = {"file": (os.path.basename(file_path), fh, "application/json")}
        r = requests.post(url, headers=HEADERS_AUTH(token), files=files, data=data, timeout=180)
        r.raise_for_status()

    return _json_or_none(r) or {}


def import_scan_smart(dd_url: str, token: str, file_path: str, product_name: str, engagement_name: str) -> Tuple[str, dict]:
    try:
        res = _reimport(dd_url, token, file_path, product_name, engagement_name)
        return "reimport", res
    except requests.HTTPError as e:
        code = e.response.status_code if e.response is not None else None
        txt = e.response.text[:500] if e.response is not None else str(e)
        log_warn(f"reimport-scan failed ({code}): {txt}")
        res = _import(dd_url, token, file_path, product_name, engagement_name)
        return "import", res


def count_from_api(api_response: Union[dict, list, None]) -> Optional[int]:
    if not isinstance(api_response, dict):
        return None

    for key in ("findings_count", "results_count", "count", "imported_findings", "created", "success"):
        val = api_response.get(key)
        if isinstance(val, int) and val >= 0:
            return val

    for k in ("result", "results"):
        nested = api_response.get(k)
        if isinstance(nested, dict):
            inner = count_from_api(nested)
            if isinstance(inner, int):
                return inner

    return None
