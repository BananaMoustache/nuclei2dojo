import shutil
import subprocess
import tempfile
import uuid
from typing import Optional, List

from .utils import log_info


def ensure_nuclei() -> None:
    if shutil.which("nuclei") is None:
        raise RuntimeError("Nuclei not found in PATH. Make sure 'nuclei' is executable.")


def _join_exclude_templates(exclude_templates: Optional[List[str]]) -> Optional[str]:
    if not exclude_templates:
        return None
    cleaned = [x.strip() for x in exclude_templates if x and x.strip()]
    if not cleaned:
        return None
    return ",".join(cleaned)


def _clean_headers(headers: Optional[List[str]]) -> List[str]:
    if not headers:
        return []
    out: List[str] = []
    for h in headers:
        if h is None:
            continue
        hs = str(h).strip()
        if not hs:
            continue
        out.append(hs)
    return out


def nuclei_single(
    url: str,
    json_export_path: Optional[str] = None,
    timeout_sec: int = 1800,
    severity: Optional[str] = None,
    include_tags: Optional[str] = None,
    exclude_tags: Optional[str] = None,
    exclude_templates: Optional[List[str]] = None,
    rate_limit: Optional[int] = None,
    concurrency: Optional[int] = None,
    templates: Optional[List[str]] = None,
    headers: Optional[List[str]] = None,
    verbose: bool = False,
) -> str:
    ensure_nuclei()

    if json_export_path is None:
        json_export_path = f"{tempfile.gettempdir()}/nuclei_single_{uuid.uuid4().hex}.json"

    cmd: List[str] = ["nuclei", "-u", url, "-json-export", json_export_path]

    if verbose:
        cmd.insert(1, "-v")

    for h in _clean_headers(headers):
        cmd += ["-H", h]

    if severity:
        cmd += ["-severity", severity]

    if include_tags:
        cmd += ["-tags", include_tags]

    if exclude_tags:
        cmd += ["-exclude-tags", exclude_tags]

    joined_exclude_templates = _join_exclude_templates(exclude_templates)
    if joined_exclude_templates:
        cmd += ["-exclude-templates", joined_exclude_templates]

    if rate_limit:
        cmd += ["-rl", str(rate_limit)]

    if concurrency:
        cmd += ["-c", str(concurrency)]

    if templates:
        for t in templates:
            cmd += ["-t", t]

    log_info(f"nuclei single: {' '.join(cmd)}")
    subprocess.run(cmd, check=True, timeout=timeout_sec)
    return json_export_path


def nuclei_list(
    list_file: str,
    json_export_path: Optional[str] = None,
    timeout_sec: int = 3600,
    severity: Optional[str] = None,
    include_tags: Optional[str] = None,
    exclude_tags: Optional[str] = None,
    exclude_templates: Optional[List[str]] = None,
    rate_limit: Optional[int] = None,
    concurrency: Optional[int] = None,
    templates: Optional[List[str]] = None,
    headers: Optional[List[str]] = None,
    verbose: bool = False,
) -> str:
    ensure_nuclei()

    if json_export_path is None:
        json_export_path = f"{tempfile.gettempdir()}/nuclei_list_{uuid.uuid4().hex}.json"

    cmd: List[str] = ["nuclei", "-list", list_file, "-json-export", json_export_path]

    if verbose:
        cmd.insert(1, "-v")

    for h in _clean_headers(headers):
        cmd += ["-H", h]

    if severity:
        cmd += ["-severity", severity]

    if include_tags:
        cmd += ["-tags", include_tags]

    if exclude_tags:
        cmd += ["-exclude-tags", exclude_tags]

    joined_exclude_templates = _join_exclude_templates(exclude_templates)
    if joined_exclude_templates:
        cmd += ["-exclude-templates", joined_exclude_templates]

    if rate_limit:
        cmd += ["-rl", str(rate_limit)]

    if concurrency:
        cmd += ["-c", str(concurrency)]

    if templates:
        for t in templates:
            cmd += ["-t", t]

    log_info(f"nuclei list: {' '.join(cmd)}")
    subprocess.run(cmd, check=True, timeout=timeout_sec)
    return json_export_path
