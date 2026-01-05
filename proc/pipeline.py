import os
import re
import json
import shutil
import socket
import argparse
import tempfile
import subprocess
from collections import defaultdict
from typing import Dict, List, Optional, Set, Tuple

import requests

from .config import DEFECTDOJO_URL, API_KEY, DEFAULT_OUT_DIR, PROD_TYPE_NAME
from .utils import (
    now_str,
    slugify,
    split_by_host_to_json_arrays,
    count_findings_from_file,
    canonical_host_from_any,
    sanitize_nuclei_file,
    log_info,
    log_ok,
    log_warn,
    log_err,
    log_section,
)
from .nuclei_runner import nuclei_list, nuclei_single
from .dojo_client import match_product_for_host, import_scan_smart, count_from_api


PRODUCT_NAME_TEMPLATE = os.environ.get("DD_PRODUCT_FMT", "ASM ({host})")
HTTPX_BIN = os.environ.get("HTTPX_BIN", "httpx")
HTTPX_TIMEOUT = int(os.environ.get("HTTPX_TIMEOUT", "900"))

BASE_INCLUDE_TAGS: Set[str] = {
    "exposure",
    "misconfig",
    "panel",
    "default-login",
    "tech",
    "fingerprint",
    "cve",
    "takeover",
    "web",
}
BASE_EXCLUDE_TAGS: Set[str] = {"fuzz", "dos", "bruteforce", "network"}
BASE_EXCLUDE_TEMPLATES: List[str] = ["http/fuzzing/", "network/", "dns/"]


def guess_tech_filter_from_template(template_path: str) -> List[str]:
    if not template_path:
        return []

    try:
        with open(template_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.read().splitlines()
    except Exception:
        return []

    tags: List[str] = []

    for line in lines:
        raw = line.split("#", 1)[0].rstrip()
        low = raw.strip().lower()
        if not low.startswith("tags:"):
            continue

        after = raw.split(":", 1)[1].strip()
        if not after:
            continue

        after = after.strip().strip('"').strip("'").strip("[]")
        parts = re.split(r"[, ]+", after)

        for p in parts:
            p = p.strip().strip("'\"").lower()
            p = re.sub(r"[^a-z0-9._-]+", "", p)
            if p and p not in tags:
                tags.append(p)

    generic = {
        "cve",
        "http",
        "https",
        "tcp",
        "udp",
        "rce",
        "xss",
        "lfi",
        "sqli",
        "misconfig",
        "exposure",
        "web",
        "tech",
        "fingerprint",
        "takeover",
    }

    return [t for t in tags if t not in generic]


def _resolve_ip(host: str) -> Optional[str]:
    try:
        return socket.gethostbyname(host)
    except Exception:
        return None


def _render_product_name(host: str) -> str:
    ip = _resolve_ip(host) or ""
    try:
        return PRODUCT_NAME_TEMPLATE.format(host=host, ip=ip)
    except Exception:
        return f"ASM ({host})"


def _upload_host_json(dd_url: str, token: str, host: str, json_path: str) -> None:
    matched = match_product_for_host(dd_url, token, host)
    engagement = f"ASM - {host}"

    if matched:
        product_name = matched
        log_info(f"Product matched: {product_name!r} (host={host})")
    else:
        product_name = _render_product_name(host)
        log_info(f"No product matched. Auto-creating Product={product_name!r} (type={PROD_TYPE_NAME!r})")

    mode, res = import_scan_smart(dd_url, token, json_path, product_name, engagement)
    cnt = count_from_api(res)
    if not isinstance(cnt, int) or cnt < 0:
        cnt = count_findings_from_file(json_path) or 0

    log_ok(f"{mode}: host={host} product={product_name!r} findings={cnt}")


def _ensure_auth(args: argparse.Namespace) -> Tuple[str, str]:
    dd_url = args.dd_url or DEFECTDOJO_URL
    token = args.dd_token or API_KEY
    if not token:
        raise SystemExit("[!] DD token is required. Use --dd-token or set DD_TOKEN.")
    return dd_url, token


def _run_httpx(hosts_file: str) -> str:
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", delete=False, suffix=".json") as tf:
        out_path = tf.name

    cmd = [
        HTTPX_BIN,
        "-l",
        hosts_file,
        "-status-code",
        "-tech-detect",
        "-title",
        "-content-length",
        "-json",
        "-o",
        out_path,
    ]

    try:
        log_info(f"httpx: {' '.join(cmd)}")
        subprocess.run(
            cmd,
            check=True,
            timeout=HTTPX_TIMEOUT,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except FileNotFoundError:
        raise SystemExit("[!] httpx binary not found. Install it or set HTTPX_BIN.")
    except subprocess.CalledProcessError as e:
        raise SystemExit(f"[!] httpx failed: {e}")
    except subprocess.TimeoutExpired:
        raise SystemExit("[!] httpx timed out.")

    return out_path


def _parse_httpx_json(json_path: str) -> Dict[str, List[str]]:
    tech_by_host: Dict[str, List[str]] = {}

    try:
        with open(json_path, "r", encoding="utf-8", errors="ignore") as f:
            for raw in f:
                line = raw.strip()
                if not line:
                    continue

                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue

                if not isinstance(rec, dict):
                    continue

                host_val = rec.get("host") or rec.get("input") or rec.get("url") or rec.get("original-input") or ""
                host = canonical_host_from_any(host_val)
                if not host or host == "unknown":
                    continue

                tech_by_host.setdefault(host, [])

                tech_list = rec.get("tech") or rec.get("technologies") or []
                if not isinstance(tech_list, list):
                    continue

                techs = [str(t).strip() for t in tech_list if str(t).strip()]
                for t in techs:
                    if t not in tech_by_host[host]:
                        tech_by_host[host].append(t)
    finally:
        try:
            os.remove(json_path)
        except Exception:
            pass

    return tech_by_host


def _print_httpx_summary(tech_by_host: Dict[str, List[str]]) -> None:
    log_section("httpx tech-detect")
    if not tech_by_host:
        log_warn("No hosts returned from httpx output.")
        return

    for host in sorted(tech_by_host.keys()):
        techs = tech_by_host.get(host) or []
        if techs:
            log_info(f"{host}: {', '.join(techs)}")
        else:
            log_warn(f"{host}: (no tech detected)")


def _build_tags_for_technologies(techs: List[str]) -> Set[str]:
    tags: Set[str] = set()
    low = [t.lower() for t in (techs or [])]

    if any("wordpress" in t for t in low):
        tags.update({"wordpress", "wp", "php"})
    if any("php" in t for t in low):
        tags.add("php")
    if any(("asp.net" in t) or ("aspnet" in t) for t in low):
        tags.add("aspnet")
    if any("iis" in t for t in low):
        tags.update({"iis", "microsoft", "windows"})
    if any("nginx" in t for t in low):
        tags.add("nginx")
    if any(("ubuntu" in t) or ("debian" in t) or ("centos" in t) or ("red hat" in t) or ("redhat" in t) for t in low):
        tags.add("linux")
    if any("windows server" in t for t in low):
        tags.add("windows")

    if any("laravel" in t for t in low):
        tags.update({"laravel", "php"})
    if any("django" in t for t in low):
        tags.update({"django", "python"})
    if any("flask" in t for t in low):
        tags.update({"flask", "python"})
    if any("drupal" in t for t in low):
        tags.update({"drupal", "php"})
    if any("joomla" in t for t in low):
        tags.update({"joomla", "php"})

    if any("jquery" in t for t in low):
        tags.update({"jquery", "javascript", "js"})
    if any("react" in t for t in low):
        tags.update({"react", "javascript", "js"})
    if any(("vue.js" in t) or ("vuejs" in t) or (t.strip() == "vue") for t in low):
        tags.update({"vue", "javascript", "js"})
    if any("angular" in t for t in low):
        tags.update({"angular", "javascript", "js"})
    if any(("node.js" in t) or ("nodejs" in t) or (t.strip() == "node") for t in low):
        tags.update({"nodejs", "javascript", "js"})
    if any(("nuxt.js" in t) or ("nuxtjs" in t) or (t.strip() == "nuxt") for t in low):
        tags.update({"nuxt", "javascript", "js"})

    if not tags:
        tags.add("tech")

    return tags


def _run_httpx_and_build_profile(hosts_file: str) -> Tuple[Dict[str, List[str]], Optional[str]]:
    json_path = _run_httpx(hosts_file)
    tech_by_host = _parse_httpx_json(json_path)

    _print_httpx_summary(tech_by_host)

    if not tech_by_host:
        raise SystemExit("[!] httpx returned no hosts; cannot build profile.")

    all_tags: Set[str] = set(BASE_INCLUDE_TAGS)
    for _, techs in tech_by_host.items():
        all_tags.update(_build_tags_for_technologies(techs))

    include_tags = ",".join(sorted(all_tags)) if all_tags else None
    log_info(f"Aggregated nuclei tags: include_tags={include_tags!r}")
    return tech_by_host, include_tags


def _split_required_keywords_from_arg(s: Optional[str]) -> List[str]:
    if not s:
        return []
    out: List[str] = []
    for p in str(s).split(","):
        p = p.strip().lower()
        if p:
            out.append(p)
    return out


def run_mode_list(args: argparse.Namespace) -> None:
    dd_url, token = _ensure_auth(args)
    out_dir = args.out_dir or str(DEFAULT_OUT_DIR)
    os.makedirs(out_dir, exist_ok=True)

    template_mode = bool(getattr(args, "cve_template", None))
    scanned_hosts: Set[str] = set()
    skipped_hosts: Set[str] = set()
    temp_targets_file: Optional[str] = None

    try:
        if template_mode:
            required_keywords = _split_required_keywords_from_arg(getattr(args, "cve_tech_filter", None))

            if not required_keywords and getattr(args, "cve_auto_filter", False):
                guessed = guess_tech_filter_from_template(args.cve_template)
                required_keywords = [x.lower() for x in guessed if x and x.strip()]
                if required_keywords:
                    log_info(f"Auto-derived tech filter from template tags: {required_keywords} template={args.cve_template!r}")
                else:
                    raise SystemExit(
                        f"[!] --cve-auto-filter is enabled but no usable tech tags were derived from template={args.cve_template!r}. "
                        f"Add --cve-tech-filter (e.g. react) or use a template with specific tags."
                    )

            needs_httpx = bool(required_keywords)
            tech_by_host: Dict[str, List[str]] = {}
            if needs_httpx:
                tech_by_host, _ = _run_httpx_and_build_profile(args.targets)

            lines_by_host: Dict[str, List[str]] = defaultdict(list)
            with open(args.targets, "r", encoding="utf-8", errors="ignore") as f:
                for raw in f:
                    line = raw.strip()
                    if not line:
                        continue
                    host = canonical_host_from_any(line)
                    lines_by_host[host].append(line)

            if required_keywords:
                for host in lines_by_host.keys():
                    techs = tech_by_host.get(host, [])
                    lowtechs = [t.lower() for t in techs]
                    is_match = any((kw in t) for kw in required_keywords for t in lowtechs)
                    if is_match:
                        scanned_hosts.add(host)
                    else:
                        skipped_hosts.add(host)

                if not scanned_hosts:
                    log_warn(f"No hosts matched tech filter={required_keywords!r} for template={args.cve_template!r}. Nothing scanned.")
                    return

                with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", delete=False, suffix=".txt") as tf:
                    temp_targets_file = tf.name
                    for host in sorted(scanned_hosts):
                        for line in lines_by_host.get(host, []):
                            tf.write(line + "\n")

                log_section("Template mode")
                log_info(f"template={args.cve_template!r} scanned={len(scanned_hosts)} skipped={len(skipped_hosts)}")

                combined_json = nuclei_list(
                    temp_targets_file,
                    severity=args.severity,
                    rate_limit=args.rate_limit,
                    concurrency=args.concurrency,
                    templates=[args.cve_template],
                    verbose=args.verbose,
                )
            else:
                log_section("Template mode")
                log_info(f"template={args.cve_template!r} (no tech filter) scanning all targets")

                combined_json = nuclei_list(
                    args.targets,
                    severity=args.severity,
                    rate_limit=args.rate_limit,
                    concurrency=args.concurrency,
                    templates=[args.cve_template],
                    verbose=args.verbose,
                )

        else:
            if args.profile == "httpx":
                _, include_tags = _run_httpx_and_build_profile(args.targets)
                exclude_tags = ",".join(sorted(BASE_EXCLUDE_TAGS)) if BASE_EXCLUDE_TAGS else None

                combined_json = nuclei_list(
                    args.targets,
                    severity=args.severity,
                    include_tags=include_tags,
                    exclude_tags=exclude_tags,
                    exclude_templates=BASE_EXCLUDE_TEMPLATES,
                    rate_limit=args.rate_limit,
                    concurrency=args.concurrency,
                    verbose=args.verbose,
                )
            else:
                combined_json = nuclei_list(
                    args.targets,
                    severity=args.severity,
                    rate_limit=args.rate_limit,
                    concurrency=args.concurrency,
                    verbose=args.verbose,
                )

        host_files = split_by_host_to_json_arrays(combined_json, out_dir, write_jsonl=False)

        if args.save_json:
            dst = os.path.join(out_dir, f"nuclei_combined_{now_str()}.json")
            shutil.copy2(combined_json, dst)
            log_info(f"Combined JSON copied: {dst}")

        if not args.save_json:
            try:
                os.remove(combined_json)
            except Exception:
                pass

        ok, total = 0, len(host_files)
        for host, path in host_files.items():
            try:
                sanitize_nuclei_file(path)
                _upload_host_json(dd_url, token, host, path)
                ok += 1
            except requests.HTTPError as e:
                code = e.response.status_code if e.response is not None else "??"
                txt = e.response.text[:500] if e.response is not None else str(e)
                log_err(f"host={host} HTTP {code}: {txt}")
            except Exception as e:
                log_err(f"host={host}: {e}")
            finally:
                if not args.save_json:
                    try:
                        os.remove(path)
                    except Exception:
                        pass

        log_ok(f"Done. {ok}/{total} host(s) processed.")

    finally:
        if temp_targets_file:
            try:
                os.remove(temp_targets_file)
            except Exception:
                pass


def run_mode_single(args: argparse.Namespace) -> None:
    dd_url, token = _ensure_auth(args)
    target = args.target
    if not target:
        raise SystemExit("[!] Single mode requires --target.")

    out_dir = args.out_dir or str(DEFAULT_OUT_DIR)
    os.makedirs(out_dir, exist_ok=True)

    host = canonical_host_from_any(target)
    templates = [args.cve_template] if getattr(args, "cve_template", None) else None

    if args.profile == "httpx":
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", delete=False, suffix=".txt") as tf:
            tf.write(target.strip() + "\n")
            hosts_file = tf.name

        try:
            tech_by_host, _ = _run_httpx_and_build_profile(hosts_file)
            techs = tech_by_host.get(host, [])
            tags_for_host = set(BASE_INCLUDE_TAGS).union(_build_tags_for_technologies(techs)) if techs else set(BASE_INCLUDE_TAGS)
            include_tags = ",".join(sorted(tags_for_host)) if tags_for_host else None
            exclude_tags = ",".join(sorted(BASE_EXCLUDE_TAGS)) if BASE_EXCLUDE_TAGS else None

            log_section("Single target profile")
            log_info(f"host={host} include_tags={include_tags!r} exclude_tags={exclude_tags!r}")

            tmp_json = nuclei_single(
                target,
                severity=args.severity,
                include_tags=include_tags,
                exclude_tags=exclude_tags,
                exclude_templates=BASE_EXCLUDE_TEMPLATES,
                rate_limit=args.rate_limit,
                concurrency=args.concurrency,
                templates=templates,
                verbose=args.verbose,
            )

            sanitize_nuclei_file(tmp_json)
            _upload_host_json(dd_url, token, host, tmp_json)

            if args.save_json:
                dst = os.path.join(out_dir, f"nuclei_{slugify(host)}_{now_str()}.json")
                shutil.copy2(tmp_json, dst)
                log_info(f"JSON copied: {dst}")
            else:
                try:
                    os.remove(tmp_json)
                except Exception:
                    pass
        finally:
            try:
                os.remove(hosts_file)
            except Exception:
                pass
    else:
        tmp_json = nuclei_single(
            target,
            severity=args.severity,
            rate_limit=args.rate_limit,
            concurrency=args.concurrency,
            templates=templates,
            verbose=args.verbose,
        )

        sanitize_nuclei_file(tmp_json)
        _upload_host_json(dd_url, token, host, tmp_json)

        if args.save_json:
            dst = os.path.join(out_dir, f"nuclei_{slugify(host)}_{now_str()}.json")
            shutil.copy2(tmp_json, dst)
            log_info(f"JSON copied: {dst}")
        else:
            try:
                os.remove(tmp_json)
            except Exception:
                pass
