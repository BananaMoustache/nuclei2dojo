import os
import shutil
import argparse
import subprocess
import socket
import json
import tempfile
from typing import Dict, List

import requests

from .config import (
    DEFECTDOJO_URL,
    API_KEY,
    DEFAULT_OUT_DIR,
    PROD_TYPE_NAME,
)
from .utils import (
    now_str,
    slugify,
    split_by_host_to_json_arrays,
    count_findings_from_file,
    canonical_host_from_any,
    sanitize_nuclei_file,
)
from .nuclei_runner import nuclei_list, nuclei_single
from .dojo_client import (
    match_product_for_host,
    import_scan_smart,
    count_from_api,
)

PRODUCT_NAME_TEMPLATE = os.environ.get("DD_PRODUCT_FMT", "ASM ({host})")

HTTPX_BIN = os.environ.get("HTTPX_BIN", "httpx")
HTTPX_TIMEOUT = int(os.environ.get("HTTPX_TIMEOUT", "900"))

BASE_INCLUDE_TAGS = {
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
BASE_EXCLUDE_TAGS = {
    "fuzz",
    "dos",
    "bruteforce",
    "network",
}
BASE_EXCLUDE_TEMPLATES = [
    "http/fuzzing/",
    "network/",
    "dns/",
]

def sanitize_nuclei_json(path: str) -> None:
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        print(f"[WRN] Cannot load JSON {path}: {e}")
        return

    if not isinstance(data, list):
        print(f"[WRN] JSON {path} is not a list, skipping sanitize")
        return

    cleaned = []
    dropped = 0

    for i, it in enumerate(data):
        if not isinstance(it, dict):
            dropped += 1
            continue

        url = it.get("matched-at") or it.get("url") or it.get("host")
        if not url:
            dropped += 1
            continue

        host = canonical_host_from_any(url)
        if not host:
            dropped += 1
            continue

        tmpl = it.get("template-id") or it.get("template") or it.get("id")
        typ = it.get("type")
        matcher = it.get("matcher-name") or it.get("matcher")
        if not tmpl:
            tmpl = f"nuclei-unknown-template-{i}"
        if not typ:
            typ = "http"
        if not matcher:
            matcher = "default"

        it["matched-at"] = str(url)
        it["host"] = str(host)
        it["template-id"] = str(tmpl)
        it["type"] = str(typ)
        it["matcher-name"] = str(matcher)

        cleaned.append(it)

    if dropped:
        print(
            f"[WRN] sanitize_nuclei_json: dropped {dropped} records "
            f"that is not compatible with the Dojo parser"
        )

    if not cleaned:
        print(f"[WRN] sanitize_nuclei_json: all record in {path} dropped, empty file.")
        with open(path, "w", encoding="utf-8") as f:
            json.dump([], f, ensure_ascii=False)
        return

    with open(path, "w", encoding="utf-8") as f:
        json.dump(cleaned, f, ensure_ascii=False)


def _resolve_ip(host: str) -> str | None:
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
        print(f"[INF] Product match → '{product_name}' (host={host})")
    else:
        product_name = _render_product_name(host)
        print(
            f"[INF] No product matched. Auto-create Product='{product_name}' (type='{PROD_TYPE_NAME}')"
        )

    mode, res = import_scan_smart(dd_url, token, json_path, product_name, engagement)
    cnt = count_from_api(res)
    if not isinstance(cnt, int) or cnt == 0:
        cnt = count_findings_from_file(json_path) or 0
    print(f"[OK] {mode} → '{host}' → Product='{product_name}' → findings: {cnt}")


def _ensure_auth(args: argparse.Namespace) -> tuple[str, str]:
    dd_url = args.dd_url or DEFECTDOJO_URL
    token = args.dd_token or API_KEY
    if not token:
        raise SystemExit(
            "[!] DD token is required. Use --dd-token, .env (DD_TOKEN), or ENV."
        )
    return dd_url, token


def _run_httpx(hosts_file: str) -> str:
    """Run httpx against hosts_file and return path ke file JSON output."""
    with tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", delete=False, suffix=".json"
    ) as tf:
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
        print(f"[INF] httpx profiling: {' '.join(cmd)}")
        subprocess.run(cmd, check=True, timeout=HTTPX_TIMEOUT)
    except FileNotFoundError:
        raise SystemExit(
            "[!] httpx binary not found. Install it and ensure it is in $PATH "
            "or set HTTPX_BIN env var."
        )
    except subprocess.CalledProcessError as e:
        raise SystemExit(f"[!] httpx failed: {e}")
    except subprocess.TimeoutExpired:
        raise SystemExit("[!] httpx timed out.")

    return out_path


def _parse_httpx_json(json_path: str) -> Dict[str, List[str]]:
    """Parse httpx -json/-o output menjadi {host: [tech,...]}."""
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

                host_val = (
                    rec.get("host")
                    or rec.get("input")
                    or rec.get("url")
                    or rec.get("original-input")
                    or ""
                )
                host = canonical_host_from_any(host_val)

                tech_list = rec.get("tech") or rec.get("technologies") or []
                if not isinstance(tech_list, list):
                    continue

                techs = [str(t).strip() for t in tech_list if str(t).strip()]
                if not techs:
                    continue

                lst = tech_by_host.setdefault(host, [])
                for t in techs:
                    if t not in lst:
                        lst.append(t)
    finally:
        try:
            os.remove(json_path)
        except Exception:
            pass

    return tech_by_host


def _build_tags_for_technologies(techs: List[str]) -> set[str]:
    """Map daftar teknologi → nuclei tags."""
    tags: set[str] = set()
    low = [t.lower() for t in techs]

    # server / platform
    if any("wordpress" in t for t in low):
        tags.update({"wordpress", "wp", "php"})
    if any("php" in t for t in low):
        tags.add("php")
    if any("asp.net" in t or "aspnet" in t for t in low):
        tags.add("aspnet")
    if any("iis" in t for t in low):
        tags.update({"iis", "microsoft", "windows"})
    if any("nginx" in t for t in low):
        tags.add("nginx")
    if any("apache" in t for t in low):
        tags.add("apache")
    if any(
        "ubuntu" in t
        or "debian" in t
        or "centos" in t
        or "red hat" in t
        or "redhat" in t
    for t in low):
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
    if any("vue.js" in t or "vuejs" in t or "vue.js" in t for t in low):
        tags.update({"vue", "javascript", "js"})
    if any("angular" in t for t in low):
        tags.update({"angular", "javascript", "js"})
    if any("onsen ui" in t or "onsen-ui" in t or "onsen" in t for t in low):
        tags.update({"onsen", "javascript", "js"})
    if any("cloudflare" in t for t in low):
        tags.update({"cloudflare", "cdn"})
    if any("akamai" in t for t in low):
        tags.update({"akamai", "cdn"})
    if any("fastly" in t for t in low):
        tags.update({"fastly", "cdn"})
    if any("cdnjs" in t for t in low):
        tags.update({"cdnjs", "cdn", "javascript"})
    if any("osano" in t for t in low):
        tags.update({"osano", "cookie-consent"})
    if any("dreamweaver" in t for t in low):
        tags.add("dreamweaver")
    if not tags:
        tags.add("tech")

    return tags


def _run_httpx_and_build_profiles(
    hosts_file: str,
) -> tuple[Dict[str, List[str]], str | None]:
    """Run httpx dan derive nuclei tags (profile) for all host.

    Return:
        (tech_by_host, include_tags_for_nuclei)
    """
    json_path = _run_httpx(hosts_file)
    tech_by_host = _parse_httpx_json(json_path)

    if not tech_by_host:
        raise SystemExit(
            "[!] httpx does not return any technological data. "
            "Nuclei will not be executed."
        )

    all_tags: set[str] = set(BASE_INCLUDE_TAGS)
    for host, techs in tech_by_host.items():
        tags = _build_tags_for_technologies(techs)
        print(f"[INF] Profile {host}: tech={techs} → tags={sorted(tags)}")
        all_tags.update(tags)

    include_tags = ",".join(sorted(all_tags)) if all_tags else None
    print(f"[INF] Aggregated nuclei tags from httpx: {include_tags!r}")
    return tech_by_host, include_tags


def run_mode_list(args: argparse.Namespace) -> None:
    dd_url, token = _ensure_auth(args)
    out_dir = args.out_dir or str(DEFAULT_OUT_DIR)
    os.makedirs(out_dir, exist_ok=True)

    if args.profile == "httpx":
        tech_by_host, include_tags = _run_httpx_and_build_profiles(args.targets)
        exclude_tags = (
            ",".join(sorted(BASE_EXCLUDE_TAGS)) if BASE_EXCLUDE_TAGS else None
        )
        combined_json = nuclei_list(
            args.targets,
            severity=args.severity,
            include_tags=include_tags,
            exclude_tags=exclude_tags,
            exclude_templates=BASE_EXCLUDE_TEMPLATES,
            rate_limit=args.rate_limit,
            concurrency=args.concurrency,
        )
    else:
        combined_json = nuclei_list(
            args.targets,
            severity=args.severity,
            rate_limit=args.rate_limit,
            concurrency=args.concurrency,
        )

    host_files = split_by_host_to_json_arrays(combined_json, out_dir, write_jsonl=False)

    if args.save_json:
        dst = os.path.join(out_dir, f"nuclei_list_{now_str()}.json")
        shutil.copy2(combined_json, dst)
        print(f"[+] Combined JSON copied: {dst}")

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
            print(
                f"[ERR] {host}: HTTP {e.response.status_code} -> {e.response.text[:500]}"
            )
        except Exception as e:
            print(f"[ERR] {host}: {e}")
        finally:
            if not args.save_json:
                try:
                    os.remove(path)
                except Exception:
                    pass

    print(f"[=] Done: {ok}/{total} hosts processed.")


def run_mode_single(args: argparse.Namespace) -> None:
    dd_url, token = _ensure_auth(args)
    target = args.target
    if not target:
        raise SystemExit("[!] Single mode requires --target.")

    out_dir = args.out_dir or str(DEFAULT_OUT_DIR)
    os.makedirs(out_dir, exist_ok=True)

    print(f"\n[+] Single target: {target}")
    host = canonical_host_from_any(target)

    if args.profile == "httpx":
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", delete=False
        ) as tf:
            tf.write(target.strip() + "\n")
            hosts_file = tf.name

        try:
            tech_by_host, _ = _run_httpx_and_build_profiles(hosts_file)
            techs = tech_by_host.get(host, [])
            tags_for_host = (
                BASE_INCLUDE_TAGS.union(_build_tags_for_technologies(techs))
                if techs
                else set(BASE_INCLUDE_TAGS)
            )
            include_tags = (
                ",".join(sorted(tags_for_host)) if tags_for_host else None
            )
            exclude_tags = (
                ",".join(sorted(BASE_EXCLUDE_TAGS)) if BASE_EXCLUDE_TAGS else None
            )

            print(
                f"[INF] Using profile for {host}: tech={techs} "
                f"→ include_tags={include_tags!r}, exclude_tags={exclude_tags!r}, "
                f"exclude_templates={BASE_EXCLUDE_TEMPLATES}"
            )

            tmp_json = nuclei_single(
                target,
                severity=args.severity,
                include_tags=include_tags,
                exclude_tags=exclude_tags,
                exclude_templates=BASE_EXCLUDE_TEMPLATES,
                rate_limit=args.rate_limit,
                concurrency=args.concurrency,
            )
            sanitize_nuclei_file(tmp_json)
            _upload_host_json(dd_url, token, host, tmp_json)

            if args.save_json:
                dst = os.path.join(out_dir, f"nuclei_{slugify(host)}_{now_str()}.json")
                shutil.copy2(tmp_json, dst)
                print(f"[+] JSON copied: {dst}")
            else:
                try:
                    os.remove(tmp_json)
                except Exception:
                    pass

        except requests.HTTPError as e:
            print(f"[ERR] HTTP {e.response.status_code} -> {e.response.text[:500]}")
        except SystemExit:
            raise
        except Exception as e:
            print(f"[ERR] {e}")
        finally:
            try:
                os.remove(hosts_file)
            except Exception:
                pass

    else:
        try:
            tmp_json = nuclei_single(
                target,
                severity=args.severity,
                rate_limit=args.rate_limit,
                concurrency=args.concurrency,
            )
            _upload_host_json(dd_url, token, host, tmp_json)

            if args.save_json:
                dst = os.path.join(out_dir, f"nuclei_{slugify(host)}_{now_str()}.json")
                shutil.copy2(tmp_json, dst)
                print(f"[+] JSON copied: {dst}")
            else:
                try:
                    os.remove(tmp_json)
                except Exception:
                    pass

        except requests.HTTPError as e:
            print(f"[ERR] HTTP {e.response.status_code} -> {e.response.text[:500]}")
        except Exception as e:
            print(f"[ERR] {e}")
