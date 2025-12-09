import os
import shutil
import argparse
import subprocess
import socket
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
)
from .nuclei_runner import nuclei_list, nuclei_single
from .dojo_client import (
    match_product_for_host,
    import_scan_smart,
    count_from_api,
)

PRODUCT_NAME_TEMPLATE = os.environ.get("DD_PRODUCT_FMT", "ASM ({host})")

WEBANALYZE_BIN = os.environ.get("WEBANALYZE_BIN", "webanalyze")
WEBANALYZE_TIMEOUT = int(os.environ.get("WEBANALYZE_TIMEOUT", "900"))

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


def _run_webanalyze_update() -> None:
    """Run `webanalyze -update` to ensure technologies.json is present/updated."""
    try:
        print("[INF] webanalyze -update …")
        subprocess.run(
            [WEBANALYZE_BIN, "-update"],
            check=True,
            timeout=WEBANALYZE_TIMEOUT,
        )
    except FileNotFoundError:
        raise SystemExit(
            "[!] webanalyze binary not found. Install it and ensure it is in $PATH "
            "or set WEBANALYZE_BIN env var."
        )
    except subprocess.CalledProcessError as e:
        raise SystemExit(f"[!] webanalyze -update failed: {e}")
    except subprocess.TimeoutExpired:
        raise SystemExit("[!] webanalyze -update timed out.")


def _parse_webanalyze_output(stdout: str) -> Dict[str, List[str]]:
    """Parse webanalyze text output into {host: [technologies]}.

    Example block:

        http://testasp.vulnweb.com (0.6s):
            DreamWeaver,  (Editors)
            IIS, 8.5 (Web servers)
    """
    tech_by_host: Dict[str, List[str]] = {}
    current_host: str | None = None

    for raw in stdout.splitlines():
        line = raw.strip()
        if not line:
            continue

        if line.startswith(":: ") or " technologies.json" in line:
            continue

        if "://" in line and line.endswith("):"):
            url_part = line.split(" ", 1)[0]
            host = canonical_host_from_any(url_part)
            current_host = host
            tech_by_host.setdefault(host, [])
            continue

        if current_host:
            name = line.split(",", 1)[0].strip()
            if name:
                techs = tech_by_host.setdefault(current_host, [])
                if name not in techs:
                    techs.append(name)

    return tech_by_host


def _build_tags_for_technologies(techs: List[str]) -> set[str]:
    """Map webanalyze technologies → nuclei tags."""
    tags: set[str] = set()
    low = [t.lower() for t in techs]

    if any("wordpress" in t for t in low):
        tags.update({"wordpress", "wp"})
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
    if any("ubuntu" in t or "debian" in t or "centos" in t or "red hat" in t for t in low):
        tags.add("linux")
    if any("windows server" in t for t in low):
        tags.add("windows")
    if not tags:
        tags.add("tech")

    return tags


def _run_webanalyze_and_build_profiles(
    hosts_file: str,
) -> tuple[Dict[str, List[str]], str | None]:
    """Run webanalyze and derive nuclei tags (profile) for all hosts.

    Return:
        (technologies_by_host, include_tags_for_nuclei)
    """
    _run_webanalyze_update()

    try:
        print(f"[INF] webanalyze -hosts {hosts_file} …")
        proc = subprocess.run(
            [WEBANALYZE_BIN, "-hosts", hosts_file],
            check=True,
            timeout=WEBANALYZE_TIMEOUT,
            text=True,
            capture_output=True,
        )
    except FileNotFoundError:
        raise SystemExit(
            "[!] webanalyze binary not found. Install it and ensure it is in $PATH "
            "or set WEBANALYZE_BIN env var."
        )
    except subprocess.CalledProcessError as e:
        raise SystemExit(f"[!] webanalyze -hosts failed: {e}")
    except subprocess.TimeoutExpired:
        raise SystemExit("[!] webanalyze -hosts timed out.")

    stdout = proc.stdout or ""
    tech_by_host = _parse_webanalyze_output(stdout)

    if not tech_by_host:
        raise SystemExit(
            "[!] webanalyze did not return any fingerprint data. "
            "Nuclei will NOT be executed."
        )

    all_tags: set[str] = set(BASE_INCLUDE_TAGS)
    for host, techs in tech_by_host.items():
        tags = _build_tags_for_technologies(techs)
        print(f"[INF] Profile for {host}: technologies={techs} → tags={sorted(tags)}")
        all_tags.update(tags)

    include_tags = ",".join(sorted(all_tags)) if all_tags else None
    print(f"[INF] Aggregated nuclei tags from profiles: {include_tags!r}")
    return tech_by_host, include_tags


def run_mode_list(args: argparse.Namespace) -> None:
    dd_url, token = _ensure_auth(args)
    out_dir = args.out_dir or str(DEFAULT_OUT_DIR)
    os.makedirs(out_dir, exist_ok=True)

    if args.profile == "webanalyze":
        tech_by_host, include_tags = _run_webanalyze_and_build_profiles(args.targets)
        exclude_tags = ",".join(sorted(BASE_EXCLUDE_TAGS)) if BASE_EXCLUDE_TAGS else None
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


    host_files = split_by_host_to_json_arrays(combined_json, out_dir, write_jsonl=True)

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

    import tempfile

    print(f"\n[+] Single target: {target}")
    host = canonical_host_from_any(target)

    if args.profile == "webanalyze":
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", delete=False) as tf:
            tf.write(target.strip() + "\n")
            hosts_file = tf.name

        try:
            tech_by_host, _ = _run_webanalyze_and_build_profiles(hosts_file)
            techs = tech_by_host.get(host, [])
            tags_for_host = BASE_INCLUDE_TAGS.union(_build_tags_for_technologies(techs)) if techs else set(BASE_INCLUDE_TAGS)
            include_tags = ",".join(sorted(tags_for_host)) if tags_for_host else None
            exclude_tags = ",".join(sorted(BASE_EXCLUDE_TAGS)) if BASE_EXCLUDE_TAGS else None
            
            print(
                f"[INF] Using profile for {host}: technologies={techs} "
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
