import os
import argparse

from .config import DEFAULT_OUT_DIR


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Nuclei -> DefectDojo bridge: scan (list/single) and upload results per host.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    p.add_argument(
        "--mode",
        choices=["list", "single"],
        required=True,
        help="list=scan targets file; single=scan one URL.",
    )

    p.add_argument(
        "--targets",
        help="Path to targets file (mode=list). One URL/host per line.",
    )

    p.add_argument(
        "--target",
        help="Single target URL (mode=single).",
    )

    p.add_argument(
        "--dd-url",
        default=os.environ.get("DD_URL"),
        help="DefectDojo API v2 base URL (or ENV DD_URL).",
    )

    p.add_argument(
        "--dd-token",
        default=os.environ.get("DD_TOKEN"),
        help="DefectDojo API token (or ENV DD_TOKEN).",
    )

    p.add_argument(
        "--out-dir",
        default=str(DEFAULT_OUT_DIR),
        help="Output folder (per-host JSONs).",
    )

    p.add_argument(
        "--save-json",
        action="store_true",
        help="Keep combined/per-host JSON files instead of deleting temp files.",
    )

    p.add_argument(
        "-s",
        "--severity",
        help="Nuclei severity filter, e.g. info or low,medium,high,critical.",
    )

    p.add_argument(
        "-rl",
        "--rate-limit",
        type=int,
        help="Requests per second limit for Nuclei (e.g. 120).",
    )

    p.add_argument(
        "-c",
        "--concurrency",
        type=int,
        help="Worker concurrency for Nuclei (e.g. 80).",
    )

    p.add_argument(
        "-H",
        "--header",
        action="append",
        default=[],
        help="Custom header (repeatable), like nuclei -H. Example: -H 'Authorization: Bearer xxx' -H 'Cookie: a=b'",
    )

    p.add_argument(
        "--profile",
        choices=["default", "httpx"],
        default="default",
        help="default=nuclei without tech profiling; httpx=run httpx -tech-detect and build nuclei tags profile.",
    )

    p.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Verbose output and pass -v to nuclei.",
    )

    p.add_argument(
        "--cve-template",
        help="Run only this nuclei template (any template path). Example: http/cves/2025/CVE-2025-55182.yaml",
    )

    p.add_argument(
        "--cve-tech-filter",
        help="Comma-separated technology keywords required to scan a host when using --cve-template (from httpx -tech-detect). Example: react or wordpress,php",
    )

    p.add_argument(
        "--cve-auto-filter",
        action="store_true",
        help="If --cve-template is used and --cve-tech-filter is empty, try reading template YAML 'tags:' and auto-derive a tech filter.",
    )

    return p
