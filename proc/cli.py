import os
import argparse
from .config import DEFAULT_OUT_DIR


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Nuclei → DefectDojo bridge: scan (list/single) and upload results per-host.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument(
        "--mode",
        choices=["list", "single"],
        required=True,
        help="list: scan using a targets file; single: scan a single URL.",
    )
    p.add_argument(
        "--targets", help="Path to a .txt file containing targets (mode=list)."
    )
    p.add_argument("--target", help="Single target URL (mode=single).")
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
        help="Output folder if you want to keep the combined JSON.",
    )
    p.add_argument(
        "--save-json",
        action="store_true",
        help="Keep combined/per-host JSON files instead of deleting temp files.",
    )
    p.add_argument(
        "-s",
        "--severity",
        help="Nuclei severity filter, e.g. 'info' or 'low,medium,high,critical'.",
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
        "--profile",
        choices=["default", "webanalyze"],
        default="default",
        help=(
            "Scan mode: 'default' = nuclei without tech profiling; "
            "'webanalyze' = tech-profiled scan using webanalyze + nuclei tags."
        ),
    )
    return p
