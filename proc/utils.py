import json
import os
from datetime import datetime, timezone
from urllib.parse import urlparse
from typing import Dict, List, Iterable


def now_str() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def utc_today() -> str:
    return datetime.now(timezone.utc).date().isoformat()


def slugify(text: str) -> str:
    import re as _re

    text = (text or "").strip().lower()
    text = _re.sub(r"[^a-z0-9\-_.]+", "-", text)
    text = _re.sub(r"-{2,}", "-", text).strip("-")
    return text or "unknown"


def _strip_port_from_netloc(netloc: str) -> str:
    if not netloc:
        return ""
    import re as _re

    m = _re.match(r"^\[(?P<h>.+)\](?::\d+)?$", netloc)
    if m:
        return m.group("h")
    return _re.sub(r":\d+$", "", netloc)


def canonical_host_from_any(s: str) -> str:
    if not s:
        return "unknown"
    s = str(s).strip()

    if "://" in s:
        p = urlparse(s)
        base = p.netloc or p.path or s
    else:
        p = urlparse("dummy://" + s)
        base = p.netloc or p.path or s

    base = base.split("/")[0]
    host = _strip_port_from_netloc(base)
    host = host or s
    return host.lower()


def iter_nuclei_records(path: str) -> Iterable[dict]:
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        data = f.read().strip()
    if not data:
        return

    try:
        obj = json.loads(data)
        if isinstance(obj, dict):
            yield obj
            return
        if isinstance(obj, list):
            for rec in obj:
                if isinstance(rec, dict):
                    yield rec
            return
    except json.JSONDecodeError:
        pass

    for line in data.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict):
            yield obj
        elif isinstance(obj, list):
            for rec in obj:
                if isinstance(rec, dict):
                    yield rec


def count_findings_from_file(json_path: str) -> int:
    try:
        with open(json_path, "r", encoding="utf-8", errors="ignore") as f:
            data = f.read().strip()
        if not data:
            return 0
        try:
            obj = json.loads(data)
            if isinstance(obj, list):
                return len([x for x in obj if isinstance(x, dict)])
            if isinstance(obj, dict):
                return 1
        except json.JSONDecodeError:
            pass
        return sum(1 for _ in iter_nuclei_records(json_path))
    except Exception:
        return 0


def extract_host_from_record(rec: dict) -> str:
    for key in ("host", "ip", "url", "matched-at"):
        val = rec.get(key)
        if val:
            h = canonical_host_from_any(val)
            if h and h != "unknown":
                return h

    req = rec.get("request")
    if isinstance(req, dict):
        val = req.get("url")
        if val:
            h = canonical_host_from_any(val)
            if h and h != "unknown":
                return h

    return "unknown"


def split_by_host_to_json_arrays(
    src_json_path: str, out_dir: str, write_jsonl: bool = True
) -> Dict[str, List[dict]]:
    os.makedirs(out_dir, exist_ok=True)

    buckets: Dict[str, List[dict]] = {}
    total = 0
    for rec in iter_nuclei_records(src_json_path):
        total += 1
        if not isinstance(rec, dict):
            continue
        host = extract_host_from_record(rec)
        buckets.setdefault(host, []).append(rec)

    print(f"[+] Findings: {total} | Unique hosts: {len(buckets)}")

    host_files: Dict[str, str] = {}
    ts = now_str()

    for host, records in buckets.items():
        safe_host = slugify(host)
        out_path = os.path.join(out_dir, f"nuclei_{safe_host}_{ts}.json")
        with open(out_path, "w", encoding="utf-8") as f:
            if write_jsonl:
                for r in records:
                    f.write(json.dumps(r, ensure_ascii=False) + "\n")
            else:
                json.dump(records, f, ensure_ascii=False, indent=2)

        host_files[host] = out_path
        print(
            f"    - {host}: {len(records)} → {out_path} ({'JSONL' if write_jsonl else 'JSON'})"
        )

    return host_files

def sanitize_nuclei_file(path: str) -> None:
    try:
        recs = list(iter_nuclei_records(path))
    except Exception as e:
        print(f"[WRN] sanitize_nuclei_file: cannot iterate {path}: {e}")
        return

    if not recs:
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump([], f, ensure_ascii=False)
        except Exception:
            pass
        return

    cleaned = []
    dropped = 0

    for i, it in enumerate(recs):
        if not isinstance(it, dict):
            dropped += 1
            continue

        url = it.get("matched-at") or it.get("url") or it.get("host")
        if not url:
            dropped += 1
            continue
            
        host = canonical_host_from_any(url)
        if not host or host == "unknown":
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
            f"[WRN] sanitize_nuclei_file: dropped {dropped} records yang tidak kompatibel dengan parser Dojo"
        )

    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(cleaned, f, ensure_ascii=False)
    except Exception as e:
        print(f"[WRN] sanitize_nuclei_file: failed writing cleaned JSON: {e}")

