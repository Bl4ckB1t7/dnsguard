#!/usr/bin/env python3
"""Convert a reviewed domain list into a DNSGuard first-run seed.

This helper only writes a local JSON file. It never performs DNS UPDATE.
"""

import argparse
import json
import os
import re
import tempfile
import sys
from datetime import datetime, timezone

MAX_BYTES = 4 * 1024 * 1024
MAX_DOMAINS = 100_000
LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


def normalize_domain(value: str, label: str) -> str:
    value = value.strip().lower().rstrip(".")
    labels = value.split(".")
    if not value or len(value) > 253 or len(labels) < 2 or "*" in value or "_" in value:
        raise ValueError(f"{label}: invalid domain")
    if any(not LABEL_RE.fullmatch(item) for item in labels):
        raise ValueError(f"{label}: invalid domain")
    return value


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--zone", required=True)
    args = parser.parse_args()

    if os.path.islink(args.input) or not os.path.isfile(args.input):
        raise SystemExit("白名单文件必须是普通文件且不能是符号链接")
    if os.path.getsize(args.input) > MAX_BYTES:
        raise SystemExit("白名单文件超过 4 MiB 限制")
    if os.path.lexists(args.output):
        raise SystemExit("拒绝覆盖已有白名单 JSON")

    zone = normalize_domain(args.zone, "RPZ_ZONE") + "."
    domains: list[str] = []
    seen: set[str] = set()
    with open(args.input, "r", encoding="utf-8", errors="strict") as handle:
        for line_number, raw in enumerate(handle, 1):
            if line_number > MAX_DOMAINS:
                raise SystemExit("白名单条目超过 100000 条限制")
            value = raw.split("#", 1)[0].strip()
            if not value:
                continue
            domain = normalize_domain(value, f"白名单第 {line_number} 行")
            if domain not in seen:
                seen.add(domain)
                domains.append(domain)
    if not domains:
        raise SystemExit("白名单文件为空")

    rules = [
        {
            "domain": domain,
            "action": "passthru",
            "type": "CNAME",
            "value": "rpz-passthru.",
            "reason": "preflight whitelist import",
            "status": "draft",
        }
        for domain in domains
    ]
    payload = {
        "version": 1,
        "source": "rpz-connect",
        "mode": "global",
        "generatedAt": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "zone": zone,
        "rules": rules,
    }
    parent = os.path.dirname(os.path.abspath(args.output)) or "."
    os.makedirs(parent, mode=0o750, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".dnsguard-whitelist-", suffix=".tmp", dir=parent, text=True)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, ensure_ascii=False, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, args.output)
    except Exception:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise
    print(f"PASS: 已导出 {len(domains)} 条白名单初始规则（draft，未写入 BIND）: {args.output}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        raise SystemExit(1)
