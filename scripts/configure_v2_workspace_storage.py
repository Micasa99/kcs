#!/usr/bin/env python3
"""Build the local-path ConfigMap patch for one KCS GPU worker."""

from __future__ import annotations

import json
import sys


def main() -> None:
    if len(sys.argv) != 3:
        raise SystemExit("usage: configure_v2_workspace_storage.py NODE PATH")
    node, path = sys.argv[1:]
    config_map = json.load(sys.stdin)
    raw = config_map.get("data", {}).get("config.json")
    if not isinstance(raw, str):
        raise SystemExit("local-path-config lacks data.config.json")
    config = json.loads(raw)
    entries = config.get("nodePathMap")
    if not isinstance(entries, list):
        raise SystemExit("local-path-config lacks nodePathMap")
    updated = [entry for entry in entries if entry.get("node") != node]
    updated.append({"node": node, "paths": [path]})
    config["nodePathMap"] = updated
    patch = {"data": {"config.json": json.dumps(config, separators=(",", ":"))}}
    json.dump(patch, sys.stdout, separators=(",", ":"))


if __name__ == "__main__":
    main()
