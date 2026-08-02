"""Bounded child process for one supervisor-approved conformance action."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

from .actions import run_agent_action


def main() -> None:
    raw = sys.stdin.buffer.read(4097)
    if len(raw) > 4096:
        raise ValueError("conformance action frame exceeded its bound")
    value: Any = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError("conformance action frame must be an object")
    runtime_url = os.environ.get("RC_PUBLIC_RUNTIME_BASE_URL")
    result = run_agent_action(
        Path(os.environ.get("KCS_WORKSPACE", "/workspace")), value, runtime_url
    )
    sys.stdout.write(json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n")
    raise SystemExit(0 if result.get("ok") is True else 1)


if __name__ == "__main__":
    main()
