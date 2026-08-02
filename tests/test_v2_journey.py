"""Opt-in wrapper for the dedicated-host KCS V2 Journey."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.v2_live


def test_v2_live_journey() -> None:
    config = os.environ.get("KCS_V2_LIVE_CONFIG")
    evidence_dir = os.environ.get("KCS_V2_LIVE_EVIDENCE_DIR")
    if os.environ.get("KCS_V2_LIVE") != "1" or not config or not evidence_dir:
        pytest.skip("requires KCS_V2_LIVE=1, KCS_V2_LIVE_CONFIG, and KCS_V2_LIVE_EVIDENCE_DIR")

    repository = Path(__file__).resolve().parents[1]
    subprocess.run(
        [
            sys.executable,
            str(repository / "scripts" / "run_v2_attempt_journey.py"),
            "--config",
            config,
            "--evidence-dir",
            evidence_dir,
        ],
        cwd=repository,
        check=True,
    )
