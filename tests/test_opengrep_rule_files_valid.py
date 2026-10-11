"""Every Opengrep rule file must pass `opengrep --validate`.

A schema error makes Opengrep reject the whole file, and the scan then
reports no findings from it rather than failing. Requires the Opengrep binary.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from rowan.taint.opengrep_adapter import OpengrepAdapter

RULES_DIR = Path(__file__).parent.parent / "rules"
RULE_FILES = sorted(
    [*RULES_DIR.glob("*_taint.yaml"), *RULES_DIR.glob("*_opengrep.yaml"), *(RULES_DIR / "converted").glob("*.yaml")]
)

_adapter = OpengrepAdapter()
pytestmark = pytest.mark.skipif(
    not _adapter.is_installed(),
    reason="Opengrep binary not installed; validation needs it.",
)


@pytest.mark.parametrize("rule_file", RULE_FILES, ids=lambda p: p.name)
def test_rule_file_is_valid(rule_file):
    proc = subprocess.run(
        [_adapter.binary, "scan", "--validate", "--config", str(rule_file)],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert proc.returncode == 0, proc.stdout[-2000:] + proc.stderr[-2000:]
