"""JS-CRYPTO-002 and DK-CONFIG-006 report at INFO.

Math.random() on sight and a Dockerfile without HEALTHCHECK are hygiene
signals, not vulnerabilities, so both rules ship at INFO. This runs the full
pipeline so converter output, adapter mapping and enrichment are all covered.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from rowan.config import ScanConfig
from rowan.core.findings import Severity
from rowan.pipeline import ScanPipeline
from rowan.taint.opengrep_adapter import OpengrepAdapter

pytestmark = pytest.mark.skipif(
    not OpengrepAdapter().is_installed(), reason="Opengrep binary not installed"
)


@pytest.fixture(scope="module")
def findings(tmp_path_factory) -> list:
    root = tmp_path_factory.mktemp("hygiene")
    (root / "token.js").write_text(
        "function makeId() {\n  return Math.random().toString(36);\n}\n",
        encoding="utf-8",
    )
    (root / "Dockerfile").write_text(
        'FROM python:3.12-slim\nCOPY app.py /app.py\nCMD ["python", "/app.py"]\n',
        encoding="utf-8",
    )
    config = ScanConfig(target=root, no_sca=True, report_view="full")
    return ScanPipeline(config).run().findings


@pytest.mark.parametrize(
    ("rule_id", "filename"),
    [("JS-CRYPTO-002", "token.js"), ("DK-CONFIG-006", "Dockerfile")],
)
def test_reported_at_info(findings, rule_id, filename):
    hits = [f for f in findings if f.rule_id == rule_id and Path(f.file_path).name == filename]
    assert hits, f"{rule_id} not reported; got {[f.rule_id for f in findings]}"
    assert all(f.severity == Severity.INFO for f in hits)
