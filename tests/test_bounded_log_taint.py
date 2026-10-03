"""Run actual taint rules before proof-based forging calibration."""

from pathlib import Path

import pytest

from rowan.config import ScanConfig
from rowan.core.findings import ScanResult
from rowan.passes.base import ScanContext
from rowan.passes.enrichment import EnrichmentPass
from rowan.taint.opengrep_adapter import OpengrepAdapter

RULES = Path(__file__).parent.parent / "rules" / "python_taint.yaml"
pytestmark = pytest.mark.skipif(
    not OpengrepAdapter().is_installed(), reason="Opengrep not installed"
)


@pytest.mark.parametrize(
    "body,bounded",
    [
        ('logging.info("value=%s", int(request.args["value"]))', True),
        ('value = float(request.args["value"])\nlogging.info(f"value={value:.2f}")', True),
        ('logging.info("value=%d", request.args["value"])', True),
        ('logging.info("value=%s", request.args["value"])', False),
        ('value: int = request.args["value"]\nlogging.info("value=%s", value)', False),
        (
            'value = int(request.args["value"])\nvalue = request.args["other"]\nlogging.info(value)',
            False,
        ),
        (
            'value = int(request.args["value"])\nif request.args["switch"]:\n    value = request.args["other"]\nlogging.info(value)',
            False,
        ),
        ('logging.info("%d %s", 3, request.args["value"])', False),
    ],
)
def test_log_output_proof_preserves_unbounded_taint(tmp_path, body, bounded):
    path = tmp_path / "handler.py"
    path.write_text(
        "import logging\nfrom flask import request\ndef handler():\n"
        + "".join("    " + line + "\n" for line in body.splitlines())
    )
    raw = [
        f
        for f in OpengrepAdapter().scan_with_rules(tmp_path, [RULES], languages=["python"])
        if f.rule_id == "TNT-LOG-001"
    ]
    if not bounded:
        assert raw, "vulnerable control must reach the raw taint rule"
    ctx = ScanContext(target_path=tmp_path, config=ScanConfig(target=tmp_path), result=ScanResult())
    kept = EnrichmentPass()._suppress_bounded_log_forging(raw, ctx)
    assert bool(kept) is not bounded


@pytest.mark.parametrize(
    "render",
    [
        'logging.info("%c", int(request.args["value"]))',
        'value = int(request.args["value"])\nlogging.info(f"{value:c}")',
    ],
)
def test_numeric_character_rendering_can_forge_a_newline(tmp_path, render):
    # Runtime counterexample to treating every numeric format as neutralizing.
    assert "%c" % 10 == "\n"  # noqa: UP031 - exercise the percent formatter
    assert format(10, "c") == "\n"
    path = tmp_path / "handler.py"
    path.write_text(
        "import logging\nfrom flask import request\ndef handler():\n"
        + "".join("    " + line + "\n" for line in render.splitlines())
    )
    raw = [
        f
        for f in OpengrepAdapter().scan_with_rules(tmp_path, [RULES], languages=["python"])
        if f.rule_id == "TNT-LOG-001"
    ]
    assert raw
    ctx = ScanContext(target_path=tmp_path, config=ScanConfig(target=tmp_path), result=ScanResult())
    assert EnrichmentPass()._suppress_bounded_log_forging(raw, ctx)
