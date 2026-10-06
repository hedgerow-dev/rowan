"""Tests for degraded-scan reliability + observability + registry pass-through."""

import json

from rowan.config import ScanConfig
from rowan.core.findings import (
    Category,
    Finding,
    ScanResult,
    Severity,
)
from rowan.passes.base import ScanContext
from rowan.passes.taint import TaintPass
from rowan.reporters import to_json, to_sarif, to_text
from rowan.taint.opengrep_adapter import ScanOutcome


def test_merge_propagates_degraded_passes():
    base = ScanResult()
    assert base.degraded is False

    other = ScanResult()
    other.degraded_passes["taint"] = "opengrep timed out on 1/3 batches"

    base.merge(other)

    assert base.degraded is True
    assert base.degraded_passes["taint"] == "opengrep timed out on 1/3 batches"


def test_to_json_includes_degraded_and_warnings():
    result = ScanResult(
        findings=[
            Finding(
                rule_id="X", message="m", severity=Severity.HIGH,
                category=Category.GENERAL, file_path="a.py", start_line=1,
            )
        ],
    )
    result.degraded_passes["taint"] = "opengrep timed out (timeout=600s)"

    data = json.loads(to_json(result))

    assert data["summary"]["degraded"] is True
    assert any("opengrep timed out" in w for w in data["summary"]["warnings"])
    assert any(w.startswith("taint:") for w in data["summary"]["warnings"])


def test_to_json_not_degraded_by_default():
    result = ScanResult()
    data = json.loads(to_json(result))
    assert data["summary"]["degraded"] is False
    assert data["summary"]["warnings"] == []


def test_to_text_banner_when_degraded():
    result = ScanResult()
    result.degraded_passes["taint"] = "opengrep timed out (timeout=600s)"
    text = to_text(result)
    assert "WARNING: degraded scan (" in text
    assert "INCOMPLETE" in text


def test_to_text_never_calls_an_incomplete_empty_scan_clean():
    result = ScanResult()
    result.degraded_passes["taint"] = "Opengrep is unavailable"
    text = to_text(result)
    assert "No vulnerabilities found." not in text
    assert "INCOMPLETE" in text


def test_self_test_fails_without_engine(monkeypatch):
    from click.testing import CliRunner

    from rowan.cli import main
    from rowan.taint import OpengrepAdapter

    monkeypatch.setattr(OpengrepAdapter, "is_installed", lambda self: False)
    result = CliRunner().invoke(main, ["self-test"])
    assert result.exit_code == 1
    assert "Opengrep not found" in result.output


def test_to_sarif_run_properties_when_degraded():
    result = ScanResult()
    result.degraded_passes["taint"] = "opengrep timed out (timeout=600s)"
    sarif = to_sarif(result)
    props = sarif["runs"][0]["properties"]
    assert props["rowanDegraded"] is True
    assert any("opengrep timed out" in w for w in props["rowanWarnings"])


class _FakeAdapter:
    """Stand-in for OpengrepAdapter that returns a fixed outcome."""

    def __init__(self, outcome: ScanOutcome):
        self._outcome = outcome
        self._timeout = 0
        self._workers = 1

    def is_installed(self) -> bool:
        return True

    def get_version(self) -> str:
        return "0.0-test"

    def configure(self, timeout=None, workers=None, jobs=None, cpu_budget=None) -> None:
        if timeout is not None:
            self._timeout = timeout
        if workers is not None:
            self._workers = workers

    def scan_collect_with_rules(self, *args, **kwargs) -> ScanOutcome:
        return self._outcome


class _UnavailableAdapter:
    def is_installed(self) -> bool:
        return False


def _make_taint_pass(tmp_path, outcome: ScanOutcome):
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "ai_taint.yaml").write_text("rules: []\n")

    target = tmp_path / "proj"
    target.mkdir()
    (target / "app.py").write_text("import os\nos.system(input())\n")

    pass_ = TaintPass(rules_dir=rules_dir)
    pass_._adapter = _FakeAdapter(outcome)
    return pass_, target


def test_taint_pass_sets_degraded_on_timeout(tmp_path):
    outcome = ScanOutcome(
        findings=[],
        status="timeout",
        batches_total=3,
        batches_failed=3,
        timeouts=3,
        message="all 3 opengrep batch(es) failed",
    )
    pass_, target = _make_taint_pass(tmp_path, outcome)

    config = ScanConfig(target=target, taint_timeout=600)
    ctx = ScanContext(target_path=target, config=config, result=ScanResult())

    result = pass_.run(ctx)

    assert "taint" in result.degraded_passes
    assert "600s" in result.degraded_passes["taint"]
    assert "3/3" in result.degraded_passes["taint"]
    assert result.degraded is True


def test_taint_pass_partial_keeps_findings_and_degrades(tmp_path):
    kept = Finding(
        rule_id="kept", message="kept", severity=Severity.HIGH,
        category=Category.GENERAL, file_path="app.py", start_line=2,
    )
    outcome = ScanOutcome(
        findings=[kept],
        status="partial",
        batches_total=3,
        batches_failed=1,
        message="1/3 opengrep batch(es) failed",
    )
    pass_, target = _make_taint_pass(tmp_path, outcome)

    config = ScanConfig(target=target)
    ctx = ScanContext(target_path=target, config=config, result=ScanResult())

    result = pass_.run(ctx)

    assert len(result.findings) == 1
    assert "taint" in result.degraded_passes
    assert result.degraded is True


def test_taint_pass_non_timeout_failure_does_not_blame_timeout(tmp_path):
    """A batch that fails for a real, non-timeout reason (e.g. the locale/
    encoding bug where opengrep can't even read its own rule config under a
    C/POSIX locale) must not tell the user to raise --taint-timeout or
    --taint-workers -- no timeout value will ever fix that. The degraded
    message should instead surface the actual cause opengrep reported."""
    outcome = ScanOutcome(
        findings=[],
        status="error",
        batches_total=1,
        batches_failed=1,
        timeouts=0,
        message="all 1 opengrep batch(es) failed -- "
        "UnicodeDecodeError: 'ascii' codec can't decode byte 0xe2",
    )
    pass_, target = _make_taint_pass(tmp_path, outcome)

    config = ScanConfig(target=target, taint_timeout=600)
    ctx = ScanContext(target_path=target, config=config, result=ScanResult())

    result = pass_.run(ctx)

    degraded_message = result.degraded_passes["taint"]
    assert "raise --taint-timeout" not in degraded_message
    assert "--taint-workers" not in degraded_message
    assert "UnicodeDecodeError" in degraded_message
    assert result.degraded is True


def test_taint_pass_ok_not_degraded(tmp_path):
    outcome = ScanOutcome(findings=[], status="ok", batches_total=2, batches_failed=0)
    pass_, target = _make_taint_pass(tmp_path, outcome)

    config = ScanConfig(target=target)
    ctx = ScanContext(target_path=target, config=config, result=ScanResult())

    result = pass_.run(ctx)

    assert result.degraded is False


def test_taint_pass_marks_missing_opengrep_incomplete(tmp_path):
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    target = tmp_path / "project"
    target.mkdir()

    pass_ = TaintPass(rules_dir=rules_dir)
    pass_._adapter = _UnavailableAdapter()
    result = pass_.run(
        ScanContext(target_path=target, config=ScanConfig(target=target), result=ScanResult())
    )

    assert result.degraded is True
    assert "taint" in result.degraded_passes
    assert result.metadata["opengrep_execution"] == {"status": "unavailable", "mode": "taint"}


def test_chunk_files_respects_workers_and_batch_size():
    from pathlib import Path

    from rowan.taint.opengrep_adapter import OpengrepAdapter

    files = [Path(f"f{i}.py") for i in range(10)]

    one = OpengrepAdapter._chunk_files(files, workers=1, batch_size=150)
    assert len(one) == 1

    many = OpengrepAdapter._chunk_files(files, workers=4, batch_size=150)
    assert len(many) == 4
    assert sum(len(b) for b in many) == 10

    by_size = OpengrepAdapter._chunk_files(files, workers=1, batch_size=3)
    assert len(by_size) == 4
    assert sum(len(b) for b in by_size) == 10


def test_parse_failure_names_the_file_and_the_fix(tmp_path):
    """PL-09: the scan stays degraded, but says which file and how to skip it."""
    from rowan.config import ScanConfig
    from rowan.pipeline import ScanPipeline

    (tmp_path / "good.py").write_text("x = 1\n", encoding="utf-8")
    (tmp_path / "legacy.py").write_text('print "legacy python 2"\n', encoding="utf-8")
    result = ScanPipeline(ScanConfig(target=tmp_path, enable_sca=False)).run()
    reason = result.degraded_passes["source_snapshot"]
    assert "1 Python parse failure(s): legacy.py" in reason
    assert "--exclude" in reason
