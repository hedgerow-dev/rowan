"""Tests for baseline / diff mode."""

from __future__ import annotations

from rowan import baseline
from rowan.core.findings import Category, Finding, ScanResult, Severity
from rowan.passes.enrichment import EnrichmentPass, _thresholds_cache


def _finding(file_path, line, rule_id="NS-X", msg="m", cat=Category.INJECTION):
    return Finding(
        rule_id=rule_id,
        message=msg,
        severity=Severity.HIGH,
        category=cat,
        file_path=str(file_path),
        start_line=line,
    )


def test_fingerprint_stable_across_line_shift(tmp_path):
    """A finding that moves to a new line keeps the same fingerprint."""
    f = tmp_path / "a.py"
    f.write_text("import os\nos.system(x)\n")  # sink on line 2
    baseline._line_cache.clear()
    fp_before = baseline.fingerprint(_finding(f, 2), tmp_path)

    f.write_text("\n\n\nimport os\nos.system(x)\n")  # same sink, now line 5
    baseline._line_cache.clear()
    fp_after = baseline.fingerprint(_finding(f, 5), tmp_path)

    assert fp_before == fp_after


def test_fingerprint_differs_for_different_code(tmp_path):
    f = tmp_path / "a.py"
    f.write_text("os.system(x)\neval(y)\n")
    baseline._line_cache.clear()
    assert baseline.fingerprint(_finding(f, 1), tmp_path) != baseline.fingerprint(_finding(f, 2), tmp_path)


def test_fingerprint_uses_fresh_source_after_same_path_edit(tmp_path):
    f = tmp_path / "a.py"
    f.write_text("os.system(old_value)\n")
    before = baseline.fingerprint(_finding(f, 1), tmp_path)

    f.write_text("os.system(new_value)\n")
    after = baseline.fingerprint(_finding(f, 1), tmp_path)

    assert after != before


def test_thresholds_reload_after_same_path_edit(tmp_path):
    path = tmp_path / "thresholds.yaml"
    path.write_text("rules:\n  OLD:\n    enabled: false\n")
    _thresholds_cache.clear()
    assert "OLD" in EnrichmentPass._load_thresholds(path)

    path.write_text("rules:\n  NEW:\n    enabled: false\n")

    assert "NEW" in EnrichmentPass._load_thresholds(path)


def test_write_and_load_roundtrip(tmp_path):
    f = tmp_path / "a.py"
    f.write_text("os.system(x)\n")
    result = ScanResult()
    result.add_finding(_finding(f, 1))
    bpath = tmp_path / "baseline.json"

    assert baseline.write_baseline(result, bpath, tmp_path) == 1
    baseline._line_cache.clear()
    loaded = baseline.load_baseline(bpath)
    assert baseline.fingerprint(_finding(f, 1), tmp_path) in loaded


def test_filter_new_suppresses_known_keeps_new(tmp_path):
    f = tmp_path / "a.py"
    f.write_text("os.system(x)\neval(y)\n")
    result = ScanResult()
    result.add_finding(_finding(f, 1, rule_id="NS-CMD"))
    bpath = tmp_path / "b.json"
    baseline.write_baseline(result, bpath, tmp_path)

    # New scan: the known finding plus a genuinely new one.
    rescan = ScanResult()
    rescan.add_finding(_finding(f, 1, rule_id="NS-CMD"))   # known
    rescan.add_finding(_finding(f, 2, rule_id="NS-EVAL"))  # new
    baseline._line_cache.clear()

    suppressed = baseline.filter_new(rescan, baseline.load_baseline(bpath), tmp_path)

    assert suppressed == 1
    assert len(rescan.findings) == 1
    assert rescan.findings[0].rule_id == "NS-EVAL"


def test_write_baseline_covers_hidden_findings(tmp_path, monkeypatch):
    """PL-03: a baseline written from a filtered run must hold every finding,
    so a later --audit or --severity run does not report them as new."""
    import json

    from rowan.config import ScanConfig
    from rowan.core.findings import Severity as Sev
    from rowan.pipeline import ScanPipeline

    app = tmp_path / "app"
    app.mkdir()
    (app / "a.py").write_text("import pickle\n\ndef load(blob):\n    return pickle.loads(blob)\n")
    # Hide everything from the view, and filter to CRITICAL only.
    monkeypatch.setattr(ScanPipeline, "_in_actionable_view", lambda self, f: False)
    base = tmp_path / "base.json"
    shown = ScanPipeline(ScanConfig(
        target=app, no_sca=True, report_view="actionable", severity=Sev.CRITICAL,
        write_baseline_path=base,
    )).run()
    full = ScanPipeline(ScanConfig(target=app, no_sca=True, report_view="full")).run()

    payload = json.loads(base.read_text())
    assert shown.findings == []
    assert len(full.findings) >= 1
    assert set(payload["fingerprints"]) == {baseline.fingerprint(f, app) for f in full.findings}
    assert payload["view"] == "actionable"
    assert payload["severity"] == "critical"


def test_duplicate_code_lines_get_distinct_fingerprints(tmp_path):
    """Identical lines in one file must not collapse into a single entry."""
    f = tmp_path / "a.py"
    f.write_text("os.system(x)\nos.system(x)\n")
    result = ScanResult()
    result.add_finding(_finding(f, 1))
    result.add_finding(_finding(f, 2))
    bpath = tmp_path / "b.json"

    assert baseline.write_baseline(result, bpath, tmp_path) == 2


def test_new_duplicate_is_not_hidden_by_old_baseline_entry(tmp_path):
    f = tmp_path / "a.py"
    f.write_text("os.system(x)\n")
    first = ScanResult()
    first.add_finding(_finding(f, 1))
    bpath = tmp_path / "b.json"
    baseline.write_baseline(first, bpath, tmp_path)

    f.write_text("os.system(x)\nos.system(x)\n")  # a second copy is added
    rescan = ScanResult()
    rescan.add_finding(_finding(f, 1))
    rescan.add_finding(_finding(f, 2))
    baseline._line_cache.clear()

    suppressed = baseline.filter_new(rescan, baseline.load_baseline(bpath), tmp_path)

    assert suppressed == 1
    assert len(rescan.findings) == 1


def test_load_baseline_rejects_unknown_version(tmp_path):
    import pytest

    bpath = tmp_path / "b.json"
    bpath.write_text('{"version": 99, "fingerprints": []}')

    with pytest.raises(ValueError, match="version"):
        baseline.load_baseline(bpath)
