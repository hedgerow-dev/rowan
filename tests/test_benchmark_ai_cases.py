"""Tests for the ai_cases benchmark corpus (BACKLOG JG-03).

ai_cases is the taint-ON corpus for AI-surface rules across languages.
vuln_cases is scanned with no_taint=True, so a `mode: taint` rule can never
score there; this corpus exists to give those rules a recall number. Most
tests here mock the scan; the last one runs the real scanner on the Python
seed and is skipped when Opengrep is not installed.
"""

from __future__ import annotations

import importlib.util
import json
import shutil
import sys
from pathlib import Path

import pytest

from rowan.core.findings import Category, Finding, Severity
from rowan.taint.opengrep_adapter import OpengrepAdapter

CORPUS = Path(__file__).parent.parent / "benchmark" / "ground_truth" / "ai_cases"


def _load_benchmark_module():
    script_path = Path(__file__).parent.parent / "scripts" / "benchmark.py"
    spec = importlib.util.spec_from_file_location("benchmark_ai_cases", script_path)
    module = importlib.util.module_from_spec(spec)
    sys.modules["benchmark_ai_cases"] = module
    spec.loader.exec_module(module)
    return module


def _finding(rule_id: str, file_path: Path):
    return Finding(
        rule_id=rule_id, message=rule_id, severity=Severity.HIGH,
        category=Category.GENERAL, file_path=str(file_path), start_line=1,
    )


def _write_corpus(root: Path, cases: list[dict]) -> Path:
    for case in cases:
        target = root / case["file"]
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("x = 1\n", encoding="utf-8")
    (root / "manifest.json").write_text(json.dumps({"cases": cases}), encoding="utf-8")
    return root


SEED_CASES = [
    {"file": "python/llm_sql.py", "language": "python", "cwe": 89,
     "expected_rule_id": "TNT-LLMOUT-001", "pool": "regression"},
    {"file": "java/placeholder_llm_sql.java", "language": "java", "cwe": 89,
     "expected_rule_id": "tnt-ja-ai-llmout-sql-001", "pool": "holdout"},
    {"file": "go/placeholder_mcp_exec.go", "language": "go", "cwe": 78,
     "expected_rule_id": "tnt-go-ai-mcptool-exec-001", "pool": "holdout"},
]


def _seed_corpus(tmp_path: Path) -> Path:
    """The original three-case seed, as a synthetic corpus so the real one can grow."""
    return _write_corpus(tmp_path / "ai_cases", SEED_CASES)


def _point_benchmark_at(benchmark, monkeypatch, corpus: Path, baseline: dict) -> None:
    monkeypatch.setattr(benchmark, "AI_CASES_DIR", corpus)
    baseline_path = corpus.parent / "baseline.json"
    baseline_path.write_text(json.dumps(baseline), encoding="utf-8")
    monkeypatch.setattr(benchmark, "BASELINE_PATH", baseline_path)


def test_seed_manifest_loads_with_required_keys(tmp_path):
    benchmark = _load_benchmark_module()
    cases = benchmark.load_ai_cases_manifest(_seed_corpus(tmp_path))
    assert [c["file"] for c in cases] == [
        "python/llm_sql.py",
        "java/placeholder_llm_sql.java",
        "go/placeholder_mcp_exec.go",
    ]
    for case in cases:
        assert case["language"] == case["file"].split("/")[0]
        assert case["expected_rule_id"]
    assert [c.get("pool", "regression") for c in cases] == ["regression", "holdout", "holdout"]


def test_manifest_rejects_missing_required_key(tmp_path):
    benchmark = _load_benchmark_module()
    corpus = _write_corpus(tmp_path, [{"file": "python/a.py", "language": "python", "cwe": 89}])
    with pytest.raises(ValueError, match="expected_rule_id"):
        benchmark.load_ai_cases_manifest(corpus)


def test_manifest_rejects_duplicate_basename_within_language(tmp_path):
    benchmark = _load_benchmark_module()
    corpus = _write_corpus(
        tmp_path,
        [
            {"file": "python/a.py", "language": "python", "expected_rule_id": "R1"},
            {"file": "python/sub/a.py", "language": "python", "expected_rule_id": "R2"},
        ],
    )
    with pytest.raises(ValueError, match="duplicate basename"):
        benchmark.load_ai_cases_manifest(corpus)


def test_manifest_allows_same_basename_across_languages(tmp_path):
    benchmark = _load_benchmark_module()
    corpus = _write_corpus(
        tmp_path,
        [
            {"file": "python/llm_sql.py", "language": "python", "expected_rule_id": "R1"},
            {"file": "java/llm_sql.py", "language": "java", "expected_rule_id": "R2"},
        ],
    )
    assert len(benchmark.load_ai_cases_manifest(corpus)) == 2


def test_run_ai_cases_scores_missing_rule_as_miss_and_reports_one_third(monkeypatch, tmp_path):
    """Mocked scan: only the Python seed produces its expected rule, so the two
    placeholder cases (whose rule ids do not exist yet) must be plain MISSes."""
    benchmark = _load_benchmark_module()
    scanned: list[Path] = []

    def fake_scan(target: Path, **_kwargs):
        scanned.append(target)
        if target.name == "python":
            return [_finding("TNT-LLMOUT-001", target / "llm_sql.py")], {}
        if target.name == "go":
            # An unrelated rule firing in the file must not credit the case.
            return [_finding("SOME-OTHER-RULE", target / "placeholder_mcp_exec.go")], {}
        return [], {}

    monkeypatch.setattr(benchmark, "_scan_dir_retrying", fake_scan)
    report = benchmark.run_ai_cases(_seed_corpus(tmp_path))

    assert sorted(p.name for p in scanned) == ["go", "java", "python"]
    assert report["degraded"] == {}
    by_file = {r.file: r for r in report["results"]}
    assert by_file["python/llm_sql.py"].found
    assert by_file["python/llm_sql.py"].matched_rule_ids == ["TNT-LLMOUT-001"]
    assert not by_file["java/placeholder_llm_sql.java"].found
    assert not by_file["go/placeholder_mcp_exec.go"].found
    assert by_file["go/placeholder_mcp_exec.go"].matched_rule_ids == []
    scores = report["scores"]
    assert scores["overall"] == {"recall": 1 / 3, "hits": 1, "total": 3}
    assert scores["regression"] == {"recall": 1.0, "hits": 1, "total": 1}
    assert scores["holdout"] == {"recall": 0.0, "hits": 0, "total": 2}


def test_main_prints_placeholder_misses_and_passes(monkeypatch, capsys, tmp_path):
    benchmark = _load_benchmark_module()
    _point_benchmark_at(
        benchmark, monkeypatch, _seed_corpus(tmp_path),
        {"ai_cases_recall": 1 / 3, "ai_cases_regression": 1.0, "ai_cases_holdout": 0.0},
    )

    def fake_scan(target: Path, **_kwargs):
        if target.name == "python":
            return [_finding("TNT-LLMOUT-001", target / "llm_sql.py")], {}
        return [], {}

    monkeypatch.setattr(benchmark, "_scan_dir_retrying", fake_scan)
    monkeypatch.setattr(sys, "argv", ["benchmark.py", "--corpus", "ai_cases"])
    assert benchmark.main() == 0
    out = capsys.readouterr().out
    assert "[MISS] [holdout] java/placeholder_llm_sql.java" in out
    assert "[MISS] [holdout] go/placeholder_mcp_exec.go" in out
    assert "[OK  ] python/llm_sql.py" in out
    assert "overall recall:    33.3% (1/3)" in out
    assert "REGRESSION" not in out


def test_main_fails_when_ai_cases_recall_drops_below_baseline(monkeypatch, capsys, tmp_path):
    benchmark = _load_benchmark_module()
    _point_benchmark_at(
        benchmark, monkeypatch, _seed_corpus(tmp_path),
        {"ai_cases_recall": 1 / 3, "ai_cases_regression": 1.0, "ai_cases_holdout": 0.0},
    )
    monkeypatch.setattr(benchmark, "_scan_dir_retrying", lambda target, **_k: ([], {}))
    monkeypatch.setattr(sys, "argv", ["benchmark.py", "--corpus", "ai_cases"])
    assert benchmark.main() == 1
    out = capsys.readouterr().out
    assert "REGRESSION: ai_cases_recall=0.0000 fell below baseline 0.3333" in out
    assert "REGRESSION: ai_cases_regression=0.0000 fell below baseline 1.0000" in out


def test_run_ai_cases_refuses_degraded_scan(monkeypatch):
    benchmark = _load_benchmark_module()
    monkeypatch.setattr(
        benchmark, "_scan_dir_retrying", lambda target, **_k: ([], {"opengrep": "exit 2"})
    )
    report = benchmark.run_ai_cases(CORPUS)
    assert report["degraded"] == {"opengrep": "exit 2"}
    assert report["results"] == []


@pytest.mark.skipif(
    not OpengrepAdapter().is_installed(),
    reason="Opengrep binary not installed; this test needs a live taint scan.",
)
def test_real_scan_detects_python_seed(tmp_path):
    """Integration path: the real scanner (taint on) credits the Python seed.
    Only the Python case is copied so the test runs one scan, not three."""
    benchmark = _load_benchmark_module()
    seed = "python/llm_sql.py"
    (tmp_path / "python").mkdir()
    shutil.copy(CORPUS / seed, tmp_path / seed)
    manifest = json.loads((CORPUS / "manifest.json").read_text(encoding="utf-8"))
    cases = [c for c in manifest["cases"] if c["file"] == seed]
    (tmp_path / "manifest.json").write_text(json.dumps({"cases": cases}), encoding="utf-8")

    report = benchmark.run_ai_cases(tmp_path)
    assert report["degraded"] == {}
    (result,) = report["results"]
    assert result.found, "TNT-LLMOUT-001 did not fire on the seed; vuln_cases (taint off) would hide this"
    assert result.matched_rule_ids == ["TNT-LLMOUT-001"]
    assert report["scores"]["overall"]["recall"] == 1.0
