"""Tests for the ai_apps benchmark corpus (BACKLOG JG-11, PY-02).

ai_apps holds three small deliberately vulnerable oracle apps (Java Spring
AI, Go mcp-go, Python FastAPI over the current agent SDKs) under
benchmark/ground_truth/ai_apps/*/, each with a Langfail-shaped
ground_truth.yaml. Unlike ai_cases (isolated snippets), these apps
carry the multi-file controller -> service -> tool/agent shapes the JG-09/
JG-11 surveys found in real repos, so recall here is where the JG-13
cross-file decision gets its numbers.

Most tests here validate the shipped ground truth or mock the scan; the last
one runs the real scanner on the Go app and is skipped when Opengrep is not
installed.
"""

from __future__ import annotations

import importlib.util
import json
import re
import sys
from pathlib import Path

import pytest
import yaml

from rowan.core.findings import Category, Finding, Severity
from rowan.taint.opengrep_adapter import OpengrepAdapter

REPO = Path(__file__).parent.parent
AI_APPS_DIR = REPO / "benchmark" / "ground_truth" / "ai_apps"
JAVA_APP = AI_APPS_DIR / "java"
GO_APP = AI_APPS_DIR / "go"
PYTHON_APP = AI_APPS_DIR / "python"
RULE_ID_RE = re.compile(r"^(?:tnt-(?:ja|go)-ai-|CF-(?:JAVA|GO)-)")
PYTHON_RULE_ID_RE = re.compile(r"^(?:tnt-py-ai-|TNT-|ns-aiml-|NS-|CF-|AGENT-|MCP-)")

# Expected ids that no rule or pass emits yet. Every expected_rule_ids entry
# in every app must either exist today (an `id:` in rules/*.yaml or a quoted
# literal in rowan/passes/*.py) or be listed here, so a typo cannot hide
# behind "the rule has not landed yet". Remove an id from this set when its
# rule lands.
PLANNED_RULE_IDS = frozenset(
    {
        # JG-12: Go system-prompt rule, decided but not written.
        "tnt-go-ai-sysprompt-001",
        # PY-04..PY-08 (BACKLOG.md "Python agent-surface defence").
        "tnt-py-ai-localexec-001",
        "tnt-py-ai-bypassperm-001",
        "tnt-py-ai-msghistory-001",
        "tnt-py-ai-mcpopenapi-001",
        "tnt-py-ai-mcpauth-001",
        "tnt-py-ai-sessionscope-001",
        "tnt-py-ai-handoffpriv-001",
        "tnt-py-ai-hitl-001",
        "tnt-py-ai-skfilter-001",
        "tnt-py-ai-sktemplate-001",
    }
)


def _existing_rule_ids() -> set[str]:
    """Rule ids that exist today: `- id: X` in rules/**/*.yaml, or a quoted
    "X" literal in rowan/passes/*.py (the passes name their ids as
    string constants or inline `rule_id="X"` arguments)."""
    ids: set[str] = set()
    for path in (REPO / "rules").rglob("*.yaml"):
        ids.update(re.findall(r"^\s*-\s*id:\s*([\w-]+)\s*$", path.read_text(encoding="utf-8"), re.M))
    for path in (REPO / "rowan" / "passes").glob("*.py"):
        ids.update(re.findall(r'"([A-Za-z]+(?:-[A-Za-z0-9]+)+-\d{3})"', path.read_text(encoding="utf-8")))
    return ids


def _load_benchmark_module():
    script_path = Path(__file__).parent.parent / "scripts" / "benchmark.py"
    spec = importlib.util.spec_from_file_location("benchmark_ai_apps", script_path)
    module = importlib.util.module_from_spec(spec)
    sys.modules["benchmark_ai_apps"] = module
    spec.loader.exec_module(module)
    return module


def _finding(rule_id: str, file_path: Path, line: int):
    return Finding(
        rule_id=rule_id, message=rule_id, severity=Severity.HIGH,
        category=Category.GENERAL, file_path=str(file_path), start_line=line,
    )


def _validate_ground_truth(app_dir: Path, gt: dict, rule_id_re: re.Pattern = RULE_ID_RE) -> list[str]:
    """Every source/sink/decoy file must exist under app_dir, every symbol
    given must appear (as a whole word) somewhere in that file, and every
    expected_rule_ids entry must match rule_id_re."""
    errors: list[str] = []

    def _check_location(owner_id: str, role: str, entry: dict) -> None:
        file = entry.get("file")
        if not file:
            return
        path = app_dir / file
        if not path.is_file():
            errors.append(f"{owner_id}: {role}.file {file!r} does not exist under {app_dir}")
            return
        symbol = entry.get("symbol")
        if symbol and not re.search(r"\b" + re.escape(symbol) + r"\b", path.read_text(encoding="utf-8")):
            errors.append(f"{owner_id}: {role}.symbol {symbol!r} not found in {file}")

    def _check_rule_ids(owner_id: str, rule_ids) -> None:
        for rid in rule_ids or []:
            if not rule_id_re.match(rid):
                errors.append(f"{owner_id}: expected_rule_id {rid!r} does not match {rule_id_re.pattern!r}")

    for v in gt.get("vulnerabilities", []):
        vid = v.get("id", "?")
        _check_location(vid, "source", v.get("source") or {})
        _check_location(vid, "sink", v.get("sink") or {})
        _check_rule_ids(vid, v.get("expected_rule_ids"))

    for d in gt.get("decoys", []):
        did = d.get("id", "?")
        _check_location(did, "location", d.get("location") or {})
        _check_rule_ids(did, d.get("expected_rule_ids"))

    return errors


@pytest.mark.parametrize(
    "app_dir,expected_prefix",
    [(JAVA_APP, "tnt-ja-ai-"), (GO_APP, "tnt-go-ai-")],
    ids=["java", "go"],
)
def test_ground_truth_references_resolve(app_dir, expected_prefix):
    gt = yaml.safe_load((app_dir / "ground_truth.yaml").read_text(encoding="utf-8"))
    errors = _validate_ground_truth(app_dir, gt)
    assert errors == [], "\n".join(errors)

    rule_ids = [
        rid
        for entry in gt.get("vulnerabilities", []) + gt.get("decoys", [])
        for rid in entry.get("expected_rule_ids") or []
    ]
    assert rule_ids, "ground truth carries no expected_rule_ids at all"
    cross_file_prefix = "CF-JAVA-" if expected_prefix == "tnt-ja-ai-" else "CF-GO-"
    assert all(rid.startswith((expected_prefix, cross_file_prefix)) for rid in rule_ids)


def test_python_ground_truth_references_resolve():
    gt = yaml.safe_load((PYTHON_APP / "ground_truth.yaml").read_text(encoding="utf-8"))
    errors = _validate_ground_truth(PYTHON_APP, gt, PYTHON_RULE_ID_RE)
    assert errors == [], "\n".join(errors)


@pytest.mark.parametrize("app_dir", [JAVA_APP, GO_APP, PYTHON_APP], ids=["java", "go", "python"])
def test_every_expected_rule_id_exists_or_is_planned(app_dir):
    """A typo in expected_rule_ids would otherwise read as a permanent MISS.
    Each id must be emitted by a rule or pass today, or sit in
    PLANNED_RULE_IDS; and every planned id that has since landed must be
    removed from that set so the allow-list does not rot."""
    gt = yaml.safe_load((app_dir / "ground_truth.yaml").read_text(encoding="utf-8"))
    existing = _existing_rule_ids()
    expected = {
        rid
        for entry in gt.get("vulnerabilities", []) + gt.get("decoys", [])
        for rid in entry.get("expected_rule_ids") or []
    }
    unknown = sorted(rid for rid in expected if rid not in existing and rid not in PLANNED_RULE_IDS)
    assert unknown == [], f"expected_rule_ids neither exist nor are planned: {unknown}"
    landed = sorted(rid for rid in expected if rid in existing and rid in PLANNED_RULE_IDS)
    assert landed == [], f"remove landed ids from PLANNED_RULE_IDS: {landed}"


def test_python_planned_ids_are_marked_in_notes():
    """Every planned id on a Python vulnerability says so in `notes`, so the
    ground truth reads correctly on its own."""
    gt = yaml.safe_load((PYTHON_APP / "ground_truth.yaml").read_text(encoding="utf-8"))
    unmarked = [
        v["id"]
        for v in gt["vulnerabilities"]
        if any(rid in PLANNED_RULE_IDS for rid in v.get("expected_rule_ids") or [])
        and "PLANNED" not in (v.get("notes") or "")
    ]
    assert unmarked == [], f"planned ids without a PLANNED note: {unmarked}"


def test_python_planned_ids_each_have_an_ai_case():
    """PY-02: one ai_cases/python fixture per planned Python id, pool holdout."""
    manifest = json.loads(
        (REPO / "benchmark" / "ground_truth" / "ai_cases" / "manifest.json").read_text(encoding="utf-8")
    )
    by_rule = {c["expected_rule_id"]: c for c in manifest["cases"] if c["language"] == "python"}
    planned_python = {rid for rid in PLANNED_RULE_IDS if rid.startswith("tnt-py-ai-")}
    missing = sorted(planned_python - set(by_rule))
    assert missing == [], f"planned Python ids without an ai_cases fixture: {missing}"
    for rid in planned_python:
        assert by_rule[rid].get("pool") == "holdout", rid


@pytest.mark.parametrize("app_dir", [JAVA_APP, GO_APP, PYTHON_APP], ids=["java", "go", "python"])
def test_ground_truth_has_all_three_tiers(app_dir):
    gt = yaml.safe_load((app_dir / "ground_truth.yaml").read_text(encoding="utf-8"))
    tiers = {v.get("tier") for v in gt.get("vulnerabilities", [])}
    assert tiers == {1, 2, 3}, f"expected tiers 1/2/3, got {tiers}"


@pytest.mark.parametrize("app_dir", [JAVA_APP, GO_APP], ids=["java", "go"])
def test_ground_truth_seeds_10_to_15_vulns_and_has_decoys(app_dir):
    gt = yaml.safe_load((app_dir / "ground_truth.yaml").read_text(encoding="utf-8"))
    vulns = gt.get("vulnerabilities", [])
    decoys = gt.get("decoys", [])
    assert 10 <= len(vulns) <= 15
    assert len(decoys) >= 3
    assert len({v["id"] for v in vulns}) == len(vulns), "duplicate vulnerability id"
    assert len({d["id"] for d in decoys}) == len(decoys), "duplicate decoy id"


def test_python_ground_truth_seeds_22_to_26_vulns_and_has_decoys():
    gt = yaml.safe_load((PYTHON_APP / "ground_truth.yaml").read_text(encoding="utf-8"))
    vulns = gt.get("vulnerabilities", [])
    decoys = gt.get("decoys", [])
    assert 22 <= len(vulns) <= 26
    assert len(decoys) >= 5
    assert len({v["id"] for v in vulns}) == len(vulns), "duplicate vulnerability id"
    assert len({d["id"] for d in decoys}) == len(decoys), "duplicate decoy id"


def test_python_decoys_resolve_to_a_function_scope():
    """Python decoy scoring is symbol-scoped through the AST resolver; a decoy
    whose symbol is not a def would fall back to file-level matching and be
    blamed for the real finding it sits next to."""
    benchmark = _load_benchmark_module()
    gt = yaml.safe_load((PYTHON_APP / "ground_truth.yaml").read_text(encoding="utf-8"))
    for d in gt["decoys"]:
        loc = d["location"]
        assert benchmark._function_line_range(PYTHON_APP / loc["file"], loc["symbol"]) is not None, d["id"]


def test_ai_app_decoy_fp_scopes_python_decoy_by_function(tmp_path):
    """A finding inside the vulnerable sibling function must not be blamed on
    the decoy next to it in the same .py file."""
    benchmark = _load_benchmark_module()
    app_dir = tmp_path / "python"
    app_dir.mkdir()
    src = app_dir / "tools.py"
    src.write_text(
        "def read(path):\n"
        "    return open(path).read()\n"
        "\n"
        "def read_safe(path):\n"
        "    if not ok(path):\n"
        "        return ''\n"
        "    return open(path).read()\n",
        encoding="utf-8",
    )
    index = [(str(src), 2, "AGENT-TOOL-001")]
    assert benchmark._ai_app_decoy_fp(index, app_dir, "tools.py", "read_safe", ["AGENT-TOOL-001"]) is False
    index = [(str(src), 7, "AGENT-TOOL-001")]
    assert benchmark._ai_app_decoy_fp(index, app_dir, "tools.py", "read_safe", ["AGENT-TOOL-001"]) is True


def test_brace_scope_line_range_go_ignores_call_site_before_declaration(tmp_path):
    """Regression test: a call site like `go startDebugServer(s)` also
    matches a bare `\\bsymbol\\s*(` search and must not be mistaken for the
    function's own declaration line."""
    benchmark = _load_benchmark_module()
    src = tmp_path / "widget.go"
    src.write_text(
        "package widget\n"
        "\n"
        "func caller() {\n"
        '\tHandlerSafe("x")\n'
        "}\n"
        "\n"
        "func Handler(ctx string) string {\n"
        "\treturn sink(ctx)\n"
        "}\n"
        "\n"
        "func HandlerSafe(ctx string) string {\n"
        "\tif !allowed(ctx) {\n"
        '\t\treturn ""\n'
        "\t}\n"
        "\treturn sink(ctx)\n"
        "}\n",
        encoding="utf-8",
    )
    assert benchmark._brace_scope_line_range(src, "Handler") == (7, 9)
    assert benchmark._brace_scope_line_range(src, "HandlerSafe") == (11, 16)


def test_brace_scope_line_range_java_ignores_call_site_before_declaration(tmp_path):
    benchmark = _load_benchmark_module()
    src = tmp_path / "Widget.java"
    src.write_text(
        "class Widget {\n"
        "    void caller() {\n"
        '        runAction("x");\n'
        "    }\n"
        "\n"
        "    public String runAction(String action) {\n"
        "        return sink(action);\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )
    assert benchmark._brace_scope_line_range(src, "runAction") == (6, 8)


def _write_app(root: Path, name: str, source: str, gt: dict) -> Path:
    app_dir = root / name
    app_dir.mkdir(parents=True)
    (app_dir / "widget.go").write_text(source, encoding="utf-8")
    (app_dir / "ground_truth.yaml").write_text(yaml.safe_dump(gt), encoding="utf-8")
    return app_dir


_MOCK_SOURCE = (
    "package widget\n"
    "\n"
    "func Handler(ctx string) string {\n"
    "\treturn sink(ctx)\n"
    "}\n"
    "\n"
    "func HandlerSafe(ctx string) string {\n"
    "\tif !allowed(ctx) {\n"
    '\t\treturn ""\n'
    "\t}\n"
    "\treturn sink(ctx)\n"
    "}\n"
)

_MOCK_GT = {
    "meta": {"app": "widget-app"},
    "vulnerabilities": [
        {
            "id": "W-01",
            "tier": 1,
            "sink": {"file": "widget.go", "symbol": "Handler", "line_hint": 4},
            "expected_rule_ids": ["tnt-go-ai-mcptool-exec-001"],
        }
    ],
    "decoys": [
        {
            "id": "WD-01",
            "location": {"file": "widget.go", "symbol": "HandlerSafe"},
            "expected_rule_ids": ["tnt-go-ai-mcptool-exec-001"],
        }
    ],
}


def test_run_ai_apps_scores_hit_and_ignores_out_of_window_finding(monkeypatch, tmp_path):
    """A finding at the sink's line_hint is a HIT; the same rule firing
    elsewhere in the file (here, inside the decoy's own body, well outside
    the +/-5 line window) must not credit the vulnerability."""
    benchmark = _load_benchmark_module()
    root = tmp_path / "ai_apps"
    root.mkdir()
    app_dir = _write_app(root, "go", _MOCK_SOURCE, _MOCK_GT)
    monkeypatch.setattr(benchmark, "AI_APPS_DIR", root)

    def fake_scan(target: Path, **_kwargs):
        assert target == app_dir
        return [
            _finding("tnt-go-ai-mcptool-exec-001", app_dir / "widget.go", 4),
            _finding("tnt-go-ai-mcptool-exec-001", app_dir / "widget.go", 11),
        ], {}

    monkeypatch.setattr(benchmark, "_scan_dir_retrying", fake_scan)
    report = benchmark.run_ai_apps()

    app = report["apps"]["go"]
    assert app["degraded"] == {}
    assert app["hits"] == 1
    assert app["total"] == 1
    assert app["rows"][0]["hit"] is True
    assert app["decoy_fp_ids"] == ["WD-01"]


def test_run_ai_apps_no_decoy_false_positive_when_only_vuln_fires(monkeypatch, tmp_path):
    benchmark = _load_benchmark_module()
    root = tmp_path / "ai_apps"
    root.mkdir()
    app_dir = _write_app(root, "go", _MOCK_SOURCE, _MOCK_GT)
    monkeypatch.setattr(benchmark, "AI_APPS_DIR", root)

    monkeypatch.setattr(
        benchmark,
        "_scan_dir_retrying",
        lambda target, **_k: ([_finding("tnt-go-ai-mcptool-exec-001", app_dir / "widget.go", 4)], {}),
    )
    report = benchmark.run_ai_apps()
    app = report["apps"]["go"]
    assert app["hits"] == 1
    assert app["decoy_fp_ids"] == []


def test_run_ai_apps_records_miss_when_expected_rule_absent(monkeypatch, tmp_path):
    benchmark = _load_benchmark_module()
    root = tmp_path / "ai_apps"
    root.mkdir()
    _write_app(root, "go", _MOCK_SOURCE, _MOCK_GT)
    monkeypatch.setattr(benchmark, "AI_APPS_DIR", root)
    monkeypatch.setattr(benchmark, "_scan_dir_retrying", lambda target, **_k: ([], {}))

    report = benchmark.run_ai_apps()
    app = report["apps"]["go"]
    assert app["hits"] == 0
    assert app["rows"][0]["hit"] is False
    assert app["recall"] == 0.0
    assert app["decoy_fp_ids"] == []


def test_run_ai_apps_refuses_degraded_scan(monkeypatch, tmp_path):
    benchmark = _load_benchmark_module()
    root = tmp_path / "ai_apps"
    root.mkdir()
    _write_app(root, "go", _MOCK_SOURCE, _MOCK_GT)
    monkeypatch.setattr(benchmark, "AI_APPS_DIR", root)
    monkeypatch.setattr(
        benchmark, "_scan_dir_retrying", lambda target, **_k: ([], {"opengrep": "exit 2"})
    )

    report = benchmark.run_ai_apps()
    assert report["apps"]["go"]["degraded"] == {"opengrep": "exit 2"}
    assert "rows" not in report["apps"]["go"]


def test_run_ai_apps_returns_none_without_any_ground_truth(tmp_path, monkeypatch):
    benchmark = _load_benchmark_module()
    empty = tmp_path / "ai_apps"
    empty.mkdir()
    monkeypatch.setattr(benchmark, "AI_APPS_DIR", empty)
    assert benchmark.run_ai_apps() is None


@pytest.mark.skipif(
    not OpengrepAdapter().is_installed(),
    reason="Opengrep binary not installed; this test needs a live taint scan.",
)
def test_real_scan_on_go_app_matches_ground_truth_shape():
    """Integration path: the real scanner runs taint+cross-file over the
    committed Go oracle app. Assert on shape (counts, not which specific
    rules currently fire) since the JG-04..06/JG-10 rules are landing in
    concurrent work and individual hit/miss outcomes will keep changing."""
    benchmark = _load_benchmark_module()
    report = benchmark.run_ai_apps()
    assert report is not None
    app = report["apps"]["go"]
    assert app["degraded"] == {}
    gt = yaml.safe_load((GO_APP / "ground_truth.yaml").read_text(encoding="utf-8"))
    assert app["total"] == len(gt["vulnerabilities"])
    assert app["decoy_total"] == len(gt["decoys"])
    assert 0.0 <= app["recall"] <= 1.0
