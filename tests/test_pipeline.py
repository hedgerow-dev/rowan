"""Tests for pipeline components."""

from pathlib import Path
from threading import Barrier

import pytest
from hayward import ModelFileScanner

import rowan.pipeline as pipeline_module
from rowan.config import ScanConfig
from rowan.core.findings import Category, Finding, ScanResult, Severity
from rowan.core.rules import load_neuroscan_rules
from rowan.passes.enrichment import EnrichmentPass
from rowan.passes.file_scan import FileScanPass
from rowan.pipeline import ScanPipeline
from rowan.scan_plan import PlannedPass, ScanPlan
from rowan.taint.opengrep_adapter import OpengrepAdapter


def test_neuroscan_rules_load():
    """Verify NeuroScan rules load correctly."""
    rules_dir = Path(__file__).parent.parent / "rules"
    neuroscan_path = rules_dir / "neuroscan.yaml"

    if not neuroscan_path.exists():
        pytest.fail("rules/neuroscan.yaml not found")

    rules = load_neuroscan_rules(neuroscan_path)
    assert len(rules) > 0
    assert all(r.metadata.id for r in rules)
    assert all(r.metadata.severity for r in rules)
    assert all(r.metadata.category for r in rules)


def test_missing_opengrep_is_incomplete_and_not_advertised_as_dataflow(tmp_path, monkeypatch):
    (tmp_path / "app.php").write_text("<?php eval($_GET['code']);\n", encoding="utf-8")
    monkeypatch.setattr(OpengrepAdapter, "is_installed", lambda self: False)

    result = ScanPipeline(ScanConfig(target=tmp_path, no_sca=True)).run()

    assert result.degraded is True
    assert "taint" in result.degraded_passes
    capability = result.metadata["analysis_capability"]
    assert capability["opengrep_status"] == "unavailable"
    assert capability["dataflow_languages"] == []
    assert capability["cross_file_languages"] == []
    assert "php" in capability["patterns_only_languages"]


def test_unsupported_source_languages_are_reported_in_capability(tmp_path, monkeypatch):
    (tmp_path / "app.py").write_text("value = 1\n", encoding="utf-8")
    (tmp_path / "b.swift").write_text("val x = 1\n", encoding="utf-8")
    (tmp_path / "c").mkdir()
    (tmp_path / "c" / "d.swift").write_text("val x = 1\n", encoding="utf-8")
    (tmp_path / "e.scala").write_text("val x = 1\n", encoding="utf-8")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "x.swift").write_text("val x = 1\n", encoding="utf-8")
    monkeypatch.setattr(OpengrepAdapter, "is_installed", lambda self: False)

    result = ScanPipeline(ScanConfig(target=tmp_path, no_sca=True)).run()

    capability = result.metadata["analysis_capability"]
    assert capability["unsupported_languages"] == {"swift": 2, "scala": 1}


def test_empty_language_scope_needs_no_engine_and_advertises_no_dataflow(tmp_path, monkeypatch):
    def unexpected_probe(self):
        raise AssertionError("an empty authoritative scope must not probe Opengrep")

    monkeypatch.setattr(OpengrepAdapter, "is_installed", unexpected_probe)

    result = ScanPipeline(ScanConfig(target=tmp_path, languages=["rust"], no_sca=True)).run()

    assert result.files_scanned == 0
    assert result.degraded is False
    assert result.metadata["analysis_capability"]["dataflow_languages"] == []
    taint = next(
        outcome for outcome in result.metadata["pass_outcomes"] if outcome["name"] == "taint"
    )
    assert taint["status"] == "completed"


def test_javascript_scope_never_parses_python_sources(tmp_path):
    (tmp_path / "ignored.py").write_text(
        "import pickle\npickle.loads(user_input)\n", encoding="utf-8"
    )
    (tmp_path / "app.js").write_text("const value = input;\n", encoding="utf-8")

    result = ScanPipeline(
        ScanConfig(
            target=tmp_path,
            languages=["javascript"],
            no_sca=True,
            no_taint=True,
            legacy_neuroscan=True,
        )
    ).run()

    assert result.metadata["scope_summary"] == {
        "source_files": 1,
        "languages": {"javascript": 1},
    }
    assert result.metadata["source_snapshot"]["python_ast_misses"] == 0
    assert all(f.file_path != str(tmp_path / "ignored.py") for f in result.findings)


def test_pipeline_marks_proven_empty_specialist_inputs_not_applicable(tmp_path):
    (tmp_path / "app.py").write_text("print('ok')\n", encoding="utf-8")

    result = ScanPipeline(
        ScanConfig(
            target=tmp_path,
            no_sca=True,
            no_taint=True,
            legacy_neuroscan=True,
        )
    ).run()

    executed = {item["name"] for item in result.metadata["pass_outcomes"]}
    inapplicable = {item["name"]: item["reason"] for item in result.metadata["inapplicable_passes"]}
    assert {"mfv", "mcpconfig"}.isdisjoint(executed)
    assert inapplicable["mfv"] == "no model artifacts in resolved inventory"
    assert inapplicable["mcpconfig"] == "no MCP configuration files in resolved inventory"
    assert inapplicable["instruction_smuggling"] == "no instruction/prose files in resolved inventory"


def test_route_only_passes_skip_without_http_routes(tmp_path):
    def scan():
        return ScanPipeline(
            ScanConfig(target=tmp_path, no_sca=True, no_taint=True, legacy_neuroscan=True)
        ).run()

    route_only = {"model_extraction", "membership_inference"}
    (tmp_path / "app.py").write_text(
        "@mock.patch('os.path.exists')\ndef check(exists):\n    return 1\n", encoding="utf-8"
    )

    result = scan()

    executed = {item["name"] for item in result.metadata["pass_outcomes"]}
    inapplicable = {item["name"]: item["reason"] for item in result.metadata["inapplicable_passes"]}
    assert route_only.isdisjoint(executed)
    for name in route_only:
        assert inapplicable[name] == "no HTTP route handlers in Python sources"

    (tmp_path / "api.py").write_text(
        "@app.post('/predict')\ndef predict():\n    return 1\n", encoding="utf-8"
    )

    result = scan()

    assert route_only <= {item["name"] for item in result.metadata["pass_outcomes"]}


def test_pipeline_records_pass_outcomes(tmp_path):
    (tmp_path / "app.py").write_text("print('ok')\n", encoding="utf-8")

    result = ScanPipeline(
        ScanConfig(
            target=tmp_path,
            no_sca=True,
            no_taint=True,
            no_cross_file=True,
            legacy_neuroscan=True,
        )
    ).run()

    outcomes = result.metadata["pass_outcomes"]
    assert outcomes
    assert outcomes[0]["name"] == "file_scan"
    assert all(outcome["status"] in {"completed", "degraded"} for outcome in outcomes)
    assert all(outcome["duration_seconds"] >= 0 for outcome in outcomes)
    assert all(outcome["files_scanned"] >= 0 for outcome in outcomes)
    assert all(isinstance(outcome["findings_delta"], int) for outcome in outcomes)
    skipped = {outcome["name"]: outcome for outcome in result.metadata["skipped_passes"]}
    assert skipped["taint"]["reason"] == "no_taint with legacy_neuroscan"
    assert skipped["sca"]["reason"] == "no_sca"
    assert skipped["crossfile"]["reason"] == "no_cross_file"
    assert skipped["authz"]["reason"] == "authz not enabled"
    assert skipped["multiagent"]["reason"] == "multiagent not enabled"
    assert all(outcome["status"] == "explicitly_disabled" for outcome in skipped.values())
    assert result.metadata["scope_summary"] == {
        "source_files": 1,
        "languages": {"python": 1},
    }
    assert result.metadata["source_snapshot"]["read_failures"] == 0
    assert result.metadata["source_snapshot"]["parse_failures"] == 0
    assert result.metadata["resolved_policy"] == {
        "report_view": "full",
        "name": "default",
        "contract": {
            "deterministic": True,
            "source_analysis": "local",
            "llm": False,
            "source_egress": False,
            "advisory_network": False,
            "live_target": False,
        },
        "languages": ["all"],
        "sca": False,
        "taint": False,
        "converted_regex": False,
        "cross_file": False,
        "authz": False,
        "multiagent": False,
        "profile": "auto",
    }
    assert result.metadata["filter_counts"] == {
        "pre_ast_enrichment": len(result.findings),
        "post_ast_enrichment": len(result.findings),
        "pre_enrichment": len(result.findings),
        "post_enrichment": len(result.findings),
        "pre_view": len(result.findings),
        "post_view": len(result.findings),
        "post_severity": len(result.findings),
        "post_baseline": len(result.findings),
        "post_ignore": len(result.findings),
    }
    assert result.metadata["view"] == "full"
    assert result.metadata["coverage_summary"] == {
        "status": "complete",
        "selected_passes": len(outcomes) + len(result.metadata["inapplicable_passes"]),
        "completed_passes": len(outcomes),
        "not_applicable_passes": len(result.metadata["inapplicable_passes"]),
        "explicitly_disabled_passes": len(skipped),
        "incomplete_passes": [],
    }


def test_pipeline_stages_independent_detectors_and_merges_in_plan_order(tmp_path, monkeypatch):
    """Independent detection overlaps, but correlation waits for every result."""
    events: list[str] = []
    detector_barrier = Barrier(2)

    class Step:
        def __init__(self, name: str):
            self.name = name

        def run(self, context):
            events.append(f"start:{self.name}")
            if self.name in {"detector-a", "detector-b"}:
                detector_barrier.wait(timeout=1)
                events.append(f"done:{self.name}")
            elif self.name in {"crossfile", "js_crossfile"}:
                assert {"done:detector-a", "done:detector-b"} <= set(events)
            return ScanResult()

    names = (
        "file_scan",
        "detector-a",
        "detector-b",
        "crossfile",
        "js_crossfile",
        "ast_enrichment",
        "enrichment",
    )
    plan = ScanPlan(
        tuple(
            PlannedPass(name, True, "test", lambda runtime, name=name: Step(name)) for name in names
        ),
        {
            "name": "test",
            "contract": {},
            "report_view": "full",
            "languages": ["all"],
            "sca": False,
            "taint_dataflow": False,
            "converted_regex": False,
            "cross_file": True,
            "authz": False,
            "multiagent": False,
            "profile": "auto",
        },
    )
    monkeypatch.setattr(pipeline_module, "build_scan_plan", lambda config: plan)

    result = ScanPipeline(ScanConfig(target=tmp_path, concurrency=2)).run()

    outcomes = result.metadata["pass_outcomes"]
    assert [item["name"] for item in outcomes] == list(names)
    assert [item["stage"] for item in outcomes] == [
        "discovery",
        "detection",
        "detection",
        "correlation",
        "correlation",
        "enrichment",
        "enrichment",
    ]
    assert {"done:detector-a", "done:detector-b"} <= set(events)


def test_actionable_view_keeps_mfv_coverage_health_when_skip_is_hidden(tmp_path, monkeypatch):
    monkeypatch.setattr(ModelFileScanner, "MAX_SCAN_BYTES", 16)
    (tmp_path / "oversized.pkl").write_bytes(b"x" * 17)

    result = ScanPipeline(
        ScanConfig(
            target=tmp_path,
            no_sca=True,
            no_taint=True,
            no_cross_file=True,
            legacy_neuroscan=True,
            report_view="actionable",
        )
    ).run()

    assert not any(f.rule_id == "MFV-SKIP-001" for f in result.findings)
    assert result.degraded is True
    assert "mfv" in result.degraded_passes
    assert result.metadata["mfv_coverage"] == {
        "status": "incomplete",
        "skipped_artifacts": 1,
        "skip_reasons": ["MFV-SKIP-001"],
    }


def test_python_parse_failure_marks_scan_degraded(tmp_path):
    (tmp_path / "broken.py").write_text("def broken(:\n", encoding="utf-8")

    result = ScanPipeline(
        ScanConfig(
            target=tmp_path,
            no_sca=True,
            no_taint=True,
            no_cross_file=True,
            legacy_neuroscan=True,
        )
    ).run()

    assert result.degraded is True
    assert result.metadata["source_snapshot"]["parse_failures"] == 1
    assert "1 Python parse failure" in result.degraded_passes["source_snapshot"]


def test_file_scan_pass(test_project_dir):
    """Test file scan pass detects vulnerable patterns."""
    rules_dir = Path(__file__).parent.parent / "rules"
    neuroscan_path = rules_dir / "neuroscan.yaml"

    if not neuroscan_path.exists():
        pytest.fail("rules/neuroscan.yaml not found")

    rules = load_neuroscan_rules(neuroscan_path)
    assert len(rules) > 0

    config = ScanConfig(target=test_project_dir)
    ctx = type(
        "Ctx",
        (),
        {"target_path": test_project_dir, "config": config, "result": ScanResult(), "metadata": {}},
    )()

    fs_pass = FileScanPass(rules)
    result = fs_pass.run(ctx)

    assert result.files_scanned > 0

    # Check that vulnerable files produce findings
    rule_ids = {f.rule_id for f in result.findings}
    assert len(rule_ids) > 0

    # Print diagnostic info
    for f in result.findings:
        print(f"  {f.severity.value.upper():8s} {f.rule_id:20s} {f.file_path}:{f.start_line}")


def test_enrichment_dedup():
    """Test enrichment pass deduplication."""
    from rowan.core.findings import Category, Finding

    ctx = type(
        "Ctx",
        (),
        {
            "target_path": Path("."),
            "config": ScanConfig(target=Path(".")),
            "result": ScanResult(
                findings=[
                    Finding(
                        rule_id="TEST-001",
                        message="Test",
                        severity=Severity.HIGH,
                        category=Category.GENERAL,
                        file_path="a.py",
                        start_line=10,
                    ),
                    Finding(
                        rule_id="TEST-001",
                        message="Test",
                        severity=Severity.HIGH,
                        category=Category.GENERAL,
                        file_path="a.py",
                        start_line=10,
                    ),
                    Finding(
                        rule_id="TEST-001",
                        message="Test",
                        severity=Severity.HIGH,
                        category=Category.GENERAL,
                        file_path="a.py",
                        start_line=10,
                    ),
                ]
            ),
            "metadata": {},
        },
    )()

    enrich = EnrichmentPass(dedup_threshold=3)
    enrich.run(ctx)

    assert len(ctx.result.findings) == 1


def test_enrichment_confidence():
    """Test confidence scoring in enrichment."""
    from rowan.core.findings import Category, Finding, TaintFlow, TaintNode

    findings = [
        Finding(
            rule_id="TEST-001",
            message="Test",
            severity=Severity.HIGH,
            category=Category.GENERAL,
            file_path="a.py",
            start_line=10,
            engine="neuroscan",
            confidence=1.0,
        ),
        Finding(
            rule_id="TEST-002",
            message="Test",
            severity=Severity.HIGH,
            category=Category.GENERAL,
            file_path="b.py",
            start_line=20,
            engine="opengrep",
            confidence=1.0,
            taint_flow=TaintFlow(
                source=TaintNode(file_path="b.py", line=5),
                sink=TaintNode(file_path="b.py", line=20),
                intermediate=[],
            ),
        ),
    ]

    ctx = type(
        "Ctx",
        (),
        {
            "target_path": Path("."),
            "config": ScanConfig(target=Path(".")),
            "result": ScanResult(findings=findings),
            "metadata": {},
        },
    )()

    enrich = EnrichmentPass()
    enrich.run(ctx)

    neuro = next(f for f in ctx.result.findings if f.engine == "neuroscan")
    assert neuro.confidence <= 0.7

    taint = next(f for f in ctx.result.findings if f.engine == "opengrep")
    assert taint.confidence >= 0.80


def test_pipeline_on_fixtures(test_project_dir):
    """Integration test: run pipeline on test fixtures."""
    import logging

    logging.basicConfig(level=logging.WARNING)

    config = ScanConfig(
        target=test_project_dir,
        no_sca=True,
        no_taint=True,  # Skip Opengrep unless installed
        languages=["python"],
        legacy_neuroscan=True,
    )

    pipeline = ScanPipeline(config)
    result = pipeline.run()

    assert result.files_scanned > 0
    print(f"\n  Files: {result.files_scanned}, Findings: {result.total_count}")
    for f in result.findings:
        print(f"    {f.severity.value:8s} {f.rule_id:20s} {Path(f.file_path).name}:{f.start_line}")


def _finding(severity, category, *, tier=None, engine="opengrep"):
    f = Finding(
        rule_id="X",
        message="m",
        severity=severity,
        category=category,
        file_path="a.py",
        start_line=1,
        engine=engine,
    )
    if tier is not None:
        f.metadata["evidence_tier"] = tier
    return f


def test_actionable_view_predicate(tmp_path):
    """--actionable keeps HIGH/CRITICAL and dangerous-sink / computed-evidence /
    secret-crypto MEDIUM, and hides LOW/INFO and surface-signal MEDIUM."""
    pipe = ScanPipeline(ScanConfig(target=tmp_path))

    # HIGH/CRITICAL always shown regardless of category/tier.
    assert pipe._in_actionable_view(_finding(Severity.CRITICAL, Category.SSRF, tier="pattern-only"))
    assert pipe._in_actionable_view(_finding(Severity.HIGH, Category.AI_ML, tier="self-evident"))

    # LOW/INFO always hidden.
    assert not pipe._in_actionable_view(
        _finding(Severity.LOW, Category.DESERIALIZATION, tier="taint-flow")
    )
    assert not pipe._in_actionable_view(_finding(Severity.INFO, Category.INJECTION, tier="engine"))

    # MEDIUM kept when it names a dangerous sink even pattern-only (recall:
    # pickle/eval/sqli fixtures are detected pattern-only yet real).
    assert pipe._in_actionable_view(
        _finding(Severity.MEDIUM, Category.DESERIALIZATION, tier="pattern-only")
    )
    assert pipe._in_actionable_view(
        _finding(Severity.MEDIUM, Category.COMMAND_INJECTION, tier="pattern-only")
    )
    # MEDIUM kept with computed evidence regardless of category.
    assert pipe._in_actionable_view(_finding(Severity.MEDIUM, Category.SSRF, tier="taint-flow"))
    # MEDIUM kept for self-evident secret/crypto exposure.
    assert pipe._in_actionable_view(
        _finding(Severity.MEDIUM, Category.SECRETS, tier="self-evident")
    )
    assert pipe._in_actionable_view(_finding(Severity.MEDIUM, Category.CRYPTO, tier="self-evident"))

    # MEDIUM hidden for surface-signal noise: SSRF outbound-HTTP presence and
    # AI/ML "presence" rules with no computed evidence.
    assert not pipe._in_actionable_view(
        _finding(Severity.MEDIUM, Category.SSRF, tier="pattern-only")
    )
    assert not pipe._in_actionable_view(
        _finding(Severity.MEDIUM, Category.AI_ML, tier="self-evident")
    )
    assert not pipe._in_actionable_view(
        _finding(Severity.MEDIUM, Category.CONFIG, tier="self-evident")
    )


def test_actionable_flag_default_off_preserves_all_findings(tmp_path):
    """The ScanConfig default is the full view (library/tests see everything);
    the CLI is what defaults to the actionable view."""
    assert ScanConfig(target=tmp_path).report_view == "full"
    pipe = ScanPipeline(ScanConfig(target=tmp_path))
    # A surface-signal MEDIUM is out of the actionable view predicate.
    surface = _finding(Severity.MEDIUM, Category.SSRF, tier="pattern-only")
    assert not pipe._in_actionable_view(surface)  # would be hidden IF --actionable


def test_dom_xss_on_client_js_not_floored_to_info(tmp_path):
    """A DOM-XSS sink in a plain client-side .js file (no server framework
    import) must keep its severity, not be floored to INFO by the web-context
    gate -- it is a real reflected/DOM XSS. Regression for the vuln_cases
    innerhtml_xss.js case hidden by --actionable before the fix."""
    js = tmp_path / "widget.js"
    js.write_text("function render(el, s){ el.innerHTML = s; }\n", encoding="utf-8")

    finding = Finding(
        rule_id="NS-XSS-002",
        message="innerHTML DOM XSS sink",
        severity=Severity.MEDIUM,
        category=Category.XSS,
        file_path=str(js),
        start_line=1,
        engine="opengrep",
    )
    out = EnrichmentPass()._suppress_web_rules_on_non_web_files([finding])
    kept = out[0]
    assert kept.severity == Severity.MEDIUM, "client-side JS DOM-XSS must not be floored to INFO"
    assert not kept.metadata.get("web_context_gate")


def test_dom_xss_gate_still_floors_ssrf_on_client_js(tmp_path):
    """The client-JS exemption is scoped to XSS: a JS SSRF surface signal with
    no server import is still floored (that is the noise the gate exists for)."""
    js = tmp_path / "net.js"
    js.write_text("fetch(userUrl)\n", encoding="utf-8")
    finding = Finding(
        rule_id="NS-SSRF-103",
        message="outbound HTTP",
        severity=Severity.MEDIUM,
        category=Category.SSRF,
        file_path=str(js),
        start_line=1,
        engine="opengrep",
    )
    out = EnrichmentPass()._suppress_web_rules_on_non_web_files([finding])
    assert out[0].severity == Severity.INFO
    assert out[0].metadata.get("web_context_gate")


def test_sqli_on_user_id_param_not_suppressed_as_uuid(tmp_path):
    """`WHERE id = {user_id}` is textbook SQLi. The uuid-target suppressor must
    NOT downgrade it just because the variable name ends in `_id` -- that
    silently hid real SQLi. A genuine `_uuid` target stays suppressed."""

    def _sqli(fname, line_src):
        p = tmp_path / fname
        p.write_text(f"def q(cursor, x):\n    {line_src}\n", encoding="utf-8")
        f = Finding(
            rule_id="NS-SQLI-001",
            message="Raw SQL",
            severity=Severity.MEDIUM,
            category=Category.INJECTION,
            file_path=str(p),
            start_line=2,
            engine="opengrep",
        )
        return f

    ep = EnrichmentPass()
    user_id = _sqli("a.py", 'cursor.execute(f"SELECT * FROM t WHERE id = {user_id}")')
    row_uuid = _sqli("b.py", 'cursor.execute(f"SELECT * FROM t WHERE id = {row_uuid}")')

    out = ep._suppress_uuid_sql_targets([user_id, row_uuid])
    by_file = {Path(f.file_path).name: f for f in out}
    assert by_file["a.py"].severity == Severity.MEDIUM, "user_id SQLi must survive"
    assert not by_file["a.py"].metadata.get("uuid_sql_target")
    assert by_file["b.py"].metadata.get("uuid_sql_target"), "genuine _uuid target still suppressed"


def test_rule_class_taxonomy():
    """Surface/hygiene rules classify as inventory; everything else as
    vulnerability (the safe default)."""
    from rowan.core.rule_class import is_inventory_rule, rule_class

    for rid in ("ns-aiml-047", "NS-SSRF-001", "NS-SSRF-103", "ns-aiml-076", "RB-PATH-001"):
        assert is_inventory_rule(rid), rid
        assert rule_class(rid) == "inventory"
    # Real vulnerability rules (and unknown rule ids) default to vulnerability.
    for rid in ("NS-SQLI-001", "NS-DESER-001", "NS-AIML-001", "totally-unknown"):
        assert not is_inventory_rule(rid), rid
        assert rule_class(rid) == "vulnerability"


def test_actionable_hides_inventory_unless_computed(tmp_path):
    """A pattern-only inventory finding is a surface signal -> hidden from
    --actionable even at MEDIUM; the same rule with a proven taint flow is
    kept (the surface is backed by real dataflow)."""
    pipe = ScanPipeline(ScanConfig(target=tmp_path))

    inv_pattern = _finding(Severity.MEDIUM, Category.SSRF, tier="pattern-only")
    inv_pattern.rule_id = "NS-SSRF-001"
    assert not pipe._in_actionable_view(inv_pattern)

    inv_taint = _finding(Severity.MEDIUM, Category.SSRF, tier="taint-flow")
    inv_taint.rule_id = "NS-SSRF-001"
    assert pipe._in_actionable_view(inv_taint), "taint-backed inventory finding must be actionable"

    # An inventory rule that happens to be in a dangerous-sink category is
    # still hidden pattern-only (guard against category leaking it back in).
    inv_danger_cat = _finding(Severity.MEDIUM, Category.COMMAND_INJECTION, tier="pattern-only")
    inv_danger_cat.rule_id = "ns-aiml-076"
    assert not pipe._in_actionable_view(inv_danger_cat)


def test_confirmed_view_requires_taint_for_dangerous_medium(tmp_path):
    """--confirmed drops a pattern-only dangerous-sink MEDIUM but keeps the same
    finding when taint-confirmed (intra- OR cross-file), requires evidence even at HIGH/CRITICAL,
    and keeps self-evident secrets/crypto. This is the high-precision view."""
    pipe = ScanPipeline(ScanConfig(target=tmp_path))

    # Pattern-only dangerous-sink MEDIUM: kept by --actionable, dropped by --confirmed.
    patt = _finding(Severity.MEDIUM, Category.DESERIALIZATION, tier="pattern-only")
    assert pipe._in_actionable_view(patt)
    assert not pipe._in_confirmed_view(patt)

    # Taint-confirmed dangerous MEDIUM: kept by both (intra-file taint flow).
    taint = _finding(Severity.MEDIUM, Category.INJECTION, tier="taint-flow")
    assert pipe._in_confirmed_view(taint)
    unresolved = _finding(Severity.MEDIUM, Category.INJECTION, tier="taint-flow-unresolved")
    assert pipe._in_actionable_view(unresolved)
    assert not pipe._in_confirmed_view(unresolved)

    # Cross-file finding: CrossFilePass tags evidence_tier="taint-flow", so it is
    # kept by --confirmed -- cross-file taint is never dropped.
    xfile = _finding(Severity.MEDIUM, Category.INJECTION, tier="taint-flow", engine="crossfile")
    assert pipe._in_confirmed_view(xfile)

    # Severity cannot bypass the evidence requirement.
    assert not pipe._in_confirmed_view(
        _finding(Severity.HIGH, Category.COMMAND_INJECTION, tier="pattern-only")
    )
    # Self-evident secret/crypto kept (match is the finding, no dataflow claim).
    assert pipe._in_confirmed_view(_finding(Severity.MEDIUM, Category.SECRETS, tier="self-evident"))
    # LOW/INFO never kept.
    assert not pipe._in_confirmed_view(
        _finding(Severity.LOW, Category.INJECTION, tier="taint-flow")
    )


def test_log_forging_not_floored_to_high(tmp_path):
    """CWE-117 log forging rides the injection category + taint machinery but is
    not RCE, so the dangerous-sink HIGH floor must skip it while still flooring a
    real code-exec sink (CWE-502 pickle) in the same category."""
    js = tmp_path / "app.py"
    js.write_text(
        "from flask import request\n@app.route('/x')\ndef x():\n    pass\n", encoding="utf-8"
    )

    def mk(cwe):
        f = Finding(
            rule_id="R",
            message="m",
            severity=Severity.MEDIUM,
            category=Category.INJECTION,
            file_path=str(js),
            start_line=1,
            engine="opengrep",
            cwe_ids=[cwe],
        )
        # taint-flow present so the floor's evidence precondition is met
        from rowan.core.findings import TaintFlow, TaintNode

        f.taint_flow = TaintFlow(
            source=TaintNode(file_path=str(js), line=1, snippet="request.data"),
            sink=TaintNode(file_path=str(js), line=1),
        )
        return f

    log = mk(117)
    rce = mk(502)
    EnrichmentPass()._apply_sink_severity_floor([log, rce])
    assert log.severity == Severity.MEDIUM, "log forging (CWE-117) must not be floored to HIGH"
    assert rce.severity == Severity.HIGH, "pickle RCE (CWE-502) must still be floored to HIGH"


def test_go_operator_tooling_paths_are_no_attacker():
    """Go/dev operator-tooling dirs (tools/, cli/) are no-attacker context so a
    path-traversal there is capped, but a server entrypoint (cmd/.../main.go)
    and a real HTTP handler stay attacker-facing."""
    from rowan.analysis.test_paths import is_no_attacker_path

    assert is_no_attacker_path("tools/migrate-canvas/main.go")
    assert is_no_attacker_path("internal/cli/cli.go")
    # cmd/ holds the server main -> must NOT be capped; handlers stay in-scope.
    assert not is_no_attacker_path("cmd/server/main.go")
    assert not is_no_attacker_path("internal/handler/chat.go")


def test_authz_findings_survive_actionable_view(tmp_path):
    """BOLA/IDOR findings from the authz engines must not be dropped by the
    actionable view: they are only produced when the user opts into --authz,
    the profile filter must not floor them, and the view must keep them.
    Regression: js_authz corpus recall went to 0 in the actionable view."""
    from rowan.core.findings import ScanResult
    from rowan.passes.base import ScanContext

    for engine in ("authz", "js_authz"):
        f = Finding(
            rule_id="AUTHZ-BOLA-001",
            message="BOLA",
            severity=Severity.MEDIUM,
            category=Category.AUTH,
            file_path=str(tmp_path / "h.js"),
            start_line=1,
            engine=engine,
        )
        # profile filter must not demote an authz-engine finding even under the
        # library profile (whose disabled set includes AUTH).
        ctx = ScanContext(
            target_path=tmp_path,
            config=ScanConfig(target=tmp_path, profile="library"),
            result=ScanResult(findings=[f]),
        )
        out = EnrichmentPass()._apply_profile_filter([f], ctx)
        assert out[0].severity == Severity.MEDIUM, f"{engine} floored by profile filter"
        assert not out[0].metadata.get("profile_filtered")
        # and once it carries the engine tier, the view keeps it.
        f.metadata["evidence_tier"] = "engine"
        assert ScanPipeline(ScanConfig(target=tmp_path))._in_actionable_view(f)


def test_trust_remote_code_kept_in_views(tmp_path):
    """trust_remote_code=True (NS-AIML-001) is a self-evident code-exec risk the
    labeled corpus marks must-detect; it must survive both --actionable and the
    stricter --confirmed even though its category (ai_ml) is a surface one."""
    pipe = ScanPipeline(ScanConfig(target=tmp_path))
    f = _finding(Severity.MEDIUM, Category.AI_ML, tier="self-evident")
    f.rule_id = "NS-AIML-001"
    assert pipe._in_actionable_view(f)
    assert pipe._in_confirmed_view(f)


def test_ns_path_003_literal_path_not_flagged(tmp_path):
    """NS-PATH-003 must not flag a hardcoded literal path (FileResponse(
    "app.html"), send_file('logo.png')) as user-controlled traversal, while a
    user-controlled argument still fires. Regression: autogen's
    FileResponse("app_agent.html") was a HIGH false positive."""
    app = tmp_path / "app.py"
    app.write_text(
        "from flask import request, send_file\n"
        "from fastapi.responses import FileResponse\n"
        "def a():\n"
        "    return FileResponse('app_agent.html')\n"  # literal -> no fire
        "def b():\n"
        "    return send_file('static/logo.png')\n"  # literal -> no fire
        "def c():\n"
        "    return send_file(request.args.get('f'))\n",  # user input -> fires
        encoding="utf-8",
    )
    res = ScanPipeline(
        ScanConfig(target=tmp_path, no_sca=True, no_cross_file=True, report_view="full")
    ).run()
    hits = {f.start_line for f in res.findings if "NS-PATH-003" in f.reported_rule_ids()}
    assert 4 not in hits, "literal FileResponse path must not be flagged"
    assert 6 not in hits, "literal send_file path must not be flagged"
    assert 8 in hits, "user-controlled send_file path must still be flagged"


def test_log_forging_is_audit_only_in_views(tmp_path):
    """Log forging (CWE-117) is a real hygiene issue but not an exploitation
    primitive, so it is audit-only: never in the actionable or confirmed views
    regardless of severity or evidence tier. A non-117 taint finding stays in."""
    pipe = ScanPipeline(ScanConfig(target=tmp_path))

    def logf(sev, tier):
        f = _finding(sev, Category.INJECTION, tier=tier)
        f.cwe_ids = [117]
        return f

    # taint-confirmed and even mis-rated HIGH: still audit-only.
    assert not pipe._in_actionable_view(logf(Severity.MEDIUM, "taint-flow"))
    assert not pipe._in_confirmed_view(logf(Severity.MEDIUM, "taint-flow"))
    assert not pipe._in_actionable_view(logf(Severity.HIGH, "taint-flow"))
    # a real injection (not log forging) with the same tier is kept.
    keep = _finding(Severity.MEDIUM, Category.INJECTION, tier="taint-flow")
    keep.cwe_ids = [89]
    assert pipe._in_actionable_view(keep)


def test_unreadable_manifest_is_a_warning(tmp_path, monkeypatch, caplog):
    # A manifest path that exists but cannot be read (here, a directory)
    # must degrade to a warning, not crash the scan.
    (tmp_path / "converted" / "_manifest.json").mkdir(parents=True)
    pipeline = ScanPipeline(ScanConfig(target=tmp_path, no_sca=True))
    pipeline._load_conversion_manifest(tmp_path)

    assert "Could not load conversion manifest" in caplog.text


def test_custom_rules_dir_without_converted_is_degraded(tmp_path):
    """PL-05: regex rules in a custom rules_dir that were never converted run
    nowhere in the default engine; the scan must say so, naming the dir."""
    import yaml

    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    rules = yaml.safe_load((Path(__file__).parent.parent / "rules" / "neuroscan.yaml").read_text())
    rule = next(r for r in rules["rules"] if r["id"] == "NS-DESER-001")
    (rules_dir / "custom.yaml").write_text(yaml.safe_dump({"rules": [rule]}), encoding="utf-8")
    src = tmp_path / "src"
    src.mkdir()
    (src / "app.py").write_text("import pickle\n\ndef load(b):\n    return pickle.loads(b)\n", encoding="utf-8")

    result = ScanPipeline(ScanConfig(target=src, rules_dir=rules_dir, no_sca=True)).run()

    assert "converted-regex" in result.degraded_passes
    assert str(rules_dir) in result.degraded_passes["converted-regex"]


def test_taint_crash_reports_failed_status(tmp_path, monkeypatch):
    """PL-06: a crashed taint pass must not read as 'not-requested'."""
    def crash(*args, **kwargs):
        raise RuntimeError("simulated adapter crash")

    monkeypatch.setattr(OpengrepAdapter, "is_installed", lambda self: True)
    monkeypatch.setattr(OpengrepAdapter, "scan_collect_with_rules", crash)
    # Engine failure reporting only needs a Python source file.
    (tmp_path / "app.py").write_text("value = 1\n", encoding="utf-8")

    result = ScanPipeline(ScanConfig(target=tmp_path, no_sca=True)).run()

    capability = result.metadata["analysis_capability"]
    assert "taint" in result.degraded_passes
    assert capability["opengrep_status"] == "failed"


def test_no_opengrep_use_still_reports_not_requested(tmp_path):
    # --no-taint alone still runs Opengrep for the converted regex rules;
    # only the legacy regex engine leaves it entirely unused.
    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
    result = ScanPipeline(
        ScanConfig(target=tmp_path, no_sca=True, no_taint=True, legacy_neuroscan=True)
    ).run()
    assert result.metadata["analysis_capability"]["opengrep_status"] == "not-requested"


def test_run_twice_starts_from_an_empty_result(tmp_path, monkeypatch):
    """PL-14: a second run() must not start with the first run's findings.

    Enrichment dedup hides the duplicates in the final count, so compare the
    count entering the enrichment stage.
    """
    # A weak-hash finding exercises state reset without a command-execution fixture.
    (tmp_path / "app.py").write_text(
        "import hashlib\nvalue = hashlib.md5(b'fixture').hexdigest()\n",
        encoding="utf-8",
    )
    before_enrichment = []
    original = ScanPipeline._run_stage

    def spy(self, stage_name, steps, **kwargs):
        if stage_name == "enrichment":
            before_enrichment.append(len(self._context.result.findings))
        return original(self, stage_name, steps, **kwargs)

    monkeypatch.setattr(ScanPipeline, "_run_stage", spy)
    pipeline = ScanPipeline(ScanConfig(target=tmp_path, enable_sca=False))
    first = pipeline.run()
    second = pipeline.run()
    assert first.findings
    assert second is not first
    assert before_enrichment[0] == before_enrichment[1]


def test_scan_manifest_records_versions_and_rule_hash(tmp_path):
    from rowan import __version__

    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")

    first = ScanPipeline(ScanConfig(target=tmp_path, no_sca=True, no_taint=True)).run()
    second = ScanPipeline(ScanConfig(target=tmp_path, no_sca=True, no_taint=True)).run()

    manifest = first.metadata["scan_manifest"]
    assert manifest["rowan_version"] == __version__
    assert len(manifest["rule_set_sha256"]) == 64
    assert manifest["rule_set_sha256"] == second.metadata["scan_manifest"]["rule_set_sha256"]


def test_scan_manifest_rule_hash_changes_with_rules(tmp_path):
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "a.yaml").write_text("rules: []\n", encoding="utf-8")
    target = tmp_path / "app"
    target.mkdir()
    (target / "app.py").write_text("x = 1\n", encoding="utf-8")
    cfg = dict(target=target, rules_dir=rules, no_sca=True, no_taint=True)

    before = ScanPipeline(ScanConfig(**cfg)).run().metadata["scan_manifest"]["rule_set_sha256"]
    (rules / "a.yaml").write_text("rules: []\n# changed\n", encoding="utf-8")
    after = ScanPipeline(ScanConfig(**cfg)).run().metadata["scan_manifest"]["rule_set_sha256"]

    assert before != after


def test_scan_manifest_rule_hash_covers_converted_rules(tmp_path):
    rules = tmp_path / "rules"
    (rules / "converted").mkdir(parents=True)
    (rules / "a.yaml").write_text("rules: []\n", encoding="utf-8")
    converted = rules / "converted" / "b.yaml"
    converted.write_text("rules: []\n", encoding="utf-8")
    target = tmp_path / "app"
    target.mkdir()
    (target / "app.py").write_text("x = 1\n", encoding="utf-8")
    cfg = dict(target=target, rules_dir=rules, no_sca=True, no_taint=True)

    before = ScanPipeline(ScanConfig(**cfg)).run().metadata["scan_manifest"]["rule_set_sha256"]
    converted.write_text("rules: []\n# changed\n", encoding="utf-8")
    after = ScanPipeline(ScanConfig(**cfg)).run().metadata["scan_manifest"]["rule_set_sha256"]

    assert before != after
