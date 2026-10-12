"""Regression test for the precision/recall benchmark harness (issue #76).

Runs the vuln_cases corpus (benchmark/ground_truth/vuln_cases/) through
scripts/benchmark.py's own scoring logic and asserts 100% recall. This
folds the benchmark's recall check into the normal test suite, so a rule
change that silently breaks a ground-truth case is caught by `pytest`,
not just by someone remembering to run the benchmark manually.

Requires the Opengrep binary (skipped entirely if not installed, matching
the project's convention -- CI does not install it currently, see
.github/workflows/ci.yml).
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from rowan.core.findings import (
    Category,
    Finding,
    ScanResult,
    Severity,
    TaintFlow,
    TaintNode,
)
from rowan.taint.opengrep_adapter import OpengrepAdapter

pytestmark = pytest.mark.skipif(
    not OpengrepAdapter().is_installed(),
    reason="Opengrep binary not installed; the benchmark harness needs a live scan.",
)


def _load_benchmark_module():
    script_path = Path(__file__).parent.parent / "scripts" / "benchmark.py"
    spec = importlib.util.spec_from_file_location("benchmark", script_path)
    module = importlib.util.module_from_spec(spec)
    sys.modules["benchmark"] = module
    spec.loader.exec_module(module)
    return module


def _fake_finding(rule_id, file_path, line, category, cwes, engine="opengrep", message=""):
    return SimpleNamespace(
        rule_id=rule_id,
        file_path=file_path,
        start_line=line,
        category=SimpleNamespace(value=category),
        cwe_ids=cwes,
        engine=engine,
        message=message,
        metadata={},
    )


def test_distinct_finding_attribution_reports_duplicates_decoys_and_mismatches(tmp_path):
    benchmark = _load_benchmark_module()
    source = tmp_path / "app.py"
    source.write_text(
        "def unsafe():\n"
        "    value = request.args['q']\n"
        "    return eval(value)\n\n"
        "def safe():\n"
        "    value = request.args['q']\n"
        "    return render_template('fixed.html', value=value)\n\n"
        "def query():\n"
        "    return db.execute(request.args['q'])\n",
        encoding="utf-8",
    )
    gt = {
        "vulnerabilities": [
            {"id": "V1", "cwe": "CWE-94", "sink": {"file": "app.py", "line_hint": 3}},
            {"id": "V2", "cwe": "CWE-89", "sink": {"file": "app.py", "line_hint": 10}},
        ],
        "decoys": [
            {
                "id": "D1",
                "resembles": "V1 (code injection)",
                "location": {"file": "app.py", "symbol": "safe"},
            }
        ],
    }
    findings = [
        _fake_finding("EVAL-1", str(source), 3, "injection", [94]),
        _fake_finding("EVAL-2", str(source), 3, "general", [94], engine="neuroscan"),
        _fake_finding("EVAL-FP", str(source), 7, "injection", [94]),
        _fake_finding("WRONG-CWE", str(source), 10, "xss", [79], message="SQL injection"),
    ]

    report = benchmark._score_distinct_findings(gt, findings, tmp_path, {"V1"})

    assert report["true_positive_vulnerability_ids"] == ["V1"]
    assert report["distinct_true_positives"] == 1
    assert report["duplicate_findings"] == 1
    assert list(report["duplicates_by_vulnerability"]) == ["V1"]
    assert report["false_positive_decoy_ids"] == ["D1"]
    assert report["false_positive_decoys"] == 1
    assert any(row["vulnerability_id"] == "V2" for row in report["cwe_mismatches"])
    assert any(row["rule_id"] == "EVAL-2" for row in report["category_mismatches"])
    assert report["per_engine"]["opengrep"] == {
        "findings": 3,
        "distinct_tp": 1,
        "duplicates": 0,
        "decoy_fp": 1,
    }
    assert report["per_engine"]["neuroscan"]["duplicates"] == 1
    assert report["per_rule"]["EVAL-FP"]["decoy_fp"] == 1


def test_distinct_attribution_rejects_unrelated_cross_file_symbols(tmp_path):
    benchmark = _load_benchmark_module()
    source = tmp_path / "api.py"
    source.write_text("def unrelated():\n    pass\n", encoding="utf-8")
    gt = {
        "vulnerabilities": [
            {
                "id": "V1",
                "cwe": "CWE-829",
                "sink": {"file": "loader.py", "line_hint": 50},
                "taint_path": ["api.py:upload_plugin", "loader.py:load_plugins"],
            }
        ],
        "decoys": [],
    }
    finding = _fake_finding(
        "CF-SINK-001",
        str(source),
        1,
        "supply_chain",
        [829],
        message=("Cross-file taint: unrelated() in api.py reaches a sink via run_pipeline()"),
    )

    report = benchmark._score_distinct_findings(gt, [finding], tmp_path, {"V1"})

    assert report["distinct_true_positives"] == 0
    assert len(report["unmatched_findings"]) == 1


def test_vuln_cases_full_recall():
    benchmark = _load_benchmark_module()
    scores, results = benchmark.run_vuln_cases()

    # #106: only the regression pool gates. This used to assert 1.0 on
    # *overall* recall, which passed only because the holdout pool was empty --
    # an assumption the pool split exists precisely to break. Asserting it
    # again would mean any honest generalization miss fails the suite, which
    # would in turn pressure whoever added the holdout case to tune a rule
    # against it. Holdout recall is reported, never gated.
    reg = scores["regression"]
    reg_misses = [r for r in results if not r.found and r.pool == "regression"]
    assert reg["recall"] is None or reg["recall"] == 1.0, (
        f"regression-pool recall must be 1.0, got {reg}. "
        f"Missed: {[(m.file, m.expected) for m in reg_misses]}"
    )
    assert scores["holdout"]["recall"] is not None, (
        "the holdout pool must be populated -- an empty holdout reports no "
        "generalization signal at all"
    )


def test_vuln_cases_reports_taint_recall(monkeypatch):
    """BACKLOG RT-04: vuln_cases was scored with taint off only, so no
    `mode: taint` rule could ever be credited there. The corpus is now scored
    twice; the regex-only pool still gates, the taint-on numbers are reported
    alongside as `*_taint`."""
    benchmark = _load_benchmark_module()
    calls = []

    def fake_scan_dir(path, **kwargs):
        calls.append(kwargs)
        return []

    monkeypatch.setattr(benchmark, "_scan_dir", fake_scan_dir)
    scores, results = benchmark.run_vuln_cases()
    assert [c.get("no_taint", False) for c in calls] == [True, False]
    assert {"regression", "holdout", "overall"} <= scores.keys()
    assert {"regression_taint", "holdout_taint", "overall_taint"} <= scores.keys()
    assert results and all(not r.found for r in results)


def test_vuln_cases_pool_split_and_gating():
    """#106: cases carry a pool; only 'regression' should gate. A holdout MISS
    must not fail the regression gate."""
    benchmark = _load_benchmark_module()
    result_cls = benchmark.VulnCaseResult
    rows = [
        result_cls("a.py", "x", found=True, matched_rule_ids=[], pool="regression"),
        result_cls("b.py", "x", found=True, matched_rule_ids=[], pool="regression"),
        result_cls("c.py", "x", found=False, matched_rule_ids=[], pool="holdout"),
    ]
    assert benchmark._pool_recall(rows, "regression") == {"recall": 1.0, "hits": 2, "total": 2}
    assert benchmark._pool_recall(rows, "holdout") == {"recall": 0.0, "hits": 0, "total": 1}
    # empty pool -> recall None, never a spurious 1.0 that would mask "no cases"
    assert benchmark._pool_recall(rows, "nonexistent")["recall"] is None


def test_vuln_cases_cwe_class_fallback():
    """#107: a case whose exact rule_id/category isn't matched is still credited
    when a finding in the file is CWE-class-consistent."""
    benchmark = _load_benchmark_module()

    class _F:
        def __init__(self, rule_id, cat, msg):
            self.rule_id = rule_id
            self.message = msg
            self.category = type("C", (), {"value": cat})()

    # deserialization case (CWE-502): a differently-named/categorized finding
    # whose message carries the class ("pickle") is credited by cwe_class.
    findings = [_F("SOME-NEW-RULE", "general", "unsafe pickle.load on request data")]
    matched = benchmark._class_consistent(findings, 502)
    assert matched, "a class-consistent (pickle/CWE-502) finding should be credited"

    # an unrelated finding is not credited for CWE-502.
    unrelated = [_F("NS-XSS-001", "xss", "innerHTML assignment")]
    assert benchmark._class_consistent(unrelated, 502) == []

    # a CWE with no keyword mapping never yields class-based credit.
    assert benchmark._class_consistent(findings, 639) == []


@pytest.mark.corpus
def test_clean_models_zero_findings():
    benchmark = _load_benchmark_module()
    total_fp, details, scanned = benchmark.run_clean_models()

    if scanned == 0:
        pytest.skip("clean_models corpus not fetched locally; run scripts/fetch_clean_models.py")
    assert total_fp == 0, (
        f"Expected 0 findings on the clean-model corpus, got {total_fp}: {details}"
    )


def test_vuln_app_class_consistency_scoring():
    """The vuln_app scorer must require both proximity AND vuln-class
    consistency -- an unrelated finding near a sink line must not be credited,
    an uncatchable-class CWE (IDOR) must never be a hit, and a class WITH
    keywords (mass-assignment) must still reject an unrelated nearby finding."""
    benchmark = _load_benchmark_module()

    # CWE -> keyword mapping: deserialization has keywords, IDOR has none (639
    # is the sole deliberate holdout -- see the AUTHZ-BOLA-* semantic path).
    assert benchmark._cwe_keywords("CWE-502")  # deserialization -> non-empty
    assert benchmark._cwe_keywords("LLM01")  # prompt injection -> non-empty
    assert benchmark._cwe_keywords("CWE-639") == ()  # IDOR -> uncatchable

    # CWE-915 (mass assignment) DOES have a real keyword mapping now -- unlike
    # 639, actual rules in the corpus (ns-bb-005/RB-AUTH-001)
    # target this class by declared CWE, they just don't fire on every mass-
    # assignment shape yet. The keywords are narrow enough that an unrelated
    # finding near a mass-assignment sink still isn't credited.
    mass_assign_kw = benchmark._cwe_keywords("CWE-915")
    assert mass_assign_kw
    unrelated_setattr_sink = [
        (
            "/app/dvml/services/config_loader.py",
            20,
            "deserialization ns-deser-003 yaml.load() without safeloader",
        )
    ]
    assert (
        benchmark._hit(unrelated_setattr_sink, "dvml/services/config_loader.py", 23, mass_assign_kw)
        is False
    )

    sink_file = "dvml/ml/model_loader.py"
    deser_kw = benchmark._cwe_keywords("CWE-502")

    # A class-consistent finding near the sink line counts.
    hit_index = [
        ("/app/dvml/ml/model_loader.py", 30, "deserialization ns-deser-001 pickle.load rce")
    ]
    assert benchmark._hit(hit_index, sink_file, 30, deser_kw) is True

    # A finding of the WRONG class near the same sink line must NOT count.
    wrong_class = [("/app/dvml/ml/model_loader.py", 30, "xss ns-xss-005 autoescape")]
    assert benchmark._hit(wrong_class, sink_file, 30, deser_kw) is False

    # Right class but far from the sink line must NOT count.
    far = [("/app/dvml/ml/model_loader.py", 300, "deserialization pickle.load")]
    assert benchmark._hit(far, sink_file, 30, deser_kw) is False

    # Empty keywords (uncatchable class) => never a hit, even with a nearby finding.
    assert benchmark._hit(hit_index, sink_file, 30, ()) is False

    # Rowan metadata, when present, is authoritative over incidental wording in
    # a composite message. A correct CWE receives credit even if the message is
    # terse; a wrong CWE cannot receive credit merely because it says "pickle".
    metadata_hit = [("/app/dvml/ml/model_loader.py", 30, "general terse finding", (502,))]
    assert benchmark._hit(metadata_hit, sink_file, 30, (), 502) is True
    metadata_mismatch = [("/app/dvml/ml/model_loader.py", 30, "deserialization pickle.load", (79,))]
    assert benchmark._hit(metadata_mismatch, sink_file, 30, deser_kw, 502) is False

    # LLM01 is an OWASP class, not a numeric CWE. A Rowan finding's numeric
    # CWE must therefore not erase the narrowly-defined LLM keyword path.
    llm_index = [("/app/dvml/ml/model_loader.py", 30, "agent capability dispatch", (284,))]
    assert benchmark._hit(llm_index, sink_file, 30, benchmark._cwe_keywords("LLM01")) is True


def test_vuln_app_taint_path_fallback_for_multi_hop_findings(tmp_path):
    """Multi-hop findings (e.g. cross-file taint) are anchored at a call site
    along the taint path, not the ground truth's sink line. The fallback
    credits them there without line proximity, but only inside a declared
    hop function (RT-11) and under the same class-consistency bar."""
    benchmark = _load_benchmark_module()

    taint_path = [
        "dvml/api/agent.py:chat (message)",
        "dvml/agent/core.py:run_agent (LLM decides tool call)",
        "dvml/agent/tools.py:run_sql (arbitrary SQL)",
    ]
    files = benchmark._taint_path_files(taint_path)
    assert files == {"dvml/api/agent.py", "dvml/agent/core.py", "dvml/agent/tools.py"}
    hops = benchmark._taint_path_hops(taint_path)

    core = tmp_path / "dvml" / "agent" / "core.py"
    core.parent.mkdir(parents=True)
    core.write_text("def run_agent(msg):\n    return llm(msg)\n", encoding="utf-8")
    reports = tmp_path / "dvml" / "api" / "reports.py"
    reports.parent.mkdir(parents=True)
    reports.write_text("def report(x):\n    return run_agent(x)\n", encoding="utf-8")

    llm_kw = benchmark._cwe_keywords("LLM01")
    ident = "general cf-chat reaches a sink via chat from agent"
    # reports.py is not on the path.
    assert benchmark._hit_anywhere_on_path(
        [(str(reports), 2, ident)], files, llm_kw, None, None, hops
    ) is False
    # Inside run_agent, a declared hop, far from any sink line: counts.
    assert benchmark._hit_anywhere_on_path(
        [(str(core), 2, ident)], files, llm_kw, None, None, hops
    ) is True
    # Wrong class on the right line still does not count.
    assert benchmark._hit_anywhere_on_path(
        [(str(core), 2, "xss ns-xss-005 autoescape")], files, llm_kw, None, None, hops
    ) is False


def test_llm_keywords_do_not_false_credit_generic_injection_messages():
    """DEF-N: Semgrep's *generic* eval-detected/SQLi rule messages routinely
    say "this may be a code injection vulnerability" -- if the LLM01 keyword
    set included the bare word "injection", that sentence alone would falsely
    credit Semgrep for detecting an LLM prompt-injection / agent-tool-abuse
    vuln it has no purpose-built rule for at all. Confirmed against the exact
    real Semgrep message this bug produced."""
    benchmark = _load_benchmark_module()
    llm_kw = benchmark._cwe_keywords("LLM01")

    generic_eval_message = (
        "python.lang.security.audit.eval-detected.eval-detected detected the use of eval(). "
        "eval() can be dangerous if used to evaluate dynamic content. if this content can be "
        "input from outside the program, this may be a code injection vulnerability."
    ).lower()
    assert not any(kw in generic_eval_message for kw in llm_kw), (
        f"a generic 'code injection' message must not satisfy the LLM01 keyword set, "
        f"got keywords: {llm_kw}"
    )

    # A real agent/prompt-injection-aware message must still match.
    genuine_message = (
        "cross-file taint: chat() in agent.py reaches run_agent() -- prompt injection risk"
    )
    assert any(kw in genuine_message for kw in llm_kw)


def test_file_write_keywords_do_not_false_credit_orm_write_messages():
    """DEF-30: CWE-73 (arbitrary file write) previously included the bare word
    "write" -- which coincidentally matches TNT-STORED-001's genuine but
    unrelated "is persisted to the database via an ORM write" message, giving
    false credit for an arbitrary-file-write vuln that no rule actually
    detects. Confirmed against the exact real finding message that triggered
    this (V10 on ModelForge, scored via the taint_path fallback)."""
    benchmark = _load_benchmark_module()
    file_write_kw = benchmark._cwe_keywords("CWE-73")

    orm_write_message = (
        "xss tnt-stored-001 user-controlled input is persisted to the database via an orm "
        "write without html-escaping or validation. if this data is later rendered without "
        "escaping"
    )
    assert not any(kw in orm_write_message for kw in file_write_kw), (
        f"a generic ORM-write message must not satisfy the CWE-73 keyword set, "
        f"got keywords: {file_write_kw}"
    )

    # A genuine arbitrary-file-write finding must still match.
    genuine_message = (
        "path_traversal ns-path-003 os.path.join without containment check: arbitrary file write"
    )
    assert any(kw in genuine_message for kw in file_write_kw)


def test_taint_path_symbols_extracts_structured_hops_only():
    """Only the structured 'file:symbol[ -> symbol2][ / symbol3]' prefix of
    each entry counts as a declared hop -- free-form prose inside notes/
    quotes (e.g. a comparison to an unrelated function) must not leak in,
    and entries with no ':' at all (pure descriptive asides) are skipped."""
    benchmark = _load_benchmark_module()

    taint_path = [
        "dvml/api/datasets.py:create_dataset (webhook_url persisted)",
        "dvml/workers/tasks.py:import_dataset -> _notify (worker POSTs on completion) OR sync POST on archive import",
        "requests.post(webhook_url) with NO is_safe_url gate — unlike fetch()",
    ]
    symbols = benchmark._taint_path_symbols(taint_path)
    assert symbols == {"create_dataset", "import_dataset", "_notify"}
    assert "fetch" not in symbols  # only appears inside a descriptive aside, not a declared hop

    multi_tool_path = [
        "dvml/agent/tools.py:run_sql (arbitrary SQL) / read_file (arbitrary read) / http_get (SSRF) / calc (eval)",
    ]
    assert benchmark._taint_path_symbols(multi_tool_path) == {
        "run_sql",
        "read_file",
        "http_get",
        "calc",
    }


def test_cf_caller_callee_parses_real_cross_file_message():
    benchmark = _load_benchmark_module()
    ident = (
        "general cf-sink-001 cross-file taint [direct, sink]: get_blob() in models.py "
        "reaches a sink via read_artifact() from registry.py. path traversal: ..."
    )
    assert benchmark._cf_caller_callee(ident) == ("get_blob", "read_artifact")

    # A non-CF finding (or an abbreviated fixture) can't be parsed -- callers
    # must treat that as "skip the extra check," not "reject."
    assert benchmark._cf_caller_callee("xss ns-xss-005 autoescape") is None


def test_hit_anywhere_on_path_rejects_wrong_callee_same_taint_path_file(tmp_path):
    """DEF-N: a class-consistent CF- finding on a taint_path file must name
    this vuln's declared caller AND callee, not a different mechanism sharing
    the file (a properly gated fetch() next to the unguarded _notify())."""
    benchmark = _load_benchmark_module()

    taint_path = [
        "dvml/api/datasets.py:create_dataset (webhook_url persisted)",
        "dvml/workers/tasks.py:import_dataset -> _notify (worker POSTs on completion)",
    ]
    files = benchmark._taint_path_files(taint_path)
    symbols = benchmark._taint_path_symbols(taint_path)
    hops = benchmark._taint_path_hops(taint_path)
    ssrf_kw = benchmark._cwe_keywords("CWE-918")
    tasks = tmp_path / "dvml" / "workers" / "tasks.py"
    tasks.parent.mkdir(parents=True)
    tasks.write_text(
        "def import_dataset(url):\n    fetch(url)\n    _notify(url)\n",
        encoding="utf-8",
    )

    wrong_callee = [(
        str(tasks), 2,
        "general cf-sink-001 cross-file taint [direct, sink]: import_dataset() in tasks.py "
        "reaches a sink via fetch() from fetcher.py. outbound http request",
    )]
    assert benchmark._hit_anywhere_on_path(wrong_callee, files, ssrf_kw, symbols, None, hops) is False

    right_callee = [(
        str(tasks), 3,
        "general cf-sink-001 cross-file taint [direct, sink]: import_dataset() in tasks.py "
        "reaches a sink via _notify() from tasks.py. outbound http request",
    )]
    assert benchmark._hit_anywhere_on_path(right_callee, files, ssrf_kw, symbols, None, hops) is True

    # Not our CF- shape: no caller/callee check, but still anchored in a hop.
    unparseable = [(str(tasks), 2, "ssrf ns-ssrf-001 outbound http request")]
    assert benchmark._hit_anywhere_on_path(unparseable, files, ssrf_kw, symbols, None, hops) is True


def test_ssti_keywords_do_not_false_credit_unrelated_autoescape_message():
    """DEF-N: CWE-1336 (SSTI) previously included the bare word "template",
    which coincidentally matches an unrelated autoescape=False/XSS finding
    on the exact same rendering function -- giving false credit for a
    second-order, cache-laundered SSTI vuln with no actual detection of the
    from_string()/SSTI behavior itself."""
    benchmark = _load_benchmark_module()
    ssti_kw = benchmark._cwe_keywords("CWE-1336")

    autoescape_message = (
        "general cf-sink-001 cross-file taint [direct, sink]: report() in models.py "
        "reaches a sink via render_report() from reports.py. jinja2 environment(autoescape=false) "
        "renders template variables without html escaping"
    )
    assert not any(kw in autoescape_message for kw in ssti_kw)

    genuine_ssti_message = (
        "ssti ns-ssti-001 rendering templates from user-controlled strings enables ssti -> rce"
    )
    assert any(kw in genuine_ssti_message for kw in ssti_kw)


def test_vuln_app_skips_without_env(monkeypatch):
    """run_vuln_app returns None (skips cleanly) when ROWAN_VULN_APP_PATH is unset."""
    benchmark = _load_benchmark_module()
    monkeypatch.delenv("ROWAN_VULN_APP_PATH", raising=False)
    assert benchmark.run_vuln_app(with_semgrep=False) is None


def test_cve_cases_empty_manifest_skips():
    """#105: the committed manifest has no cases; run_cve_cases skips cleanly
    (nothing fetched, no failure) exactly like an unfetched clean_models run."""
    benchmark = _load_benchmark_module()
    _scores, results, fetched = benchmark.run_cve_cases()
    assert results == []
    assert fetched == 0


def test_cve_cases_scores_a_fetched_fixture(tmp_path, monkeypatch):
    """#105: a fetched checkout with a real sink is scored by file+line+CWE class.
    Uses a synthetic checkout so the code path is covered without a network fetch."""
    benchmark = _load_benchmark_module()
    monkeypatch.setattr(benchmark, "GROUND_TRUTH", tmp_path)

    checkout = tmp_path / "cve_cases" / "cache" / "demo-cve" / "src"
    checkout.mkdir(parents=True)
    (checkout / "loader.py").write_text(
        "import pickle, flask\n"
        "request = flask.request\n"
        "def load():\n"
        "    data = request.data\n"
        "    return pickle.loads(data)  # CWE-502 sink\n"
    )
    (tmp_path / "cve_cases" / "manifest.json").write_text(
        json.dumps(
            {
                "cases": [
                    {
                        "id": "demo-cve",
                        "cwe": 502,
                        "repo": "x",
                        "commit": "x",
                        "subdir": "src",
                        "sink_file": "src/loader.py",
                        "sink_line": 5,
                        "pool": "regression",
                    }
                ]
            }
        )
    )

    scores, results, fetched = benchmark.run_cve_cases()
    assert fetched == 1
    assert results[0].found is True, "pickle.loads CWE-502 sink should be detected"
    assert scores["regression"]["recall"] == 1.0

    # An unfetched case is skipped, never a failure.
    (tmp_path / "cve_cases" / "manifest.json").write_text(
        json.dumps(
            {
                "cases": [
                    {
                        "id": "not-fetched",
                        "cwe": 89,
                        "repo": "x",
                        "commit": "x",
                        "sink_file": "a.py",
                        "sink_line": 1,
                    }
                ]
            }
        )
    )
    _scores2, results2, fetched2 = benchmark.run_cve_cases()
    assert fetched2 == 0
    assert results2[0].fetched is False and results2[0].found is False


def test_js_authz_corpus_recall_and_precision():
    """The self-contained JS BOLA tier gates JSAuthzPass: every vuln fixture
    fires, every guarded/fused decoy stays silent."""
    benchmark = _load_benchmark_module()
    report = benchmark.run_js_authz_cases()
    if report is None:
        pytest.skip("tree-sitter not installed")
    assert report["recall"] == 1.0
    assert report["decoy_fps"] == 0
    assert report["ok"] is True


def test_decoy_class_keywords_derive_from_referenced_vulns():
    """A decoy's class comes from the CWEs of the vulnerabilities its
    `resembles` field names, not from parsing its prose -- so the scorer stays
    correct when a decoy's wording changes."""
    benchmark = _load_benchmark_module()
    cwe_by_id = {"V03": "CWE-22", "V24": "CWE-22", "V08": "CWE-89"}

    traversal = benchmark._decoy_class_keywords(
        {"resembles": "V03/V24 (path traversal)"}, cwe_by_id
    )
    assert "traversal" in traversal
    assert "sqli" not in traversal

    # CWE-639 decoys resolve to no keywords -- IDOR is graded by the
    # AUTHZ-BOLA path instead, so they must fall out of this scorer.
    assert (
        benchmark._decoy_class_keywords({"resembles": "V65 (ownership IDOR)"}, {"V65": "CWE-639"})
        == ()
    )
    # A decoy naming a vulnerability that doesn't exist resolves to nothing.
    assert benchmark._decoy_class_keywords({"resembles": "V67 hypothetical"}, cwe_by_id) == ()


def test_symbol_class_hit_is_scoped_to_the_decoy_function(tmp_path):
    """A decoy routinely shares a file with the vulnerability it is paired
    against, so a file-only test would blame the decoy for the real finding in
    the neighbouring function."""
    benchmark = _load_benchmark_module()
    src = tmp_path / "experiments.py"
    src.write_text(
        "def search_by_tag(tag):\n"  # 1  decoy (safe)
        "    return db.execute(text('... :tag'), {'tag': tag})\n"  # 2
        "\n"  # 3
        "def search_vulnerable(tag):\n"  # 4  the real vuln
        "    return db.execute(f'SELECT * FROM t WHERE tag = {tag}')\n",  # 5
        encoding="utf-8",
    )
    kw = benchmark._cwe_keywords("CWE-89")
    index = [
        (str(src), 5, "injection ns-sqli-005 sql statement assembled with an interpolated f-string")
    ]

    assert (
        benchmark._symbol_class_hit(index, tmp_path, "experiments.py", "search_by_tag", kw) is False
    )
    assert (
        benchmark._symbol_class_hit(index, tmp_path, "experiments.py", "search_vulnerable", kw)
        is True
    )

    # Wrong class inside the decoy's own body is not that decoy's false
    # positive -- the decoy's claim is narrow ("this is not SQLi").
    off_class = [(str(src), 2, "crypto ns-crypto-001 md5 is cryptographically broken")]
    assert (
        benchmark._symbol_class_hit(off_class, tmp_path, "experiments.py", "search_by_tag", kw)
        is False
    )


def test_score_decoys_separates_authz_graded_from_genuinely_unscored(tmp_path):
    """CWE-639 decoys can't be keyword-scored. One tagged `authz_model` is
    fully covered by _score_authz_bola; one without it is scored by nothing at
    all, which is a ground-truth gap and must be reported, not hidden."""
    benchmark = _load_benchmark_module()
    src = tmp_path / "notes.py"
    src.write_text("def scoped_read(uid):\n    return q(uid)\n", encoding="utf-8")

    gt = {
        "vulnerabilities": [{"id": "V61", "cwe": "CWE-639"}, {"id": "V65", "cwe": "CWE-639"}],
        "decoys": [
            {
                "id": "D41",
                "resembles": "V65 (ownership IDOR)",
                "authz_model": "ownership",
                "location": {"file": "notes.py", "symbol": "scoped_read"},
            },
            {
                "id": "D37",
                "resembles": "V61 (cross-tenant note leak)",
                "location": {"file": "notes.py", "symbol": "scoped_read"},
            },
        ],
    }
    report = benchmark._score_decoys(gt, [], tmp_path)
    assert report["authz_graded_ids"] == ["D41"]
    assert report["unscored_ids"] == ["D37"]
    assert report["scored"] == 0
    assert report["false_positives"] == 0


def test_score_decoys_counts_an_in_class_finding_and_spares_known_unlabeled(tmp_path):
    benchmark = _load_benchmark_module()
    src = tmp_path / "experiments.py"
    src.write_text(
        "def ask_structured(q):\n"
        "    return db.execute(text(f'... WHERE {col} = :value'), {'value': v})\n",
        encoding="utf-8",
    )
    seed = tmp_path / "cli.py"
    seed.write_text("def seed_command():\n    pw = 'admin123'\n", encoding="utf-8")

    gt = {
        "vulnerabilities": [{"id": "V33", "cwe": "CWE-89"}],
        "decoys": [
            {
                "id": "D10",
                "resembles": "V33 (text-to-SQL injection)",
                "location": {"file": "experiments.py", "symbol": "ask_structured"},
            }
        ],
        "known_unlabeled": [
            {
                "id": "KU02",
                "cwe": "CWE-798",
                "location": {"file": "cli.py", "symbol": "seed_command"},
            }
        ],
    }
    index = [
        (
            str(src),
            2,
            "injection ns-sqli-005 sql statement assembled with an interpolated f-string",
        ),
        (str(seed), 2, "secrets ns-secret-001 hardcoded password credential"),
    ]
    report = benchmark._score_decoys(gt, index, tmp_path)

    assert report["false_positive_ids"] == ["D10"]
    # known_unlabeled is reported but never penalized -- flagging seeded demo
    # credentials is correct behaviour, not a false positive.
    assert report["known_unlabeled_hit_ids"] == ["KU02"]
    assert report["false_positives"] == 1


def test_vuln_cases_holdout_pool_is_populated_and_cwe_only_cases_are_supported():
    """The holdout pool is the generalization signal (#106) and was empty until
    now -- `holdout recall: n/a (0/0)` -- which made "never author against the
    ground truth" a purely social rule with no measurement behind it.

    Holdout cases are declared with a `cwe` and no `expected_rule_id`/
    `expected_category`: naming either bakes our own taxonomy into the oracle,
    so a rule rename or re-categorization would register as a generalization
    failure that never happened. The scorer must credit those purely through
    the #107 CWE-class fallback rather than raising KeyError."""
    manifest_path = (
        Path(__file__).parent.parent / "benchmark" / "ground_truth" / "vuln_cases" / "manifest.json"
    )
    cases = json.loads(manifest_path.read_text())["cases"]
    holdout = [c for c in cases if c.get("pool") == "holdout"]

    assert holdout, "the holdout pool must not be empty -- it is the only generalization signal"
    # Spread across languages: a holdout that is all-Python would measure one
    # engine path, not generalization.
    assert len({c["language"] for c in holdout}) >= 5

    corpus = manifest_path.parent
    for case in holdout:
        assert case.get("cwe"), f"{case['file']} must declare a CWE to be scoreable"
        assert (corpus / case["file"]).is_file(), f"{case['file']} is registered but missing"

    cwe_only = [c for c in holdout if "expected_rule_id" not in c and "expected_category" not in c]
    assert cwe_only, "at least one CWE-only case must exercise the class-fallback path"


# ---------------------------------------------------------------------------
# ai_native_rule scorer (#183/#197): unlike authz_model (graded by semantic
# model class against a single rule family, AUTHZ-BOLA-001), each AI-native
# category is its own distinct rule_id -- these tests cover the exact-rule-id
# matching and per-rule aggregation logic directly with synthetic fixtures,
# so a regression here is caught without needing a local vuln-app checkout.
# ---------------------------------------------------------------------------


def test_ai_native_hit_requires_exact_rule_id_and_proximity():
    benchmark = _load_benchmark_module()
    sink_file = "langfail/core/security.py"

    # Right rule_id, within the window: hit.
    index = [("/app/langfail/core/security.py", 212, "ns-aiml-133")]
    assert benchmark._ai_native_hit(index, sink_file, 212, "ns-aiml-133") is True

    # A DIFFERENT rule_id firing at the exact same line must NOT count -- this
    # is the whole reason ai_native_rule is scored by exact id, not by CWE
    # keyword class like _hit(): two unrelated AI-native rules can plausibly
    # both fire near the same MCP-handling code.
    wrong_rule = [("/app/langfail/core/security.py", 212, "ns-aiml-999")]
    assert benchmark._ai_native_hit(wrong_rule, sink_file, 212, "ns-aiml-133") is False

    # Right rule_id, far outside the window: not a hit.
    far = [("/app/langfail/core/security.py", 900, "ns-aiml-133")]
    assert benchmark._ai_native_hit(far, sink_file, 212, "ns-aiml-133") is False

    # No line_hint given: proximity check is skipped entirely.
    assert benchmark._ai_native_hit(far, sink_file, None, "ns-aiml-133") is True


def test_ai_native_false_positive_scoped_to_decoy_function_body(tmp_path):
    """A finding inside the decoy's own function is a false positive;
    the SAME rule firing in a neighboring function (e.g. the paired vuln,
    which routinely shares a file with its decoy) must not blame the decoy --
    mirrors _authz_false_positive's function-range scoping (DEF-46 is the
    exact failure mode this guards: a nearby sibling function's own
    detection leaking across a boundary)."""
    benchmark = _load_benchmark_module()

    src = tmp_path / "security.py"
    src.write_text(
        "def verify_mcp_token(token):\n"  # lines 1-3: vuln
        "    return decode(token)\n"
        "\n"
        "def verify_mcp_token_safe(token):\n"  # lines 4-6: decoy
        "    return decode(token, audience=RESOURCE_ID)\n"
    )
    decoy_file = "security.py"

    # A finding landing inside the decoy's own body (line 5) is a false positive.
    fp_index = [(str(src), 5, "ns-aiml-133")]
    assert (
        benchmark._ai_native_false_positive(
            fp_index, tmp_path, decoy_file, "verify_mcp_token_safe", "ns-aiml-133"
        )
        is True
    )

    # The vuln's own finding, in the SIBLING function (line 2), must not be
    # blamed on the decoy just because they share a file.
    sibling_index = [(str(src), 2, "ns-aiml-133")]
    assert (
        benchmark._ai_native_false_positive(
            sibling_index, tmp_path, decoy_file, "verify_mcp_token_safe", "ns-aiml-133"
        )
        is False
    )

    # A DIFFERENT rule_id firing inside the decoy's own body must not count
    # against THIS rule's precision.
    other_rule_index = [(str(src), 5, "ns-aiml-999")]
    assert (
        benchmark._ai_native_false_positive(
            other_rule_index, tmp_path, decoy_file, "verify_mcp_token_safe", "ns-aiml-133"
        )
        is False
    )


def test_score_ai_native_per_rule_aggregation(tmp_path):
    """_score_ai_native aggregates recall/precision per ai_native_rule and
    reports false-positive decoy ids, mirroring _score_authz_bola's shape."""
    benchmark = _load_benchmark_module()

    src = tmp_path / "app.py"
    src.write_text(
        "def do_unsafe():\n"
        "    pass\n"
        "\n"
        "def do_safe():\n"
        "    pass\n"
        "\n"
        "def do_unsafe2():\n"
        "    pass\n"
        "\n"
        "def do_safe2():\n"
        "    pass\n"
    )

    gt = {
        "vulnerabilities": [
            {
                "id": "V1",
                "ai_native_rule": "RULE-A",
                "sink": {"file": "app.py", "line_hint": 1},
            },
            {
                # Far from the false-positive finding at line 10 below (outside
                # VULN_APP_SINK_WINDOW) so that finding can ONLY count as the
                # decoy's false positive, not coincidentally also as V2's hit.
                "id": "V2",
                "ai_native_rule": "RULE-B",
                "sink": {"file": "app.py", "line_hint": 500},
            },
        ],
        "decoys": [
            {
                "id": "D1",
                "ai_native_rule": "RULE-A",
                "location": {"file": "app.py", "symbol": "do_safe"},
            },
            {
                "id": "D2",
                "ai_native_rule": "RULE-B",
                "location": {"file": "app.py", "symbol": "do_safe2"},
            },
        ],
    }

    # RULE-A: recall hit (finding at its vuln's sink), precision clean (no
    # finding in its decoy's body). RULE-B: recall miss (no finding at all),
    # and its decoy incorrectly flagged (a false positive).
    index = [
        (str(src), 1, "RULE-A"),
        (str(src), 10, "RULE-B"),  # inside do_safe2's body -> false positive
    ]

    result = benchmark._score_ai_native(gt, index, tmp_path)
    assert result["per_rule"]["RULE-A"] == {
        "tp": 1,
        "fn": 0,
        "fp": 0,
        "decoys": 1,
        "recall": 1.0,
        "precision": 1.0,
    }
    assert result["per_rule"]["RULE-B"]["tp"] == 0
    assert result["per_rule"]["RULE-B"]["fn"] == 1
    assert result["per_rule"]["RULE-B"]["fp"] == 1
    assert result["per_rule"]["RULE-B"]["recall"] == 0.0
    assert result["per_rule"]["RULE-B"]["precision"] == 0.0
    assert result["overall_recall"] == 0.5
    assert result["overall_precision"] == 0.5
    assert result["false_positive_decoy_ids"] == ["D2"]

    # No ai_native_rule-tagged entries at all -> None, not an empty dict, so
    # an older vuln-app checkout is skipped rather than reported as 0/0.
    assert benchmark._score_ai_native({"vulnerabilities": [], "decoys": []}, [], tmp_path) is None


@pytest.mark.corpus
def test_ai_native_rule_ground_truth_self_consistency(monkeypatch):
    """Oracle self-consistency (#197): every ai_native_rule-tagged vuln's sink
    and every tagged decoy's location must resolve to a real function in the
    checked-out source, and no two entries may collide on id. Requires
    ROWAN_VULN_APP_PATH; skipped (not failed) otherwise, matching every other
    vuln_app-dependent test in this file."""
    benchmark = _load_benchmark_module()
    resolved = benchmark._resolve_vuln_app()
    if resolved is None:
        pytest.skip("set ROWAN_VULN_APP_PATH to a local vuln-app checkout to run this check")
    app_dir, gt = resolved

    vulns = [v for v in gt.get("vulnerabilities", []) if v.get("ai_native_rule")]
    decoys = [d for d in gt.get("decoys", []) if d.get("ai_native_rule")]
    assert vulns, "expected at least one ai_native_rule-tagged vulnerability"
    assert decoys, "expected at least one ai_native_rule-tagged decoy"

    ids = [v["id"] for v in vulns] + [d["id"] for d in decoys]
    assert len(ids) == len(set(ids)), f"duplicate ai_native_rule-tagged ids: {ids}"

    for v in vulns:
        raw_sink = v["sink"]
        sinks = raw_sink if isinstance(raw_sink, list) else [raw_sink]
        for s in sinks:
            line_range = benchmark._function_line_range(app_dir / s["file"], s["symbol"])
            assert line_range is not None, (
                f"{v['id']}: sink symbol '{s['symbol']}' not found in {s['file']}"
            )

    for d in decoys:
        loc = d["location"]
        line_range = benchmark._function_line_range(app_dir / loc["file"], loc["symbol"])
        assert line_range is not None, (
            f"{d['id']}: decoy symbol '{loc['symbol']}' not found in {loc['file']}"
        )


def test_cross_file_corpus_gates_recall_and_negatives():
    """BACKLOG RT-19: the cross_file corpus must score every positive and no
    negative on the current engine. Before it existed no gated number
    exercised CrossFilePass at all."""
    benchmark = _load_benchmark_module()
    report = benchmark.run_cross_file_cases()
    assert report is not None and not report["degraded"]
    misses = [r["dir"] for r in report["rows"] if r["expected"] == "detect" and not r["found"]]
    fps = [r["dir"] for r in report["rows"] if r["expected"] == "clean" and r["found"]]
    assert not misses, misses
    assert not fps, fps
    assert report["ok"]


def test_report_volume_tracks_raw_and_clustered_counts_without_scoring(tmp_path):
    benchmark = _load_benchmark_module()
    findings = []
    for caller, line in (("first", 4), ("second", 8), ("third", 12)):
        findings.append(Finding(
            rule_id="CF-SINK-001",
            message=f"{caller} reaches pickle.loads",
            severity=Severity.HIGH,
            category=Category.DESERIALIZATION,
            file_path=str(tmp_path / f"{caller}.py"),
            start_line=line,
            engine="crossfile",
            taint_flow=TaintFlow(
                source=TaintNode(file_path=str(tmp_path / f"{caller}.py"), line=line),
                sink=TaintNode(file_path=str(tmp_path / "sink.py"), line=3),
            ),
            metadata={
                "cross_file": True,
                "caller": caller,
                "sink_rule_id": "NS-DESER-001",
                "sink_symbol": "pickle.loads",
            },
        ))

    benchmark._REPORT_VOLUME.update(scans=0, raw_findings=0, review_clusters=0)
    benchmark._record_report_volume(ScanResult(findings=findings), tmp_path)

    assert benchmark._REPORT_VOLUME == {
        "scans": 1,
        "raw_findings": 3,
        "review_clusters": 1,
    }


def test_taint_path_hops_survive_nested_parens_and_prose():
    """RT-11: the oracle's hop names must parse even when the note has nested
    parens, quotes or a trailing clause."""
    benchmark = _load_benchmark_module()
    hops = benchmark._taint_path_hops([
        "langfail/core/security.py:legacy_access_key (unsalted md5(password) stored — at rest)",
        "langfail/api/agent.py:iterate (max_rounds, int()-cast but not clamped)",
        'langfail/mcp_server.py:check_http_auth (headers.get("Authorization") == f"Bearer x")',
        "langfail/agent/core.py:run_agent use_memory=True (recall() pulls ALL memories)",
        "langfail/api/agent.py:execute -> langfail/agent/core.py:run_agent_guarded",
        "langfail/ml/model_loader.py:load_model_verified -> _VerifiedUnpickler.find_class (allow-list)",
        "dvml/workers/tasks.py:import_dataset -> _notify (worker POSTs) OR sync POST on archive import",
        "requests.post(webhook_url) with NO gate, unlike fetch()",
    ])
    assert hops == {
        ("langfail/core/security.py", "legacy_access_key"),
        ("langfail/api/agent.py", "iterate"),
        ("langfail/mcp_server.py", "check_http_auth"),
        ("langfail/agent/core.py", "run_agent"),
        ("langfail/api/agent.py", "execute"),
        ("langfail/agent/core.py", "run_agent_guarded"),
        ("langfail/ml/model_loader.py", "load_model_verified"),
        ("langfail/ml/model_loader.py", "_VerifiedUnpickler.find_class"),
        ("dvml/workers/tasks.py", "import_dataset"),
        ("dvml/workers/tasks.py", "_notify"),
    }


def test_off_window_credit_needs_a_finding_inside_a_declared_hop(tmp_path):
    """RT-11: a same-class finding elsewhere in a taint_path file is not a
    detection of this vulnerability; one inside a declared hop function is."""
    benchmark = _load_benchmark_module()
    src = tmp_path / "app" / "loader.py"
    src.parent.mkdir()
    src.write_text(
        "import pickle\n\n"
        "def _deserialize(b):\n"
        "    return pickle.loads(b)\n\n"
        "def load_model_verified(b):\n"
        "    return pickle.loads(b)\n",
        encoding="utf-8",
    )
    taint_path = ["app/loader.py:load_model_verified (allow-list bypass)"]
    files = benchmark._taint_path_files(taint_path)
    hops = benchmark._taint_path_hops(taint_path)
    kw = benchmark._cwe_keywords("CWE-502")
    elsewhere = [(str(src), 4, "deserialization ns-deser-001 pickle.loads", (502,))]
    inside = [(str(src), 7, "deserialization ns-deser-001 pickle.loads", (502,))]
    assert benchmark._hit_anywhere_on_path(elsewhere, files, kw, None, 502, hops) is False
    assert benchmark._hit_anywhere_on_path(inside, files, kw, None, 502, hops) is True
