"""Tests for the Opengrep adapter (--json output parsing, binary detection).

GitHub issue #118: switched internal parsing from SARIF to Opengrep's native
--json output, which carries each rule's full metadata: block (category/cwe/
fix/confidence/original_severity/etc.) inline per result -- SARIF 1.22.0
does not propagate arbitrary metadata: into its properties at all (confirmed
empirically), which is why category/severity/cwe/fix used to need a
separate conversion-manifest side-channel just to recover what the rule
already declared.
"""

import json
import subprocess
from pathlib import Path

import pytest

from rowan.taint.opengrep_adapter import OpengrepAdapter

SAMPLE_JSON = {
    "results": [
        {
            "check_id": "test.taint.pickle",
            "path": "src/app.py",
            "start": {"line": 15, "col": 5},
            "end": {"line": 15, "col": 30},
            "extra": {
                "message": "User-controlled data reaches pickle.loads()",
                "severity": "ERROR",
                "metadata": {"cwe": ["CWE-502"], "category": "deserialization"},
                "dataflow_trace": {
                    "taint_source": [
                        "CliLoc",
                        [
                            {"path": "src/app.py", "start": {"line": 12, "col": 1}},
                            "data = request.args.get('payload')",
                        ],
                    ],
                    "intermediate_vars": [],
                    "taint_sink": [
                        "CliLoc",
                        [
                            {"path": "src/app.py", "start": {"line": 15, "col": 5}},
                            "pickle.loads(data)",
                        ],
                    ],
                },
            },
        },
        {
            "check_id": "test.taint.eval",
            "path": "src/app.py",
            "start": {"line": 42, "col": 1},
            "end": {"line": 42, "col": 20},
            "extra": {
                "message": "User input flows into eval()",
                "severity": "ERROR",
                "metadata": {},
            },
        },
    ],
}


def test_parse_json():
    adapter = OpengrepAdapter()
    findings = adapter._parse_json_output(json.dumps(SAMPLE_JSON))

    assert len(findings) == 2

    f1 = findings[0]
    assert f1.rule_id == "pickle"
    assert f1.file_path == "src/app.py"
    assert f1.start_line == 15
    assert f1.severity.value == "high"
    assert f1.category.value == "deserialization"
    assert len(f1.cwe_ids) == 1
    assert 502 in f1.cwe_ids
    assert f1.engine == "opengrep"

    # Taint flow
    assert f1.taint_flow is not None
    assert f1.taint_flow.source is not None
    assert f1.taint_flow.source.line == 12
    assert f1.taint_flow.sink is not None
    assert f1.taint_flow.sink.line == 15

    f2 = findings[1]
    assert f2.rule_id == "eval"
    assert f2.start_line == 42
    assert f2.taint_flow is None  # No dataflow_trace in this result


def test_remediation_surfaces_directly_from_metadata():
    """No conversion-manifest lookup needed -- metadata.fix on the result
    itself must populate Finding.metadata['remediation']."""
    data = {
        "results": [
            {
                "check_id": "TNT-DESER-001",
                "path": "app.py",
                "start": {"line": 3, "col": 1},
                "end": {"line": 3, "col": 10},
                "extra": {
                    "message": "test",
                    "severity": "ERROR",
                    "metadata": {"fix": "use a safe alternative"},
                },
            },
        ],
    }
    adapter = OpengrepAdapter()
    findings = adapter._parse_json_output(json.dumps(data))
    assert len(findings) == 1
    assert findings[0].metadata["remediation"] == "use a safe alternative"


def test_original_severity_restores_critical_and_low():
    """A converted regex rule's original 5-tier severity (critical/low),
    preserved under metadata.original_severity, must override the lossy
    3-tier ERROR/WARNING/INFO mapping -- directly, with no manifest lookup."""
    def _make(orig_sev: str) -> dict:
        return {
            "results": [
                {
                    "check_id": "NS-TEST-001",
                    "path": "app.py",
                    "start": {"line": 1, "col": 1},
                    "end": {"line": 1, "col": 5},
                    "extra": {
                        "message": "test",
                        "severity": "WARNING",
                        "metadata": {"original_severity": orig_sev},
                    },
                },
            ],
        }

    adapter = OpengrepAdapter()

    critical = adapter._parse_json_output(json.dumps(_make("critical")))
    assert critical[0].severity.value == "critical"

    low = adapter._parse_json_output(json.dumps(_make("low")))
    assert low[0].severity.value == "low"


def test_adapter_binary_detection():
    """Test that OpengrepAdapter can detect the binary."""
    adapter = OpengrepAdapter()

    # This should not crash, just return False if not installed
    installed = adapter.is_installed()

    if installed:
        assert adapter.get_version()
        print(f"  Opengrep version: {adapter.get_version()}")
    else:
        print("  Opengrep not installed (expected in test environment)")


def test_availability_and_version_probe_is_cached(monkeypatch):
    """One adapter must execute ``--version`` at most once."""
    calls = []

    def fake_run(args, **kwargs):
        calls.append(args)
        return subprocess.CompletedProcess(args, returncode=0, stdout="opengrep 1.2.3\n", stderr="")

    monkeypatch.setattr("rowan.taint.opengrep_adapter.subprocess.run", fake_run)
    adapter = OpengrepAdapter()
    monkeypatch.setattr(type(adapter), "binary", property(lambda self: "opengrep"))

    assert adapter.is_installed() is True
    assert adapter.is_installed() is True
    assert adapter.get_version() == "opengrep 1.2.3"
    assert calls == [["opengrep", "--version"]]


def test_successful_probe_is_shared_until_the_binary_changes(monkeypatch, tmp_path):
    """New adapters reuse a successful probe of the same binary file."""
    binary = tmp_path / "opengrep"
    binary.write_text("v1", encoding="utf-8")
    calls = []

    def fake_run(args, **kwargs):
        calls.append(args)
        return subprocess.CompletedProcess(args, returncode=0, stdout="opengrep 1.2.3\n", stderr="")

    monkeypatch.setattr("rowan.taint.opengrep_adapter.subprocess.run", fake_run)
    monkeypatch.setattr("rowan.taint.opengrep_adapter._VERSION_PROBES", {})
    monkeypatch.setattr(OpengrepAdapter, "binary", property(lambda self: str(binary)))

    assert OpengrepAdapter().is_installed() is True
    assert OpengrepAdapter().get_version() == "opengrep 1.2.3"
    assert len(calls) == 1

    binary.write_text("v2 is longer", encoding="utf-8")
    assert OpengrepAdapter().is_installed() is True
    assert len(calls) == 2


def test_failed_availability_probe_is_cached(monkeypatch):
    calls = []

    def fake_run(args, **kwargs):
        calls.append(args)
        raise FileNotFoundError

    monkeypatch.setattr("rowan.taint.opengrep_adapter.subprocess.run", fake_run)
    adapter = OpengrepAdapter()
    monkeypatch.setattr(type(adapter), "binary", property(lambda self: "opengrep"))

    assert adapter.is_installed() is False
    assert adapter.is_installed() is False
    assert adapter.get_version() == "unknown"
    assert calls == [["opengrep", "--version"]]


def test_explicit_refresh_observes_engine_installed_after_cached_failure(monkeypatch):
    calls = []

    def fake_run(args, **kwargs):
        calls.append(args)
        if len(calls) == 1:
            raise FileNotFoundError
        return subprocess.CompletedProcess(
            args,
            returncode=0,
            stdout="opengrep 2.0.0\n",
            stderr="",
        )

    monkeypatch.setattr("rowan.taint.opengrep_adapter.subprocess.run", fake_run)
    adapter = OpengrepAdapter()
    monkeypatch.setattr(type(adapter), "binary", property(lambda self: "opengrep"))

    assert adapter.is_installed() is False
    assert adapter.is_installed() is False
    assert adapter.refresh_availability() is True
    assert adapter.get_version() == "opengrep 2.0.0"
    assert calls == [["opengrep", "--version"], ["opengrep", "--version"]]


def test_category_inference():
    """Test category inference from rule IDs and messages."""
    from rowan.core.findings import Category
    from rowan.taint.opengrep_adapter import _infer_category

    assert _infer_category("pickle_rce", "pickle.loads on tainted data") == Category.DESERIALIZATION
    assert _infer_category("ssrf_detect", "HTTP request with user URL") == Category.SSRF
    assert _infer_category("ssti", "Jinja2 template injection") == Category.SSTI
    assert _infer_category("sqli", "SQL injection risk") == Category.INJECTION
    assert _infer_category("cmd_injection", "os.system with input") == Category.COMMAND_INJECTION
    assert _infer_category("unknown_rule", "some generic message") == Category.GENERAL


def test_resolve_category_prefers_declared_category():
    from rowan.core.findings import Category
    from rowan.taint.opengrep_adapter import _resolve_category

    # Valid declared category wins even if the message would infer differently.
    assert _resolve_category("some-rule", "pickle.loads", {"category": "ssrf"}) == Category.SSRF
    # Invalid/unmapped declared category (e.g. "security") falls back to inference.
    assert _resolve_category("sqli", "SQL injection risk", {"category": "security"}) == Category.INJECTION
    # No declared category at all falls back to inference.
    assert _resolve_category("ssti", "Jinja2 template injection", {}) == Category.SSTI


def test_operator_input_siblings_resolve_to_the_001_category():
    """EXT-19: the `-002` operator-input siblings declare `category: security`
    (not a Category value), so they land wherever their id and message
    infer. Each must resolve to the same category as its `-001`, or the
    enrichment thresholds, dangerous-sink handling and JG-15 demotion would
    treat an env-sourced command injection as `general`."""
    from pathlib import Path

    import yaml

    from rowan.core.findings import Category
    from rowan.core.rule_class import rule_class
    from rowan.taint.opengrep_adapter import _resolve_category

    expected = {
        "tnt-ja-sqli": Category.INJECTION,
        "tnt-ja-cmdi": Category.COMMAND_INJECTION,
        "tnt-ja-path": Category.PATH_TRAVERSAL,
        "tnt-ja-ssrf": Category.SSRF,
        "tnt-go-sqli": Category.INJECTION,
        "tnt-go-cmdi": Category.COMMAND_INJECTION,
        "tnt-go-path": Category.PATH_TRAVERSAL,
        "tnt-go-ssrf": Category.SSRF,
    }
    rules_dir = Path(__file__).parent.parent / "rules"
    by_id = {}
    for name in ("java_taint.yaml", "go_taint.yaml"):
        for rule in yaml.safe_load((rules_dir / name).read_text())["rules"]:
            by_id[rule["id"]] = rule
    for stem, category in expected.items():
        for suffix in ("-001", "-002"):
            rule = by_id[stem + suffix]
            got = _resolve_category(rule["id"], rule["message"], rule.get("metadata", {}))
            assert got == category, (rule["id"], got)
            assert rule_class(rule["id"]) == "vulnerability"
        assert by_id[stem + "-002"]["metadata"]["source_kind"] == "operator_input"
        assert by_id[stem + "-002"]["severity"] == "WARNING"
        assert by_id[stem + "-002"]["pattern-sinks"] == by_id[stem + "-001"]["pattern-sinks"]


def test_cwe_parsing():
    """Test CWE ID extraction from extra metadata."""
    from rowan.taint.opengrep_adapter import _parse_cwe_ids

    assert _parse_cwe_ids({"cwe": ["CWE-502", "CWE-94"]}) == [502, 94]
    assert _parse_cwe_ids({"cwe": [502]}) == [502]
    assert _parse_cwe_ids({"cwe": ["CWE-79"]}) == [79]
    assert _parse_cwe_ids({}) == []
    assert _parse_cwe_ids({"cwe": "CWE-89"}) == []  # Not a list


def _namespaced_json(raw_rule_id: str) -> dict:
    """Build a minimal --json dict whose result uses the given (raw) check_id."""
    return {
        "results": [
            {
                "check_id": raw_rule_id,
                "path": "src/views.py",
                "start": {"line": 23, "col": 9},
                "end": {"line": 23, "col": 30},
                "extra": {
                    "message": "User input flows into logger.info()",
                    "severity": "ERROR",
                    "metadata": {"cwe": ["CWE-117"]},
                },
            },
        ],
    }


def test_namespaced_rule_id_is_cleaned():
    """opengrep namespaces check_id with the temp config dir path; strip it."""
    adapter = OpengrepAdapter()
    raw = "var.folders.tmp.rowan_rules_abc.TNT-LOG-001"
    findings = adapter._parse_json_output(json.dumps(_namespaced_json(raw)))

    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "TNT-LOG-001"
    assert f.severity.value == "high"
    assert 117 in f.cwe_ids
    # location still parsed correctly
    assert f.file_path == "src/views.py"
    assert f.start_line == 23
    assert f.start_column == 9
    # no leaked filesystem path anywhere in the id/metadata
    assert "var.folders" not in f.rule_id
    assert "var.folders" not in f.metadata.get("rule_name", "")


def test_already_clean_rule_id_unchanged():
    """A check_id with no namespace prefix passes through untouched."""
    from rowan.taint.opengrep_adapter import _clean_rule_id

    assert _clean_rule_id("TNT-SQLI-002") == "TNT-SQLI-002"
    assert _clean_rule_id(None) == "unknown"
    assert _clean_rule_id("") == "unknown"
    assert _clean_rule_id("a.b.c.TNT-ML-009") == "TNT-ML-009"

    adapter = OpengrepAdapter()
    findings = adapter._parse_json_output(json.dumps(_namespaced_json("TNT-SQLI-002")))
    assert len(findings) == 1
    assert findings[0].rule_id == "TNT-SQLI-002"


def test_run_batch_requests_json_and_dataflow_traces(tmp_path, monkeypatch):
    """The `opengrep scan` invocation must pass --json (not --sarif, which
    doesn't propagate rule metadata) and --dataflow-traces (without which
    Opengrep's output omits the dataflow trace for every result, so
    _extract_taint_flow() always returns None and every taint-mode finding
    silently loses its source/sink path -- BACKLOG.md DEF-2 "Related")."""
    captured_args = {}

    def fake_run(args, **kwargs):
        captured_args["args"] = args
        return subprocess.CompletedProcess(
            args, returncode=0, stdout=json.dumps({"results": []}), stderr=""
        )

    monkeypatch.setattr("rowan.taint.opengrep_adapter.subprocess.run", fake_run)

    adapter = OpengrepAdapter()
    monkeypatch.setattr(type(adapter), "binary", property(lambda self: "opengrep"))

    target = tmp_path / "app.py"
    target.write_text("x = 1\n", encoding="utf-8")

    adapter._run_batch(
        batch=[target],
        rules_dir=tmp_path,
        languages=None,
        taint_intrafile=True,
        extra_configs=[],
    )

    assert "--json" in captured_args["args"]
    assert "--sarif" not in captured_args["args"]
    assert "--dataflow-traces" in captured_args["args"]


def test_run_batch_disables_opengreps_own_per_rule_timeout(tmp_path, monkeypatch):
    """DEF-20: Opengrep defaults to a 5s-per-rule-per-file wall-clock timeout
    and silently skips a file entirely once 3 rules have timed out on it
    (--timeout-threshold). Both are wall-clock-based, so under system load
    the same rule/file pair can produce fewer findings on one run than
    another with zero code changes in between -- a real scan-to-scan
    reproducibility risk in a security tool. Both must be explicitly
    disabled (set to 0/unlimited); the adaptively-scaled per-batch
    subprocess timeout is the intended safety net instead.
    """
    captured_args = {}

    def fake_run(args, **kwargs):
        captured_args["args"] = args
        return subprocess.CompletedProcess(
            args, returncode=0, stdout=json.dumps({"results": []}), stderr=""
        )

    monkeypatch.setattr("rowan.taint.opengrep_adapter.subprocess.run", fake_run)

    adapter = OpengrepAdapter()
    monkeypatch.setattr(type(adapter), "binary", property(lambda self: "opengrep"))

    target = tmp_path / "app.py"
    target.write_text("x = 1\n", encoding="utf-8")

    adapter._run_batch(
        batch=[target],
        rules_dir=tmp_path,
        languages=None,
        taint_intrafile=True,
        extra_configs=[],
    )

    args = captured_args["args"]
    assert "--timeout" in args
    assert args[args.index("--timeout") + 1] == "0"
    assert "--timeout-threshold" in args
    assert args[args.index("--timeout-threshold") + 1] == "0"


def test_run_batch_forces_utf8_locale_on_child(tmp_path, monkeypatch):
    """Under a C/POSIX locale, opengrep's bundled Python decodes rule config
    files (Path.read_text() with no explicit encoding) using the process
    locale's codeset, which is ASCII under C/POSIX. Any non-ASCII byte in a
    rule YAML file's comments/messages -- this repo's own rule corpus has
    plenty, e.g. typographic dashes -- then makes opengrep raise
    UnicodeDecodeError while reading its own config, before scanning
    anything, silently zeroing every taint finding.

    Verified empirically against the actual opengrep binary (not assumed):
    PYTHONUTF8=1 alone and PYTHONIOENCODING=utf-8 alone both fail to fix
    this; only forcing LC_ALL/LANG to a UTF-8 codeset (LC_ALL=C.UTF-8) does.
    This test asserts the subprocess is invoked with that override rather
    than re-running the slow/awkward real-subprocess-under-forced-locale
    path end to end.
    """
    monkeypatch.setenv("SOME_UNRELATED_PARENT_VAR", "drop-me")
    monkeypatch.setenv("OPENAI_API_KEY", "not-a-real-key")
    monkeypatch.setenv("LC_ALL", "C")
    monkeypatch.setenv("LANG", "C")

    captured_kwargs = {}

    def fake_run(args, **kwargs):
        captured_kwargs.update(kwargs)
        return subprocess.CompletedProcess(
            args, returncode=0, stdout=json.dumps({"results": []}), stderr=""
        )

    monkeypatch.setattr("rowan.taint.opengrep_adapter.subprocess.run", fake_run)

    adapter = OpengrepAdapter()
    monkeypatch.setattr(type(adapter), "binary", property(lambda self: "opengrep"))

    target = tmp_path / "app.py"
    target.write_text("x = 1\n", encoding="utf-8")

    adapter._run_batch(
        batch=[target],
        rules_dir=tmp_path,
        languages=None,
        taint_intrafile=True,
        extra_configs=[],
    )

    child_env = captured_kwargs.get("env")
    assert child_env is not None, "opengrep must be run with an explicit env override"
    assert child_env["LC_ALL"] == "C.UTF-8"
    assert child_env["LANG"] == "C.UTF-8"
    # Only allowlisted variables are inherited: PATH stays, secrets and
    # unrelated variables do not reach the child.
    assert "PATH" in child_env
    assert "OPENAI_API_KEY" not in child_env
    assert "SOME_UNRELATED_PARENT_VAR" not in child_env


def test_run_batch_returns_stderr_detail_on_non_timeout_failure(tmp_path, monkeypatch):
    """A non-timeout batch failure (e.g. the locale/encoding error above, or
    any other opengrep crash) must surface its real stderr-derived cause
    through the returned tuple, not just a bare status string -- callers
    need this to avoid misattributing the failure to a timeout (see
    rowan/passes/taint.py's degraded-message construction)."""

    def fake_run(args, **kwargs):
        return subprocess.CompletedProcess(
            args, returncode=2, stdout="", stderr="UnicodeDecodeError: boom"
        )

    monkeypatch.setattr("rowan.taint.opengrep_adapter.subprocess.run", fake_run)

    adapter = OpengrepAdapter()
    monkeypatch.setattr(type(adapter), "binary", property(lambda self: "opengrep"))

    target = tmp_path / "app.py"
    target.write_text("x = 1\n", encoding="utf-8")

    findings, status, detail = adapter._run_batch(
        batch=[target],
        rules_dir=tmp_path,
        languages=None,
        taint_intrafile=True,
        extra_configs=[],
    )

    assert findings == []
    assert status == "error"
    assert "UnicodeDecodeError: boom" in detail


def test_run_batch_timeout_has_no_redundant_detail(tmp_path, monkeypatch):
    """A genuine subprocess timeout should still report status="timeout"
    with an empty detail string -- the timeout itself is the cause, already
    conveyed by the status, and scan_collect()'s "(N timed out)" summary
    would otherwise be duplicated per-batch in the aggregated message."""

    def fake_run(args, **kwargs):
        raise subprocess.TimeoutExpired(cmd=args, timeout=1)

    monkeypatch.setattr("rowan.taint.opengrep_adapter.subprocess.run", fake_run)

    adapter = OpengrepAdapter()
    monkeypatch.setattr(type(adapter), "binary", property(lambda self: "opengrep"))

    target = tmp_path / "app.py"
    target.write_text("x = 1\n", encoding="utf-8")

    findings, status, detail = adapter._run_batch(
        batch=[target],
        rules_dir=tmp_path,
        languages=None,
        taint_intrafile=True,
        extra_configs=[],
    )

    assert findings == []
    assert status == "timeout"
    assert detail == ""


def test_symlinks_are_not_handed_to_opengrep(tmp_path):
    """Issue #273: opengrep does not follow a symlink given as an explicit
    target -- it reports "File not found" and exits 2, and because that status
    is per-batch it discards every finding from the other files in the batch.

    chainlit ships a symlinked README.md and discourse 20 symlinks, which is
    why those two corpus repos reported a partial batch on every scan and
    silently lost findings from unrelated files (chainlit 54 -> 47).

    The link's target is walked on its own merits, so skipping the link loses
    no coverage and avoids double-reporting the same content.
    """
    real = tmp_path / "real.py"
    real.write_text("import os\nos.system('x')\n", encoding="utf-8")
    (tmp_path / "link.py").symlink_to(real)
    (tmp_path / "README.md").symlink_to(real)

    collected = OpengrepAdapter()._discover_files(tmp_path, None)
    names = {p.name for p in collected}

    assert "real.py" in names, "the real file must still be scanned"
    assert "link.py" not in names, "a symlink must never be handed to opengrep"
    assert "README.md" not in names
    assert not any(p.is_symlink() for p in collected)


def test_unsupported_language_is_rejected_before_any_subprocess(tmp_path, monkeypatch):
    """A typo must fail closed, never become an unrestricted directory scan."""
    (tmp_path / "app.py").write_text("eval(input())\n", encoding="utf-8")
    called = False

    def fake_run(args, **kwargs):
        nonlocal called
        called = True
        raise AssertionError("unsupported language must be rejected before probing or scanning")

    monkeypatch.setattr("rowan.taint.opengrep_adapter.subprocess.run", fake_run)

    with pytest.raises(ValueError, match=r"Unsupported language\(s\): pythn"):
        OpengrepAdapter().scan_collect(tmp_path, tmp_path, languages=["pythn"])
    assert called is False


def test_mixed_supported_and_unsupported_languages_reject_entire_scope(tmp_path):
    with pytest.raises(ValueError, match="pythn"):
        OpengrepAdapter()._build_batches(
            tmp_path, languages=["python", "pythn"], workers=1, batch_size=150
        )


def test_explicit_supported_language_with_no_files_has_no_directory_fallback(tmp_path):
    (tmp_path / "app.js").write_text("eval(userInput)\n", encoding="utf-8")

    batches = OpengrepAdapter()._build_batches(
        tmp_path, languages=["python"], workers=1, batch_size=150
    )

    assert batches == []


def test_candidate_discovery_matches_walk_and_never_rewalks(tmp_path, monkeypatch):
    included_py = tmp_path / "app.py"
    included_js = tmp_path / "app.js"
    included_py.write_text("value = 1\n", encoding="utf-8")
    included_js.write_text("const value = 1;\n", encoding="utf-8")
    hidden = tmp_path / ".private" / "hidden.py"
    hidden.parent.mkdir()
    hidden.write_text("value = 2\n", encoding="utf-8")
    vendored = tmp_path / "node_modules" / "dep.js"
    vendored.parent.mkdir()
    vendored.write_text("const dep = 1;\n", encoding="utf-8")
    declaration = tmp_path / "notes.txt"
    declaration.write_text("not source\n", encoding="utf-8")
    adapter = OpengrepAdapter()
    standalone = adapter._discover_files(tmp_path, None)
    candidates = tuple(path for path in tmp_path.rglob("*") if path.is_file())

    def unexpected_walk(self, pattern):
        raise AssertionError(f"unexpected repository walk: {self} {pattern}")

    monkeypatch.setattr(Path, "rglob", unexpected_walk)
    reused = adapter._discover_files(tmp_path, None, candidates=candidates)

    assert reused == standalone


def test_empty_candidates_produce_no_batches_without_directory_fallback(
    tmp_path, monkeypatch
):
    (tmp_path / "outside_scope.py").write_text("eval(input())\n", encoding="utf-8")

    def unexpected_walk(self, pattern):
        raise AssertionError(f"unexpected repository walk: {self} {pattern}")

    monkeypatch.setattr(Path, "rglob", unexpected_walk)
    batches = OpengrepAdapter()._build_batches(
        tmp_path,
        languages=None,
        workers=1,
        batch_size=150,
        candidates=(),
    )

    assert batches == []


def test_candidate_batches_reapply_language_selection(tmp_path, monkeypatch):
    python_file = tmp_path / "app.py"
    js_file = tmp_path / "app.js"
    python_file.write_text("value = 1\n", encoding="utf-8")
    js_file.write_text("const value = 1;\n", encoding="utf-8")

    def unexpected_walk(self, pattern):
        raise AssertionError(f"unexpected repository walk: {self} {pattern}")

    monkeypatch.setattr(Path, "rglob", unexpected_walk)
    batches = OpengrepAdapter()._build_batches(
        tmp_path,
        languages=["javascript"],
        workers=1,
        batch_size=150,
        candidates=(python_file, js_file),
    )

    assert batches == [[js_file]]


def test_scan_collect_batches_exact_candidates_without_walk(tmp_path, monkeypatch):
    files = []
    for index in range(3):
        path = tmp_path / f"file_{index}.py"
        path.write_text(f"value = {index}\n", encoding="utf-8")
        files.append(path)

    adapter = OpengrepAdapter()
    monkeypatch.setattr(adapter, "is_installed", lambda: True)
    seen_batches = []

    def fake_batch(batch, *args, **kwargs):
        seen_batches.append(batch)
        return [], "ok", ""

    monkeypatch.setattr(adapter, "_run_batch", fake_batch)

    def unexpected_walk(self, pattern):
        raise AssertionError(f"unexpected repository walk: {self} {pattern}")

    monkeypatch.setattr(Path, "rglob", unexpected_walk)
    outcome = adapter.scan_collect(
        tmp_path,
        tmp_path,
        workers=1,
        batch_size=2,
        candidates=files,
    )

    assert outcome.status == "ok"
    assert outcome.batches_total == 2
    assert [path for batch in seen_batches for path in batch] == files


def test_auto_batch_policy_keeps_small_exact_scope_single_process(tmp_path, monkeypatch):
    files = []
    for index in range(8):
        path = tmp_path / f"file_{index}.py"
        path.write_text("value = 1\n", encoding="utf-8")
        files.append(path)

    adapter = OpengrepAdapter()
    monkeypatch.setattr(adapter, "is_installed", lambda: True)
    monkeypatch.setattr(adapter, "_bounded_cpu_count", lambda: 8)
    seen = []
    monkeypatch.setattr(
        adapter,
        "_run_batch",
        lambda batch, *args, **kwargs: (seen.append((batch, kwargs)) or ([], "ok", "")),
    )

    outcome = adapter.scan_collect(tmp_path, tmp_path, candidates=files)

    assert outcome.batches_total == 1
    assert outcome.workers == 1
    assert outcome.jobs_per_batch is None
    assert [path for batch, _ in seen for path in batch] == files


def test_auto_batch_policy_caps_jobs_against_bounded_cpu(tmp_path, monkeypatch):
    files = []
    for index in range(400):
        path = tmp_path / f"file_{index}.py"
        path.write_text("value = 1\n", encoding="utf-8")
        files.append(path)

    adapter = OpengrepAdapter(jobs=3)
    monkeypatch.setattr(adapter, "is_installed", lambda: True)
    monkeypatch.setattr(adapter, "_bounded_cpu_count", lambda: 8)
    monkeypatch.setattr(adapter, "_run_batch", lambda *args, **kwargs: ([], "ok", ""))

    outcome = adapter.scan_collect(tmp_path, tmp_path, candidates=files)

    # 400 files require three 150-file batches. jobs=3 constrains automatic
    # *concurrency* to floor(8 / 3) = two child processes at a time.
    assert outcome.batches_total == 3
    assert outcome.workers == 2
    assert outcome.jobs_per_batch == 3


def test_explicit_worker_override_is_not_changed_by_auto_policy(tmp_path, monkeypatch):
    files = []
    for index in range(400):
        path = tmp_path / f"file_{index}.py"
        path.write_text("value = 1\n", encoding="utf-8")
        files.append(path)

    adapter = OpengrepAdapter(jobs=3)
    monkeypatch.setattr(adapter, "is_installed", lambda: True)
    monkeypatch.setattr(adapter, "_bounded_cpu_count", lambda: 2)
    monkeypatch.setattr(adapter, "_run_batch", lambda *args, **kwargs: ([], "ok", ""))

    outcome = adapter.scan_collect(tmp_path, tmp_path, workers=4, candidates=files)

    assert outcome.batches_total == 4
    assert outcome.workers == 4
    assert outcome.jobs_per_batch == 3


def test_auto_timeout_accounts_for_non_python_target_size(tmp_path):
    config = tmp_path / "large.yaml"
    config.write_bytes(b"x" * (501 * 512 * 1024))

    assert OpengrepAdapter._auto_timeout(*OpengrepAdapter._target_metrics([config])) == 900


def test_configure_none_restores_automatic_controls():
    adapter = OpengrepAdapter(timeout=30, workers=2, jobs=2)

    adapter.configure(timeout=None, workers=None, jobs=None)

    assert adapter._timeout is None
    assert adapter._workers is None
    assert adapter._jobs is None


def test_scan_cpu_budget_caps_automatic_opengrep_parallelism(monkeypatch):
    monkeypatch.setattr("rowan.taint.opengrep_adapter.os.cpu_count", lambda: 64)
    adapter = OpengrepAdapter(cpu_budget=2)

    assert adapter._bounded_cpu_count() == 2

    adapter.configure(cpu_budget=None)

    assert adapter._bounded_cpu_count() == adapter._MAX_AUTO_CPU


def test_discovery_includes_supported_dockerfiles_and_github_workflows(tmp_path):
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text("FROM python:latest\n", encoding="utf-8")
    workflow = tmp_path / ".github" / "workflows" / "security.yml"
    workflow.parent.mkdir(parents=True)
    workflow.write_text("on: pull_request_target\n", encoding="utf-8")
    unrelated_github_file = tmp_path / ".github" / "dependabot.yml"
    unrelated_github_file.write_text("version: 2\n", encoding="utf-8")
    hidden_source = tmp_path / ".private" / "ignored.py"
    hidden_source.parent.mkdir()
    hidden_source.write_text("eval(input())\n", encoding="utf-8")

    collected = {
        path.relative_to(tmp_path).as_posix()
        for path in OpengrepAdapter()._discover_files(tmp_path, None)
    }

    assert "Dockerfile" in collected
    assert ".github/workflows/security.yml" in collected
    assert ".github/dependabot.yml" not in collected
    assert ".private/ignored.py" not in collected


class TestFindBinaryReconciliation:
    """Issue #224: `_find_binary()` preferred `~/.opengrep/cli/latest/` but
    `install-engine` writes to `~/.local/bin` (its actual --prefix default),
    so a scan could silently pick up an unrelated `opengrep` on PATH instead
    of the binary that was just installed and cosign-verified.
    """

    def test_prefers_local_install_over_bare_path(self, tmp_path, monkeypatch):
        fake_home = tmp_path
        local_bin = fake_home / ".local" / "bin"
        local_bin.mkdir(parents=True)
        managed_binary = local_bin / "opengrep"
        managed_binary.write_text("#!/bin/sh\necho fake\n")
        managed_binary.chmod(0o755)

        monkeypatch.setattr(Path, "home", classmethod(lambda cls: fake_home))
        # Simulate a *different* opengrep earlier on PATH that must not win.
        monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/opengrep")

        resolved = OpengrepAdapter()._find_binary()
        assert resolved == str(managed_binary)

    def test_falls_back_to_path_when_neither_managed_location_exists(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
        monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/opengrep" if name == "opengrep" else None)

        resolved = OpengrepAdapter()._find_binary()
        assert resolved == "/usr/bin/opengrep"


def test_one_malformed_result_is_skipped_not_fatal():
    import copy

    data = copy.deepcopy(SAMPLE_JSON)
    data["results"][0]["start"] = None
    data["results"][0]["extra"]["dataflow_trace"]["taint_source"] = ["CliLoc", [None, "x"]]
    findings = OpengrepAdapter()._parse_json_output(json.dumps(data))

    assert [f.start_line for f in findings] == [42]


def test_partial_batch_findings_are_kept(tmp_path, monkeypatch):
    files = []
    for index in range(2):
        path = tmp_path / f"file_{index}.py"
        path.write_text("value = 1\n", encoding="utf-8")
        files.append(path)

    adapter = OpengrepAdapter()
    monkeypatch.setattr(adapter, "is_installed", lambda: True)
    parsed = adapter._parse_json_output(json.dumps(SAMPLE_JSON))
    results = iter([(parsed, "partial", ""), ([], "ok", "")])
    monkeypatch.setattr(adapter, "_run_batch", lambda *args, **kwargs: next(results))

    outcome = adapter.scan_collect(tmp_path, tmp_path, workers=1, batch_size=1, candidates=files)

    assert len(outcome.findings) == 2
    assert outcome.status == "partial"


def test_external_rule_ids_keep_their_own_dots(tmp_path):
    """TE-17: two external rules sharing a tail must not collapse to one id."""
    from rowan.taint.opengrep_adapter import _clean_rule_id, _config_rule_ids

    (tmp_path / "vendor.yaml").write_text(
        "rules:\n"
        "- id: python.lang.security.sqli\n  pattern: x\n  message: m\n  languages: [python]\n  severity: ERROR\n"
        "- id: other.sqli\n  pattern: x\n  message: m\n  languages: [python]\n  severity: ERROR\n",
        encoding="utf-8",
    )
    ids = _config_rule_ids([str(tmp_path), "p/registry-name"])
    assert ids == {"python.lang.security.sqli", "other.sqli"}
    assert _clean_rule_id("tmp.x.python.lang.security.sqli", ids) == "python.lang.security.sqli"
    assert _clean_rule_id("tmp.x.other.sqli", ids) == "other.sqli"
    # Repo rules are unchanged.
    assert _clean_rule_id("rowan_rules_x.python_taint.TNT-CMDI-001", ids) == "TNT-CMDI-001"
