"""Tests for cross-file taint propagation pass."""

from __future__ import annotations

import ast
import tempfile
from pathlib import Path

import pytest

from rowan.config import ScanConfig
from rowan.core.findings import (
    Category,
    Finding,
    ScanResult,
    Severity,
    TaintFlow,
    TaintNode,
)
from rowan.passes.base import ScanContext
from rowan.passes.cross_file import (
    KNOWN_PROPAGATORS,
    CrossFilePass,
    _classify_path_sanitizer,
    _collect_agent_tool_nodes,
    _collect_orm_write_channels,
    _collect_python_files,
    _extract_functions,
    _extract_imports,
    _function_reads_orm_channel,
    _ImportGraph,
    _is_tool_class,
    _match_findings_to_functions,
    _propagate_cross_file,
    _resolve_relative_module,
    _structural_path_sink,
    _summarize_params,
)


@pytest.fixture
def cross_file_project():
    with tempfile.TemporaryDirectory(prefix="rowan_cf_") as tmpdir:
        root = Path(tmpdir)

        (root / "server.py").write_text(
            "from flask import request\n"
            "from utils import process_data\n"
            "\n"
            "def handle_request():\n"
            "    data = request.args.get('payload')\n"
            "    process_data(data)\n",
            encoding="utf-8",
        )

        (root / "utils.py").write_text(
            "import pickle\n\ndef process_data(raw):\n    return pickle.loads(raw)\n",
            encoding="utf-8",
        )

        yield root


@pytest.fixture
def chain_project():
    with tempfile.TemporaryDirectory(prefix="rowan_chain_") as tmpdir:
        root = Path(tmpdir)

        (root / "api.py").write_text(
            "from flask import request\n"
            "from middleware import transform\n"
            "\n"
            "def endpoint():\n"
            "    data = request.args.get('input')\n"
            "    transform(data)\n",
            encoding="utf-8",
        )

        (root / "middleware.py").write_text(
            "from sink import dangerous_op\n\ndef transform(payload):\n    dangerous_op(payload)\n",
            encoding="utf-8",
        )

        (root / "sink.py").write_text(
            "import os\n\ndef dangerous_op(cmd):\n    os.system(cmd)\n",
            encoding="utf-8",
        )

        yield root


def test_collect_python_files(cross_file_project):
    files = _collect_python_files(cross_file_project)
    names = {f.name for f in files}
    assert "server.py" in names
    assert "utils.py" in names


def test_collect_python_files_skips_hidden(cross_file_project):
    hidden = cross_file_project / ".hidden"
    hidden.mkdir()
    (hidden / "secret.py").write_text("x = 1", encoding="utf-8")
    files = _collect_python_files(cross_file_project)
    names = {f.name for f in files}
    assert "secret.py" not in names


def test_fixed_catalog_lookup_does_not_propagate_parameter_to_sink():
    safe = ast.parse(
        "def render(kind):\n"
        "    filename = BUILTIN_FILES.get(kind, 'summary.tpl')\n"
        "    return load_file(filename)\n"
    ).body[0]
    unsafe = ast.parse(
        "def render(kind):\n    filename = files.get(kind, kind)\n    return load_file(filename)\n"
    ).body[0]

    assert _summarize_params(safe, 3)[0] == frozenset()
    assert _summarize_params(unsafe, 3)[0] == frozenset({0})


def test_security_comparison_returns_decision_not_secret_material():
    function = ast.parse(
        "def verify(provided, expected):\n    return hmac.compare_digest(provided, expected)\n"
    ).body[0]
    assert _summarize_params(function, 0)[1] == frozenset()


def test_collect_python_files_skips_site_packages(cross_file_project):
    sp = cross_file_project / "site-packages"
    sp.mkdir()
    (sp / "dep.py").write_text("x = 1", encoding="utf-8")
    files = _collect_python_files(cross_file_project)
    names = {f.name for f in files}
    assert "dep.py" not in names


def test_extract_imports(cross_file_project):
    server_path = str((cross_file_project / "server.py").resolve())
    source = (cross_file_project / "server.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    graph = _extract_imports(server_path, tree)
    assert len(graph.name_to_def) > 0 or len(graph.module_to_file) > 0


def test_resolve_relative_module_single_dot(tmp_path):
    """`from . import x` (level=1) means "from this same package" -- caller_dir
    IS already that package directory, so this must resolve with ZERO parent
    hops. An off-by-one here (one hop too many) silently failed to resolve
    every single-dot relative import in any real package -- confirmed on a
    real app (ModelForge): CrossFilePass extracted 0 imports from a 37-file
    Flask app that imports its own modules almost entirely via `.`/`..`."""
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg" / "__init__.py").write_text("", encoding="utf-8")
    (tmp_path / "pkg" / "sub").mkdir()
    (tmp_path / "pkg" / "sub" / "__init__.py").write_text("", encoding="utf-8")
    (tmp_path / "pkg" / "sub" / "a.py").write_text("X = 1\n", encoding="utf-8")

    caller_dir = str(tmp_path / "pkg" / "sub")
    resolved = _resolve_relative_module(caller_dir, "a", level=1)
    assert resolved == str((tmp_path / "pkg" / "sub" / "a.py").resolve())


def test_resolve_relative_module_double_dot(tmp_path):
    """`from .. import x` (level=2) means "from the parent package" -- exactly
    one parent hop from caller_dir (which is already the level=1 package)."""
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg" / "__init__.py").write_text("", encoding="utf-8")
    (tmp_path / "pkg" / "sub").mkdir()
    (tmp_path / "pkg" / "sub" / "__init__.py").write_text("", encoding="utf-8")
    (tmp_path / "pkg" / "b.py").write_text("Y = 1\n", encoding="utf-8")

    caller_dir = str(tmp_path / "pkg" / "sub")
    resolved = _resolve_relative_module(caller_dir, "b", level=2)
    assert resolved == str((tmp_path / "pkg" / "b.py").resolve())


def test_cross_file_pass_follows_relative_imports_across_packages(tmp_path):
    """End-to-end: a real nested-package layout (api/ -> services/ -> ml/,
    the exact shape of the app that surfaced this bug) connected entirely by
    `.`/`..`-style relative imports must still produce a cross-file finding.
    Before the off-by-one fix, _resolve_relative_module returned None for
    every one of these imports, so the import graph -- and every cross-file
    finding depending on it -- was silently empty."""
    root = tmp_path / "app"
    (root / "api").mkdir(parents=True)
    (root / "api" / "__init__.py").write_text("", encoding="utf-8")
    (root / "services").mkdir()
    (root / "services" / "__init__.py").write_text("", encoding="utf-8")
    (root / "__init__.py").write_text("", encoding="utf-8")

    (root / "api" / "handler.py").write_text(
        "from flask import request\n"
        "from ..services.registry import store_artifact\n"
        "\n"
        "def upload():\n"
        "    data = request.args.get('payload')\n"
        "    store_artifact(data)\n",
        encoding="utf-8",
    )
    (root / "services" / "registry.py").write_text(
        "import pickle\n\ndef store_artifact(raw):\n    return pickle.loads(raw)\n",
        encoding="utf-8",
    )

    config = ScanConfig(target=root)
    findings = [
        Finding(
            rule_id="NS-DESER-001",
            message="pickle.load() allows arbitrary code execution",
            severity=Severity.MEDIUM,
            category=Category.DESERIALIZATION,
            file_path=str((root / "services" / "registry.py").resolve()),
            start_line=4,
            engine="opengrep",
        ),
    ]
    ctx = ScanContext(target_path=root, config=config, result=ScanResult(findings=findings))
    pass_result = CrossFilePass().run(ctx)

    cross_file_hits = [
        f for f in pass_result.findings if f.rule_id in ("CF-SINK-001", "CF-RETURN-001")
    ]
    assert cross_file_hits, (
        "expected a cross-file finding linking api/handler.py's request.args source "
        "through the ..services.registry relative import to the pickle.loads sink"
    )


def test_extract_functions(cross_file_project):
    server_path = str((cross_file_project / "server.py").resolve())
    source = (cross_file_project / "server.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    funcs = _extract_functions(server_path, tree)
    func_names = [f.name for f in funcs]
    assert "handle_request" in func_names


def test_extract_functions_detects_calls(cross_file_project):
    server_path = str((cross_file_project / "server.py").resolve())
    source = (cross_file_project / "server.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    funcs = _extract_functions(server_path, tree)
    handle = next(f for f in funcs if f.name == "handle_request")
    callee_names = [call[0] for call in handle.calls]
    assert "process_data" in callee_names


def test_extract_functions_marks_propagator():
    source = "import requests\ndef fetch(url):\n    return requests.get(url)\n"
    tree = ast.parse(source)
    funcs = _extract_functions("test.py", tree)
    fetch = next(f for f in funcs if f.name == "fetch")
    assert fetch.calls_propagator is True


def test_extract_functions_no_propagator():
    source = "def add(a, b):\n    return a + b\n"
    tree = ast.parse(source)
    funcs = _extract_functions("test.py", tree)
    add_fn = next(f for f in funcs if f.name == "add")
    assert add_fn.calls_propagator is False


def test_match_findings_to_functions():
    findings = [
        Finding(
            rule_id="TEST-001",
            message="pickle sink",
            severity=Severity.HIGH,
            category=Category.DESERIALIZATION,
            file_path="app.py",
            start_line=10,
            engine="opengrep",
            taint_flow=TaintFlow(
                source=TaintNode(file_path="app.py", line=6),
                sink=TaintNode(
                    file_path="app.py", line=10, snippet="pickle.loads(payload)"
                ),
            ),
        )
    ]
    from rowan.passes.cross_file import _FunctionSig

    real_funcs = [
        _FunctionSig(
            name="handler",
            file="app.py",
            line=5,
            params=["data"],
            calls=[],
        )
    ]
    result = _match_findings_to_functions(findings, real_funcs)
    assert result[0].has_sink is True
    assert result[0].has_source is True
    assert result[0].sink_rule_id == "TEST-001"
    assert result[0].sink_symbol == "pickle.loads"


@pytest.mark.parametrize("body, is_sink", [
    ('logger.warning(f"Please update version {value}")', False),
    ('await logger.awarning(f"Please update version {value}")', False),
    ('query = f"SELECT * FROM docs WHERE key = {value}"', True),
    ('logger.info(conn.execute(f"SELECT * FROM docs WHERE key = {value}"))', True),
    ('await logger.ainfo(conn.execute(f"SELECT * FROM docs WHERE key = {value}"))', True),
    ('logger.info(f"update {value}"); conn.execute(f"SELECT {value}")', True),
])
def test_sql_log_messages_are_not_propagated_as_query_sinks(body, is_sink):
    from rowan.passes.cross_file import _FunctionSig

    node = ast.parse('async def helper(value):\n    ' + body).body[0]
    sig = _FunctionSig(name="helper", file="helper.py", line=1,
                       end_line=2, params=["value"], calls=[])
    finding = Finding(rule_id="NS-SQLI-005", message="SQL keyword f-string",
                      severity=Severity.HIGH, category=Category.INJECTION,
                      file_path="helper.py", start_line=2, engine="opengrep")
    _match_findings_to_functions([finding], [sig],
                                def_nodes_by_line={("helper.py", "helper", 1): node})
    assert sig.has_sink is is_sink


def test_match_findings_neuroscan_sink():
    from rowan.passes.cross_file import _FunctionSig

    funcs = [
        _FunctionSig(
            name="handler",
            file="app.py",
            line=5,
            params=["data"],
            calls=[],
        )
    ]
    findings = [
        Finding(
            rule_id="NS-DESER-001",
            message="pickle.loads",
            severity=Severity.HIGH,
            category=Category.DESERIALIZATION,
            file_path="app.py",
            start_line=10,
            engine="neuroscan",
        )
    ]
    result = _match_findings_to_functions(findings, funcs)
    assert result[0].has_sink is True


def test_cross_file_pass_emits_findings(cross_file_project):
    server_resolved = str((cross_file_project / "server.py").resolve())
    utils_resolved = str((cross_file_project / "utils.py").resolve())

    taint_finding = Finding(
        rule_id="TNT-DESER-001",
        message="pickle.loads on tainted data",
        severity=Severity.HIGH,
        category=Category.DESERIALIZATION,
        file_path=utils_resolved,
        start_line=4,
        engine="opengrep",
        taint_flow=TaintFlow(
            source=TaintNode(file_path=utils_resolved, line=3),
            sink=TaintNode(file_path=utils_resolved, line=4),
        ),
    )

    source_finding = Finding(
        rule_id="NS-SSRF-001",
        message="user input",
        severity=Severity.MEDIUM,
        category=Category.SSRF,
        file_path=server_resolved,
        start_line=5,
        engine="neuroscan",
    )

    config = ScanConfig(target=cross_file_project)
    ctx = ScanContext(
        target_path=cross_file_project,
        config=config,
        result=ScanResult(findings=[taint_finding, source_finding]),
    )

    cf_pass = CrossFilePass()
    result = cf_pass.run(ctx)

    cf_findings = [f for f in result.findings if f.engine == "crossfile"]
    assert [(f.rule_id, Path(f.file_path).name, f.start_line) for f in cf_findings] == [
        ("CF-SINK-001", "server.py", 6)
    ]


def test_cross_file_pass_skips_single_file():
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / "only.py").write_text("x = 1", encoding="utf-8")

        config = ScanConfig(target=root)
        ctx = ScanContext(
            target_path=root,
            config=config,
            result=ScanResult(),
        )
        cf_pass = CrossFilePass()
        result = cf_pass.run(ctx)
        assert len(result.findings) == 0


def test_cross_file_pass_rejects_nonexistent_target_before_analysis():
    with pytest.raises(ValueError, match="target does not exist"):
        ScanConfig(target=Path("/nonexistent"))


def test_confidence_decay():
    from rowan.passes.cross_file import _emit_cross_file_finding, _FunctionSig

    findings: list[Finding] = []
    seen: set[tuple[str, str, str, str]] = set()

    caller = _FunctionSig(
        name="caller",
        file="a.py",
        line=1,
        params=[],
        calls=[],
    )
    callee = _FunctionSig(
        name="callee",
        file="b.py",
        line=1,
        params=[],
        calls=[],
        has_sink=True,
        sink_detail="pickle.loads",
    )

    _emit_cross_file_finding(findings, seen, caller, callee, ("b.py", "callee"), 0, "sink")
    assert len(findings) == 1
    assert findings[0].confidence == 0.75

    findings2: list[Finding] = []
    seen2: set[tuple[str, str, str, str]] = set()
    _emit_cross_file_finding(findings2, seen2, caller, callee, ("b.py", "callee"), 4, "sink")
    assert findings2[0].confidence == 0.35


def test_confidence_floor():
    from rowan.passes.cross_file import _emit_cross_file_finding, _FunctionSig

    findings: list[Finding] = []
    seen: set[tuple[str, str, str, str]] = set()

    caller = _FunctionSig(
        name="caller",
        file="a.py",
        line=1,
        params=[],
        calls=[],
    )
    callee = _FunctionSig(
        name="callee",
        file="b.py",
        line=1,
        params=[],
        calls=[],
        has_sink=True,
        sink_detail="os.system",
    )

    _emit_cross_file_finding(findings, seen, caller, callee, ("b.py", "callee"), 10, "sink")
    assert findings[0].confidence == 0.25


def test_dedup_cross_file_findings():
    from rowan.passes.cross_file import _emit_cross_file_finding, _FunctionSig

    findings: list[Finding] = []
    seen: set[tuple[str, str, str, str]] = set()

    caller = _FunctionSig(
        name="caller",
        file="a.py",
        line=1,
        params=[],
        calls=[],
    )
    callee = _FunctionSig(
        name="callee",
        file="b.py",
        line=1,
        params=[],
        calls=[],
        has_sink=True,
        sink_detail="test",
    )

    _emit_cross_file_finding(findings, seen, caller, callee, ("b.py", "callee"), 0, "sink")
    _emit_cross_file_finding(findings, seen, caller, callee, ("b.py", "callee"), 0, "sink")
    assert len(findings) == 1


def test_unclassified_return_lead_caps_at_low():
    """A return-direction flow whose callee has no sink classification is a lead,
    not a confirmed sink reach: it caps at LOW and is tagged so the actionable
    view can tell it apart from a classified return flow."""
    from rowan.passes.cross_file import _emit_cross_file_finding, _FunctionSig

    caller = _FunctionSig(name="caller", file="a.py", line=1, params=[], calls=[])

    def emit(callee: _FunctionSig) -> Finding:
        findings: list[Finding] = []
        _emit_cross_file_finding(findings, set(), caller, callee, ("b.py", "callee"), 0, "return")
        assert len(findings) == 1
        return findings[0]

    unclassified = emit(
        _FunctionSig(name="callee", file="b.py", line=1, params=[], calls=[], has_return_taint=True)
    )
    assert unclassified.severity == Severity.LOW
    assert unclassified.metadata["unclassified_return_lead"] is True

    classified = emit(
        _FunctionSig(
            name="callee",
            file="b.py",
            line=1,
            params=[],
            calls=[],
            has_sink=True,
            sink_detail="os.system",
            sink_cwe=[78],
        )
    )
    assert classified.severity == Severity.HIGH
    assert classified.metadata["unclassified_return_lead"] is False


def test_same_file_not_emitted():
    from rowan.passes.cross_file import _emit_cross_file_finding, _FunctionSig

    findings: list[Finding] = []
    seen: set[tuple[str, str, str, str]] = set()

    caller = _FunctionSig(
        name="caller",
        file="same.py",
        line=1,
        params=[],
        calls=[],
    )
    callee = _FunctionSig(
        name="callee",
        file="same.py",
        line=10,
        params=[],
        calls=[],
        has_sink=True,
        sink_detail="test",
    )

    _emit_cross_file_finding(findings, seen, caller, callee, ("same.py", "callee"), 0, "sink")
    assert len(findings) == 0


def test_known_propagators_include_httpx():
    assert "httpx.get" in KNOWN_PROPAGATORS
    assert "httpx.post" in KNOWN_PROPAGATORS
    assert "httpx.put" in KNOWN_PROPAGATORS
    assert "requests.post" in KNOWN_PROPAGATORS


def test_propagate_cross_file_fixpoint(cross_file_project):
    from rowan.passes.cross_file import _FunctionSig

    server_path = str((cross_file_project / "server.py").resolve())
    utils_path = str((cross_file_project / "utils.py").resolve())

    funcs = [
        _FunctionSig(
            name="handle_request",
            file=server_path,
            line=4,
            params=[],
            calls=[("process_data", None)],
            has_source=True,
        ),
        _FunctionSig(
            name="process_data",
            file=utils_path,
            line=3,
            params=["raw"],
            calls=[("loads", "pickle")],
            has_sink=True,
            sink_detail="pickle.loads on tainted data",
        ),
    ]

    import_graph = _ImportGraph()
    import_graph.name_to_def[(server_path, "process_data")] = (utils_path, "process_data")

    new_findings = _propagate_cross_file(funcs, import_graph, [], cross_file_project)

    cf = [f for f in new_findings if f.engine == "crossfile"]
    assert len(cf) >= 1
    assert any("handle_request" in f.message for f in cf)
    assert all(f.confidence >= 0.25 for f in cf)


def test_extract_functions_detects_known_sources():
    """AST source detection: a function reading request.* is marked has_source.

    Regression: without AST-level source detection, sources were only
    set from taint_flow, so cross-file emission could never fire in the default path.
    """
    src = (
        "from flask import request\n"
        "def handler():\n"
        "    return request.files['model'].read()\n"
        "def benign():\n"
        "    return compute(2 + 2)\n"
    )
    tree = ast.parse(src)
    funcs = {f.name: f for f in _extract_functions("/tmp/app.py", tree)}
    assert funcs["handler"].has_source is True
    assert funcs["benign"].has_source is False


def test_match_findings_marks_sink_regardless_of_engine_tag():
    """Regression: NeuroScan sink rules run through OpenGrep are tagged
    engine='opengrep', not 'neuroscan'. The matcher must still treat them as sinks.
    """
    from rowan.passes.cross_file import _FunctionSig

    sig = _FunctionSig(
        name="load_model",
        file="/tmp/services.py",
        line=5,
        params=["blob"],
        calls=[("load", "torch")],
    )
    finding = Finding(
        rule_id="NS-DESER-002",
        message="torch.load on tainted data",
        severity=Severity.MEDIUM,
        category=Category.DESERIALIZATION,
        file_path="/tmp/services.py",
        start_line=6,
        engine="opengrep",  # default-path tag, NOT "neuroscan"
        taint_flow=None,
    )
    out = {f.name: f for f in _match_findings_to_functions([finding], [sig])}
    assert out["load_model"].has_sink is True


def test_extract_imports_package_import_submodule_resolves_to_file(tmp_path):
    """DEF-30: `from ..services import registry` names a *file* inside the
    services package (dvml/services/registry.py), not a symbol defined in
    services/__init__.py -- but the old code always recorded it as the
    latter (name_to_def), so a call like `registry.read_artifact(x)` could
    never be resolved to registry.py's file path. This silently broke every
    cross-file edge using this (extremely common Flask-style api/+services/
    layout) import shape."""
    root = tmp_path / "app"
    (root / "api").mkdir(parents=True)
    (root / "api" / "__init__.py").write_text("", encoding="utf-8")
    (root / "services").mkdir()
    (root / "services" / "__init__.py").write_text("", encoding="utf-8")
    (root / "services" / "registry.py").write_text(
        "def read_artifact(name): ...\n", encoding="utf-8"
    )
    (root / "__init__.py").write_text("", encoding="utf-8")

    handler = root / "api" / "handler.py"
    handler.write_text("from ..services import registry\n", encoding="utf-8")

    tree = ast.parse(handler.read_text(encoding="utf-8"))
    graph = _extract_imports(str(handler.resolve()), tree)

    registry_file = str((root / "services" / "registry.py").resolve())
    assert graph.module_to_file.get((str(handler.resolve()), "registry")) == registry_file


def test_extract_imports_package_import_name_falls_back_to_name_to_def(tmp_path):
    """When the imported name is NOT a submodule file (it's a symbol defined
    inside the package's __init__.py), the old name_to_def behavior must
    still apply -- the submodule-file check should only take priority when
    such a file actually exists on disk."""
    root = tmp_path / "app"
    (root / "pkg").mkdir(parents=True)
    (root / "pkg" / "__init__.py").write_text("def helper(): ...\n", encoding="utf-8")
    (root / "__init__.py").write_text("", encoding="utf-8")

    caller = root / "caller.py"
    caller.write_text("from .pkg import helper\n", encoding="utf-8")

    tree = ast.parse(caller.read_text(encoding="utf-8"))
    graph = _extract_imports(str(caller.resolve()), tree)

    init_file = str((root / "pkg" / "__init__.py").resolve())
    assert graph.name_to_def.get((str(caller.resolve()), "helper")) == (init_file, "helper")
    assert (str(caller.resolve()), "helper") not in graph.module_to_file


def test_classify_path_sanitizer_weak_single_pass_strip():
    """A single non-recursive `.replace("../", "")` looks safe but is
    bypassable: '....//' contains '../' as a substring, and after one
    substitution pass the remaining '..' + '/' recombine into '../' again."""
    src = (
        "def sanitize_path(name):\n"
        "    cleaned = name.replace('../', '')\n"
        "    return cleaned.lstrip('/')\n"
    )
    func = ast.parse(src).body[0]
    assert _classify_path_sanitizer(func) == "weak"


def test_classify_path_sanitizer_strong_with_containment_check():
    src = (
        "def sanitize_path(base, name):\n"
        "    resolved = os.path.realpath(os.path.join(base, name))\n"
        "    if os.path.commonpath([resolved, base]) != base:\n"
        "        raise ValueError('escape')\n"
        "    return resolved\n"
    )
    func = ast.parse(src).body[0]
    assert _classify_path_sanitizer(func) == "strong"


def test_classify_path_sanitizer_strong_with_fixed_point_loop():
    src = (
        "def sanitize_path(name):\n"
        "    while '../' in name:\n"
        "        name = name.replace('../', '')\n"
        "    return name\n"
    )
    func = ast.parse(src).body[0]
    assert _classify_path_sanitizer(func) == "strong"


def test_classify_path_sanitizer_unknown_for_unrelated_function():
    """A quote-escaper (e.g. escape_sql) isn't a path sanitizer at all --
    must not be misclassified as a weak path-traversal guard."""
    src = 'def escape_sql(value):\n    return value.replace("\'", "\'\'")\n'
    func = ast.parse(src).body[0]
    assert _classify_path_sanitizer(func) == "unknown"


def test_classify_path_sanitizer_realpath_without_containment_check_is_unknown():
    """DEF-34: a function that calls os.path.realpath() as a mere
    normalization step, with NO comparison/containment check against a base
    directory, is not a sanitizer at all -- it used to be misclassified as
    "strong" just because a containment-attr name (realpath) appeared
    anywhere in the body, silently suppressing a real path-traversal
    finding downstream."""
    src = "def normalize(path):\n    return os.path.realpath(path)\n"
    func = ast.parse(src).body[0]
    assert _classify_path_sanitizer(func) == "unknown"


def test_classify_path_sanitizer_is_relative_to_counts_as_containment_check():
    """`.is_relative_to(...)`'s own return value IS the containment check --
    no further comparison needed."""
    src = (
        "def sanitize_path(base, name):\n"
        "    resolved = os.path.realpath(os.path.join(base, name))\n"
        "    if not resolved.is_relative_to(base):\n"
        "        raise ValueError('escape')\n"
        "    return resolved\n"
    )
    func = ast.parse(src).body[0]
    assert _classify_path_sanitizer(func) == "strong"


def test_classify_path_sanitizer_unrelated_loop_does_not_upgrade_weak_strip():
    """DEF-34: a loop elsewhere in the function (unrelated to the traversal
    strip) used to be enough to upgrade a single-pass `.replace('../', '')`
    to "strong" just because *some* loop existed alongside *some* replace
    call -- the loop must actually re-apply the same replace to a fixed
    point to count."""
    src = (
        "def sanitize_path(name, items):\n"
        "    name = name.replace('../', '')\n"
        "    for item in items:\n"
        "        process(item)\n"
        "    return name\n"
    )
    func = ast.parse(src).body[0]
    assert _classify_path_sanitizer(func) == "weak"


def test_classify_path_sanitizer_non_dominating_check_is_not_strong():
    """GitHub issue #124: a containment check that sits in a branch which
    does NOT dominate the function's actual return is dead code on the path
    that returns the "sanitized" value -- it must not earn "strong" just
    because it exists somewhere in the body. Here `if not
    real.startswith(BASE): raise ValueError()` only runs when `debug_mode`
    is truthy; the unconditional `return user_input` after the outer `if`
    returns the raw, unchecked input whenever `debug_mode` is falsy. Neither
    "weak" (no traversal-literal `.replace()` at all) nor "strong" applies,
    so this now degrades to "unknown" -- there is no fixed-point-loop-shaped
    fallback here for it to land on instead."""
    src = (
        "def sanitize_path(user_input):\n"
        "    if debug_mode:\n"
        "        real = os.path.realpath(user_input)\n"
        "        if not real.startswith(BASE):\n"
        "            raise ValueError()\n"
        "    return user_input\n"
    )
    func = ast.parse(src).body[0]
    assert _classify_path_sanitizer(func) == "unknown"


def test_classify_path_sanitizer_dominating_check_before_unconditional_return_is_strong():
    """Positive control for the issue #124 fix: a real, unconditional,
    dominating containment check followed by an unconditional return must
    still classify as "strong" -- the dominance requirement should not
    regress the straightforward case."""
    src = (
        "def sanitize_path(base, user_input):\n"
        "    real = os.path.realpath(user_input)\n"
        "    if not real.startswith(base):\n"
        "        raise ValueError()\n"
        "    return real\n"
    )
    func = ast.parse(src).body[0]
    assert _classify_path_sanitizer(func) == "strong"


def test_classify_path_sanitizer_check_dominates_all_of_multiple_returns():
    """A containment check before an if/else that both branches return from
    still dominates both returns (the check itself sits before the
    if/else, as an earlier sibling in the same block) -- must still be
    "strong"."""
    src = (
        "def sanitize_path(base, user_input, flag):\n"
        "    real = os.path.realpath(user_input)\n"
        "    if not real.startswith(base):\n"
        "        raise ValueError()\n"
        "    if flag:\n"
        "        return real\n"
        "    return real\n"
    )
    func = ast.parse(src).body[0]
    assert _classify_path_sanitizer(func) == "strong"


def test_classify_path_sanitizer_check_dominating_only_one_of_two_returns_is_not_strong():
    """A containment check that guards only ONE of two returns of the
    sanitized value must not count as "strong" -- the other return path
    bypasses it entirely."""
    src = (
        "def sanitize_path(base, user_input, flag):\n"
        "    if flag:\n"
        "        real = os.path.realpath(user_input)\n"
        "        if not real.startswith(base):\n"
        "            raise ValueError()\n"
        "        return real\n"
        "    return user_input\n"
    )
    func = ast.parse(src).body[0]
    assert _classify_path_sanitizer(func) == "unknown"


def test_structural_path_sink_absent_sanitizer():
    """No sanitizer at all between the base-dir join and the write call --
    the ModelForge V10 shape (save_with_metadata has no sanitize_path call)."""
    src = (
        "def save_with_metadata(data, meta):\n"
        "    rel = meta.get('storage_path') or 'default.bin'\n"
        "    target = os.path.join(str(ARTIFACT_DIR), rel)\n"
        "    os.makedirs(os.path.dirname(target), exist_ok=True)\n"
        "    with open(target, 'wb') as fh:\n"
        "        fh.write(data)\n"
    )
    func = ast.parse(src).body[0]
    has_sink, detail, _line = _structural_path_sink(func, {})
    assert has_sink is True
    assert "no sanitizer applied" in detail


def test_structural_path_sink_weak_sanitizer_still_flags():
    """The ModelForge V03 shape: sanitize_path() is called, but its
    implementation is a known-bypassable single-pass strip, so the finding
    must still surface rather than being suppressed by its mere presence."""
    src = (
        "def read_artifact(name):\n"
        "    safe = sanitize_path(name)\n"
        "    with open(os.path.join(str(ARTIFACT_DIR), safe), 'rb') as fh:\n"
        "        return fh.read()\n"
    )
    sanitizer_src = "def sanitize_path(name):\n    return name.replace('../', '')\n"
    func = ast.parse(src).body[0]
    def_nodes = {"sanitize_path": ast.parse(sanitizer_src).body[0]}
    has_sink, detail, _line = _structural_path_sink(func, def_nodes)
    assert has_sink is True
    assert "sanitize_path" in detail
    assert "bypassable" in detail


def test_structural_path_sink_strong_sanitizer_suppressed():
    """A proper containment-check sanitizer must suppress the finding --
    only weak/absent sanitizers should surface here."""
    src = (
        "def read_artifact(name):\n"
        "    safe = sanitize_path(name)\n"
        "    with open(os.path.join(str(ARTIFACT_DIR), safe), 'rb') as fh:\n"
        "        return fh.read()\n"
    )
    sanitizer_src = (
        "def sanitize_path(name):\n"
        "    resolved = os.path.realpath(os.path.join(ARTIFACT_DIR, name))\n"
        "    if os.path.commonpath([resolved, ARTIFACT_DIR]) != ARTIFACT_DIR:\n"
        "        raise ValueError('escape')\n"
        "    return resolved\n"
    )
    func = ast.parse(src).body[0]
    def_nodes = {"sanitize_path": ast.parse(sanitizer_src).body[0]}
    has_sink, _detail, _line = _structural_path_sink(func, def_nodes)
    assert has_sink is False


def test_structural_path_sink_unknown_sanitizer_suppressed():
    """An unresolvable or unrelated sanitizer call suppresses conservatively
    -- precision-first, to avoid flagging every helper function whose
    parameter happens to pass through some wrapper before a path join."""
    src = (
        "def read_artifact(name):\n"
        "    safe = normalize(name)\n"
        "    with open(os.path.join(str(ARTIFACT_DIR), safe), 'rb') as fh:\n"
        "        return fh.read()\n"
    )
    func = ast.parse(src).body[0]
    has_sink, _detail, _line = _structural_path_sink(func, {})
    assert has_sink is False


def test_structural_path_sink_no_base_dir_no_finding():
    """Joining two ordinary local variables (no ALL_CAPS/DIR-suffixed base)
    doesn't look like a trusted-root + user-part shape -- must not fire."""
    src = (
        "def combine(a, b):\n"
        "    target = os.path.join(a, b)\n"
        "    with open(target, 'rb') as fh:\n"
        "        return fh.read()\n"
    )
    func = ast.parse(src).body[0]
    has_sink, _detail, _line = _structural_path_sink(func, {})
    assert has_sink is False


def test_cross_file_pass_detects_weak_path_sanitizer_across_package_import(tmp_path):
    """End-to-end: the exact ModelForge V03 shape -- an HTTP-facing endpoint
    reads request.args and passes it through a package-imported service
    function that applies a known-bypassable sanitizer before a path join +
    open(). Reproduces the real gap this closes: NS-PATH-001 never fires
    here (no `request.` on the open() line), so without this structural
    detection, read_artifact() never becomes a sink function at all and the
    call chain is invisible to cross-file taint propagation."""
    root = tmp_path / "app"
    (root / "api").mkdir(parents=True)
    (root / "api" / "__init__.py").write_text("", encoding="utf-8")
    (root / "services").mkdir()
    (root / "services" / "__init__.py").write_text("", encoding="utf-8")
    (root / "core").mkdir()
    (root / "core" / "__init__.py").write_text("", encoding="utf-8")
    (root / "__init__.py").write_text("", encoding="utf-8")

    (root / "api" / "handler.py").write_text(
        "from flask import request\n"
        "from ..services import registry\n"
        "\n"
        "def get_blob():\n"
        "    name = request.args.get('name', '')\n"
        "    return registry.read_artifact(name)\n",
        encoding="utf-8",
    )
    (root / "services" / "registry.py").write_text(
        "import os\n"
        "from ..core.security import sanitize_path\n"
        "\n"
        "ARTIFACT_DIR = '/data/artifacts'\n"
        "\n"
        "def read_artifact(name):\n"
        "    safe = sanitize_path(name)\n"
        "    with open(os.path.join(str(ARTIFACT_DIR), safe), 'rb') as fh:\n"
        "        return fh.read()\n",
        encoding="utf-8",
    )
    (root / "core" / "security.py").write_text(
        "def sanitize_path(name):\n    return name.replace('../', '')\n",
        encoding="utf-8",
    )

    config = ScanConfig(target=root)
    ctx = ScanContext(target_path=root, config=config, result=ScanResult(findings=[]))
    pass_result = CrossFilePass().run(ctx)

    cf_hits = [
        f
        for f in pass_result.findings
        if f.rule_id == "CF-SINK-001" and f.metadata.get("callee_name") == "read_artifact"
    ]
    assert cf_hits, "expected a cross-file finding for the weak-sanitizer path-traversal chain"
    assert "bypassable" in cf_hits[0].message


def test_collect_orm_write_channels_from_constructor_kwarg():
    """The ModelForge V06 shape: a request handler builds a dict from
    request.get_json(), then passes one of its fields as a constructor
    kwarg to an ORM model -- that (Model, field) pair is a taint channel,
    independent of any direct call to whatever later reads it back."""
    src = (
        "from flask import request\n"
        "def create_dataset():\n"
        "    data = request.get_json(force=True, silent=True) or {}\n"
        "    ds = Dataset(name=data.get('name'), owner_id=g.user_id, source_url=data.get('source_url'))\n"
        "    db.session.add(ds)\n"
    )
    tree = ast.parse(src)
    channels = _collect_orm_write_channels(tree)
    assert ("Dataset", "source_url") in channels
    assert ("Dataset", "name") in channels
    assert ("Dataset", "owner_id") not in channels  # g.user_id isn't a known source


def test_collect_orm_write_channels_ignores_untainted_constructor():
    """A constructor call with no source-derived keyword must not register
    any channel -- most ORM model instantiation in a codebase is unrelated
    to any request, and treating every one as tainted would be noisy."""
    src = "def seed():\n    Dataset(name='fixture', owner_id=1, source_url=None)\n"
    tree = ast.parse(src)
    assert _collect_orm_write_channels(tree) == set()


def test_collect_orm_write_channels_respects_explicit_sink_sanitizer():
    safe = ast.parse(
        "from flask import request\n"
        "import shlex\n"
        "def create():\n"
        "    name = request.form.get('name')\n"
        "    safe_name = shlex.quote(name)\n"
        "    ArchiveJob(archive_name=safe_name)\n"
    )
    unsafe = ast.parse(
        "from flask import request\n"
        "def create():\n"
        "    name = request.form.get('name')\n"
        "    ArchiveJob(archive_name=name)\n"
    )
    assert _collect_orm_write_channels(safe) == set()
    assert ("ArchiveJob", "archive_name") in _collect_orm_write_channels(unsafe)


def test_function_reads_orm_channel_db_session_get():
    """The ModelForge worker shape: `db.session.get(Dataset, pk)` followed
    by an attribute read on the returned instance."""
    src = (
        "def import_dataset(payload):\n"
        "    ds = db.session.get(Dataset, payload['dataset_id'])\n"
        "    return fetch(ds.source_url)\n"
    )
    func = ast.parse(src).body[0]
    assert _function_reads_orm_channel(func, {("Dataset", "source_url")}) is True
    assert _function_reads_orm_channel(func, {("Dataset", "other_field")}) is False


def test_function_reads_orm_channel_query_idiom():
    """The `Model.query...()` idiom (SQLAlchemy/Django-style) must resolve
    to the same model class as `db.session.get`."""
    src = (
        "def handler():\n"
        "    ds = Dataset.query.filter_by(id=1).first()\n"
        "    return fetch(ds.source_url)\n"
    )
    func = ast.parse(src).body[0]
    assert _function_reads_orm_channel(func, {("Dataset", "source_url")}) is True


def test_function_reads_orm_channel_false_for_unrelated_attribute():
    """Reading a DIFFERENT attribute off the same model instance must not
    match -- only the specific tainted (Model, field) pair counts."""
    src = "def handler():\n    ds = db.session.get(Dataset, 1)\n    return ds.name\n"
    func = ast.parse(src).body[0]
    assert _function_reads_orm_channel(func, {("Dataset", "source_url")}) is False


def test_function_reads_orm_channel_django_objects_get():
    """DEF-36: Django's `Model.objects.get(...)` manager-pattern read must
    resolve to the same model class as SQLAlchemy's `db.session.get`."""
    src = (
        "def handler(dataset_id):\n"
        "    ds = Dataset.objects.get(id=dataset_id)\n"
        "    return fetch(ds.source_url)\n"
    )
    func = ast.parse(src).body[0]
    assert _function_reads_orm_channel(func, {("Dataset", "source_url")}) is True


def test_function_reads_orm_channel_django_objects_filter_first_chain():
    """DEF-36: Django's lazy `Model.objects.filter(...).first()` chain must
    also resolve to the model class."""
    src = (
        "def handler():\n"
        "    ds = Dataset.objects.filter(active=True).first()\n"
        "    return fetch(ds.source_url)\n"
    )
    func = ast.parse(src).body[0]
    assert _function_reads_orm_channel(func, {("Dataset", "source_url")}) is True


def test_function_reads_orm_channel_django_get_or_create():
    """DEF-36: `Model.objects.get_or_create(...)` is also a recognized read
    (single-target assignment shape -- tuple-unpacking the usual
    `(obj, created)` return isn't tracked, same limitation as every other
    ORM-read idiom here, which only matches `x = <read expr>`)."""
    src = (
        "def handler(name):\n"
        "    ds = Dataset.objects.get_or_create(name=name)\n"
        "    return fetch(ds.source_url)\n"
    )
    func = ast.parse(src).body[0]
    assert _function_reads_orm_channel(func, {("Dataset", "source_url")}) is True


def test_function_reads_orm_channel_django_objects_create_not_treated_as_read():
    """DEF-36 scope guard: `.objects.create(...)` is a WRITE, not a read --
    it must NOT be recognized by _orm_read_class, only the explicit
    get/filter/first/all/get_or_create read methods are."""
    src = (
        "def handler(name):\n"
        "    ds = Dataset.objects.create(name=name)\n"
        "    return fetch(ds.source_url)\n"
    )
    func = ast.parse(src).body[0]
    assert _function_reads_orm_channel(func, {("Dataset", "source_url")}) is False


def test_cross_file_pass_detects_second_order_orm_taint_to_ssrf(tmp_path):
    """End-to-end: the exact ModelForge V06 shape -- a request handler
    persists an untrusted URL onto a model attribute; a *different*
    function (no call edge to the writer at all -- connected only by both
    touching the same DB row) reads it back and calls a third, separate
    function that performs the actual HTTP fetch. Reproduces the real gap
    Phase 2 closes: ordinary call-graph propagation can't see the writer
    at all, since it never calls the reader -- the only link is the shared
    (Model, field) ORM channel."""
    root = tmp_path / "app"
    (root / "api").mkdir(parents=True)
    (root / "api" / "__init__.py").write_text("", encoding="utf-8")
    (root / "workers").mkdir()
    (root / "workers" / "__init__.py").write_text("", encoding="utf-8")
    (root / "services").mkdir()
    (root / "services" / "__init__.py").write_text("", encoding="utf-8")
    (root / "__init__.py").write_text("", encoding="utf-8")

    (root / "api" / "datasets.py").write_text(
        "from flask import request\n"
        "\n"
        "def create_dataset():\n"
        "    data = request.get_json(force=True, silent=True) or {}\n"
        "    ds = Dataset(name=data.get('name'), source_url=data.get('source_url'))\n"
        "    db.session.add(ds)\n"
        "    db.session.commit()\n",
        encoding="utf-8",
    )
    (root / "workers" / "tasks.py").write_text(
        "from ..services.fetcher import fetch\n"
        "\n"
        "def import_dataset(payload):\n"
        "    ds = db.session.get(Dataset, payload['dataset_id'])\n"
        "    return fetch(ds.source_url)\n",
        encoding="utf-8",
    )
    (root / "services" / "fetcher.py").write_text(
        "import requests\n\ndef fetch(url):\n    return requests.get(url)\n",
        encoding="utf-8",
    )

    config = ScanConfig(target=root)
    findings = [
        Finding(
            rule_id="NS-SSRF-001",
            message="Outbound HTTP request",
            severity=Severity.LOW,
            category=Category.SSRF,
            file_path=str((root / "services" / "fetcher.py").resolve()),
            start_line=4,
            engine="opengrep",
        ),
    ]
    ctx = ScanContext(target_path=root, config=config, result=ScanResult(findings=findings))
    pass_result = CrossFilePass().run(ctx)

    cf_hits = [
        f
        for f in pass_result.findings
        if f.rule_id == "CF-SINK-001" and f.metadata.get("callee_name") == "fetch"
    ]
    assert cf_hits, (
        "expected a cross-file finding linking create_dataset()'s ORM write "
        "of source_url to import_dataset()'s ORM read and its call to "
        "fetch(), despite there being no call edge between create_dataset() "
        "and import_dataset() at all"
    )
    assert "import_dataset" in cf_hits[0].message


def test_persistent_orm_value_reaches_same_file_ssrf_helper(tmp_path):
    root = tmp_path / "app"
    root.mkdir()
    (root / "models.py").write_text("class Dataset:\n    pass\n", encoding="utf-8")
    (root / "tasks.py").write_text(
        "import requests\n"
        "from flask import request\n"
        "from models import Dataset\n\n"
        "def create_dataset():\n"
        "    data = request.get_json()\n"
        "    return Dataset(webhook_url=data.get('webhook_url'))\n\n"
        "def import_dataset(payload):\n"
        "    ds = db.session.get(Dataset, payload['id'])\n"
        "    url = ds.webhook_url\n"
        "    return _notify(url, {'ok': True})\n\n"
        "def _notify(url, body):\n"
        "    return requests.post(url, json=body)\n",
        encoding="utf-8",
    )
    ctx = ScanContext(
        target_path=root,
        config=ScanConfig(target=root),
        result=ScanResult(
            findings=[
                Finding(
                    rule_id="NS-SSRF-001",
                    message="requests.post() outbound request",
                    severity=Severity.LOW,
                    category=Category.SSRF,
                    file_path=str((root / "tasks.py").resolve()),
                    start_line=15,
                    engine="opengrep",
                )
            ]
        ),
    )

    hits = [f for f in CrossFilePass().run(ctx).findings if f.rule_id == "PERSISTENT-TAINT-001"]
    assert len(hits) == 1
    assert hits[0].start_line == 12
    assert hits[0].category == Category.SSRF


def test_persistent_orm_read_does_not_taint_unrelated_helper_argument(tmp_path):
    root = tmp_path / "app"
    root.mkdir()
    (root / "models.py").write_text("class Dataset:\n    pass\n", encoding="utf-8")
    (root / "tasks.py").write_text(
        "import requests\n"
        "from flask import request\n"
        "from models import Dataset\n\n"
        "def create_dataset():\n"
        "    data = request.get_json()\n"
        "    return Dataset(webhook_url=data.get('webhook_url'))\n\n"
        "def import_dataset(payload, trusted_healthcheck_url):\n"
        "    ds = db.session.get(Dataset, payload['id'])\n"
        "    audit(ds.webhook_url)\n"
        "    return _notify(trusted_healthcheck_url)\n\n"
        "def _notify(url):\n"
        "    return requests.post(url)\n",
        encoding="utf-8",
    )
    ctx = ScanContext(
        target_path=root,
        config=ScanConfig(target=root),
        result=ScanResult(
            findings=[
                Finding(
                    rule_id="NS-SSRF-001",
                    message="requests.post() outbound request",
                    severity=Severity.LOW,
                    category=Category.SSRF,
                    file_path=str((root / "tasks.py").resolve()),
                    start_line=15,
                    engine="opengrep",
                )
            ]
        ),
    )

    assert not [f for f in CrossFilePass().run(ctx).findings if f.rule_id == "PERSISTENT-TAINT-001"]


def test_is_tool_class_matches_base_tool_style_names():
    src = "class ReadFileTool(BaseTool):\n    pass\n"
    class_def = ast.parse(src).body[0]
    assert _is_tool_class(class_def) is True


def test_is_tool_class_false_for_unrelated_base():
    src = "class ReadFileHelper(object):\n    pass\n"
    class_def = ast.parse(src).body[0]
    assert _is_tool_class(class_def) is False


def test_collect_agent_tool_nodes_finds_run_method_and_tool_decorator():
    """The real CrewAI/LangChain conventions: a BaseTool subclass's _run
    method, and a bare function decorated with @tool."""
    src = (
        "from crewai.tools import BaseTool\n"
        "from langchain.tools import tool\n"
        "\n"
        "class ReadFileTool(BaseTool):\n"
        "    def _run(self, file_path):\n"
        "        pass\n"
        "    def helper(self):\n"
        "        pass\n"
        "\n"
        "@tool\n"
        "def search(query):\n"
        "    pass\n"
    )
    tree = ast.parse(src)
    ids = _collect_agent_tool_nodes(tree)
    names_matched = {
        node.name
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and id(node) in ids
    }
    assert names_matched == {"_run", "search"}


def test_structural_path_sink_agent_tool_direct_absent_sanitizer():
    """The real FileReadTool shape, but WITHOUT its sanitizer: a BaseTool
    _run method passes its own argument straight to open() with no join and
    no wrapper call at all -- the agent-tool mode must catch this without
    needing a base-dir join, unlike ordinary Phase 1 detection."""
    src = (
        "def _run(self, file_path):\n"
        "    with open(file_path, 'r') as fh:\n"
        "        return fh.read()\n"
    )
    func = ast.parse(src).body[0]
    has_sink, detail, line = _structural_path_sink(func, {}, is_agent_tool=True)
    assert has_sink is True
    assert "directly" in detail
    assert line == 2


def test_structural_path_sink_agent_tool_broadened_sinks():
    """Agent-tool mode also recognizes eval/exec/subprocess/requests as
    sinks -- not just the path-related set Phase 1 targets."""
    src = "def _run(self, expr):\n    return eval(expr)\n"
    func = ast.parse(src).body[0]
    has_sink, detail, _line = _structural_path_sink(func, {}, is_agent_tool=True)
    assert has_sink is True
    assert "eval(" in detail


def test_structural_path_sink_agent_tool_strong_sanitizer_suppressed():
    """The real, properly-guarded CrewAI FileReadTool shape: a containment-
    check sanitizer between the tool argument and open() must still
    suppress the finding in agent-tool mode, same as ordinary mode."""
    src = (
        "def _run(self, file_path):\n"
        "    safe = validate_file_path(file_path)\n"
        "    with open(safe, 'r') as fh:\n"
        "        return fh.read()\n"
    )
    sanitizer_src = (
        "def validate_file_path(path):\n"
        "    resolved = os.path.realpath(path)\n"
        "    if os.path.commonpath([resolved, BASE]) != BASE:\n"
        "        raise ValueError('escape')\n"
        "    return resolved\n"
    )
    func = ast.parse(src).body[0]
    def_nodes = {"validate_file_path": ast.parse(sanitizer_src).body[0]}
    has_sink, _detail, _line = _structural_path_sink(func, def_nodes, is_agent_tool=True)
    assert has_sink is False


def test_ordinary_function_not_treated_as_agent_tool():
    """A plain function named `_run` that ISN'T inside a Tool-suffixed
    class must not get the relaxed, no-join agent-tool treatment -- that
    would be far too broad (`_run` is a common method name generally)."""
    src = "def _run(self, path):\n    with open(path, 'r') as fh:\n        return fh.read()\n"
    func = ast.parse(src).body[0]
    has_sink, _detail, _line = _structural_path_sink(func, {}, is_agent_tool=False)
    assert has_sink is False


def test_cross_file_pass_emits_standalone_agent_tool_finding(tmp_path):
    """End-to-end, the real CrewAI FileReadTool shape minus its sanitizer:
    a BaseTool subclass's _run method opens its own argument directly.
    This must be emitted as a standalone same-file finding -- unlike
    Phase 1/2, the vulnerability doesn't require crossing a file boundary
    at all, so ordinary cross-file propagation alone would never surface it."""
    root = tmp_path / "app"
    root.mkdir()
    (root / "tool.py").write_text(
        "from crewai.tools import BaseTool\n"
        "\n"
        "class ReadFileTool(BaseTool):\n"
        "    def _run(self, file_path):\n"
        "        with open(file_path, 'r') as fh:\n"
        "            return fh.read()\n",
        encoding="utf-8",
    )
    (root / "other.py").write_text("x = 1\n", encoding="utf-8")

    config = ScanConfig(target=root)
    ctx = ScanContext(target_path=root, config=config, result=ScanResult(findings=[]))
    pass_result = CrossFilePass().run(ctx)

    tool_hits = [f for f in pass_result.findings if f.rule_id == "AGENT-TOOL-001"]
    assert tool_hits, "expected a standalone AGENT-TOOL-001 finding on ReadFileTool._run"
    assert tool_hits[0].category == Category.PATH_TRAVERSAL
    assert "_run" in tool_hits[0].message


# ---------------------------------------------------------------------------
# Round-2 architectural review fixes (GitHub #153)
# ---------------------------------------------------------------------------


def test_match_findings_module_level_sink_not_attributed_to_prior_function():
    """DEF-1 (round 2): `_match_findings_to_functions` used to bind a finding
    to the closest function with `line <= finding_line`, with no upper bound
    -- so a module-level sink call BELOW the last `def` in a file got
    misattributed to that unrelated function, seeding the fixpoint with a
    false `has_sink`. `end_line` (from `ast.FunctionDef.end_lineno`) now
    bounds the match to the function's own body span."""
    src = "def handler():\n    return 1\n\nos.system(cmd)\n"
    tree = ast.parse(src)
    funcs = _extract_functions("app.py", tree)
    finding = Finding(
        rule_id="NS-CMDI-001",
        message="os.system() command injection",
        severity=Severity.HIGH,
        category=Category.COMMAND_INJECTION,
        file_path="app.py",
        start_line=4,
        engine="opengrep",
    )
    result = _match_findings_to_functions([finding], funcs)
    handler = next(f for f in result if f.name == "handler")
    assert handler.has_sink is False


def test_match_findings_sink_inside_body_span_still_attributed():
    """Regression guard for the same fix: a sink genuinely INSIDE the
    function's body must still be attributed to it."""
    src = "def handler():\n    os.system(cmd)\n    return 1\n"
    tree = ast.parse(src)
    funcs = _extract_functions("app.py", tree)
    finding = Finding(
        rule_id="NS-CMDI-001",
        message="os.system() command injection",
        severity=Severity.HIGH,
        category=Category.COMMAND_INJECTION,
        file_path="app.py",
        start_line=2,
        engine="opengrep",
    )
    result = _match_findings_to_functions([finding], funcs)
    handler = next(f for f in result if f.name == "handler")
    assert handler.has_sink is True


def test_cross_file_pass_orm_channel_resolves_class_identity_no_cross_contamination(tmp_path):
    """DEF-2 (round 2): two unrelated apps in a monorepo each define their
    own `class User` -- a tainted write to app_a's User.email must not leak
    into app_b's OWN, unrelated User.email reader just because the bare
    class name collides. Positive control (same test): a reader that
    imports app_a's ACTUAL User class still gets the channel."""
    root = tmp_path / "proj"
    (root / "app_a").mkdir(parents=True)
    (root / "app_a" / "__init__.py").write_text("", encoding="utf-8")
    (root / "app_b").mkdir()
    (root / "app_b" / "__init__.py").write_text("", encoding="utf-8")
    (root / "services").mkdir()
    (root / "services" / "__init__.py").write_text("", encoding="utf-8")
    (root / "__init__.py").write_text("", encoding="utf-8")

    (root / "app_a" / "handlers.py").write_text(
        "from flask import request\n"
        "\n"
        "class User:\n"
        "    pass\n"
        "\n"
        "def create_user():\n"
        "    data = request.get_json(force=True, silent=True) or {}\n"
        "    u = User(email=data.get('email'))\n"
        "    db.session.add(u)\n",
        encoding="utf-8",
    )
    (root / "app_b" / "models.py").write_text(
        "class User:\n    pass\n",
        encoding="utf-8",
    )
    (root / "app_b" / "reader_own.py").write_text(
        "from .models import User\n"
        "from ..services.fetcher import fetch\n"
        "\n"
        "def read_own():\n"
        "    u = User.query.filter_by(id=1).first()\n"
        "    return fetch(u.email)\n",
        encoding="utf-8",
    )
    (root / "app_b" / "reader_a.py").write_text(
        "from ..app_a.handlers import User\n"
        "from ..services.fetcher import fetch\n"
        "\n"
        "def read_from_a():\n"
        "    u = User.query.filter_by(id=1).first()\n"
        "    return fetch(u.email)\n",
        encoding="utf-8",
    )
    (root / "services" / "fetcher.py").write_text(
        "import requests\n\ndef fetch(url):\n    return requests.get(url)\n",
        encoding="utf-8",
    )

    config = ScanConfig(target=root)
    findings = [
        Finding(
            rule_id="NS-SSRF-001",
            message="Outbound HTTP request",
            severity=Severity.LOW,
            category=Category.SSRF,
            file_path=str((root / "services" / "fetcher.py").resolve()),
            start_line=4,
            engine="opengrep",
        ),
    ]
    ctx = ScanContext(target_path=root, config=config, result=ScanResult(findings=findings))
    pass_result = CrossFilePass().run(ctx)

    cf_hits = [
        f
        for f in pass_result.findings
        if f.rule_id == "CF-SINK-001" and f.metadata.get("callee_name") == "fetch"
    ]
    callers = {f.metadata.get("caller") for f in cf_hits}
    assert "read_from_a" in callers, (
        "positive control: reader_a.py imports app_a's OWN User, so it must "
        "still resolve the ORM channel and produce a cross-file finding"
    )
    assert "read_own" not in callers, (
        "reader_own.py defines its OWN unrelated User class -- it must NOT "
        "match app_a's write channel just because the bare class name "
        "'User' collides"
    )


def test_collect_orm_write_channels_resolves_defining_file_for_same_file_class():
    """Unit-level check of the resolution helper itself: a `Model(...)`
    write where `Model` is a class defined in the SAME file resolves to a
    `(defining_file, ClassName, field)` triple, not the bare 2-tuple."""
    src = (
        "from flask import request\n"
        "\n"
        "class User:\n"
        "    pass\n"
        "\n"
        "def create_user():\n"
        "    data = request.get_json() or {}\n"
        "    u = User(email=data.get('email'))\n"
    )
    tree = ast.parse(src)
    classes_by_file = {"app.py": {"User"}}
    channels = _collect_orm_write_channels(tree, "app.py", _ImportGraph(), classes_by_file)
    assert ("app.py", "User", "email") in channels


def test_propagate_cross_file_zero_arg_call_does_not_seed_source(tmp_path):
    """DEF-3 (round 2): a handler that reads `request.args` and calls
    `helper()` with NO arguments, where `helper` (a different file) has a
    sink on its own parameter, must NOT produce a cross-file finding -- a
    zero-argument call can't carry the handler's source data to helper at
    all (both under the old any-argument gate AND the #119 per-parameter
    gate: `edge_bindings` is empty for a call with no arguments, regardless
    of what helper's sink_params turns out to be). Positive control:
    `helper(data)` (same callee, WITH an argument that actually binds to
    helper's own parameter) still produces one -- this is deliberately a
    callee whose sink genuinely depends on its parameter, unlike a stale
    pre-#119 version of this fixture that called a zero-parameter helper
    with a (real-Python-invalid) extra argument, which #119 now correctly
    refuses to treat as a taint path at all."""
    root = tmp_path / "proj"
    (root / "api").mkdir(parents=True)
    (root / "api" / "__init__.py").write_text("", encoding="utf-8")
    (root / "services").mkdir()
    (root / "services" / "__init__.py").write_text("", encoding="utf-8")
    (root / "__init__.py").write_text("", encoding="utf-8")

    (root / "services" / "helper.py").write_text(
        "def helper(user_cmd):\n    import os\n    os.system(user_cmd)\n",
        encoding="utf-8",
    )

    def run_scenario(call_line: str) -> list[Finding]:
        (root / "api" / "handler.py").write_text(
            "from flask import request\n"
            "from ..services.helper import helper\n"
            "\n"
            "def endpoint():\n"
            "    data = request.args.get('x')\n"
            f"    {call_line}\n",
            encoding="utf-8",
        )
        helper_file = str((root / "services" / "helper.py").resolve())
        findings = [
            Finding(
                rule_id="NS-CMDI-001",
                message="os.system() command injection",
                severity=Severity.HIGH,
                category=Category.COMMAND_INJECTION,
                # line 3 is the actual `os.system(user_cmd)` call -- must
                # match exactly for #119's _summarize_params to attribute the
                # sink to the right parameter (unlike the old algorithm,
                # which only needed the line to fall within helper's body
                # span, not to pinpoint the exact sink statement).
                file_path=helper_file,
                start_line=3,
                engine="opengrep",
            ),
        ]
        config = ScanConfig(target=root)
        ctx = ScanContext(target_path=root, config=config, result=ScanResult(findings=findings))
        result = CrossFilePass().run(ctx)
        return [
            f
            for f in result.findings
            if f.rule_id == "CF-SINK-001" and f.metadata.get("callee_name") == "helper"
        ]

    no_arg_hits = run_scenario("helper()")
    assert no_arg_hits == [], (
        "helper() takes no arguments -- endpoint's request.args data can't "
        "possibly reach it, so no cross-file finding should be emitted"
    )

    with_arg_hits = run_scenario("helper(data)")
    assert with_arg_hits, (
        "positive control: helper(data) passes an argument, so the finding must still fire"
    )


def test_match_findings_return_taint_requires_actual_return_of_source(tmp_path):
    """DEF-4 (round 2): `has_return_taint` used to be set for ANY function
    containing a source, regardless of whether it actually returns
    source-derived data -- a handler reading `request.args` but returning a
    literal taints every caller upward via the return-direction fixpoint.
    Fix: only set it when a `Return` node's own value reads a source (or a
    source-derived local). Positive control: the same function returning
    the source-derived value still fires."""
    root = tmp_path / "proj"
    (root / "api").mkdir(parents=True)
    (root / "api" / "__init__.py").write_text("", encoding="utf-8")
    (root / "services").mkdir()
    (root / "services" / "__init__.py").write_text("", encoding="utf-8")
    (root / "__init__.py").write_text("", encoding="utf-8")

    (root / "api" / "caller.py").write_text(
        "from ..services.reader import read_value\n"
        "\n"
        "def handler():\n"
        "    value = read_value()\n"
        "    os.system(value)\n",
        encoding="utf-8",
    )

    def run_scenario(return_line: str) -> list[Finding]:
        (root / "services" / "reader.py").write_text(
            "from flask import request\n"
            "\n"
            "def read_value():\n"
            "    data = request.args.get('x')\n"
            f"    {return_line}\n",
            encoding="utf-8",
        )
        caller_file = str((root / "api" / "caller.py").resolve())
        findings = [
            Finding(
                rule_id="NS-CMDI-001",
                message="os.system() command injection",
                severity=Severity.HIGH,
                category=Category.COMMAND_INJECTION,
                file_path=caller_file,
                start_line=5,
                engine="opengrep",
            ),
        ]
        config = ScanConfig(target=root)
        ctx = ScanContext(target_path=root, config=config, result=ScanResult(findings=findings))
        result = CrossFilePass().run(ctx)
        return [
            f
            for f in result.findings
            if f.rule_id == "CF-RETURN-001"
            and f.metadata.get("callee_name") == "read_value"
            and f.metadata.get("direction") == "return"
        ]

    literal_return_hits = run_scenario("return 'constant'")
    assert literal_return_hits == [], (
        "read_value() returns a literal, not the source-derived `data` -- "
        "no return-direction finding should fire"
    )

    tainted_return_hits = run_scenario("return data")
    assert tainted_return_hits, (
        "positive control: read_value() returns the source-derived value, "
        "so the return-direction finding must still fire"
    )


def test_function_returns_source_true_only_for_actual_return_of_source():
    """Unit-level check of the underlying helper."""
    from rowan.passes.cross_file import _function_returns_source

    reads_but_returns_literal = ast.parse(
        "def f():\n    data = request.args.get('x')\n    return 'constant'\n"
    ).body[0]
    assert _function_returns_source(reads_but_returns_literal) is False

    returns_source_local = ast.parse(
        "def f():\n    data = request.args.get('x')\n    return data\n"
    ).body[0]
    assert _function_returns_source(returns_source_local) is True

    returns_source_directly = ast.parse("def f():\n    return request.args.get('x')\n").body[0]
    assert _function_returns_source(returns_source_directly) is True


def test_function_returns_source_respects_sanitizers():
    """#302's sibling bug (#301): the source-to-return path had no sanitizer
    check at all, while `_summarize_params` (parameter-to-sink) always had one.
    A function that reads a source, sanitizes it, and returns the sanitized
    value was reported as returning tainted data, so CF-RETURN-001 fired on
    both the raw and the shlex.quote()'d path in a caller. The two paths must
    agree: passing through a registered sanitizer clears taint on either."""
    from rowan.passes.cross_file import _function_returns_source, _local_source_vars

    returns_sanitized_directly = ast.parse(
        "def f():\n    value = request.args.get('cmd')\n    return shlex.quote(value)\n"
    ).body[0]
    assert _function_returns_source(returns_sanitized_directly) is False

    # Re-assigning THROUGH a sanitizer clears the variable's existing taint.
    reassigned_through_sanitizer = ast.parse(
        "def f():\n"
        "    value = request.args.get('cmd')\n"
        "    value = shlex.quote(value)\n"
        "    return value\n"
    ).body[0]
    assert _local_source_vars(reassigned_through_sanitizer) == set()
    assert _function_returns_source(reassigned_through_sanitizer) is False

    # The unsanitized path must still be caught: this is the whole point.
    returns_raw = ast.parse(
        "def f():\n    value = request.args.get('cmd')\n    return value\n"
    ).body[0]
    assert _function_returns_source(returns_raw) is True


def test_cross_file_pass_sanitizer_resolution_weakest_wins_on_ambiguity(tmp_path):
    """DEF-5 (round 2): `def_nodes` used to be a project-wide bare-name map
    (`setdefault`, first-parse-order wins) -- two functions both named
    `sanitize` (one strong, one weak) resolved to whichever one happened to
    parse first, globally. Now `def_nodes` is keyed `(file, name)`, so
    file B's `read_artifact()` calling its OWN same-file `sanitize` always
    resolves to file B's (weak) definition, regardless of which file the
    directory walk happens to visit first -- confirmed by naming the strong
    file so it sorts BEFORE the weak file alphabetically in one run, and
    AFTER it in the other. A caller in a third file feeds `read_artifact()`
    request-derived data so the cross-file finding actually has something
    to attach to."""

    def run_scenario(strong_file_name: str, weak_file_name: str) -> list[Finding]:
        root = tmp_path / f"proj_{strong_file_name}_{weak_file_name}".replace(".py", "")
        root.mkdir()
        (root / strong_file_name).write_text(
            "import os\n"
            "\n"
            "def sanitize(name, base):\n"
            "    resolved = os.path.realpath(os.path.join(base, name))\n"
            "    if os.path.commonpath([resolved, base]) != base:\n"
            "        raise ValueError('escape')\n"
            "    return resolved\n",
            encoding="utf-8",
        )
        (root / weak_file_name).write_text(
            "import os\n"
            "\n"
            "ARTIFACT_DIR = '/data/artifacts'\n"
            "\n"
            "def sanitize(name):\n"
            "    return name.replace('../', '')\n"
            "\n"
            "def read_artifact(name):\n"
            "    safe = sanitize(name)\n"
            "    with open(os.path.join(str(ARTIFACT_DIR), safe), 'rb') as fh:\n"
            "        return fh.read()\n",
            encoding="utf-8",
        )
        weak_module = weak_file_name[:-3]
        (root / "caller.py").write_text(
            "from flask import request\n"
            f"from {weak_module} import read_artifact\n"
            "\n"
            "def get_blob():\n"
            "    name = request.args.get('name', '')\n"
            "    return read_artifact(name)\n",
            encoding="utf-8",
        )
        config = ScanConfig(target=root)
        ctx = ScanContext(target_path=root, config=config, result=ScanResult(findings=[]))
        result = CrossFilePass().run(ctx)
        return [
            f
            for f in result.findings
            if f.rule_id == "CF-SINK-001" and f.metadata.get("callee_name") == "read_artifact"
        ]

    # Strong sanitizer's file sorts alphabetically BEFORE the weak one.
    hits_strong_first = run_scenario("a_strong.py", "b_weak.py")
    assert hits_strong_first, (
        "read_artifact() in the weak file calls its OWN same-file "
        "'sanitize' -- the finding must surface regardless of the strong "
        "file elsewhere sorting/parsing first"
    )
    assert "bypassable" in hits_strong_first[0].message

    # Same shapes, reversed alphabetical order -- same result required.
    hits_weak_first = run_scenario("z_strong.py", "a_weak.py")
    assert hits_weak_first
    assert "bypassable" in hits_weak_first[0].message


def test_classify_sanitizer_by_name_weakest_wins_when_ambiguous():
    """Unit-level check: when a sanitizer name can't be resolved through the
    caller's own file or import graph (no file_path/import_graph context, or
    genuinely ambiguous), classifying every same-named candidate and taking
    the WEAKEST verdict is the conservative, no-silent-false-negative
    choice."""
    from rowan.passes.cross_file import _classify_sanitizer_by_name

    strong_src = (
        "def sanitize(name, base):\n"
        "    resolved = os.path.realpath(os.path.join(base, name))\n"
        "    if os.path.commonpath([resolved, base]) != base:\n"
        "        raise ValueError('escape')\n"
        "    return resolved\n"
    )
    weak_src = "def sanitize(name):\n    return name.replace('../', '')\n"
    strong_node = ast.parse(strong_src).body[0]
    weak_node = ast.parse(weak_src).body[0]

    def_nodes = {("a.py", "sanitize"): strong_node, ("b.py", "sanitize"): weak_node}
    def_nodes_by_name = {"sanitize": [("a.py", strong_node), ("b.py", weak_node)]}

    # No file_path context at all (can't resolve via same-file/import graph)
    # -- must fall back to classifying every candidate and taking "weak".
    verdict = _classify_sanitizer_by_name("sanitize", def_nodes, None, None, def_nodes_by_name)
    assert verdict == "weak"


# ---------------------------------------------------------------------------
# Issue #154: TaintFlow reconstruction, call-site anchoring, stable rule ids
# ---------------------------------------------------------------------------


def test_cross_file_finding_carries_taint_flow_across_three_hops(tmp_path):
    """Defect 1 acceptance: a 3-hop chain (source file A -> helper file B ->
    sink file C) produces a CF-SINK-001 finding whose taint_flow has a
    source node in A, at least one intermediate node in B, and a sink node
    in C at the sink's real line."""
    root = tmp_path / "proj"
    root.mkdir()

    (root / "a.py").write_text(
        "from flask import request\n"
        "from b import helper_func\n"
        "\n"
        "def handler():\n"
        "    data = request.args.get('x')\n"
        "    helper_func(data)\n",
        encoding="utf-8",
    )
    (root / "b.py").write_text(
        "from c import sink_func\n\ndef helper_func(y):\n    sink_func(y)\n",
        encoding="utf-8",
    )
    (root / "c.py").write_text(
        "import os\n\ndef sink_func(z):\n    os.system(z)\n",
        encoding="utf-8",
    )

    a_path = str((root / "a.py").resolve())
    b_path = str((root / "b.py").resolve())
    c_path = str((root / "c.py").resolve())

    findings = [
        Finding(
            rule_id="NS-CMDI-001",
            message="os.system() command injection",
            severity=Severity.HIGH,
            category=Category.COMMAND_INJECTION,
            file_path=c_path,
            start_line=4,
            engine="opengrep",
            cwe_ids=[78],
        ),
    ]
    config = ScanConfig(target=root)
    ctx = ScanContext(target_path=root, config=config, result=ScanResult(findings=findings))
    result = CrossFilePass().run(ctx)

    hits = [
        f
        for f in result.findings
        if f.rule_id == "CF-SINK-001" and f.metadata.get("caller") == "handler"
    ]
    assert hits, (
        "expected a cross-file finding for handler() reaching sink_func() via helper_func()"
    )
    finding = hits[0]

    assert finding.category == Category.COMMAND_INJECTION
    assert finding.cwe_ids == [78]

    assert finding.taint_flow is not None
    assert finding.taint_flow.source is not None
    assert finding.taint_flow.source.file_path == a_path

    assert finding.taint_flow.sink is not None
    assert finding.taint_flow.sink.file_path == c_path
    assert finding.taint_flow.sink.line == 4

    assert any(n.file_path == b_path for n in finding.taint_flow.intermediate), (
        "expected at least one intermediate hop in helper file B"
    )


def test_cross_file_finding_anchored_at_call_site_not_def_line(tmp_path):
    """Defect 2 acceptance: a caller whose cross-file call is 20+ lines below
    its own `def` must produce a finding whose start_line is the call line,
    not the def line."""
    root = tmp_path / "proj"
    root.mkdir()

    lines = [
        "from flask import request\n",
        "from helper import helper_func\n",
        "\n",
        "def handler():\n",
        "    data = request.args.get('x')\n",
    ]
    for i in range(25):
        lines.append(f"    # filler line {i}\n")
    lines.append("    helper_func(data)\n")
    (root / "caller.py").write_text("".join(lines), encoding="utf-8")
    call_line = len(lines)  # helper_func(data) is the last line written

    (root / "helper.py").write_text(
        "import os\n\ndef helper_func(y):\n    os.system(y)\n",
        encoding="utf-8",
    )

    helper_path = str((root / "helper.py").resolve())
    findings = [
        Finding(
            rule_id="NS-CMDI-001",
            message="os.system() command injection",
            severity=Severity.HIGH,
            category=Category.COMMAND_INJECTION,
            file_path=helper_path,
            start_line=4,
            engine="opengrep",
        ),
    ]
    config = ScanConfig(target=root)
    ctx = ScanContext(target_path=root, config=config, result=ScanResult(findings=findings))
    result = CrossFilePass().run(ctx)

    hits = [
        f
        for f in result.findings
        if f.rule_id == "CF-SINK-001" and f.metadata.get("callee_name") == "helper_func"
    ]
    assert hits, "expected a cross-file finding for handler() reaching helper_func()"
    assert hits[0].start_line == call_line, (
        f"expected start_line to be the call site ({call_line}), not the def line (4)"
    )
    assert hits[0].start_line != 4


class TestObjectStateChannel:
    """#300: second-order taint through plain object / KV state.

    One function writes untrusted data under a literal key
    (`store.set("k", request.args.get(...))`), a different function in a
    different file reads it back (`store.get("k")`) and sinks it. No call edge,
    no ORM model, no vector store, so none of the other channels see it.

    Keyed on the literal key rather than the vector channel's coarse
    project-wide bit, because `set`/`get` are far too generic to arm coarsely.
    """

    @staticmethod
    def _channels(src: str):
        from rowan.passes.cross_file import _collect_objstate_write_channels

        return _collect_objstate_write_channels(ast.parse(src))

    @staticmethod
    def _reads(src: str, channels) -> bool:
        from rowan.passes.cross_file import _function_reads_objstate_channel

        func = next(
            n
            for n in ast.walk(ast.parse(src))
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
        )
        return _function_reads_objstate_channel(func, channels)

    def test_tainted_write_arms_the_key_and_a_matching_read_is_a_source(self):
        channels = self._channels(
            "def save():\n    store.set('report_cmd', request.args.get('cmd'))\n"
        )
        assert channels == {("__objstate__", "store", "report_cmd")}
        assert self._reads("def run():\n    return store.get('report_cmd')\n", channels)

    def test_subscript_forms_are_recognized_on_both_sides(self):
        channels = self._channels(
            "def save():\n    store['report_cmd'] = request.args.get('cmd')\n"
        )
        assert channels == {("__objstate__", "store", "report_cmd")}
        assert self._reads("def run():\n    return store['report_cmd']\n", channels)

    def test_untainted_write_does_not_arm_the_channel(self):
        """The arming gate is what keeps `.get()` from being a source
        everywhere: a constant write arms nothing."""
        assert self._channels("def save():\n    store.set('report_cmd', 'ls -la')\n") == set()

    def test_a_different_key_does_not_match(self):
        channels = self._channels(
            "def save():\n    store.set('report_cmd', request.args.get('cmd'))\n"
        )
        assert not self._reads("def run():\n    return store.get('other_key')\n", channels)

    def test_a_different_store_does_not_match(self):
        channels = self._channels(
            "def save():\n    cache.set('report_cmd', request.args.get('cmd'))\n"
        )
        assert not self._reads("def run():\n    return session_store.get('report_cmd')\n", channels)

    def test_non_literal_keys_are_ignored_on_both_sides(self):
        """A variable key can't be proven equal across files without real value
        tracking, so it deliberately arms nothing and matches nothing."""
        assert self._channels("def save():\n    store.set(key, request.args.get('cmd'))\n") == set()

        armed = {("__objstate__", "store", "report_cmd")}
        assert not self._reads("def run():\n    return store.get(key)\n", armed)

    def test_the_key_argument_itself_does_not_arm_the_channel(self):
        """Only a tainted VALUE arms it. A tainted key with an untrusted-free
        value is not a stored-taint flow."""
        assert (
            self._channels("def save():\n    store.set(request.args.get('k'), 'constant')\n")
            == set()
        )


@pytest.mark.parametrize("body", [
    "    return parse_expr(expr.replace('^', '**'))\n",
    "    cleaned = expr.strip().lower()\n    return sympy.sympify(cleaned)\n",
])
def test_agent_tool_string_method_keeps_taint(body):
    """A string method on a tool argument returns the same attacker text."""
    func = ast.parse("def _run(self, expr):\n" + body).body[0]
    has_sink, detail, _line = _structural_path_sink(func, {}, is_agent_tool=True)
    assert has_sink is True
    assert "sympify(" in detail or "parse_expr(" in detail


@pytest.mark.parametrize("check, guarded", [
    ("    if not _ARITH.fullmatch(expr):\n        raise ValueError('bad')\n", True),
    ("    if not re.fullmatch(r'[0-9x+*]+', expr):\n        return 'bad'\n", True),
    ("    if not _ARITH.search(expr):\n        raise ValueError('bad')\n", False),
    ("    if not _ARITH.fullmatch(expr):\n        print('odd')\n", False),
])
def test_agent_tool_fullmatch_allowlist_guard(check, guarded):
    src = "def _run(self, expr):\n" + check + "    return parse_expr(expr)\n"
    has_sink, _detail, _line = _structural_path_sink(ast.parse(src).body[0], {}, is_agent_tool=True)
    assert has_sink is not guarded


def test_helper_that_can_return_its_argument_is_not_a_sanitizer():
    from rowan.passes.cross_file import _classify_path_sanitizer

    passthrough = ast.parse(
        "def get_path(filename):\n"
        "    if os.path.isabs(filename):\n"
        "        return filename\n"
        "    if BASE is None:\n"
        "        raise ValueError('no base')\n"
        "    return os.path.join(BASE, filename)\n"
    ).body[0]
    unrelated = ast.parse("def get_path(filename):\n    return lookup(filename)\n").body[0]
    assert _classify_path_sanitizer(passthrough) == "absent"
    assert _classify_path_sanitizer(unrelated) == "unknown"


def test_agent_tool_fullmatch_guard_in_a_branch_does_not_clear_taint():
    src = (
        "def _run(self, expr, strict):\n"
        "    if strict:\n"
        "        if not _ARITH.fullmatch(expr):\n"
        "            raise ValueError('bad')\n"
        "    return parse_expr(expr)\n"
    )
    has_sink, _detail, _line = _structural_path_sink(ast.parse(src).body[0], {}, is_agent_tool=True)
    assert has_sink is True


def test_match_findings_to_functions_indexes_by_file():
    """XF-17: 2000 functions across 200 files; every sink finding still lands
    on its own (innermost) function after the per-file index."""
    from rowan.core.findings import Category, Finding, Severity
    from rowan.passes.cross_file import _FunctionSig, _match_findings_to_functions

    funcs, findings = [], []
    for i in range(2000):
        path, line = f"/r/file{i % 200}.py", (i // 200) * 10 + 1
        funcs.append(_FunctionSig(name=f"fn{i}", file=path, line=line, params=["x"], calls=[], end_line=line + 8))
        findings.append(Finding(rule_id="NS-CMDI-002", message="m", severity=Severity.HIGH,
                                category=Category.COMMAND_INJECTION, file_path=path, start_line=line + 3))
    # A nested function inside fn0's span must win for a line it covers.
    inner = _FunctionSig(name="inner", file="/r/file0.py", line=3, params=[], calls=[], end_line=5)
    _match_findings_to_functions(findings, [*funcs, inner], rule_map=None)

    assert inner.has_sink and inner.sink_line == 4
    assert all(f.has_sink and f.sink_line == f.line + 3 for f in funcs[1:])


def test_structural_path_sink_finding_carries_cwe(tmp_path):
    """RT-12: an AST-detected path sink (no rule finding) is still CWE-22."""
    (tmp_path / "views.py").write_text(
        "from flask import request\n"
        "from store import read_artifact\n\n"
        "def download():\n"
        "    return read_artifact(request.args['name'])\n",
        encoding="utf-8",
    )
    (tmp_path / "store.py").write_text(
        "import os\n\n"
        "def read_artifact(name):\n"
        "    with open(os.path.join(ARTIFACT_DIR, name), 'rb') as fh:\n"
        "        return fh.read()\n",
        encoding="utf-8",
    )
    ctx = ScanContext(target_path=tmp_path, config=ScanConfig(target=tmp_path), result=ScanResult())
    sinks = [f for f in CrossFilePass().run(ctx).findings if f.rule_id == "CF-SINK-001"]
    assert [(f.category, f.cwe_ids) for f in sinks] == [(Category.PATH_TRAVERSAL, [22])]
