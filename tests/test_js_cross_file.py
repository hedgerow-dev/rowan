"""Tests for JS/TS cross-file taint propagation (rowan.passes.js_cross_file).

Mirrors tests/test_cross_file.py and test_cross_file_scenarios.py: unit tests
for the tree-sitter-based extraction front-end, plus end-to-end scenario
tests that exercise the shared propagation engine via JSCrossFilePass.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from rowan.config import ScanConfig
from rowan.core.findings import Category, Finding, ScanResult, Severity
from rowan.passes.base import ScanContext
from rowan.passes.cross_file import _UNRESOLVED_QUALIFIER
from rowan.passes.js_cross_file import (
    KNOWN_JS_SOURCE_PREFIXES,
    TREE_SITTER_AVAILABLE,
    JSCrossFilePass,
    _collect_js_files,
    _get_parsers,
    _params_of,
    _resolve_js_module,
    extract_functions,
    extract_imports,
)

pytestmark = pytest.mark.skipif(
    not TREE_SITTER_AVAILABLE,
    reason="tree-sitter not installed (pip install rowan-sast[js-crossfile])",
)


def _make_project(files: dict[str, str]) -> Path:
    tmpdir = tempfile.mkdtemp(prefix="rowan_jscf_")
    root = Path(tmpdir)
    for name, content in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    return root


def _parse(file_path: Path):
    parsers = _get_parsers()
    source = file_path.read_bytes()
    tree = parsers[file_path.suffix].parse(source)
    return tree.root_node, source


def _run_js_cross_file(root: Path, findings: list[Finding] | None = None) -> ScanResult:
    config = ScanConfig(target=root)
    ctx = ScanContext(target_path=root, config=config, result=ScanResult(findings=findings or []))
    return JSCrossFilePass().run(ctx)


# ── File collection ───────────────────────────────────────────────────────


def test_collect_js_files_finds_js_and_ts():
    root = _make_project({"a.js": "1;", "b.ts": "1;", "c.py": "1"})
    found = {f.name for f in _collect_js_files(root)}
    assert found == {"a.js", "b.ts"}


def test_collect_js_files_skips_node_modules():
    root = _make_project(
        {
            "app.js": "1;",
            "node_modules/pkg/index.js": "1;",
        }
    )
    found = {f.name for f in _collect_js_files(root)}
    assert found == {"app.js"}


def test_collect_js_files_skips_minified_and_declarations():
    root = _make_project(
        {
            "app.js": "1;",
            "bundle.min.js": "1;",
            "types.d.ts": "1;",
        }
    )
    found = {f.name for f in _collect_js_files(root)}
    assert found == {"app.js"}


# ── Module resolution ─────────────────────────────────────────────────────


def test_resolve_js_module_relative_with_extension_added():
    root = _make_project({"a.js": "", "b.js": ""})
    target = _resolve_js_module(root, "./b")
    assert target == str((root / "b.js").resolve())


def test_resolve_js_module_index_file():
    root = _make_project({"a.js": "", "lib/index.js": ""})
    target = _resolve_js_module(root, "./lib")
    assert target == str((root / "lib" / "index.js").resolve())


def test_resolve_js_module_typescript_esm_js_specifier():
    # TypeScript ESM imports name the emitted file: `./b.js` means b.ts.
    root = _make_project({"a.ts": "", "b.ts": "", "c.tsx": "", "d.mts": ""})
    assert _resolve_js_module(root, "./b.js") == str((root / "b.ts").resolve())
    assert _resolve_js_module(root, "./c.js") == str((root / "c.tsx").resolve())
    assert _resolve_js_module(root, "./d.mjs") == str((root / "d.mts").resolve())


def test_resolve_js_module_bare_specifier_not_resolved():
    root = _make_project({"a.js": ""})
    assert _resolve_js_module(root, "express") is None
    assert _resolve_js_module(root, "lodash/merge") is None


def test_resolve_js_module_missing_file_returns_none():
    root = _make_project({"a.js": ""})
    assert _resolve_js_module(root, "./does_not_exist") is None


# ── Import extraction ─────────────────────────────────────────────────────


def test_extract_default_import():
    root = _make_project({"a.js": "import Foo from './foo';\n", "foo.js": ""})
    node, source = _parse(root / "a.js")
    graph = extract_imports(str((root / "a.js").resolve()), node, source)
    key = (str((root / "a.js").resolve()), "Foo")
    assert key in graph.name_to_def
    assert graph.name_to_def[key] == (str((root / "foo.js").resolve()), "default")


def test_extract_named_import_with_alias():
    root = _make_project({"a.js": "import { bar as baz } from './lib';\n", "lib.js": ""})
    node, source = _parse(root / "a.js")
    graph = extract_imports(str((root / "a.js").resolve()), node, source)
    key = (str((root / "a.js").resolve()), "baz")
    assert graph.name_to_def[key] == (str((root / "lib.js").resolve()), "bar")


def test_extract_namespace_import():
    root = _make_project({"a.js": "import * as utils from './utils';\n", "utils.js": ""})
    node, source = _parse(root / "a.js")
    graph = extract_imports(str((root / "a.js").resolve()), node, source)
    key = (str((root / "a.js").resolve()), "utils")
    assert graph.module_to_file[key] == str((root / "utils.js").resolve())


def test_extract_commonjs_require():
    root = _make_project({"a.js": "const mod = require('./mod');\n", "mod.js": ""})
    node, source = _parse(root / "a.js")
    graph = extract_imports(str((root / "a.js").resolve()), node, source)
    key = (str((root / "a.js").resolve()), "mod")
    assert graph.module_to_file[key] == str((root / "mod.js").resolve())


def test_extract_commonjs_destructured_require():
    root = _make_project(
        {
            "a.js": "const { readUserFile } = require('./db');\n",
            "db.js": "",
        }
    )
    node, source = _parse(root / "a.js")
    graph = extract_imports(str((root / "a.js").resolve()), node, source)
    key = (str((root / "a.js").resolve()), "readUserFile")
    assert graph.name_to_def[key] == (str((root / "db.js").resolve()), "readUserFile")


def test_bare_import_not_resolved():
    root = _make_project({"a.js": "import express from 'express';\n"})
    node, source = _parse(root / "a.js")
    graph = extract_imports(str((root / "a.js").resolve()), node, source)
    assert graph.name_to_def == {}
    assert graph.module_to_file == {}


# ── Function/call extraction ──────────────────────────────────────────────


def test_extract_named_function_declaration():
    root = _make_project({"a.js": "function handler(req) { return doStuff(req); }\n"})
    node, source = _parse(root / "a.js")
    funcs = extract_functions(str((root / "a.js").resolve()), node, source)
    assert len(funcs) == 1
    assert funcs[0].name == "handler"
    assert any(c[:3] == ("doStuff", None, True) for c in funcs[0].calls)


def test_extract_named_arrow_function():
    root = _make_project({"a.js": "const handler = (x) => { return helper(x); };\n"})
    node, source = _parse(root / "a.js")
    funcs = extract_functions(str((root / "a.js").resolve()), node, source)
    assert len(funcs) == 1
    assert funcs[0].name == "handler"
    assert any(c[:3] == ("helper", None, True) for c in funcs[0].calls)


def test_extract_anonymous_callback_gets_synthetic_name():
    root = _make_project({"a.js": "app.get('/x', (req, res) => { doStuff(); });\n"})
    node, source = _parse(root / "a.js")
    funcs = extract_functions(str((root / "a.js").resolve()), node, source)
    assert len(funcs) == 1
    assert funcs[0].name.startswith("<anonymous@")


def test_extract_class_method():
    root = _make_project({"a.js": "class Foo {\n  process(x) {\n    return sink(x);\n  }\n}\n"})
    node, source = _parse(root / "a.js")
    funcs = extract_functions(str((root / "a.js").resolve()), node, source)
    assert len(funcs) == 1
    assert funcs[0].name == "process"
    assert any(c[:3] == ("sink", None, True) for c in funcs[0].calls)


def test_extract_member_expression_call():
    root = _make_project({"a.js": "function f() { obj.method(x); }\n"})
    node, source = _parse(root / "a.js")
    funcs = extract_functions(str((root / "a.js").resolve()), node, source)
    assert any(c[:3] == ("method", "obj", True) for c in funcs[0].calls)


def test_function_with_known_source_marked():
    root = _make_project({"a.js": "function f(req) { return req.query.id; }\n"})
    node, source = _parse(root / "a.js")
    funcs = extract_functions(str((root / "a.js").resolve()), node, source)
    assert funcs[0].has_source is True


def test_function_without_source_not_marked():
    root = _make_project({"a.js": "function f() { return 42; }\n"})
    node, source = _parse(root / "a.js")
    funcs = extract_functions(str((root / "a.js").resolve()), node, source)
    assert funcs[0].has_source is False


# ── Destructured parameters (#164 bug 1) ──────────────────────────────────
#
# _params_of used to collect only bare `identifier` children of
# formal_parameters, so any destructured parameter -- the dominant idiom in
# Express/Next/Nest handler code -- was silently dropped and the function
# looked like it took zero params. Node names below (object_pattern,
# pair_pattern, array_pattern, assignment_pattern, rest_pattern,
# required_parameter/optional_parameter) were verified empirically against
# tree_sitter_javascript/tree_sitter_typescript, not guessed from memory.


def _find_first(node, node_type: str):
    if node.type == node_type:
        return node
    for c in node.children:
        found = _find_first(c, node_type)
        if found is not None:
            return found
    return None


def test_params_of_bare_identifiers_still_work():
    root = _make_project({"a.js": "function f(a, b) {}\n"})
    node, source = _parse(root / "a.js")
    params_node = _find_first(node, "formal_parameters")
    assert _params_of(params_node, source) == ["a", "b"]


def test_params_of_object_destructuring():
    root = _make_project({"a.js": "const f = ({ body, query }, res) => {};\n"})
    node, source = _parse(root / "a.js")
    params_node = _find_first(node, "formal_parameters")
    assert _params_of(params_node, source) == ["body", "query", "res"]


def test_params_of_nested_destructuring_array_and_default():
    root = _make_project({"a.js": "function f({ a: { b } }, [c], d = 1) {}\n"})
    node, source = _parse(root / "a.js")
    params_node = _find_first(node, "formal_parameters")
    assert _params_of(params_node, source) == ["b", "c", "d"]


def test_params_of_rest_pattern():
    root = _make_project({"a.js": "function f(a, ...rest) {}\n"})
    node, source = _parse(root / "a.js")
    params_node = _find_first(node, "formal_parameters")
    assert _params_of(params_node, source) == ["a", "rest"]


def test_params_of_object_rest():
    root = _make_project({"a.js": "function f({ a, ...others }) {}\n"})
    node, source = _parse(root / "a.js")
    params_node = _find_first(node, "formal_parameters")
    assert _params_of(params_node, source) == ["a", "others"]


def test_params_of_typescript_typed_and_default_destructuring():
    root = _make_project(
        {
            "a.ts": ("function f(req: Request, { body }: Body = {}, ...rest: any[]) {}\n"),
        }
    )
    node, source = _parse(root / "a.ts")
    params_node = _find_first(node, "formal_parameters")
    assert _params_of(params_node, source) == ["req", "body", "rest"]


def test_params_of_typescript_optional_param():
    root = _make_project({"a.ts": "function f(a?: string) {}\n"})
    node, source = _parse(root / "a.ts")
    params_node = _find_first(node, "formal_parameters")
    assert _params_of(params_node, source) == ["a"]


def test_collect_pattern_identifiers_default_inside_pair_pattern():
    # { a: b = 1 } -- the bound name is "b" (from the pair_pattern's value,
    # an assignment_pattern), not "a" (the key being destructured from).
    root = _make_project({"a.js": "function f({ a: b = 1 }) {}\n"})
    node, source = _parse(root / "a.js")
    params_node = _find_first(node, "formal_parameters")
    assert _params_of(params_node, source) == ["b"]


def test_express_handler_destructured_params_extracted_end_to_end():
    """Regression guard through the real extraction pipeline (not just the
    isolated _params_of helper): a route handler destructuring req is the
    single most common shape this bug silently broke."""
    root = _make_project(
        {
            "a.js": ("app.post('/webhook', ({ body, query }, res) => {\n    doStuff(body);\n});\n"),
        }
    )
    node, source = _parse(root / "a.js")
    funcs = extract_functions(str((root / "a.js").resolve()), node, source)
    assert len(funcs) == 1
    assert funcs[0].params == ["body", "query", "res"]


# ── Source trust model (#164 bug 2) ───────────────────────────────────────


def test_process_env_not_seeded_as_source():
    """process.env is operator-controlled config, not attacker-controlled
    input -- matching cross_file.py's KNOWN_SOURCE_PREFIXES, which has no
    os.environ entry. Seeding it as a full source made every 12-factor JS
    app config read a taint seed."""
    assert not any(
        p == "process.env" or p.startswith("process.env.") for p in KNOWN_JS_SOURCE_PREFIXES
    )
    root = _make_project({"a.js": "function f() { return process.env.SOME_CONFIG; }\n"})
    node, source = _parse(root / "a.js")
    funcs = extract_functions(str((root / "a.js").resolve()), node, source)
    assert funcs[0].has_source is False


def test_process_argv_still_seeded_as_source():
    """process.argv stays a source, mirroring sys.argv on the Python side."""
    assert "process.argv" in KNOWN_JS_SOURCE_PREFIXES
    root = _make_project({"a.js": "function f() { return process.argv[2]; }\n"})
    node, source = _parse(root / "a.js")
    funcs = extract_functions(str((root / "a.js").resolve()), node, source)
    assert funcs[0].has_source is True


# ── Member-expression call depth (#164 parity gap 3, mirrors DEF-35) ──────


def test_this_attr_chain_call_resolves_to_this():
    """this.db.query(...) -- one level of attribute chaining off `this` --
    must resolve the same way a bare this.query() call does, mirroring the
    Python pass's DEF-35 fix for self.db.query(...)."""
    root = _make_project(
        {
            "a.js": "class H {\n  handle(req) {\n    this.db.query(req.query.id);\n  }\n}\n",
        }
    )
    node, source = _parse(root / "a.js")
    funcs = extract_functions(str((root / "a.js").resolve()), node, source)
    assert any(c[:3] == ("query", "this", True) for c in funcs[0].calls)


def test_arbitrary_two_level_chain_is_unresolved_not_dropped():
    """services.payment.charge() can't be attributed to any single name --
    it must show up as an explicitly unresolved qualifier (matching
    Python's _UNRESOLVED_QUALIFIER for a.b.foo()), not vanish from the
    calls list entirely."""
    root = _make_project(
        {
            "a.js": "function f(req) { services.payment.charge(req.body.amount); }\n",
        }
    )
    node, source = _parse(root / "a.js")
    funcs = extract_functions(str((root / "a.js").resolve()), node, source)
    assert any(c[:3] == ("charge", _UNRESOLVED_QUALIFIER, True) for c in funcs[0].calls)


def test_two_levels_beyond_this_still_unresolved():
    """Only ONE level of chaining beyond `this` is trusted -- this.a.b.foo()
    (two levels) must not also get the same-file fallback."""
    root = _make_project(
        {
            "a.js": "class H {\n  handle() {\n    this.a.b.foo();\n  }\n}\n",
        }
    )
    node, source = _parse(root / "a.js")
    funcs = extract_functions(str((root / "a.js").resolve()), node, source)
    assert any(c[:3] == ("foo", _UNRESOLVED_QUALIFIER, False) for c in funcs[0].calls)


def test_this_attr_chain_reaches_cross_file_sink():
    """End-to-end: a source reaching a sink only through a this.<attr>.<method>()
    hop must not be severed -- before the fix this call got no call-graph
    edge at all."""
    root = _make_project(
        {
            "sink.js": (
                "function dangerousWrite(x) { return eval(x); }\n"
                "module.exports = { dangerousWrite };\n"
            ),
            "handler.js": (
                "const { dangerousWrite } = require('./sink');\n"
                "class Handler {\n"
                "    process(x) { return dangerousWrite(x); }\n"
                "    handle(req) {\n"
                "        const x = req.query.q;\n"
                "        this.process(x);\n"
                "    }\n"
                "}\n"
            ),
        }
    )
    sink_path = str((root / "sink.js").resolve())
    handler_path = str((root / "handler.js").resolve())
    seed_findings = [
        Finding(
            rule_id="JS-INJECT-001",
            message="eval sink",
            severity=Severity.HIGH,
            category=Category.INJECTION,
            file_path=sink_path,
            start_line=1,
            engine="opengrep",
        ),
    ]
    result = _run_js_cross_file(root, seed_findings)
    cf = [f for f in result.findings if f.engine == "crossfile"]
    assert len(cf) >= 1
    assert any(f.file_path == handler_path for f in cf)


# ── End-to-end propagation scenarios ──────────────────────────────────────


class TestCrossFileScenarios:
    """Realistic multi-file JS projects -- mirrors test_cross_file_scenarios.py."""

    def test_source_to_sink_across_files(self):
        root = _make_project(
            {
                "db.js": (
                    "const fs = require('fs');\n"
                    "function readUserFile(filename) {\n"
                    "    return fs.readFileSync(`./files/${filename}`);\n"
                    "}\n"
                    "module.exports = { readUserFile };\n"
                ),
                "api.js": (
                    "const { readUserFile } = require('./db');\n"
                    "app.get('/file', (req, res) => {\n"
                    "    const filename = req.query.name;\n"
                    "    readUserFile(filename);\n"
                    "});\n"
                ),
            }
        )
        db_path = str((root / "db.js").resolve())
        api_path = str((root / "api.js").resolve())

        seed_findings = [
            Finding(
                rule_id="JS-PATH-001",
                message="User input in filesystem path.",
                severity=Severity.HIGH,
                category=Category.PATH_TRAVERSAL,
                file_path=db_path,
                start_line=3,
                engine="opengrep",
            ),
        ]
        result = _run_js_cross_file(root, seed_findings)
        cf = [f for f in result.findings if f.engine == "crossfile"]
        assert len(cf) == 1
        assert cf[0].file_path == api_path
        assert cf[0].rule_id == "CF-SINK-001"
        assert cf[0].metadata.get("callee_name") == "readUserFile"

    def test_no_source_no_cross_file_finding(self):
        # Same call shape, but the callee's argument is a static literal --
        # no source anywhere, so no cross-file finding should be emitted.
        root = _make_project(
            {
                "db.js": (
                    "const fs = require('fs');\n"
                    "function readConfig() {\n"
                    "    return fs.readFileSync('./config/static.json');\n"
                    "}\n"
                    "module.exports = { readConfig };\n"
                ),
                "api.js": (
                    "const { readConfig } = require('./db');\n"
                    "app.get('/config', (req, res) => {\n"
                    "    readConfig();\n"
                    "});\n"
                ),
            }
        )
        db_path = str((root / "db.js").resolve())

        seed_findings = [
            Finding(
                rule_id="JS-PATH-001",
                message="User input in filesystem path.",
                severity=Severity.HIGH,
                category=Category.PATH_TRAVERSAL,
                file_path=db_path,
                start_line=3,
                engine="opengrep",
            ),
        ]
        result = _run_js_cross_file(root, seed_findings)
        cf = [f for f in result.findings if f.engine == "crossfile"]
        assert cf == []

    def test_same_file_call_not_cross_file(self):
        root = _make_project(
            {
                "app.js": (
                    "function sink(x) { return fs.readFileSync(x); }\n"
                    "function handler(req) {\n"
                    "    return sink(req.query.id);\n"
                    "}\n"
                ),
            }
        )
        app_path = str((root / "app.js").resolve())
        seed_findings = [
            Finding(
                rule_id="JS-PATH-001",
                message="sink",
                severity=Severity.HIGH,
                category=Category.PATH_TRAVERSAL,
                file_path=app_path,
                start_line=1,
                engine="opengrep",
            ),
        ]
        result = _run_js_cross_file(root, seed_findings)
        # Same-file propagation is the regular taint pass's job, not ours.
        assert all(f.engine != "crossfile" for f in result.findings)

    def test_typescript_files_supported(self):
        root = _make_project(
            {
                "db.ts": (
                    "import * as fs from 'fs';\n"
                    "export function readUserFile(filename: string): Buffer {\n"
                    "    return fs.readFileSync(`./files/${filename}`);\n"
                    "}\n"
                ),
                "api.ts": (
                    "import { readUserFile } from './db';\n"
                    "app.get('/file', (req, res) => {\n"
                    "    readUserFile(req.query.name as string);\n"
                    "});\n"
                ),
            }
        )
        db_path = str((root / "db.ts").resolve())
        api_path = str((root / "api.ts").resolve())
        seed_findings = [
            Finding(
                rule_id="JS-PATH-001",
                message="sink",
                severity=Severity.HIGH,
                category=Category.PATH_TRAVERSAL,
                file_path=db_path,
                start_line=3,
                engine="opengrep",
            ),
        ]
        result = _run_js_cross_file(root, seed_findings)
        cf = [f for f in result.findings if f.engine == "crossfile"]
        assert len(cf) == 1
        assert cf[0].file_path == api_path

    def test_skips_single_file_project(self):
        root = _make_project({"only.js": "1;"})
        result = _run_js_cross_file(root)
        assert result.findings == []

    def test_rejects_nonexistent_target_before_analysis(self):
        with pytest.raises(ValueError, match="target does not exist"):
            ScanConfig(target=Path("/nonexistent/path/xyz"))


# ── Agent tool handlers and structural parameter sinks ───────────────────

def _mcp_server(fn: str) -> str:
    return (
        "import { " + fn + ' } from "./helpers.js";\n'
        'server.tool("t", {}, async ({ name }) => {\n'
        "  return " + fn + "(name);\n"
        "});\n"
    )


def _cross_file_hits(helpers: str, fn: str) -> list:
    root = _make_project({"server.ts": _mcp_server(fn), "helpers.ts": helpers})
    return [f for f in _run_js_cross_file(root).findings if f.engine == "crossfile"]


def test_tool_argument_reaching_helper_sink_is_reported():
    hits = _cross_file_hits(
        'import * as fs from "fs";\n'
        "export function writeReport(name: string) {\n"
        "  fs.writeFileSync(name, 'x');\n"
        "}\n",
        "writeReport",
    )
    assert [(h.rule_id, h.metadata["source_kind"]) for h in hits] == [("CF-SINK-001", "tool_param")]


def test_assert_guard_and_uncalled_parameter_are_not_sinks():
    # The guarded parameter never reaches the sink; the one that does is not
    # passed by the caller.
    hits = _cross_file_hits(
        'import * as fs from "fs";\n'
        "export function resolveNote(name: string, options: { dir?: string } = {}) {\n"
        "  assertSafeBasename(name);\n"
        "  fs.mkdirSync(options.dir ?? '/notes', { recursive: true });\n"
        "  return fs.readFileSync(name, 'utf8');\n"
        "}\n",
        "resolveNote",
    )
    assert hits == []


def test_sanitizer_named_helper_is_a_barrier_not_a_relay():
    hits = _cross_file_hits(
        'import * as fs from "fs";\n'
        "function rawRead(p: string) { return fs.readFileSync(p, 'utf8'); }\n"
        "export function safeReadNote(name: string) { return rawRead(name); }\n",
        "safeReadNote",
    )
    assert hits == []


def test_promisified_exec_alias_is_a_command_sink():
    hits = _cross_file_hits(
        'import { exec } from "child_process";\n'
        'import { promisify } from "util";\n'
        "const execAsync = promisify(exec);\n"
        "export async function userInfo(name: string) {\n"
        "  return execAsync(`id ${name}`);\n"
        "}\n",
        "userInfo",
    )
    assert [h.rule_id for h in hits] == ["CF-SINK-001"]


_DISK_SERVICE = (
    'import { execSync } from "child_process";\n'
    "export class DiskService {\n"
    "  usage(dir: string) {\n"
    "    return execSync(`du -sh ${dir}`).toString();\n"
    "  }\n"
    "}\n"
)


def test_method_call_on_new_bound_receiver_resolves_to_class_file():
    server = (
        'import { DiskService } from "./service.js";\n'
        'const svc = new DiskService();\n'
        'server.tool("t", {}, async ({ dir }) => {\n'
        "  return svc.usage(dir);\n"
        "});\n"
    )
    root = _make_project({"server.ts": server, "service.ts": _DISK_SERVICE})
    hits = [f for f in _run_js_cross_file(root).findings if f.engine == "crossfile"]
    assert [(h.rule_id, Path(h.file_path).name) for h in hits] == [("CF-SINK-001", "server.ts")]


def test_method_call_on_untyped_receiver_is_not_resolved():
    # `svc` has no known class, so `svc.usage()` must not bind to whichever
    # file happens to define a `usage` method.
    server = (
        'import { DiskService } from "./service.js";\n'
        'server.tool("t", {}, async ({ dir, svc }) => {\n'
        "  return svc.usage(dir);\n"
        "});\n"
    )
    root = _make_project({"server.ts": server, "service.ts": _DISK_SERVICE})
    assert [f for f in _run_js_cross_file(root).findings if f.engine == "crossfile"] == []


def test_tsconfig_path_alias_import_resolves():
    # `~/*` maps to `./src/*`; tsconfig files routinely carry comments and
    # trailing commas, which strict JSON rejects.
    tsconfig = (
        "{\n"
        '  "compilerOptions": {\n'
        '    "baseUrl": "./",\n'
        '    /* aliases */\n'
        '    "paths": { "~/*": ["./src/*"], },  // src root\n'
        "  },\n"
        "}\n"
    )
    server = (
        'import { diskUsage } from "~/utils/disk.js";\n'
        'server.tool("t", {}, async ({ dir }) => {\n'
        "  return diskUsage(dir);\n"
        "});\n"
    )
    helper = (
        'import { execSync } from "child_process";\n'
        "export function diskUsage(dir: string) {\n"
        "  return execSync(`du -sh ${dir}`).toString();\n"
        "}\n"
    )
    root = _make_project({"tsconfig.json": tsconfig, "src/server.ts": server, "src/utils/disk.ts": helper})
    hits = [f for f in _run_js_cross_file(root).findings if f.engine == "crossfile"]
    assert [(h.rule_id, Path(h.file_path).name) for h in hits] == [("CF-SINK-001", "server.ts")]


def test_call_through_exported_object_literal_resolves_to_named_function():
    tool = (
        'import { execSync } from "child_process";\n'
        "async function runUsage(params: { dir: string }) {\n"
        "  return execSync(`du -sh ${params.dir}`).toString();\n"
        "}\n"
        "export const usageTool = {\n"
        '  name: "usage",\n'
        "  handler: runUsage,\n"
        "} as const;\n"
    )
    server = (
        'import { usageTool } from "./tool.js";\n'
        'server.tool(usageTool.name, {}, (params) => usageTool.handler(params));\n'
    )
    root = _make_project({"server.ts": server, "tool.ts": tool})
    hits = [f for f in _run_js_cross_file(root).findings if f.engine == "crossfile"]
    assert [(h.rule_id, Path(h.file_path).name) for h in hits] == [("CF-SINK-001", "server.ts")]


def test_awaited_generic_calls_are_collected():
    # tree-sitter parses `await f<T>(x)` as a call whose function node is the
    # whole `await f` expression.
    root = _make_project({"a.ts": (
        "export class Api {\n"
        "  async get(endpoint: string) {\n"
        "    const r = await this.request<Payload>(endpoint);\n"
        "    return await fetchWithRetry<Payload>(r, {});\n"
        "  }\n"
        "}\n"
    )})
    node, source = _parse(root / "a.ts")
    get = next(f for f in extract_functions(str(root / "a.ts"), node, source) if f.name == "get")
    assert [(c[0], c[1]) for c in get.calls] == [("request", "this"), ("fetchWithRetry", None)]


@pytest.mark.parametrize("barrel", [
    'export { diskUsage } from "./disk.js";\n',
    'export * from "./disk.js";\n',
])
def test_import_through_barrel_reexport_resolves(barrel):
    helper = (
        'import { execSync } from "child_process";\n'
        "export function diskUsage(dir: string) {\n"
        "  return execSync(`du -sh ${dir}`).toString();\n"
        "}\n"
    )
    server = (
        'import { diskUsage } from "./utils/index.js";\n'
        'server.tool("t", {}, async ({ dir }) => {\n'
        "  return diskUsage(dir);\n"
        "});\n"
    )
    root = _make_project({"server.ts": server, "utils/index.ts": barrel, "utils/disk.ts": helper})
    hits = [f for f in _run_js_cross_file(root).findings if f.engine == "crossfile"]
    assert [(h.rule_id, Path(h.file_path).name) for h in hits] == [("CF-SINK-001", "server.ts")]


def test_command_sink_wins_over_ssrf_sink_on_the_same_parameter():
    # fetchWithRetry-style helper: fetch(url), then a curl fallback through a
    # shell. A fixed-host URL whose path is tainted is still command injection.
    helper = (
        'import { exec } from "child_process";\n'
        'import { promisify } from "util";\n'
        "const execAsync = promisify(exec);\n"
        "export async function fetchWithRetry(url: string) {\n"
        "  try {\n"
        "    return await fetch(url);\n"
        "  } catch {\n"
        '    return await execAsync(`curl -s "${url}"`);\n'
        "  }\n"
        "}\n"
    )
    server = (
        'import { fetchWithRetry } from "./fetch.js";\n'
        'server.tool("t", {}, async ({ key }) => {\n'
        "  return fetchWithRetry(`https://api.example.com/files/${key}`);\n"
        "});\n"
    )
    root = _make_project({"server.ts": server, "fetch.ts": helper})
    hits = [f for f in _run_js_cross_file(root).findings if f.engine == "crossfile"]
    assert [(h.rule_id, h.category) for h in hits] == [("CF-SINK-001", Category.COMMAND_INJECTION)]


def test_method_call_on_factory_bound_receiver_resolves_to_class_file():
    service = _DISK_SERVICE + (
        "export function getDiskService(): DiskService {\n"
        "  return new DiskService();\n"
        "}\n"
    )
    server = (
        'import { getDiskService } from "./service.js";\n'
        "const svc = getDiskService();\n"
        'server.tool("t", {}, async ({ dir }) => {\n'
        "  return svc.usage(dir);\n"
        "});\n"
    )
    root = _make_project({"server.ts": server, "service.ts": service})
    hits = [f for f in _run_js_cross_file(root).findings if f.engine == "crossfile"]
    assert [(h.rule_id, Path(h.file_path).name) for h in hits] == [("CF-SINK-001", "server.ts")]


def test_fixed_host_path_into_ssrf_method_is_not_reported():
    # Host-only slots apply to a class method resolved through a typed receiver.
    client = (
        "export class ApiClient {\n"
        "  async get(url: string) {\n"
        "    return fetch(url);\n"
        "  }\n"
        "}\n"
    )
    server = (
        'import { ApiClient } from "./client.js";\n'
        "const api = new ApiClient();\n"
        'server.tool("t", {}, async ({ id }) => {\n'
        "  return api.get(`https://api.example.com/users/${id}`);\n"
        "});\n"
    )
    root = _make_project({"server.ts": server, "client.ts": client})
    assert [f for f in _run_js_cross_file(root).findings if f.engine == "crossfile"] == []


def test_fixed_host_path_through_relays_is_not_reported():
    # `getJson(url)` -> `fetchWithRetry(url)` -> `fetch(url)`: host-only slots
    # apply through helpers that only relay into SSRF sinks. A raw URL still
    # reports; a relay that also writes files keeps its path flow.
    retry = "export async function fetchWithRetry(url: string) {\n  return fetch(url);\n}\n"
    data = (
        'import { fetchWithRetry } from "./retry.js";\n'
        'import { writeFileSync } from "fs";\n'
        "export async function getJson(url: string) {\n"
        "  return fetchWithRetry(url);\n"
        "}\n"
        "export async function mirror(url: string) {\n"
        "  writeFileSync(url, await fetchWithRetry(url));\n"
        "}\n"
    )
    server = (
        'import { getJson, mirror } from "./data.js";\n'
        "const BASE = process.env.SNAPSHOT_BASE;\n"
        'server.tool("snap", {}, async ({ key }) => {\n'
        "  return getJson(`${BASE}/snapshots/${key}.json`);\n"
        "});\n"
        'server.tool("get", {}, async ({ target }) => {\n'
        "  return getJson(target);\n"
        "});\n"
        'server.tool("save", {}, async ({ name }) => {\n'
        "  return mirror(`${BASE}/files/${name}`);\n"
        "});\n"
    )
    root = _make_project({"server.ts": server, "data.ts": data, "retry.ts": retry})
    hits = [f for f in _run_js_cross_file(root).findings if f.engine == "crossfile"]
    assert sorted((Path(h.file_path).name, h.start_line, h.category) for h in hits) == [
        ("data.ts", 4, Category.SSRF),
        ("data.ts", 7, Category.SSRF),
        ("server.ts", 7, Category.SSRF),
        ("server.ts", 10, Category.PATH_TRAVERSAL),
    ]


_CLONER = (
    'import { execSync } from "child_process";\n'
    "export class Cloner {\n"
    "  clone(url: string) {\n"
    "    execSync(`git clone --depth 1 ${url} /tmp/x`);\n"
    "  }\n"
    "}\n"
)


def test_commander_action_argument_is_a_source():
    """MCP-03 (mcp-watch, GHSA-27m7): a commander positional argument is parsed
    process.argv, which is already a source, so it reaches the shell string."""
    cli = (
        'import { Command } from "commander";\n'
        'import { Cloner } from "./cloner.js";\n'
        "const program = new Command();\n"
        'program.command("scan").argument("<url>").action(async (url: string) => {\n'
        "  const c = new Cloner();\n"
        "  c.clone(url);\n"
        "});\n"
    )
    root = _make_project({"main.ts": cli, "cloner.ts": _CLONER})
    hits = [f for f in _run_js_cross_file(root).findings if f.engine == "crossfile"]
    assert [(h.rule_id, Path(h.file_path).name) for h in hits] == [("CF-SINK-001", "main.ts")]


def test_non_commander_action_callback_is_not_a_source():
    """`.action(cb)` on something that is not a commander command stays inert."""
    ui = (
        'import { Cloner } from "./cloner.js";\n'
        "button.action(async (url: string) => {\n"
        "  new Cloner().clone(url);\n"
        "});\n"
    )
    root = _make_project({"ui.ts": ui, "cloner.ts": _CLONER})
    assert [f for f in _run_js_cross_file(root).findings if f.engine == "crossfile"] == []


def test_missing_tree_sitter_marks_pass_degraded(tmp_path, monkeypatch):
    """Without tree-sitter the pass must say JS was not analysed, not report success."""
    import rowan.passes.js_cross_file as js_cross_file

    monkeypatch.setattr(js_cross_file, "TREE_SITTER_AVAILABLE", False)
    (tmp_path / "app.js").write_text("module.exports = 1;\n", encoding="utf-8")
    ctx = ScanContext(target_path=tmp_path, config=ScanConfig(target=tmp_path), result=ScanResult())
    result = JSCrossFilePass().run(ctx)
    assert "js_crossfile" in result.degraded_passes


def test_missing_tree_sitter_without_js_files_is_not_degraded(tmp_path, monkeypatch):
    import rowan.passes.js_cross_file as js_cross_file

    monkeypatch.setattr(js_cross_file, "TREE_SITTER_AVAILABLE", False)
    ctx = ScanContext(target_path=tmp_path, config=ScanConfig(target=tmp_path), result=ScanResult())
    assert JSCrossFilePass().run(ctx).degraded_passes == {}


def _mkdir_chain_findings(entry_arg: str) -> list[Finding]:
    root = _make_project(
        {
            "helper.js": (
                "const fs = require('fs');\n"
                "function makeDir(p) {\n"
                "  fs.mkdirSync(p);\n"
                "}\n"
                "module.exports = { makeDir };\n"
            ),
            "entry.js": (
                "const { makeDir } = require('./helper');\n"
                "function main(req) {\n"
                f"  makeDir({entry_arg});\n"
                "}\n"
            ),
        }
    )
    return [f for f in _run_js_cross_file(root).findings if f.rule_id == "CF-SINK-001"]


def test_argv_only_source_is_operator_input_capped_at_medium():
    """process.argv is the operator's own input, the same trust level Rowan gives
    sys.argv and env vars on the Opengrep path: MEDIUM, not a remote HIGH."""
    hits = _mkdir_chain_findings("process.argv[2]")
    assert [(h.severity, h.metadata.get("operator_controlled_source")) for h in hits] == [
        (Severity.MEDIUM, True)
    ]


def test_request_source_into_same_chain_stays_high():
    hits = _mkdir_chain_findings("req.body.dir")
    assert [(h.severity, h.metadata.get("operator_controlled_source")) for h in hits] == [
        (Severity.HIGH, None)
    ]


def test_source_read_in_nested_handler_does_not_taint_the_enclosing_function():
    """bootstrap() registers a request handler; the handler reads request.params,
    bootstrap() itself only passes a constant config path to the sink."""
    root = _make_project(
        {
            "helper.js": (
                "const fs = require('fs');\n"
                "function makeDir(p) {\n"
                "  fs.mkdirSync(p);\n"
                "}\n"
                "module.exports = { makeDir };\n"
            ),
            "server.js": (
                "const { makeDir } = require('./helper');\n"
                "function bootstrap(server, configDir) {\n"
                "  server.setRequestHandler('setLevel', async (request) => {\n"
                "    console.log(request.params.level);\n"
                "  });\n"
                "  makeDir(configDir);\n"
                "}\n"
            ),
        }
    )
    hits = [f for f in _run_js_cross_file(root).findings if f.rule_id == "CF-SINK-001"]
    assert hits == []


# ---------------------------------------------------------------------------
# Indirect MCP tool registration (MCP census 2026-10-20): dbhub passes a
# handler factory, Aikido's MCP registers `{name, config, cb}` objects through
# a wrapper, chrome-devtools-mcp defines `{name, schema, handler}` objects.
# ---------------------------------------------------------------------------

_HELPER_JS = (
    "const fs = require('fs');\n"
    "function makeDir(p) {\n"
    "  fs.mkdirSync(p);\n"
    "}\n"
    "module.exports = { makeDir };\n"
)


def _tool_chain_hits(server_js: str, extra: dict[str, str] | None = None) -> list[tuple[str, str]]:
    root = _make_project({"helper.js": _HELPER_JS, "server.js": server_js, **(extra or {})})
    return [
        (f.severity.value, f.metadata["caller"])
        for f in _run_js_cross_file(root).findings
        if f.rule_id == "CF-SINK-001"
    ]


def test_handler_factory_passed_to_register_tool_is_a_tool():
    hits = _tool_chain_hits(
        "const { makeDir } = require('./helper');\n"
        "function createMkdirHandler(base) {\n"
        "  return async (args) => {\n"
        "    makeDir(args.dir);\n"
        "  };\n"
        "}\n"
        "server.registerTool('mkdir', {}, createMkdirHandler('/srv'));\n"
    )
    assert [severity for severity, _caller in hits] == ["high"]


def test_imported_handler_reference_is_a_tool():
    hits = _tool_chain_hits(
        "const { handleMkdir } = require('./handlers');\n"
        "server.registerTool('mkdir', {}, handleMkdir);\n",
        {"handlers.js": (
            "const { makeDir } = require('./helper');\n"
            "async function handleMkdir(args) {\n"
            "  makeDir(args.dir);\n"
            "}\n"
            "module.exports = { handleMkdir };\n"
        )},
    )
    assert hits == [("high", "handleMkdir")]


def test_tool_definition_object_with_wrapped_member_registration():
    hits = _tool_chain_hits(
        "const { makeDir } = require('./helper');\n"
        "async function mkdirCb(args) {\n"
        "  makeDir(args.dir);\n"
        "}\n"
        "const mkdirTool = { name: 'mkdir', config: { inputSchema: {} }, cb: mkdirCb };\n"
        "server.registerTool(mkdirTool.name, mkdirTool.config, withAuth(mkdirTool.cb));\n"
    )
    assert hits == [("high", "mkdirCb")]


def test_inline_handler_in_tool_definition_object():
    hits = _tool_chain_hits(
        "const { makeDir } = require('./helper');\n"
        "const mkdirTool = defineTool(() => ({\n"
        "  name: 'mkdir',\n"
        "  schema: {},\n"
        "  handler: async (request) => {\n"
        "    makeDir(request.params.dir);\n"
        "  },\n"
        "}));\n"
    )
    assert [severity for severity, _caller in hits] == ["high"]


def test_unregistered_function_is_not_a_tool():
    assert _tool_chain_hits(
        "const { makeDir } = require('./helper');\n"
        "async function mkdirCb(args) {\n"
        "  makeDir(args.dir);\n"
        "}\n"
    ) == []


def _own_body_tool_hits(server_js: str) -> list[tuple[str, str, int]]:
    root = _make_project({"server.js": server_js})
    return [
        (f.rule_id, f.severity.value, f.start_line)
        for f in _run_js_cross_file(root).findings
        if f.rule_id.startswith("TNT-TS-AGENT-")
    ]


def test_referenced_handler_with_sink_in_its_own_body_is_reported():
    """Opengrep's TS rules only see inline handlers; the pass reports the rest."""
    assert _own_body_tool_hits(
        "const fs = require('fs');\n"
        "async function handleMkdir(args) {\n"
        "  fs.mkdirSync(args.dir);\n"
        "}\n"
        "server.registerTool('mkdir', {}, handleMkdir);\n"
    ) == [("TNT-TS-AGENT-PATH-001", "high", 3)]


def test_inline_handler_own_body_sink_is_left_to_the_opengrep_rule():
    assert _own_body_tool_hits(
        "const fs = require('fs');\n"
        "server.registerTool('mkdir', {}, async (args) => {\n"
        "  fs.mkdirSync(args.dir);\n"
        "});\n"
    ) == []


def test_job_definition_with_config_and_run_is_not_a_tool():
    assert _own_body_tool_hits(
        "const fs = require('fs');\n"
        "const job = { name: 'build', config: { retries: 2 }, run: async (opts) => {\n"
        "  fs.mkdirSync(opts.dir);\n"
        "} };\n"
    ) == []


def test_only_the_wrapped_handler_is_a_tool_not_other_wrapper_args():
    assert _own_body_tool_hits(
        "const fs = require('fs');\n"
        "async function handleMkdir(args) {\n"
        "  return args;\n"
        "}\n"
        "function auditLog(entry) {\n"
        "  fs.mkdirSync(entry.dir);\n"
        "}\n"
        "server.registerTool('mkdir', {}, withAuth(handleMkdir, auditLog));\n"
    ) == []


# ---------------------------------------------------------------------------
# Method calls on objects of unknown type (MCP census G5, 2026-10-20):
# chrome-devtools-mcp handlers call `context.saveFile(...)`, dbhub calls
# `connector.executeSQL(...)`. Fan out to the project's classes that define
# the method, when there are few of them and the name is specific.
# ---------------------------------------------------------------------------

_CONTEXT_CLASS = (
    "const fs = require('fs');\n"
    "class McpContext {\n"
    "  saveFile(target) {\n"
    "    fs.writeFileSync(target, '');\n"
    "  }\n"
    "}\n"
    "module.exports = { McpContext };\n"
)


def _fanout_hits(server_js: str, extra: dict[str, str]) -> list[tuple[str, str]]:
    root = _make_project({"server.js": server_js, **extra})
    return [
        (f.rule_id, f.metadata.get("callee_name", ""))
        for f in _run_js_cross_file(root).findings
        if f.rule_id == "CF-SINK-001"
    ]


def test_method_on_untyped_receiver_resolves_to_the_defining_class():
    hits = _fanout_hits(
        "server.registerTool('save', {}, async (args, context) => {\n"
        "  context.saveFile(args.path);\n"
        "});\n",
        {"context.js": _CONTEXT_CLASS},
    )
    assert hits == [("CF-SINK-001", "saveFile")]


def test_generic_method_name_is_not_fanned_out():
    hits = _fanout_hits(
        "server.registerTool('save', {}, async (args, store) => {\n"
        "  store.get(args.path);\n"
        "});\n",
        {"store.js": _CONTEXT_CLASS.replace("saveFile", "get")},
    )
    assert hits == []


def test_method_defined_by_many_classes_is_not_fanned_out():
    classes = {
        f"c{i}.js": _CONTEXT_CLASS.replace("McpContext", f"Ctx{i}") for i in range(6)
    }
    hits = _fanout_hits(
        "server.registerTool('save', {}, async (args, context) => {\n"
        "  context.saveFile(args.path);\n"
        "});\n",
        classes,
    )
    assert hits == []
