"""JavaScript/TypeScript cross-file taint propagation pass.

Mirrors ``rowan.passes.cross_file``'s design: builds an import graph
and call graph for the target language, then feeds them into the SAME
language-agnostic fixpoint propagation engine the Python pass uses
(``_match_findings_to_functions``, ``_propagate_cross_file``). Only the AST
extraction front-end differs -- tree-sitter instead of Python's ``ast``.

Optional dependency: requires ``tree-sitter`` + ``tree-sitter-javascript`` +
``tree-sitter-typescript`` (``pip install rowan-sast[js-crossfile]``). Skips
gracefully if not installed, the same way ``TaintPass`` skips gracefully when
the Opengrep binary isn't on PATH.
"""

from __future__ import annotations

import json
import logging
import re
import time
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from rowan.core.findings import Category, Finding, ScanResult, Severity, TaintFlow, TaintNode
from rowan.core.paths import is_within_root
from rowan.passes.base import ScanContext, scan_span
from rowan.passes.cross_file import (
    _UNRESOLVED_QUALIFIER,
    _FunctionSig,
    _ImportGraph,
    _match_findings_to_functions,
    _propagate_cross_file,
    _resolve_callee,
)
from rowan.passes.file_scan import _parts_under, is_hidden_under, is_ignored, load_ignore_patterns

logger = logging.getLogger(__name__)

try:
    import tree_sitter_javascript as _tsjs
    import tree_sitter_typescript as _tsts
    from tree_sitter import Language, Parser

    TREE_SITTER_AVAILABLE = True
except ImportError:
    TREE_SITTER_AVAILABLE = False

_JS_EXTENSIONS = (".js", ".jsx", ".mjs", ".cjs")
_TS_EXTENSIONS = (".ts", ".tsx")
_RESOLVE_EXTENSIONS = (".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs")
_TS_SOURCE_FOR_EMITTED = {
    ".js": (".ts", ".tsx"), ".jsx": (".tsx",), ".mjs": (".mts",), ".cjs": (".cts",),
}
_SKIP_DIRS = {"node_modules", "dist", "build", ".next", "out", "coverage"}
_SKIP_SUFFIXES = (".min.js", ".d.ts", ".test.js", ".test.ts", ".spec.js", ".spec.ts")

# Known taint sources for common Node.js web frameworks (Express, Koa, Next.js
# API routes). Matched as a dotted-prefix on member-expression text, mirroring
# KNOWN_SOURCE_PREFIXES in cross_file.py.
#
# `process.env` is deliberately NOT a source here, matching the Python pass's
# trust model: KNOWN_SOURCE_PREFIXES in cross_file.py includes "sys.argv" but
# has no "os.environ" entry, i.e. Python already treats env vars as
# operator-controlled rather than attacker-controlled at this same
# structural-source-list layer (a stance enrichment.py's
# EnrichmentPass._cap_exploitability / _OPERATOR_SOURCE_RE reinforces
# downstream by capping, not eliminating, os.environ/sys.argv/parse_args
# findings). Seeding every `process.env.X` read as a full remote source made
# every 12-factor JS app config read a taint seed, since config reads vastly
# outnumber genuinely attacker-controlled env vars in real code.
# `process.argv` stays, mirroring "sys.argv" on the Python side.
KNOWN_JS_SOURCE_PREFIXES: tuple[str, ...] = (
    "req.body", "req.query", "req.params", "req.headers", "req.cookies",
    "request.body", "request.query", "request.params",
    "ctx.request.body", "ctx.query", "ctx.params",
    "process.argv",
)
# The operator's own input: a chain fed only by these is capped, not dropped
# (see _FunctionSig.operator_source_only).
_OPERATOR_JS_SOURCE_PREFIXES: tuple[str, ...] = ("process.argv",)
_REMOTE_JS_SOURCE_PREFIXES: tuple[str, ...] = tuple(
    p for p in KNOWN_JS_SOURCE_PREFIXES if p not in _OPERATOR_JS_SOURCE_PREFIXES
)

# Functions that carry taint from input to output -- same role as
# KNOWN_PROPAGATORS in cross_file.py.
KNOWN_JS_PROPAGATORS: dict[str, int] = {
    "fetch": 0,
    "axios.get": 0,
    "axios.post": 0,
    "JSON.parse": 0,
}


def _get_parsers() -> dict[str, Any]:
    js_lang = Language(_tsjs.language())
    ts_lang = Language(_tsts.language_typescript())
    tsx_lang = Language(_tsts.language_tsx())
    js_parser = Parser(js_lang)
    ts_parser = Parser(ts_lang)
    tsx_parser = Parser(tsx_lang)
    return {
        ".js": js_parser, ".jsx": js_parser, ".mjs": js_parser, ".cjs": js_parser,
        ".ts": ts_parser, ".tsx": tsx_parser,
    }


def _node_text(node: Any, source: bytes) -> str:
    return source[node.start_byte:node.end_byte].decode("utf-8", errors="replace")


def _string_literal_value(node: Any, source: bytes) -> str | None:
    """Extract the literal value from a `string` node (strips quotes)."""
    for child in node.children:
        if child.type == "string_fragment":
            return _node_text(child, source)
    return None


def _collect_js_files(
    root: Path,
    ignore_patterns: list[str] | None = None,
    *,
    candidates: Iterable[Path] | None = None,
) -> list[Path]:
    """Collect scoped JS/TS files, retaining the standalone walk fallback."""
    files: list[Path] = []
    exts = _JS_EXTENSIONS + _TS_EXTENSIONS
    source_paths = root.rglob("*") if candidates is None else candidates
    for path in source_paths:
        if not path.is_file() or path.suffix not in exts:
            continue
        if is_hidden_under(path, root) or any(part in _SKIP_DIRS for part in _parts_under(path, root)):
            continue
        # A symlinked source file can point outside the scan root (CWE-59);
        # rglob does not follow a symlinked directory but does yield a
        # symlinked file as is_file()==True.
        if path.is_symlink() and not is_within_root(path, root):
            continue
        if path.name.endswith(_SKIP_SUFFIXES):
            continue
        if ignore_patterns:
            try:
                rel = path.relative_to(root)
            except ValueError:
                pass
            else:
                if is_ignored(str(rel), ignore_patterns):
                    continue
        files.append(path)
    return files


# JSONC as tsconfig.json allows it: keep strings, drop comments and trailing commas.
_JSONC_NOISE_RE = re.compile(r'("(?:\\.|[^"\\])*")|//[^\n]*|/\*[\s\S]*?\*/|,(?=\s*[}\]])')

PathAliases = list[tuple[str, list[str]]]


def _load_tsconfig_paths(tsconfig: Path) -> PathAliases:
    """`compilerOptions.paths` as (pattern, [absolute target patterns])."""
    try:
        text = tsconfig.read_text(encoding="utf-8")
        for _ in range(2):  # a comma can sit before a comment: `],  // note`
            text = _JSONC_NOISE_RE.sub(lambda m: m.group(1) or "", text)
        data = json.loads(text)
    except (OSError, ValueError) as exc:
        logger.debug("Skipping %s: %s", tsconfig, exc)
        return []
    options = data.get("compilerOptions") if isinstance(data, dict) else None
    paths = options.get("paths") if isinstance(options, dict) else None
    if not isinstance(paths, dict):
        return []
    base = tsconfig.parent / str(options.get("baseUrl", "."))
    return [
        (pattern, [str(base / t) for t in targets if isinstance(t, str)])
        for pattern, targets in paths.items()
        if isinstance(targets, list)
    ]


def _resolve_js_module(caller_dir: Path, mod_path: str, path_aliases: PathAliases = ()) -> str | None:
    """Resolve a JS/TS import specifier to a file path (simplified Node resolution).

    Relative specifiers ("./foo", "../bar") and tsconfig `paths` aliases
    ("~/utils/x") resolve to a local file; other bare specifiers ("react",
    "lodash") are npm packages and out of scope -- there is no source to
    attribute a sink/source to.
    """
    if mod_path.startswith("."):
        return _resolve_js_path((caller_dir / mod_path).resolve())
    for pattern, targets in path_aliases:
        prefix, star, suffix = pattern.partition("*")
        if star:
            if not (mod_path.startswith(prefix) and mod_path.endswith(suffix)
                    and len(mod_path) >= len(prefix) + len(suffix)):
                continue
            middle = mod_path[len(prefix):len(mod_path) - len(suffix)]
        elif mod_path != pattern:
            continue
        else:
            middle = ""
        for target in targets:
            resolved = _resolve_js_path(Path(target.replace("*", middle, 1)).resolve())
            if resolved:
                return resolved
    return None


def _resolve_js_path(base: Path) -> str | None:
    if base.is_file():
        return str(base)
    # TypeScript ESM imports name the emitted file (`./util.js` for util.ts).
    for emitted, sources in _TS_SOURCE_FOR_EMITTED.items():
        if base.suffix == emitted:
            for ext in sources:
                candidate = base.with_suffix(ext)
                if candidate.is_file():
                    return str(candidate)
    for ext in _RESOLVE_EXTENSIONS:
        candidate = Path(f"{base}{ext}")
        if candidate.is_file():
            return str(candidate)
    for ext in _RESOLVE_EXTENSIONS:
        candidate = base / f"index{ext}"
        if candidate.is_file():
            return str(candidate)
    return None


def extract_imports(
    file_path: str, root_node: Any, source: bytes, path_aliases: PathAliases = ()
) -> _ImportGraph:
    """Extract ES module imports and CommonJS require() calls from a file's tree."""
    graph = _ImportGraph()
    caller_dir = Path(file_path).parent

    for node in _walk_all(root_node):
        if node.type == "import_statement":
            _handle_import_statement(node, source, caller_dir, file_path, graph, path_aliases)
        elif node.type == "call_expression":
            _handle_require_call(node, source, caller_dir, file_path, graph, path_aliases)
    return graph


def extract_reexports(
    file_path: str, root_node: Any, source: bytes, path_aliases: PathAliases = ()
) -> tuple[dict[tuple[str, str], tuple[str, str]], list[str]]:
    """Barrel re-exports: `export { a, b as c } from "./x"` as
    {(file, exported): (target, imported)}, and `export * from "./y"` as a
    list of target files."""
    named: dict[tuple[str, str], tuple[str, str]] = {}
    stars: list[str] = []
    caller_dir = Path(file_path).parent
    for stmt in root_node.children:
        source_node = stmt.child_by_field_name("source") if stmt.type == "export_statement" else None
        mod_path = _string_literal_value(source_node, source) if source_node is not None else None
        target = _resolve_js_module(caller_dir, mod_path, path_aliases) if mod_path else None
        if target is None:
            continue
        clause = next((c for c in stmt.children if c.type == "export_clause"), None)
        if clause is None:
            if any(c.type == "*" for c in stmt.children):
                stars.append(target)
            continue
        for spec in clause.children:
            if spec.type == "export_specifier":
                imported, _, exported = _node_text(spec, source).partition(" as ")
                named[(file_path, (exported or imported).strip())] = (target, imported.strip())
    return named, stars


def _handle_import_statement(
    node: Any, source: bytes, caller_dir: Path, file_path: str, graph: _ImportGraph,
    path_aliases: PathAliases = (),
) -> None:
    source_node = node.child_by_field_name("source")
    if source_node is None:
        return
    mod_path = _string_literal_value(source_node, source)
    if not mod_path:
        return
    target = _resolve_js_module(caller_dir, mod_path, path_aliases)
    if target is None:
        return

    clause = next((c for c in node.children if c.type == "import_clause"), None)
    if clause is None:
        return
    for c in clause.children:
        if c.type == "identifier":  # default import: `import Foo from "./foo"`
            graph.name_to_def[(file_path, _node_text(c, source))] = (target, "default")
        elif c.type == "named_imports":  # `import { a, b as c } from "./x"`
            for spec in c.children:
                if spec.type != "import_specifier":
                    continue
                text = _node_text(spec, source)
                parts = text.split(" as ")
                imported = parts[0].strip()
                local = parts[1].strip() if len(parts) > 1 else imported
                graph.name_to_def[(file_path, local)] = (target, imported)
        elif c.type == "namespace_import":  # `import * as utils from "./utils"`
            ident = next((g for g in c.children if g.type == "identifier"), None)
            if ident is not None:
                graph.module_to_file[(file_path, _node_text(ident, source))] = target


def _handle_require_call(
    node: Any, source: bytes, caller_dir: Path, file_path: str, graph: _ImportGraph,
    path_aliases: PathAliases = (),
) -> None:
    func = node.child_by_field_name("function")
    if func is None or func.type != "identifier" or _node_text(func, source) != "require":
        return
    args = node.child_by_field_name("arguments")
    if args is None:
        return
    str_node = next((a for a in args.children if a.type == "string"), None)
    if str_node is None:
        return
    mod_path = _string_literal_value(str_node, source)
    if not mod_path:
        return
    target = _resolve_js_module(caller_dir, mod_path, path_aliases)
    if target is None:
        return

    parent = node.parent
    if parent is None or parent.type != "variable_declarator":
        return
    name_node = parent.child_by_field_name("name")
    if name_node is None:
        return
    if name_node.type == "identifier":  # `const mod = require("./mod")`
        local = _node_text(name_node, source)
        graph.module_to_file[(file_path, local)] = target
    elif name_node.type == "object_pattern":  # `const { a, b } = require("./mod")`
        for prop in name_node.children:
            if prop.type == "shorthand_property_identifier_pattern":
                local = _node_text(prop, source)
                graph.name_to_def[(file_path, local)] = (target, local)


def _call_function(call: Any) -> Any | None:
    """A call's callee node. tree-sitter parses `await f<T>(x)` with the
    whole `await f` as the function; unwrap it."""
    func = call.child_by_field_name("function")
    if func is not None and func.type == "await_expression" and func.named_children:
        return func.named_children[0]
    return func


def _call_has_args(call_node: Any) -> bool:
    """True if `call_node` (a `call_expression`) passes at least one
    argument -- used to gate downward source-to-callee propagation
    (`_propagate_cross_file`'s `edge_has_args`): a zero-argument call site
    can't hand the callee any tainted value."""
    args_node = call_node.child_by_field_name("arguments")
    if args_node is None:
        return False
    return any(c.is_named for c in args_node.children)


def _collect_calls(node: Any, source: bytes) -> list[tuple[str, str | None, bool, int]]:
    """Returns (callee_name, qualifier, has_args, call_lineno) per call
    expression -- the trailing lineno (tree-sitter's 0-indexed start_point
    row, converted to 1-indexed) anchors cross-file findings at the actual
    call site rather than the enclosing function's `def` line (issue #154
    Defect 2), mirroring the Python front-end's `_extract_functions`."""
    calls: list[tuple[str, str | None, bool, int]] = []

    for n in _walk_all(node):
        if n.type == "call_expression":
            func = _call_function(n)
            has_args = _call_has_args(n)
            call_line = n.start_point[0] + 1
            if func is not None:
                if func.type == "identifier":
                    calls.append((_node_text(func, source), None, has_args, call_line))
                elif func.type == "member_expression":
                    obj = func.child_by_field_name("object")
                    prop = func.child_by_field_name("property")
                    if obj is not None and prop is not None:
                        inner_obj = (
                            obj.child_by_field_name("object")
                            if obj.type == "member_expression" else None
                        )
                        if obj.type == "identifier":
                            calls.append((_node_text(prop, source), _node_text(obj, source), has_args, call_line))
                        elif obj.type == "this":
                            # this.foo() -- an instance-method call, not a
                            # module reference. _resolve_callee_file treats
                            # "this" the same as Python's self/cls.
                            calls.append((_node_text(prop, source), "this", has_args, call_line))
                        elif inner_obj is not None and inner_obj.type == "this":
                            # this.db.query() / this.session.add() -- one
                            # level of attribute chaining off `this` (an ORM
                            # session/manager attribute this pass doesn't
                            # otherwise track). Mirrors DEF-35's Python fix
                            # for self.db.query(): the method name alone is
                            # still resolvable the same way a bare
                            # this.<method>() call is above.
                            calls.append((_node_text(prop, source), "this", has_args, call_line))
                        else:
                            # Arbitrary chained qualifier, e.g.
                            # services.payment.charge() -- can't be
                            # confidently attributed to any single name.
                            # Recorded as unresolved (matching Python's
                            # _UNRESOLVED_QUALIFIER) instead of silently
                            # dropped, so it's distinguishable from a
                            # genuinely unqualified call and never
                            # fabricates a same-file edge just because a
                            # same-named function happens to exist here.
                            calls.append((_node_text(prop, source), _UNRESOLVED_QUALIFIER, has_args, call_line))
    return calls


def _reads_known_source(
    node: Any, source: bytes, prefixes: tuple[str, ...] = KNOWN_JS_SOURCE_PREFIXES
) -> bool:
    for n in _walk_own_scope(node):
        if n.type == "member_expression":
            text = _node_text(n, source)
            if any(text == p or text.startswith(p + ".") for p in prefixes):
                return True
    return False


def _returns_known_source(node: Any, source: bytes) -> bool:
    """True if any `return_statement` in the function body itself reads a
    known taint source -- mirrors Python's `_function_returns_source`. A
    function that merely CONTAINS a source read somewhere, with an
    unrelated return value, must not be treated as returning tainted data."""
    for n in _walk_all(node):
        if n.type == "return_statement" and _reads_known_source(n, source):
            return True
    return False


# Node types that get their own _FunctionSig in extract_functions.
_OWN_SIG_FUNCTION_TYPES = frozenset(
    {"function_declaration", "function_expression", "arrow_function", "method_definition"}
)


def _walk_own_scope(node: Any):
    """`_walk_all` that stops at nested functions with their own signature: a
    request handler registered inside `bootstrap()` reads its own input, not
    bootstrap()'s."""
    stack = [node]
    while stack:
        n = stack.pop()
        yield n
        stack.extend(c for c in reversed(n.children) if c.type not in _OWN_SIG_FUNCTION_TYPES)


def _walk_all(node: Any):
    """Pre-order walk with an explicit stack: a 3000-term string concatenation
    is a tree 3000 levels deep, which recursion cannot walk (XF-13)."""
    stack = [node]
    while stack:
        n = stack.pop()
        yield n
        stack.extend(reversed(n.children))


# Agent tool handlers: the model chooses their arguments, so every parameter
# is untrusted input (the same boundary rules/typescript_agent_taint.yaml uses).
_TOOL_REGISTRATION_METHODS = frozenset({"tool", "registerTool"})
_TOOL_HANDLER_KEYS = frozenset({"execute", "func"})
_TOOL_FACTORIES = frozenset({"tool", "DynamicTool", "DynamicStructuredTool"})
# Tool-definition objects registered later through generic code:
# `{name, schema, handler}` (chrome-devtools-mcp), `{name, config, cb}` (Aikido).
_TOOL_DEF_SCHEMA_KEYS = frozenset({"schema", "inputSchema", "parameters", "config"})
_TOOL_DEF_HANDLER_KEYS = frozenset({"handler", "handle", "execute", "func", "cb", "callback", "run"})


def _object_pairs(obj: Any, source: bytes) -> dict[str, Any]:
    """Key text -> value node for the `pair`s and methods of an object literal."""
    pairs: dict[str, Any] = {}
    for child in obj.named_children:
        if child.type == "pair":
            key, value = child.child_by_field_name("key"), child.child_by_field_name("value")
        elif child.type == "method_definition":
            key, value = child.child_by_field_name("name"), child
        else:
            continue
        if key is not None and value is not None:
            pairs[_node_text(key, source).strip("'\"")] = value
    return pairs


def _is_tool_definition(obj: Any, source: bytes) -> bool:
    pairs = _object_pairs(obj, source)
    if "name" not in pairs or not set(pairs) & _TOOL_DEF_HANDLER_KEYS:
        return False
    if set(pairs) & (_TOOL_DEF_SCHEMA_KEYS - {"config"}):
        return True
    # `config` alone is common in job/task objects; it counts only when it
    # carries the input schema (`{name, config: {inputSchema}, cb}`).
    config = pairs.get("config")
    return config is not None and config.type == "object" and bool(
        set(_object_pairs(config, source)) & (_TOOL_DEF_SCHEMA_KEYS - {"config"})
    )


def _is_tool_definition_handler(node: Any, source: bytes) -> bool:
    """The handler function of a tool-definition object (`handler: async (r) => ...`)."""
    parent = node.parent
    if parent is not None and parent.type == "pair":
        key, obj = parent.child_by_field_name("key"), parent.parent
    elif node.type == "method_definition":
        key, obj = node.child_by_field_name("name"), parent
    else:
        return False
    return (
        key is not None
        and obj is not None
        and obj.type == "object"
        and _node_text(key, source) in _TOOL_DEF_HANDLER_KEYS
        and _is_tool_definition(obj, source)
    )


def _tool_handler_refs(root_node: Any, source: bytes) -> tuple[set[str], set[str]]:
    """Names of functions registered as MCP tool handlers by reference, and of
    factories whose returned function is the handler.

    `registerTool(name, cfg, handleX)`, `registerTool(name, cfg, createX(id))`
    (dbhub), `registerTool(t.name, t.config, withAuth(t.cb))` with `cb: handleX`
    in a tool-definition object (Aikido). Inline handlers are recognized by
    `_is_agent_tool_handler` instead.
    """
    names: set[str] = set()
    factories: set[str] = set()
    for node in _walk_all(root_node):
        if node.type == "object" and _is_tool_definition(node, source):
            for key, value in _object_pairs(node, source).items():
                if key in _TOOL_DEF_HANDLER_KEYS and value.type == "identifier":
                    names.add(_node_text(value, source))
            continue
        if node.type != "call_expression":
            continue
        func = node.child_by_field_name("function")
        args = node.child_by_field_name("arguments")
        if func is None or args is None or func.type != "member_expression":
            continue
        if _node_text(func, source).rsplit(".", 1)[-1] not in _TOOL_REGISTRATION_METHODS:
            continue
        handler = args.named_children[-1] if args.named_children else None
        if handler is None:
            continue
        if handler.type == "identifier":
            names.add(_node_text(handler, source))
        elif handler.type == "call_expression":
            callee = handler.child_by_field_name("function")
            if callee is not None and callee.type == "identifier":
                factories.add(_node_text(callee, source))
            # A wrapper (`withAuth(handleX, log)`) wraps its first argument only.
            inner = handler.child_by_field_name("arguments")
            first = inner.named_children[0] if inner is not None and inner.named_children else None
            if first is not None and first.type == "identifier":
                names.add(_node_text(first, source))
    return names, factories


# `obj.method()` on a receiver of unknown type fans out to the project's
# classes defining `method` (MCP census G5): only for a specific method name
# defined by a handful of classes, on a plain local receiver.
_FANOUT_MAX_CLASSES = 4
_GENERIC_METHOD_NAMES = frozenset({
    "get", "set", "has", "delete", "add", "remove", "clear", "run", "call", "apply", "bind",
    "then", "catch", "finally", "map", "filter", "reduce", "forEach", "find", "some", "every",
    "push", "pop", "shift", "send", "write", "read", "end", "on", "once", "off", "emit", "close",
    "open", "start", "stop", "init", "handle", "process", "update", "create", "execute", "query",
    "parse", "toString", "toJSON", "valueOf", "log", "info", "warn", "error", "debug", "next",
    "use", "listen", "connect", "request", "fetch", "load", "save", "resolve", "reject",
    "dispose", "destroy", "render", "validate", "register", "post", "put", "patch", "invoke",
    "constructor",
})
_BUILTIN_QUALIFIERS = frozenset({
    "console", "JSON", "Math", "Object", "Array", "Promise", "Reflect", "Number", "String", "Date",
    "fs", "path", "os", "process", "window", "document", "crypto", "Buffer", "URL", "this", "super",
})


def _class_method_names(root_node: Any, source: bytes) -> set[str]:
    """Names of methods declared in this file's class bodies."""
    names: set[str] = set()
    for node in _walk_all(root_node):
        if node.type != "class_body":
            continue
        for member in node.named_children:
            if member.type == "method_definition":
                name = member.child_by_field_name("name")
                if name is not None:
                    names.add(_node_text(name, source))
    return names


def _returned_function_lines(root_node: Any, source: bytes) -> dict[str, list[int]]:
    """For each named function, the start lines of functions it returns directly
    (`return async (args) => {...}`, or an arrow whose body is a function)."""
    returned: dict[str, list[int]] = {}
    for node in _walk_all(root_node):
        name_node = None
        func = None
        if node.type == "function_declaration":
            name_node, func = node.child_by_field_name("name"), node
        elif node.type == "variable_declarator":
            value = node.child_by_field_name("value")
            if value is not None and value.type in ("arrow_function", "function_expression"):
                name_node, func = node.child_by_field_name("name"), value
        if name_node is None or func is None:
            continue
        body = func.child_by_field_name("body")
        if body is None:
            continue
        lines = [body.start_point[0] + 1] if body.type in ("arrow_function", "function_expression") else []
        for n in _walk_own_scope(body):
            if n.type == "return_statement":
                expr = next((c for c in n.named_children), None)
                if expr is not None and expr.type in ("arrow_function", "function_expression"):
                    lines.append(expr.start_point[0] + 1)
        if lines:
            returned[_node_text(name_node, source)] = lines
    return returned


def _is_agent_tool_handler(node: Any, source: bytes) -> bool:
    """True for a function passed as an MCP, Vercel AI SDK or LangChain.js tool
    handler: `server.tool(..., fn)`, `server.registerTool(..., fn)`,
    `server.setRequestHandler(CallToolRequestSchema, fn)`, `tool(fn, opts)`,
    or `execute`/`func` in `tool({...})` / `new DynamicStructuredTool({...})`."""
    parent = node.parent
    if parent is None:
        return False
    if parent.type == "arguments":
        call = parent.parent
        func = call.child_by_field_name("function") if call is not None else None
        if func is None or call.type != "call_expression":
            return False
        name = _node_text(func, source).rsplit(".", 1)[-1]
        if func.type == "member_expression" and name in _TOOL_REGISTRATION_METHODS:
            return True
        if func.type == "identifier" and name == "tool":
            return True
        if name == "setRequestHandler":
            first = next((c for c in parent.children if c.is_named), None)
            return first is not None and _node_text(first, source).endswith("CallToolRequestSchema")
        return False
    if parent.type == "pair":
        key = parent.child_by_field_name("key")
        obj = parent.parent
    elif node.type == "method_definition":
        key = node.child_by_field_name("name")
        obj = parent
    else:
        return False
    if key is None:
        return False
    if _is_tool_definition_handler(node, source):
        return True
    if _node_text(key, source) not in _TOOL_HANDLER_KEYS:
        return False
    if obj is None or obj.type != "object" or obj.parent is None or obj.parent.type != "arguments":
        return False
    call = obj.parent.parent
    if call is None:
        return False
    callee = call.child_by_field_name("function" if call.type == "call_expression" else "constructor")
    return callee is not None and _node_text(callee, source).rsplit(".", 1)[-1] in _TOOL_FACTORIES


# A commander `.action(cb)` callback receives the parsed command-line
# arguments. `process.argv` is already a source, so these parameters are too
# (MCP-03, mcp-watch). The chain must declare a command or argument, so an
# unrelated `.action(cb)` stays inert.
_CLI_CHAIN_RE = re.compile(r"\.(?:command|argument|arguments)\s*\(")


def _is_cli_action_handler(node: Any, source: bytes) -> bool:
    parent = node.parent
    if parent is None or parent.type != "arguments":
        return False
    call = parent.parent
    func = call.child_by_field_name("function") if call is not None else None
    if func is None or func.type != "member_expression":
        return False
    prop = func.child_by_field_name("property")
    if prop is None or _node_text(prop, source) != "action":
        return False
    receiver = func.child_by_field_name("object")
    return receiver is not None and bool(_CLI_CHAIN_RE.search(_node_text(receiver, source)))


# Calls whose first argument must not be attacker-controlled. Matched on the
# callee's last name, and for methods also on the receiver, so that
# `regex.exec(s)` or `tool.execute(args)` are not mistaken for sinks.
_FS_RECEIVERS = frozenset({"fs", "fsp", "fsPromises", "promises"})
_FS_METHODS = frozenset({
    "readFile", "readFileSync", "writeFile", "writeFileSync", "appendFile", "appendFileSync",
    "createReadStream", "createWriteStream", "unlink", "unlinkSync", "rm", "rmSync",
    "readdir", "readdirSync", "mkdir", "mkdirSync",
})
_BARE_SINKS: dict[str, Category] = {
    "exec": Category.COMMAND_INJECTION, "execSync": Category.COMMAND_INJECTION,
    "eval": Category.INJECTION, "fetch": Category.SSRF, "got": Category.SSRF,
    **{m: Category.PATH_TRAVERSAL for m in _FS_METHODS},
}
_MEMBER_SINKS: dict[tuple[str, str], Category] = {
    **{(r, m): Category.COMMAND_INJECTION
       for r in ("child_process", "cp", "childProcess") for m in ("exec", "execSync")},
    **{(r, m): Category.PATH_TRAVERSAL for r in _FS_RECEIVERS for m in _FS_METHODS},
    **{("axios", m): Category.SSRF for m in ("get", "post", "put", "delete", "request")},
    **{(r, m): Category.SSRF for r in ("http", "https") for m in ("get", "request")},
}
_SINK_CWE = {
    Category.COMMAND_INJECTION: 78, Category.PATH_TRAVERSAL: 22,
    Category.SSRF: 918, Category.INJECTION: 95,
}
# A sanitizer-named call: a leading verb (`validatePath`, `safeJoin`) or a
# camelCase word inside the name (`resolveSafePath`), but not `unsafeExec`
# and not zod's `safeParse`, which checks types, not shell or path content.
_SANITIZER_NAME_RE = re.compile(
    r"^(?i:basename|validate|sanitize|safe(?!parse)|assert|ensure|normalize|allowed|confine)"
    r"|[a-z](?:Safe|Valid|Sanitiz|Confine)"
)


_PROMISIFY_EXEC = frozenset({
    f"{wrap}({fn})"
    for wrap in ("promisify", "util.promisify")
    for fn in ("exec", "child_process.exec", "cp.exec", "childProcess.exec")
})


def _exec_aliases(root: Any, source: bytes) -> dict[str, Category]:
    """`const execAsync = promisify(exec)`: exec under another name."""
    aliases: dict[str, Category] = {}
    for n in _walk_all(root):
        if n.type != "variable_declarator":
            continue
        name = n.child_by_field_name("name")
        value = n.child_by_field_name("value")
        if (
            name is not None and name.type == "identifier" and value is not None
            and "".join(_node_text(value, source).split()) in _PROMISIFY_EXEC
        ):
            aliases[_node_text(name, source)] = Category.COMMAND_INJECTION
    return aliases


def _sink_category(
    call: Any, source: bytes, aliases: dict[str, Category] | None = None
) -> Category | None:
    func = _call_function(call)
    if func is None:
        return None
    if func.type == "identifier":
        name = _node_text(func, source)
        return _BARE_SINKS.get(name) or (aliases or {}).get(name)
    if func.type == "member_expression":
        obj = func.child_by_field_name("object")
        prop = func.child_by_field_name("property")
        if obj is None or prop is None:
            return None
        receiver = _node_text(obj, source).rsplit(".", 1)[-1]
        return _MEMBER_SINKS.get((receiver, _node_text(prop, source)))
    return None


def _tainted_names(node: Any, source: bytes, tainted: set[str]) -> bool:
    """True if `node` reads a tainted name outside every sanitizer call."""
    stack = [node]
    while stack:
        n = stack.pop()
        if n.type == "call_expression":
            func = _call_function(n)
            if func is not None and _SANITIZER_NAME_RE.search(_node_text(func, source).rsplit(".", 1)[-1]):
                continue
        if n.type in ("identifier", "shorthand_property_identifier") and _node_text(n, source) in tainted:
            return True
        stack.extend(n.children)
    return False


def _host_tainted(node: Any, source: bytes, tainted: set[str]) -> bool:
    """True if a tainted value can choose the host of the URL `node` builds.

    SSRF needs control of the scheme/host. A value that only lands after a
    fixed prefix (`${apiBase}/projects/${id}`, `base + "/x/" + id`) or in
    `searchParams` is path-only. `new URL(x, base)` stays host-tainted when
    `x` is: an absolute `x` replaces the base.
    """
    kind = node.type
    if kind == "parenthesized_expression" or kind in ("await_expression", "as_expression", "non_null_expression"):
        inner = next((c for c in node.children if c.is_named), None)
        return inner is not None and _host_tainted(inner, source, tainted)
    if kind in ("identifier", "member_expression", "subscript_expression"):
        return _tainted_names(node, source, tainted)
    if kind == "template_string":
        first = next((c for c in node.children if c.type in ("string_fragment", "template_substitution")), None)
        if first is None or first.type == "string_fragment":
            return False
        inner = next((c for c in first.children if c.is_named), None)
        return inner is not None and _host_tainted(inner, source, tainted)
    if kind == "binary_expression":
        op = node.child_by_field_name("operator")
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        if op is not None and _node_text(op, source) in ("??", "||", "&&"):
            return any(s is not None and _host_tainted(s, source, tainted) for s in (left, right))
        return left is not None and _host_tainted(left, source, tainted)
    if kind == "ternary_expression":
        return any(
            s is not None and _host_tainted(s, source, tainted)
            for s in (node.child_by_field_name("consequence"), node.child_by_field_name("alternative"))
        )
    if kind in ("call_expression", "new_expression"):
        func = node.child_by_field_name("function" if kind == "call_expression" else "constructor")
        name = _node_text(func, source).rsplit(".", 1)[-1] if func is not None else ""
        if _SANITIZER_NAME_RE.search(name):
            return False
        args = node.child_by_field_name("arguments")
        first = next((c for c in args.children if c.is_named), None) if args is not None else None
        if name in ("URL", "String"):
            return first is not None and _host_tainted(first, source, tainted)
        if func is not None and func.type == "member_expression":
            prop = func.child_by_field_name("property")
            if prop is not None and _node_text(prop, source) in ("toString", "trim", "toLowerCase", "href"):
                obj = func.child_by_field_name("object")
                return obj is not None and _host_tainted(obj, source, tainted)
        return False
    return False


# A literal that fixes the scheme and host: `https://host/`, `...?`, `...#`, or
# a path on the page's own origin (`/api`). Without the `/`, `?` or `#`, the
# next value can still extend the host (`https://api.x.com` + `.evil.com`).
_FIXED_HOST_PREFIX_RE = re.compile(r"^(?:[a-zA-Z][\w+.-]*://[^/?#\s]+[/?#]|/(?!/))")
_SCOPE_TYPES = frozenset({"statement_block", "program"})
_FUNCTION_TYPES = frozenset({
    "function_declaration", "function_expression", "arrow_function",
    "method_definition", "generator_function_declaration",
})


def _import_bindings(stmt: Any, source: bytes) -> set[str]:
    """Local names an `import` statement binds (default, named, namespace)."""
    names: set[str] = set()
    for n in _walk_all(stmt):
        if n.type == "import_specifier":
            local = n.child_by_field_name("alias") or n.child_by_field_name("name")
            names.add(_node_text(local, source))
        elif n.type in ("import_clause", "namespace_import"):
            names.update(_node_text(c, source) for c in n.children if c.type == "identifier")
    return names


def _const_value(ident: Any, source: bytes) -> Any | None:
    """The initializer of the `const` an identifier names, or the `import`
    statement that binds it, looked up through its enclosing blocks; None when
    the nearest binding is a parameter, a loop or catch variable, a `let`/`var`,
    or there is none in sight."""
    name = _node_text(ident, source)
    node = ident.parent
    while node is not None:
        bound: list[str] = []
        if node.type in _FUNCTION_TYPES:
            params = node.child_by_field_name("parameters")
            bound = _params_of(params, source) if params is not None else _collect_pattern_identifiers(
                node.child_by_field_name("parameter"), source)
            # `var` anywhere in the body is function-scoped.
            if any(
                n.type == "variable_declarator" and n.parent.type == "variable_declaration"
                and name in _collect_pattern_identifiers(n.child_by_field_name("name"), source)
                for n in _walk_all(node.child_by_field_name("body") or node)
            ):
                return None
        elif node.type == "for_in_statement":
            bound = _collect_pattern_identifiers(node.child_by_field_name("left"), source)
        elif node.type == "catch_clause":
            bound = _collect_pattern_identifiers(node.child_by_field_name("parameter"), source)
        if name in bound:
            return None
        if node.type in _SCOPE_TYPES:
            for stmt in node.children:
                if stmt.type == "import_statement" and name in _import_bindings(stmt, source):
                    return stmt
                decl = stmt.child_by_field_name("declaration") if stmt.type == "export_statement" else stmt
                if decl is None or decl.type not in ("lexical_declaration", "variable_declaration"):
                    continue
                for d in decl.children:
                    target = d.child_by_field_name("name") if d.type == "variable_declarator" else None
                    if target is None or name not in _collect_pattern_identifiers(target, source):
                        continue
                    if target.type == "identifier" and _node_text(decl, source).split()[0] == "const":
                        return d.child_by_field_name("value")
                    return None
        node = node.parent
    return None


def _constant(node: Any, source: bytes, depth: int = 0) -> bool:
    """A value the model cannot choose: literals, `process.env.X`, imported
    bindings (module configuration), and `const`s built only from those."""
    if depth > 4:
        return False
    kind = node.type
    if kind in ("string", "import_statement"):
        return True
    if kind == "template_string":
        return all(
            _constant(inner, source, depth + 1)
            for sub in node.children if sub.type == "template_substitution"
            for inner in sub.children if inner.is_named
        )
    if kind == "member_expression":
        return _node_text(node, source).startswith("process.env.")
    if kind == "identifier":
        value = _const_value(node, source)
        return value is not None and _constant(value, source, depth + 1)
    if kind == "binary_expression":
        op = node.child_by_field_name("operator")
        sides = (node.child_by_field_name("left"), node.child_by_field_name("right"))
        return (
            op is not None and _node_text(op, source) in ("+", "||", "??")
            and all(s is not None and _constant(s, source, depth + 1) for s in sides)
        )
    return False


def _url_parts(node: Any, source: bytes) -> list[Any]:
    """A URL expression as literal strings and opaque nodes, in order: `+`
    chains and template literals are flattened, and a `const` holding a
    string or template is inlined (`${API_BASE}/x` with a literal base)."""
    parts: list[Any] = []
    stack = [(node, 0)]
    while stack:
        n, depth = stack.pop()
        if n.type == "string":
            text = _string_literal_value(n, source) or ""
        elif n.type in ("string_fragment", "escape_sequence"):
            text = _node_text(n, source)
        else:
            text = None
        if text is not None:
            if parts and isinstance(parts[-1], str):
                parts[-1] += text
            else:
                parts.append(text)
            continue
        children: list[Any] = []
        if n.type == "template_string":
            for c in n.children:
                if c.type == "template_substitution":
                    children.extend(i for i in c.children if i.is_named)
                elif c.type in ("string_fragment", "escape_sequence"):
                    children.append(c)
        elif n.type == "binary_expression" and _node_text(n.child_by_field_name("operator"), source) == "+":
            children = [n.child_by_field_name("left"), n.child_by_field_name("right")]
        elif n.type == "parenthesized_expression":
            children = [c for c in n.children if c.is_named]
        elif n.type == "identifier" and depth < 4:
            value = _const_value(n, source)
            if value is not None and value.type in ("string", "template_string", "binary_expression"):
                children = [value]
        if children:
            stack.extend((c, depth + (n.type == "identifier")) for c in reversed(children))
        else:
            parts.append(n)
    return parts


def _host_fixed(node: Any, source: bytes, depth: int = 0) -> bool:
    """True only when the URL `node` builds keeps a fixed scheme and host
    whatever the model supplies: a literal prefix that ends past the host, or
    a constant base followed by a literal `/`, `?` or `#`.

    Stricter than `_host_tainted`, which knows the tainted names: this judges
    an Opengrep finding without them, so `${API_BASE}${path}` stays (a `path`
    of `.evil.com/` moves the host).
    """
    if depth > 4:
        return False
    if node.type in ("parenthesized_expression", "await_expression", "as_expression", "non_null_expression"):
        inner = next((c for c in node.children if c.is_named), None)
        return inner is not None and _host_fixed(inner, source, depth + 1)
    if node.type == "ternary_expression":
        branches = (node.child_by_field_name("consequence"), node.child_by_field_name("alternative"))
        return all(b is not None and _host_fixed(b, source, depth + 1) for b in branches)
    if node.type == "identifier":
        value = _const_value(node, source)
        if value is not None and value.type not in ("string", "template_string", "binary_expression"):
            return _host_fixed(value, source, depth + 1)
    parts = _url_parts(node, source)
    if not parts:
        return False
    first = parts[0]
    if isinstance(first, str):
        return len(parts) == 1 or bool(_FIXED_HOST_PREFIX_RE.match(first))
    return (
        _constant(first, source)
        and len(parts) > 1 and isinstance(parts[1], str) and parts[1][:1] in ("/", "?", "#")
    )


def _fixed_host_lines(tree: Any, source: bytes) -> set[int]:
    """1-based lines where every SSRF call spanning the line keeps a fixed host."""
    verdicts: dict[int, bool] = {}
    for n in _walk_all(tree):
        if n.type != "call_expression" or _sink_category(n, source) != Category.SSRF:
            continue
        args = n.child_by_field_name("arguments")
        first = next((a for a in args.children if a.is_named), None) if args is not None else None
        fixed = first is not None and _host_fixed(first, source)
        for line in range(n.start_point[0] + 1, n.end_point[0] + 2):
            verdicts[line] = verdicts.get(line, True) and fixed
    return {line for line, fixed in verdicts.items() if fixed}


def _drop_fixed_host_ssrf(findings: list[Finding], parsers: dict[str, Any], root: Path) -> list[Finding]:
    """Opengrep's tool-argument SSRF rule reports any tainted value in a URL.
    Drop a finding when every SSRF call on its line keeps a fixed host: the
    model then only chooses a path or query (`${API_BASE}/cases/${id}`)."""
    kept: list[Finding] = []
    fixed_lines: dict[Path, set[int]] = {}
    for f in findings:
        path = Path(f.file_path) if Path(f.file_path).is_absolute() else root / f.file_path
        if f.engine != "opengrep" or f.rule_id != _TOOL_RULE_BY_CATEGORY[Category.SSRF] or path.suffix not in parsers:
            kept.append(f)
            continue
        if path not in fixed_lines:
            try:
                source = path.read_bytes()
                fixed_lines[path] = _fixed_host_lines(parsers[path.suffix].parse(source).root_node, source)
            except OSError:
                fixed_lines[path] = set()
        if f.start_line not in fixed_lines[path]:
            kept.append(f)
    return kept


def _guarded_names(body: Any, source: bytes) -> set[str]:
    """Names checked by a sanitizer-named statement (`assertSafeBasename(name);`),
    which throws on bad input rather than returning a cleaned value."""
    guarded: set[str] = set()
    for n in _walk_all(body):
        call = (
            next((c for c in n.children if c.is_named), None)
            if n.type == "expression_statement" else None
        )
        if call is not None and call.type == "await_expression":
            call = next((c for c in call.children if c.is_named), None)
        func = _call_function(call) if call is not None and call.type == "call_expression" else None
        if func is not None and _SANITIZER_NAME_RE.search(_node_text(func, source).rsplit(".", 1)[-1]):
            guarded.update(
                _node_text(a, source) for a in _walk_all(call.child_by_field_name("arguments"))
                if a.type == "identifier"
            )
    return guarded


def _derive_tainted(
    body: Any, seeds: Iterable[str], source: bytes, *, host: bool = False
) -> set[str]:
    """`seeds` plus locals assigned from them (`const dir = opts.saveDir || X`),
    minus names a sanitizer-named statement checked. With `host`, a local is
    tainted only when a seed can choose its URL host (see `_host_tainted`)."""
    guarded = _guarded_names(body, source)
    tainted = set(seeds) - guarded
    reads = _host_tainted if host else _tainted_names
    for _ in range(3):
        before = len(tainted)
        for n in _walk_all(body):
            if n.type == "variable_declarator":
                value = n.child_by_field_name("value")
                if value is not None and reads(value, source, tainted):
                    tainted.update(_collect_pattern_identifiers(n.child_by_field_name("name"), source))
        tainted -= guarded
        if len(tainted) == before:
            break
    return tainted


def _param_sink(
    body: Any, params: list[str], source: bytes, aliases: dict[str, Category] | None = None
) -> tuple[int, Category, str] | None:
    """The first call in `body` whose first argument carries a parameter into a
    sink. Parameters flow through locals; a sanitizer call or statement stops them.
    A command or path sink wins over an SSRF one: it needs no control of the
    URL host (a `fetch(url)` with a curl-through-shell fallback).
    """
    tainted = _derive_tainted(body, params, source)
    host_tainted: set[str] | None = None
    ssrf: tuple[int, Category, str] | None = None
    for n in _walk_all(body):
        if n.type != "call_expression":
            continue
        category = _sink_category(n, source, aliases)
        args = n.child_by_field_name("arguments")
        first = next((c for c in args.children if c.is_named), None) if args is not None else None
        if category is None or first is None:
            continue
        if category == Category.SSRF:
            if host_tainted is None:
                host_tainted = _derive_tainted(body, params, source, host=True)
            reaches = _host_tainted(first, source, host_tainted)
        else:
            reaches = _tainted_names(first, source, tainted)
        if not reaches:
            continue
        sink = (n.start_point[0] + 1, category, _node_text(_call_function(n), source))
        if category != Category.SSRF:
            return sink
        ssrf = ssrf or sink
    return ssrf


def _collect_pattern_identifiers(node: Any | None, source: bytes) -> list[str]:
    """Recursively collect bound identifier names from a JS/TS binding pattern.

    Handles plain identifiers, object/array destructuring (nested to any
    depth), default values (`assignment_pattern`), rest elements
    (`rest_pattern`), and TypeScript's `required_parameter`/
    `optional_parameter` wrappers -- which carry the actual pattern in a
    "pattern" field alongside a type annotation and/or default value that
    must NOT be treated as a binding.

    Node names verified empirically against tree_sitter_javascript and
    tree_sitter_typescript (see #164): `object_pattern` children are either
    `shorthand_property_identifier_pattern` (bare `{ a }`) or `pair_pattern`
    (`{ a: b }`, whose bound name lives in the "value" field, not "key");
    `assignment_pattern` binds via its "left" field, the "right" field is
    just the default-value expression and must not be walked.
    """
    names: list[str] = []

    def walk(n: Any | None) -> None:
        if n is None:
            return
        t = n.type
        if t in ("identifier", "shorthand_property_identifier_pattern"):
            names.append(_node_text(n, source))
        elif t in ("required_parameter", "optional_parameter"):
            walk(n.child_by_field_name("pattern"))
        elif t == "assignment_pattern":
            walk(n.child_by_field_name("left"))
        elif t == "pair_pattern":
            walk(n.child_by_field_name("value"))
        elif t in ("object_pattern", "array_pattern", "rest_pattern"):
            for c in n.children:
                walk(c)
        # else: punctuation, type_annotation, "this" params, default-value
        # expressions -- not a binding, nothing to collect.

    walk(node)
    return names


def _params_of(formal_params_node: Any | None, source: bytes) -> list[str]:
    if formal_params_node is None:
        return []
    names: list[str] = []
    for c in formal_params_node.children:
        names.extend(_collect_pattern_identifiers(c, source))
    return names


def _destructured_param_names(formal_params_node: Any | None, source: bytes) -> frozenset[str]:
    """Names bound by an object or array pattern among the parameters."""
    names: set[str] = set()
    if formal_params_node is None:
        return frozenset()
    for c in formal_params_node.named_children:
        pattern = (
            c.child_by_field_name("pattern")
            if c.type in ("required_parameter", "optional_parameter")
            else c
        )
        if pattern is not None and pattern.type == "assignment_pattern":
            pattern = pattern.child_by_field_name("left")
        if pattern is not None and pattern.type in ("object_pattern", "array_pattern"):
            names.update(_collect_pattern_identifiers(pattern, source))
    return frozenset(names)


def _param_slots(formal_params_node: Any | None, source: bytes) -> list[list[str]]:
    """Names bound by each positional parameter (a destructured one binds several)."""
    if formal_params_node is None:
        return []
    return [
        _collect_pattern_identifiers(c, source) for c in formal_params_node.children if c.is_named
    ]


def _tainted_arg_slots(
    body: Any, tainted: set[str], source: bytes, *, host: bool = False
) -> dict[tuple[int, str], frozenset[int]]:
    """Per (call line, callee name), the argument positions carrying taint.
    With `host`, only arguments whose URL host the taint can choose count."""
    slots: dict[tuple[int, str], set[int]] = {}
    for n in _walk_all(body):
        if n.type != "call_expression":
            continue
        func = _call_function(n)
        args = n.child_by_field_name("arguments")
        if func is None or args is None:
            continue
        name_node = func.child_by_field_name("property") if func.type == "member_expression" else func
        if name_node is None:
            continue
        key = (n.start_point[0] + 1, _node_text(name_node, source))
        for i, arg in enumerate(c for c in args.children if c.is_named):
            reaches = (
                _host_tainted(arg, source, tainted) if host else _tainted_names(arg, source, tainted)
            )
            if reaches or _reads_known_source(arg, source):
                slots.setdefault(key, set()).add(i)
    return {k: frozenset(v) for k, v in slots.items()}


def _receiver_bindings(nodes: Iterable[Any], source: bytes) -> dict[str, str]:
    """`name = new Class(...)` bindings among `nodes`, as {name: "Class"}, and
    `name = factory(...)` ones as {name: "factory()"}: the class is then the
    factory's declared return type (see `_factory_classes`)."""
    classes: dict[str, str] = {}
    for n in nodes:
        if n.type != "variable_declarator":
            continue
        name = n.child_by_field_name("name")
        value = n.child_by_field_name("value")
        if name is None or value is None or name.type != "identifier":
            continue
        if value.type == "new_expression":
            ctor = value.child_by_field_name("constructor")
            if ctor is not None and ctor.type == "identifier":
                classes[_node_text(name, source)] = _node_text(ctor, source)
        elif value.type == "call_expression":
            func = value.child_by_field_name("function")
            if func is not None and func.type == "identifier":
                classes[_node_text(name, source)] = f"{_node_text(func, source)}()"
    return classes


def _factory_classes(root_node: Any, source: bytes) -> dict[str, str]:
    """Module-level `function getX(): Class`, as {"getX": "Class"}."""
    classes: dict[str, str] = {}
    for stmt in root_node.children:
        if stmt.type == "export_statement":
            stmt = stmt.child_by_field_name("declaration") or stmt
        if stmt.type != "function_declaration":
            continue
        name = stmt.child_by_field_name("name")
        annotation = stmt.child_by_field_name("return_type")
        kind = annotation.named_children[0] if annotation is not None and annotation.named_children else None
        if name is not None and kind is not None and kind.type == "type_identifier":
            classes[_node_text(name, source)] = _node_text(kind, source)
    return classes


def _annotated_params(params_node: Any | None, source: bytes) -> dict[str, str]:
    """TypeScript `name: Class` parameters, as {name: Class}."""
    classes: dict[str, str] = {}
    for p in params_node.children if params_node is not None else ():
        if p.type not in ("required_parameter", "optional_parameter"):
            continue
        pattern = p.child_by_field_name("pattern")
        annotation = p.child_by_field_name("type")
        kind = annotation.named_children[0] if annotation is not None and annotation.named_children else None
        if pattern is not None and pattern.type == "identifier" and kind is not None and kind.type == "type_identifier":
            classes[_node_text(pattern, source)] = _node_text(kind, source)
    return classes


def _module_nodes(root_node: Any) -> Iterable[Any]:
    """Declarators at module scope, including exported ones."""
    for stmt in root_node.children:
        if stmt.type == "export_statement":
            stmt = stmt.child_by_field_name("declaration") or stmt
        if stmt.type in ("lexical_declaration", "variable_declaration"):
            yield from stmt.children


def _object_members(root_node: Any, source: bytes) -> dict[str, dict[str, str]]:
    """Module-level `const tool = { handler: runTool, run }`, as
    {"tool": {"handler": "runTool", "run": "run"}}: a call `tool.handler()`
    runs the named function."""
    objects: dict[str, dict[str, str]] = {}
    for n in _module_nodes(root_node):
        if n.type != "variable_declarator":
            continue
        name = n.child_by_field_name("name")
        value = n.child_by_field_name("value")
        while value is not None and value.type in ("as_expression", "satisfies_expression", "parenthesized_expression"):
            value = value.named_children[0] if value.named_children else None
        if name is None or name.type != "identifier" or value is None or value.type != "object":
            continue
        members: dict[str, str] = {}
        for prop in value.named_children:
            if prop.type == "shorthand_property_identifier":
                members[_node_text(prop, source)] = _node_text(prop, source)
            elif prop.type == "pair":
                key = prop.child_by_field_name("key")
                val = prop.child_by_field_name("value")
                if key is not None and val is not None and val.type == "identifier":
                    members[_node_text(key, source).strip("'\"")] = _node_text(val, source)
        if members:
            objects[_node_text(name, source)] = members
    return objects


def extract_functions(
    file_path: str,
    root_node: Any,
    source: bytes,
    tool_handler_spans: list[tuple[int, int]] | None = None,
    typed_calls: list[tuple[_FunctionSig, int, str]] | None = None,
    tool_definition_lines: list[int] | None = None,
) -> list[_FunctionSig]:
    """Extract function declarations, arrow functions, and class methods.

    `tool_handler_spans`, when given, collects the line spans of agent tool
    handlers. `typed_calls`, when given, collects `(sig, call_index, Class)`
    for method calls on a receiver whose class is known (`svc: Class`
    parameter, `svc = new Class()` or `svc = getClass()`), for
    JSCrossFilePass to resolve once the import graph is complete.
    """
    funcs: list[_FunctionSig] = []
    aliases = _exec_aliases(root_node, source)
    module_receivers = _receiver_bindings(_module_nodes(root_node), source)

    def add_function(
        node: Any, name: str, line: int, end_line: int, params_node: Any, body_node: Any | None
    ) -> None:
        if body_node is None:
            return
        params = _params_of(params_node, source)
        # Argument positions that carry taint let the engine match a call
        # against the callee parameters that reach its sink (`sink_params`).
        arg_slots = _tainted_arg_slots(body_node, _derive_tainted(body_node, params, source), source)
        host_slots = _tainted_arg_slots(
            body_node, _derive_tainted(body_node, params, source, host=True), source, host=True
        )
        # A sanitizer-named helper validates what it is given: a barrier in the
        # call graph, neither a sink nor a relay to its callees' sinks.
        is_sanitizer = bool(_SANITIZER_NAME_RE.search(name))
        calls = [] if is_sanitizer else [
            # (..., resolved_file, tainted_slots, persistent_slots,
            # resolved_qualname, host_slots): see _use_host_slots_for_ssrf.
            (*c, None, arg_slots.get((c[3], c[0]), frozenset()), frozenset(), None,
             host_slots.get((c[3], c[0]), frozenset()))
            for c in _collect_calls(body_node, source)
        ]
        calls_propagator = any(
            cn in KNOWN_JS_PROPAGATORS or (mq is not None and f"{mq}.{cn}" in KNOWN_JS_PROPAGATORS)
            for cn, mq, *_rest in calls
        )
        is_tool_handler = _is_agent_tool_handler(node, source)
        if is_tool_handler and tool_handler_spans is not None:
            tool_handler_spans.append((line, end_line))
        if tool_definition_lines is not None and _is_tool_definition_handler(node, source):
            tool_definition_lines.append(line)
        remote_source = (
            _reads_known_source(body_node, source, _REMOTE_JS_SOURCE_PREFIXES) or is_tool_handler
        )
        operator_source = (
            _reads_known_source(body_node, source, _OPERATOR_JS_SOURCE_PREFIXES)
            or _is_cli_action_handler(node, source)
        )
        sig = _FunctionSig(
            name=name,
            file=file_path,
            line=line,
            end_line=end_line,
            params=params,
            calls=calls,
            calls_propagator=calls_propagator,
            has_source=remote_source or operator_source,
            operator_source_only=operator_source and not remote_source,
            destructured_params=_destructured_param_names(params_node, source),
            has_return_taint=_returns_known_source(body_node, source),
        )
        sink = _param_sink(body_node, [] if is_sanitizer else params, source, aliases)
        if sink is not None:
            sig.sink_params = frozenset(
                i for i, names in enumerate(_param_slots(params_node, source))
                if not is_sanitizer and _param_sink(body_node, names, source, aliases) is not None
            )
            sig.has_sink = True
            sig.sink_line, sig.sink_category, sig.sink_symbol = sink
            sig.sink_cwe = [_SINK_CWE[sig.sink_category]]
            sig.sink_rule_id = "JS-PARAM-SINK"
            sig.sink_detail = f"A parameter reaches {sig.sink_symbol}()."
        if typed_calls is not None:
            receivers = {
                **module_receivers,
                **_receiver_bindings(_walk_all(body_node), source),
                **_annotated_params(params_node, source),
            }
            for i, (_callee, qualifier, *_rest) in enumerate(calls):
                if qualifier in receivers:
                    typed_calls.append((sig, i, receivers[qualifier]))
        funcs.append(sig)

    for node in _walk_all(root_node):
        end_line = node.end_point[0] + 1
        if node.type == "function_declaration":
            name_node = node.child_by_field_name("name")
            if name_node is not None:
                add_function(
                    node, _node_text(name_node, source), node.start_point[0] + 1, end_line,
                    node.child_by_field_name("parameters"), node.child_by_field_name("body"),
                )
        elif node.type in ("function_expression", "arrow_function"):
            # Prefer a real name from an enclosing `const name = ...`. Most
            # arrow functions in route-handler / middleware style code are
            # passed directly as call arguments though (e.g.
            # `app.get('/x', (req, res) => {...})`) and have no binding at
            # all -- synthesize a unique, file-scoped name so the function
            # is still tracked as a node in the call graph (it can both read
            # a source and call into a sink-bearing function, which is
            # exactly the shape cross-file propagation needs to see).
            parent = node.parent
            name = None
            if parent is not None and parent.type == "variable_declarator":
                name_node = parent.child_by_field_name("name")
                if name_node is not None and name_node.type == "identifier":
                    name = _node_text(name_node, source)
            if name is None:
                name = f"<anonymous@{node.start_point[0] + 1}>"
            add_function(
                node, name, node.start_point[0] + 1, end_line,
                node.child_by_field_name("parameters"), node.child_by_field_name("body"),
            )
        elif node.type == "method_definition":
            name_node = node.child_by_field_name("name")
            if name_node is not None:
                add_function(
                    node, _node_text(name_node, source), node.start_point[0] + 1, end_line,
                    node.child_by_field_name("parameters"), node.child_by_field_name("body"),
                )
    return funcs


def default_export_name(root_node: Any, source: bytes) -> str | None:
    """Name of the file's `export default function name(...)` / `export
    default name;`, so a default import can be keyed by the real function
    name instead of the literal "default" (XF-04)."""
    for node in root_node.children:
        if node.type != "export_statement" or not any(c.type == "default" for c in node.children):
            continue
        for c in node.children:
            if c.type in ("function_declaration", "class_declaration"):
                name_node = c.child_by_field_name("name")
                if name_node is not None:
                    return _node_text(name_node, source)
            if c.type == "identifier":
                return _node_text(c, source)
    return None


def _use_host_slots_for_ssrf(funcs: list[_FunctionSig], imports: _ImportGraph) -> None:
    """Into a callee that only leads to SSRF sinks, only arguments that can
    choose the URL host carry the taint (`api(buildPath(id))` passes a
    fixed-host path). That holds for the function calling `fetch` and for a
    relay (`getJson(url)` -> `fetchWithRetry(url)`) with no sink of its own
    whose every tainted call into the project goes to such a function."""
    by_key = {(f.file, f.name): f for f in funcs}

    def callee_of(caller: _FunctionSig, call: tuple) -> _FunctionSig | None:
        name, qualifier = call[0], call[1]
        if call[4]:  # resolved by JSCrossFilePass (class method, object member)
            return by_key.get((call[4], call[7] or name))
        if qualifier in (None, "this") and (caller.file, name) in by_key:
            return by_key[(caller.file, name)]
        resolved = _resolve_callee(caller.file, name, qualifier, imports)
        return by_key.get(resolved) if resolved is not None else None

    callees = {id(f): [callee_of(f, c) if len(c) >= 9 else None for c in f.calls] for f in funcs}
    ssrf_only = {id(f) for f in funcs if f.sink_category == Category.SSRF}
    changed = True
    while changed:
        changed = False
        for f in funcs:
            if id(f) in ssrf_only or f.has_sink:
                continue
            tainted = [c for call, c in zip(f.calls, callees[id(f)], strict=True) if c is not None and call[5]]
            if tainted and all(id(c) in ssrf_only for c in tainted):
                ssrf_only.add(id(f))
                changed = True

    for caller in funcs:
        caller.calls = [
            (*call[:5], call[8], *call[6:]) if callee is not None and id(callee) in ssrf_only else call
            for call, callee in zip(caller.calls, callees[id(caller)], strict=True)
        ]


_TOOL_RULE_BY_CATEGORY = {
    Category.COMMAND_INJECTION: "TNT-TS-AGENT-CMDI-001",
    Category.PATH_TRAVERSAL: "TNT-TS-AGENT-PATH-001",
    Category.SSRF: "TNT-TS-AGENT-SSRF-001",
}
_SAME_FILE_MAX_HOPS = 4


def _same_file_tool_flows(
    funcs: list[_FunctionSig],
    tool_spans: list[tuple[str, int, int]],
    indirect_handlers: set[tuple[str, int]] = frozenset(),
) -> list[Finding]:
    """Tool argument -> same-file helper chain -> structural sink.

    Opengrep's intra-file mode does not follow `this.method()`, and the
    cross-file engine only reports edges between files, so a class-based MCP
    server (`setRequestHandler` -> `this.handleX(args)` -> `this.writeX(path)`)
    fell through both. Each hop needs a tainted argument; the last one must
    bind to a parameter that reaches the sink (`sink_params`).
    """
    by_key = {(f.file, f.name): f for f in funcs}
    starts = {(file, start) for file, start, _end in tool_spans}
    findings: list[Finding] = []
    for handler in funcs:
        if (handler.file, handler.line) not in starts:
            continue
        # A handler registered by reference or in a tool-definition object is
        # invisible to the inline-only Opengrep rules, so its own sink is ours.
        own_rule = _TOOL_RULE_BY_CATEGORY.get(handler.sink_category)
        if (handler.file, handler.line) in indirect_handlers and handler.sink_params and own_rule:
            findings.append(Finding(
                rule_id=own_rule,
                message=(
                    f"An agent tool argument reaches {handler.sink_symbol}() in the "
                    f"tool handler {handler.name}() itself."
                ),
                severity=Severity.HIGH,
                category=handler.sink_category,
                file_path=handler.file,
                start_line=handler.sink_line,
                cwe_ids=list(handler.sink_cwe),
                engine="crossfile",
                taint_flow=TaintFlow(
                    source=TaintNode(file_path=handler.file, line=handler.line),
                    sink=TaintNode(file_path=handler.file, line=handler.sink_line),
                ),
                metadata={"source_kind": "tool_param", "callee_name": handler.name},
            ))
        frontier: list[tuple[_FunctionSig, list[TaintNode]]] = [(handler, [])]
        seen = {(handler.file, handler.name)}
        for _hop in range(_SAME_FILE_MAX_HOPS):
            next_frontier: list[tuple[_FunctionSig, list[TaintNode]]] = []
            for caller, path in frontier:
                for call in caller.calls:
                    name, qualifier, _has_args, line, _resolved, slots = call[:6]
                    slots = frozenset(slots)
                    callee = by_key.get((caller.file, name))
                    if qualifier not in (None, "this") or not slots or callee is None:
                        continue
                    hops = [*path, TaintNode(file_path=caller.file, line=line)]
                    rule_id = _TOOL_RULE_BY_CATEGORY.get(callee.sink_category)
                    if callee.has_sink and callee.sink_params and slots & callee.sink_params and rule_id:
                        findings.append(Finding(
                            rule_id=rule_id,
                            message=(
                                f"An agent tool argument reaches {callee.sink_symbol}() in "
                                f"{callee.name}() through {len(hops)} same-file call(s)."
                            ),
                            severity=Severity.HIGH,
                            category=callee.sink_category,
                            file_path=callee.file,
                            start_line=callee.sink_line,
                            cwe_ids=list(callee.sink_cwe),
                            engine="crossfile",
                            taint_flow=TaintFlow(
                                source=TaintNode(file_path=handler.file, line=handler.line),
                                sink=TaintNode(file_path=callee.file, line=callee.sink_line),
                                intermediate=hops,
                            ),
                            metadata={"source_kind": "tool_param", "callee_name": callee.name},
                        ))
                    # A function can both hold a sink and pass the value on.
                    if (callee.file, callee.name) not in seen:
                        seen.add((callee.file, callee.name))
                        next_frontier.append((callee, hops))
            frontier = next_frontier
    return findings


class JSCrossFilePass:
    name = "js_crossfile"

    def run(self, context: ScanContext) -> ScanResult:
        start = time.perf_counter()
        result = ScanResult()

        target = context.target_path
        if not target.exists():
            return result

        ignore_patterns = load_ignore_patterns(target, context.config)
        candidates = None
        if context.source_inventory is not None:
            languages = {"javascript", "typescript"}
            candidates = tuple(
                source.path
                for source in context.source_inventory.files
                if source.languages & languages
                and source.path.suffix in (_JS_EXTENSIONS + _TS_EXTENSIONS)
            )
        js_files = _collect_js_files(
            target,
            ignore_patterns=ignore_patterns,
            candidates=candidates,
        )
        if not js_files:
            return result
        if not TREE_SITTER_AVAILABLE:
            result.degraded_passes[self.name] = (
                "tree-sitter not installed (pip install 'rowan[js-crossfile]'); "
                "JS/TS cross-file taint was not run"
            )
            return result

        parsers = _get_parsers()
        all_imports = _ImportGraph()
        all_funcs: list[_FunctionSig] = []
        tool_spans: list[tuple[str, int, int]] = []
        default_exports: dict[str, str] = {}
        typed_calls: list[tuple[_FunctionSig, int, str]] = []
        local_classes: set[tuple[str, str]] = set()
        object_members: dict[tuple[str, str], dict[str, str]] = {}
        factory_classes: dict[tuple[str, str], str] = {}
        reexports: dict[tuple[str, str], tuple[str, str]] = {}
        star_exports: dict[str, list[str]] = {}
        handler_refs: list[tuple[str, set[str], set[str]]] = []
        method_files: dict[str, set[str]] = {}
        # Handlers Opengrep's inline-only TS rules cannot see: (file, line).
        indirect_handlers: set[tuple[str, int]] = set()
        returned_functions: dict[tuple[str, str], list[int]] = {}

        # tsconfig `paths` aliases apply to files under the nearest tsconfig
        # inside the scan root. None marks a directory with no tsconfig.
        root = target.resolve()
        tsconfig_paths: dict[Path, PathAliases | None] = {}

        def aliases_for(file: Path) -> PathAliases:
            for d in file.parents:
                if not is_within_root(d, root):
                    return []
                if d not in tsconfig_paths:
                    tsconfig = d / "tsconfig.json"
                    tsconfig_paths[d] = _load_tsconfig_paths(tsconfig) if tsconfig.is_file() else None
                if tsconfig_paths[d] is not None:
                    return tsconfig_paths[d]
            return []

        for js_file in js_files:
            parser = parsers.get(js_file.suffix)
            if parser is None:
                continue
            try:
                source = js_file.read_bytes()
                tree = parser.parse(source)
            except (OSError, ValueError) as exc:
                logger.debug("Skipping %s: %s", js_file, exc)
                continue

            file_str = str(js_file.resolve())
            file_aliases = aliases_for(js_file.resolve())
            file_imports = extract_imports(file_str, tree.root_node, source, file_aliases)
            named, stars = extract_reexports(file_str, tree.root_node, source, file_aliases)
            reexports.update(named)
            star_exports[file_str] = stars
            all_imports.name_to_def.update(file_imports.name_to_def)
            all_imports.module_to_file.update(file_imports.module_to_file)

            spans: list[tuple[int, int]] = []
            file_typed_calls: list[tuple[_FunctionSig, int, str]] = []
            definition_lines: list[int] = []
            try:
                file_funcs = extract_functions(
                    file_str, tree.root_node, source, spans, file_typed_calls, definition_lines
                )
            except RecursionError:
                # Walkers are iterative; this guards the remaining expression
                # helpers so one pathological file cannot abort the pass (XF-13).
                logger.warning("JSCrossFilePass: %s nests too deeply; skipping its functions", js_file)
                file_funcs, spans, file_typed_calls = [], [], []
            all_funcs.extend(file_funcs)
            typed_calls.extend(file_typed_calls)
            factory_classes.update(
                ((file_str, name), cls) for name, cls in _factory_classes(tree.root_node, source).items()
            )
            object_members.update(
                ((file_str, obj), members)
                for obj, members in _object_members(tree.root_node, source).items()
            )
            local_classes.update(
                (file_str, _node_text(n.child_by_field_name("name"), source))
                for n in _walk_all(tree.root_node)
                if n.type == "class_declaration" and n.child_by_field_name("name") is not None
            )
            tool_spans.extend((file_str, start, end) for start, end in spans)
            indirect_handlers.update((file_str, line) for line in definition_lines)
            handler_refs.append((file_str, *_tool_handler_refs(tree.root_node, source)))
            for method in _class_method_names(tree.root_node, source):
                method_files.setdefault(method, set()).add(file_str)
            returned_functions.update(
                ((file_str, name), lines)
                for name, lines in _returned_function_lines(tree.root_node, source).items()
            )
            default_name = default_export_name(tree.root_node, source)
            if default_name:
                default_exports[file_str] = default_name

        # `import runner from './shell.js'` is recorded as (shell.js,
        # "default"); rewrite it to the exported function's own name so the
        # call-graph key matches the definition.
        for local, (target, imported) in list(all_imports.name_to_def.items()):
            if imported == "default" and target in default_exports:
                all_imports.name_to_def[local] = (target, default_exports[target])

        # An import from a barrel file names the barrel; follow its re-exports
        # to the file that defines the name.
        defined = {(f.file, f.name) for f in all_funcs} | local_classes | set(object_members)

        found_defs: dict[tuple[str, str], tuple[str, str] | None] = {}

        def definition(file: str, name: str, depth: int = 0) -> tuple[str, str] | None:
            key = (file, name)
            if key in defined:
                return key
            if key in found_defs or depth >= 5:
                return found_defs.get(key)
            found_defs[key] = None  # also breaks re-export cycles
            if key in reexports:
                found_defs[key] = definition(*reexports[key], depth + 1)
            else:
                for star in star_exports.get(file, ()):
                    found_defs[key] = definition(star, name, depth + 1)
                    if found_defs[key]:
                        break
            return found_defs[key]

        for local, (target_file, imported) in list(all_imports.name_to_def.items()):
            if (target_file, imported) not in defined:
                found = definition(target_file, imported)
                if found:
                    all_imports.name_to_def[local] = found

        # Tool handlers registered by reference: their arguments are model-chosen.
        sig_by_name = {(f.file, f.name): f for f in all_funcs}
        sig_by_line = {(f.file, f.line): f for f in all_funcs}

        def mark_tool_handler(sig: _FunctionSig | None) -> None:
            if sig is None:
                return
            indirect_handlers.add((sig.file, sig.line))
            if not (sig.has_source and not sig.operator_source_only):
                sig.has_source, sig.operator_source_only = True, False
                tool_spans.append((sig.file, sig.line, sig.end_line))

        for file_str, names, factories in handler_refs:
            for name in names:
                key = (file_str, name) if (file_str, name) in sig_by_name else all_imports.name_to_def.get((file_str, name))
                mark_tool_handler(sig_by_name.get(key) if key else None)
            for name in factories:
                key = (file_str, name) if (file_str, name) in returned_functions else all_imports.name_to_def.get((file_str, name))
                for line in returned_functions.get(key, ()) if key else ():
                    mark_tool_handler(sig_by_line.get((key[0], line)))

        # `svc.usage()` on a receiver of known class: the method lives in the
        # file that defines (or imports) the class.
        def class_file(file: str, cls: str) -> str | None:
            imported = all_imports.name_to_def.get((file, cls))
            return imported[0] if imported else (file if (file, cls) in local_classes else None)

        for sig, i, cls in typed_calls:
            if cls.endswith("()"):
                factory = all_imports.name_to_def.get((sig.file, cls[:-2])) or (sig.file, cls[:-2])
                returned = factory_classes.get(factory)
                cls_file = class_file(factory[0], returned) if returned else None
            else:
                cls_file = class_file(sig.file, cls)
            if cls_file:
                call = sig.calls[i]
                sig.calls[i] = (*call[:4], cls_file, *call[5:])

        # `tool.handler()` where `tool` is an object literal naming a function.
        for sig in all_funcs:
            for i, call in enumerate(sig.calls):
                callee, qualifier = call[0], call[1]
                if qualifier is None or call[4] is not None:
                    continue
                owner = all_imports.name_to_def.get((sig.file, qualifier)) or (sig.file, qualifier)
                target_name = object_members.get(owner, {}).get(callee)
                if target_name:
                    sig.calls[i] = (*call[:4], owner[0], *call[5:7], target_name, *call[8:])

        # `context.saveFile(p)` on a parameter or local of unknown type: one
        # call edge per class that defines the method, when that is few.
        for sig in all_funcs:
            fanned: list[tuple] = []
            for i, call in enumerate(sig.calls):
                callee, qualifier = call[0], call[1]
                if (
                    call[4] is not None
                    or qualifier is None
                    or qualifier == _UNRESOLVED_QUALIFIER
                    or "." in qualifier
                    or qualifier in _BUILTIN_QUALIFIERS
                    or qualifier in sig.destructured_params
                    or callee in _GENERIC_METHOD_NAMES
                    or (sig.file, qualifier) in all_imports.module_to_file
                ):
                    continue
                files = sorted(method_files.get(callee, ()))
                if not 1 <= len(files) <= _FANOUT_MAX_CLASSES:
                    continue
                sig.calls[i] = (*call[:4], files[0], *call[5:])
                fanned.extend((*call[:4], f, *call[5:]) for f in files[1:])
            sig.calls.extend(fanned)

        logger.info(
            "JSCrossFilePass: %d files, %d functions, %d imports",
            len(js_files), len(all_funcs), len(all_imports.name_to_def),
        )

        # Only evidence marks a sink: a traced taint finding, or the structural
        # parameter-to-sink check in extract_functions. A pattern-only match
        # knows nothing about which value reaches the call, and with agent
        # tool handlers as sources it turned every matched helper into a HIGH
        # cross-file "taint-flow" finding.
        context.result.findings = _drop_fixed_host_ssrf(context.result.findings, parsers, root)
        all_findings = [
            f for f in context.result.findings
            if f.engine in ("opengrep", "neuroscan")
            and Path(f.file_path).suffix in (_JS_EXTENSIONS + _TS_EXTENSIONS)
            and f.taint_flow is not None
        ]
        all_funcs = _match_findings_to_functions(all_findings, all_funcs)
        _use_host_slots_for_ssrf(all_funcs, all_imports)

        # Cross-file edges need two files; same-file tool flows do not.
        new_findings = (
            _propagate_cross_file(all_funcs, all_imports, all_findings, target)
            if len(js_files) >= 2 else []
        )
        new_findings += _same_file_tool_flows(all_funcs, tool_spans, indirect_handlers)
        for f in new_findings:
            # Anchored inside an agent tool handler: the model chose the value.
            if any(f.file_path == file and start <= f.start_line <= end for file, start, end in tool_spans):
                f.metadata["source_kind"] = "tool_param"
            result.add_finding(f)

        duration = time.perf_counter() - start
        scan_span(self.name, duration)
        logger.info(
            "JSCrossFilePass: %d cross-file findings in %.1fs",
            len(new_findings), duration,
        )
        return result
