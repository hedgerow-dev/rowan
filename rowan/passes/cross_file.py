"""Cross-file taint propagation pass.

Runs AFTER TaintPass. Parses all Python files with the `ast` module to build
an import graph and call graph, then propagates taint across file boundaries.

When file A calls function F from file B, and F's parameter reaches a sink
in file B, and file A passes user-controlled data to F, this pass emits a
new cross-file Finding pinning the call site in file A.
"""

from __future__ import annotations

import ast
import logging
import re
import time
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path

from rowan.analysis.ast_sanitizers import fstring_assignment_lines, logging_fstring_lines
from rowan.analysis.dominance import (
    collect_dominating_candidates as _collect_dominating_candidates,
)
from rowan.analysis.orm_reads import (
    is_pascal_case as _is_pascal_case,
)
from rowan.analysis.orm_reads import (
    orm_classes_by_var as _orm_classes_by_var,
)
from rowan.analysis.request_sources import (
    call_returns_llm_output as _call_returns_llm_output,
)
from rowan.analysis.request_sources import (
    dotted_name as _dotted_name,
)
from rowan.analysis.request_sources import (
    expr_reads_llm_output as _expr_reads_llm_output,
)
from rowan.analysis.request_sources import (
    expr_reads_source as _expr_reads_request_source,
)
from rowan.analysis.request_sources import (
    function_reads_llm_output as _function_reads_llm_output,
)
from rowan.analysis.request_sources import (
    function_reads_source as _function_reads_request_source,
)
from rowan.analysis.stmt_walk import iter_body_statements as _iter_body_statements
from rowan.analysis.test_paths import is_test_path as _is_test_path
from rowan.core.confidence import BOUNDARY_SOURCE, CROSSFILE_TAINT
from rowan.core.finding_clusters import concrete_sink_symbol
from rowan.core.findings import (
    Category,
    Finding,
    ScanResult,
    Severity,
    TaintFlow,
    TaintNode,
)
from rowan.core.paths import iter_within_root
from rowan.core.sanitizers import call_sanitizers, shape_sanitizers
from rowan.passes.base import ScanContext, scan_span
from rowan.passes.sources import filter_python_paths, iter_python_sources

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Known propagator functions: functions that carry taint from input to output
# These model multi-step chains: user_input → propagator → sink
# Each entry: (function_name, arg_index_that_carries_taint, propagates_to_return)
# ---------------------------------------------------------------------------
KNOWN_PROPAGATORS: dict[str, int] = {
    "hf_hub_download": 0,  # repo_id → file path carries taint
    "snapshot_download": 0,  # repo_id → directory path carries taint
    "base64.b64decode": 0,  # encoded → decoded bytes carry taint
    "base64.standard_b64decode": 0,
    "base64.urlsafe_b64decode": 0,
    "base64.b64encode": 0,
    "base64.standard_b64encode": 0,
    "base64.urlsafe_b64encode": 0,
    "binascii.a2b_base64": 0,
    "json.loads": 0,  # string → parsed dict carries taint
    "pickle.loads": 0,  # bytes → unpickled object (itself a sink, but also propagates)
    "torch.load": 0,  # path → model carries taint
    "joblib.load": 0,  # path → object carries taint
    "requests.get": 0,  # URL → response carries taint
    "requests.post": 0,  # URL → response carries taint
    "httpx.get": 0,  # URL → response carries taint
    "httpx.post": 0,  # URL → response carries taint
    "httpx.put": 0,  # URL → response carries taint
}

# KNOWN_SOURCE_PREFIXES / _dotted_name / _function_reads_source /
# _expr_reads_source now live in rowan.analysis.request_sources and are
# imported above under their historical private names.


def _expr_reads_source(expr: ast.expr) -> bool:
    """True if `expr` reads anything untrusted -- an HTTP request source or
    model output.

    This pass treats LLM output as a taint source; `AuthzPass` deliberately
    does not, so the union lives here rather than in `expr_reads_source`
    itself. See `analysis.request_sources` for why model output qualifies and
    why the cross-file layer is where it matters.
    """
    return _expr_reads_request_source(expr) or _expr_reads_llm_output(expr)


def _first_source_read_line(func_node: ast.AST) -> int:
    """Line of the first statement in `func_node` whose own expressions read
    a source, or 0 when none does directly (e.g. a channel or boundary)."""
    for stmt in _iter_body_statements(getattr(func_node, "body", [])):
        for child in ast.iter_child_nodes(stmt):
            if isinstance(child, ast.expr) and _expr_reads_source(child):
                return stmt.lineno
    return 0


def _function_reads_source(node: ast.AST) -> bool:
    """True if the function body reads an HTTP request source or model output."""
    return _function_reads_request_source(node) or _function_reads_llm_output(node)


# ---------------------------------------------------------------------------
# File-backed second-order channels.
#
# TNT-PATH-003 used an Opengrep propagator to describe a required
# write-then-read chain. Propagators are optional paths, so the rule also
# matched direct `input() -> eval/exec` flows with no file operation. These
# helpers make the persistence channel explicit: an externally supplied path
# and payload must be written, and a later dangerous loader must read the same
# canonical path expression.
# ---------------------------------------------------------------------------

_FILE_READ_METHODS = frozenset({"read_bytes", "read_text"})
_DANGEROUS_FILE_CONSUMERS = frozenset(
    {
        "pickle.load",
        "pickle.loads",
        "torch.load",
        "joblib.load",
        "exec",
        "eval",
        "os.system",
        "subprocess.call",
        "subprocess.Popen",
        "subprocess.run",
    }
)


def _loaded_names(expr: ast.AST) -> set[str]:
    return {
        node.id
        for node in ast.walk(expr)
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load)
    }


def _file_channel_functions(tree: ast.AST) -> list[ast.FunctionDef | ast.AsyncFunctionDef]:
    return [
        node
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    ]


def _function_nodes(func: ast.FunctionDef | ast.AsyncFunctionDef) -> list[ast.AST]:
    nodes: list[ast.AST] = []

    class Visitor(ast.NodeVisitor):
        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
            return

        def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
            return

        def visit_Lambda(self, node: ast.Lambda) -> None:
            return

        def generic_visit(self, node: ast.AST) -> None:
            nodes.append(node)
            super().generic_visit(node)

    visitor = Visitor()
    for statement in func.body:
        visitor.visit(statement)
    return nodes


def _source_key(expr: ast.expr) -> str | None:
    if not _expr_reads_source(expr):
        return None
    if isinstance(expr, ast.Call):
        name = _dotted_name(expr.func) or "input"
        if name.rsplit(".", 1)[-1] in {"input", "getenv"}:
            return None
        literal = next(
            (arg.value for arg in expr.args if isinstance(arg, ast.Constant)), None
        )
        return f"$INPUT:{name}:{literal!r}"
    if isinstance(expr, ast.Subscript):
        name = _dotted_name(expr.value) or "input"
        if name.startswith(("sys.argv", "os.environ")):
            return None
        key = expr.slice.value if isinstance(expr.slice, ast.Constant) else "*"
        return f"$INPUT:{name}:{key!r}"
    name = _dotted_name(expr) or "value"
    if name.startswith(("sys.argv", "os.environ")):
        return None
    return f"$INPUT:{name}"


def _expr_reads_remote_file_source(expr: ast.expr) -> bool:
    return any(
        isinstance(node, ast.expr) and _source_key(node) is not None
        for node in ast.walk(expr)
    )


def _canonical_file_path(
    expr: ast.expr, values: dict[str, ast.expr], seen: set[str] | None = None
) -> str | None:
    seen = set() if seen is None else seen
    if isinstance(expr, ast.Name) and expr.id in values and expr.id not in seen:
        return _canonical_file_path(values[expr.id], values, seen | {expr.id})
    if isinstance(expr, ast.Constant) and isinstance(expr.value, (str, bytes)):
        return repr(expr.value)
    if isinstance(expr, ast.BinOp) and isinstance(expr.op, (ast.Div, ast.Add)):
        left = _canonical_file_path(expr.left, values, seen)
        right = _canonical_file_path(expr.right, values, seen)
        if left and right:
            return f"({left}/{right})"
    if isinstance(expr, ast.Call):
        name = _dotted_name(expr.func) or ""
        if name in {"Path", "pathlib.Path"} and expr.args:
            inner = _canonical_file_path(expr.args[0], values, seen)
            return f"Path({inner})" if inner else None
        if name in {"os.path.join", "posixpath.join", "ntpath.join"}:
            parts = [_canonical_file_path(arg, values, seen) for arg in expr.args]
            return f"join({','.join(parts)})" if parts and all(parts) else None
        source = _source_key(expr)
        if source:
            return source
    if isinstance(expr, (ast.Subscript, ast.Attribute)):
        source = _source_key(expr)
        if source:
            return source
    return None


def _function_value_map(
    func: ast.FunctionDef | ast.AsyncFunctionDef,
    before_line: int | None = None,
) -> dict[str, ast.expr]:
    values: dict[str, ast.expr] = {}
    for node in _function_nodes(func):
        if (
            isinstance(node, (ast.Assign, ast.AnnAssign))
            and node.value is not None
            and (before_line is None or node.lineno < before_line)
        ):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                if isinstance(target, ast.Name):
                    values[target.id] = node.value
    return values


def _function_tainted_names(
    func: ast.FunctionDef | ast.AsyncFunctionDef,
    before_line: int | None = None,
) -> set[str]:
    tainted: set[str] = set()
    assignments = [
        node
        for node in _function_nodes(func)
        if isinstance(node, (ast.Assign, ast.AnnAssign))
        and node.value is not None
        and (before_line is None or node.lineno < before_line)
    ]
    while True:
        changed = False
        for node in assignments:
            value = node.value
            if not (
                _expr_reads_remote_file_source(value) or (_loaded_names(value) & tainted)
            ):
                continue
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                if isinstance(target, ast.Name) and target.id not in tainted:
                    tainted.add(target.id)
                    changed = True
        if not changed:
            return tainted


def _expr_is_tainted(expr: ast.expr, tainted: set[str]) -> bool:
    return _expr_reads_remote_file_source(expr) or bool(_loaded_names(expr) & tainted)


def _written_file_channel(
    call: ast.Call, values: dict[str, ast.expr], tainted: set[str]
) -> str | None:
    if (
        isinstance(call.func, ast.Attribute)
        and call.func.attr in {"write_bytes", "write_text"}
        and call.args
        and _expr_is_tainted(call.args[0], tainted)
    ):
        path = _canonical_file_path(call.func.value, values)
        return path if path and "$INPUT:" in path else None
    if (
        isinstance(call.func, ast.Attribute)
        and call.func.attr == "write"
        and call.args
        and _expr_is_tainted(call.args[0], tainted)
        and isinstance(call.func.value, ast.Call)
        and (_dotted_name(call.func.value.func) or "") == "open"
        and call.func.value.args
    ):
        path = _canonical_file_path(call.func.value.args[0], values)
        return path if path and "$INPUT:" in path else None
    return None


def _read_file_channel(
    expr: ast.expr,
    values: dict[str, ast.expr],
    read_values: dict[str, str],
) -> str | None:
    if isinstance(expr, ast.Name):
        if expr.id in read_values:
            return read_values[expr.id]
        if expr.id in values:
            return _read_file_channel(values[expr.id], values, read_values)
    if isinstance(expr, ast.Call):
        if (
            isinstance(expr.func, ast.Attribute)
            and expr.func.attr in _FILE_READ_METHODS
        ):
            return _canonical_file_path(expr.func.value, values)
        if (_dotted_name(expr.func) or "") == "open" and expr.args:
            return _canonical_file_path(expr.args[0], values)
    return None


def _collect_file_write_channels(
    parsed: list[tuple[str, ast.AST]],
) -> dict[str, tuple[str, int]]:
    channels: dict[str, tuple[str, int]] = {}
    for file_path, tree in parsed:
        for func in _file_channel_functions(tree):
            for call in (node for node in _function_nodes(func) if isinstance(node, ast.Call)):
                values = _function_value_map(func, call.lineno)
                tainted = _function_tainted_names(func, call.lineno)
                channel = _written_file_channel(call, values, tainted)
                if channel:
                    channels.setdefault(channel, (file_path, call.lineno))
    return channels


def _file_channel_findings(
    parsed: list[tuple[str, ast.AST]],
    channels: dict[str, tuple[str, int]],
) -> list[Finding]:
    findings: list[Finding] = []
    if not channels:
        return findings
    for file_path, tree in parsed:
        for func in _file_channel_functions(tree):
            assignments = sorted(
                (
                    node
                    for node in _function_nodes(func)
                    if isinstance(node, (ast.Assign, ast.AnnAssign)) and node.value is not None
                ),
                key=lambda node: node.lineno,
            )
            for call in (node for node in _function_nodes(func) if isinstance(node, ast.Call)):
                name = _dotted_name(call.func) or ""
                if name not in _DANGEROUS_FILE_CONSUMERS or not call.args:
                    continue
                values = _function_value_map(func, call.lineno)
                read_values: dict[str, str] = {}
                for node in assignments:
                    if node.lineno >= call.lineno:
                        continue
                    assignment_values = _function_value_map(func, node.lineno)
                    channel = _read_file_channel(
                        node.value, assignment_values, read_values
                    )
                    if channel is None:
                        continue
                    targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                    for target in targets:
                        if isinstance(target, ast.Name):
                            read_values[target.id] = channel
                channel = _read_file_channel(call.args[0], values, read_values)
                if channel not in channels:
                    continue
                writer_file, writer_line = channels[channel]
                findings.append(
                    Finding(
                        rule_id="TNT-PATH-003",
                        message=(
                            "Externally controlled bytes are written to an externally "
                            "selected file path and later loaded or executed from the "
                            "same file channel."
                        ),
                        severity=Severity.HIGH,
                        category=Category.PATH_TRAVERSAL,
                        file_path=file_path,
                        start_line=call.lineno,
                        confidence=CROSSFILE_TAINT,
                        cwe_ids=[22, 502],
                        engine="crossfile",
                        metadata={
                            "persistent_channel": "file",
                            "channel": channel,
                            "writer_file": writer_file,
                            "writer_line": writer_line,
                            "caller": func.name,
                        },
                    )
                )
    return findings


# ---------------------------------------------------------------------------
# Second-order taint through ORM persistence.
#
# A request handler often doesn't pass untrusted data directly to a sink --
# it writes it onto a model attribute (`Dataset(source_url=data.get(...))`),
# and a *different* function (a worker, a scheduled job, another endpoint)
# reads that same attribute back out of the database later. There's no call
# edge between the writer and the reader at all, so the ordinary call-graph
# propagation above can't see it. This treats "(Model, field) written from a
# known source" as a taint channel: any function that reads that same
# (Model, field) via a recognized ORM read idiom is treated as if it read a
# source directly, feeding the same has_sink/has_source propagation.
# ---------------------------------------------------------------------------


def _bound_names(target: ast.expr) -> set[str]:
    """Every name an assignment/loop target binds, flattening tuple, list and
    starred unpacking (`a, (b, *rest) = ...`)."""
    return {n.id for n in ast.walk(target) if isinstance(n, ast.Name)}


def _local_source_vars(func_node: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    """Local variables holding tainted data.

    Three binding shapes, walked in execution order so a later statement sees
    what earlier ones tainted:

    * assignment from a source, or from an already-tainted local -- one hop,
      e.g. `data = request.get_json()` then `name = data.get("name")`;
    * tuple/list unpacking of a tainted value (`head, rest = payload`);
    * iteration over a tainted iterable (`for out in outputs:`), including
      through a wrapper such as `zip` -- batch loops over model responses are
      how AI/ML pipelines almost always consume generation results, and
      stopping at the loop boundary lost the whole flow.
    """
    tainted: set[str] = set()
    for stmt in _iter_body_statements(func_node.body):
        if isinstance(stmt, (ast.For, ast.AsyncFor)):
            if _expr_reads_source(stmt.iter) or any(n in tainted for n in _names_in(stmt.iter)):
                tainted |= _bound_names(stmt.target)
            continue
        if not (isinstance(stmt, ast.Assign) and len(stmt.targets) == 1):
            continue
        target, value = stmt.targets[0], stmt.value
        if not isinstance(target, (ast.Name, ast.Tuple, ast.List)):
            continue
        # A value passed through a recognized sanitizer is no longer tainted,
        # and re-assigning through one CLEARS the target's existing taint
        # (`value = shlex.quote(value)`). Without this, the source-to-return
        # path disagreed with `_summarize_params`, which has always applied
        # this same check on the parameter-to-sink path (#301).
        if isinstance(value, ast.Call) and _looks_sanitized(value):
            tainted -= _bound_names(target)
            continue
        if _expr_reads_source(value) or any(n in tainted for n in _names_in(value)):
            tainted |= _bound_names(target)
    return tainted


def _function_returns_source(func_node: ast.AST) -> bool:
    """True if the function contains an `ast.Return` whose own value reads a
    known taint source directly, or reads a local variable that was assigned
    from one (`_local_source_vars`) -- as opposed to merely *containing* a
    source read somewhere in its body with an unrelated return value. Only
    functions satisfying this actually carry tainted data upward to a caller
    that captures their return value."""
    if not isinstance(func_node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return False
    source_vars = _local_source_vars(func_node)
    for stmt in _iter_body_statements(func_node.body):
        if isinstance(stmt, ast.Return) and stmt.value is not None:
            # `return shlex.quote(value)` returns sanitized data, not tainted
            # data, even though `value` itself is a tainted local (#301).
            if isinstance(stmt.value, ast.Call) and _looks_sanitized(stmt.value):
                continue
            if _expr_reads_source(stmt.value) or any(
                n in source_vars for n in _names_in(stmt.value)
            ):
                return True
    return False


def _resolve_orm_class_file(
    class_name: str,
    file_path: str | None,
    import_graph: _ImportGraph | None,
    classes_by_file: dict[str, set[str]] | None,
) -> str | None:
    """Resolve which file actually defines `class_name`, from the point of
    view of `file_path` -- either a same-file `ClassDef`, or an imported
    name resolved through the import graph CrossFilePass already builds.
    Returns None (unresolvable) when neither applies, e.g. no `file_path`/
    import-graph context was supplied at all (unit-test call sites that
    exercise these helpers directly), or the class is neither locally
    defined nor imported (dynamic construction, wildcard import, etc.)."""
    if file_path is None:
        return None
    if classes_by_file is not None and class_name in classes_by_file.get(file_path, ()):
        return file_path
    if import_graph is not None:
        resolved = import_graph.name_to_def.get((file_path, class_name))
        if resolved is not None:
            return resolved[0]
    return None


def _channel_matches(
    class_name: str,
    field: str,
    defining_file: str | None,
    channels: set[tuple[str, str]] | set[tuple[str, str, str]],
) -> bool:
    """Match a (class, field[, defining_file]) read against the collected
    write channels.

    A bare `(class, field)` channel entry means the writer's class identity
    couldn't be resolved -- it matches any reader of that class/field name,
    same as the old project-wide bare-name behavior (recall-preserving
    fallback). A resolved `(defining_file, class, field)` entry only matches
    a reader that either also failed to resolve (can't be selective, so
    fall back to matching) or resolved to the SAME defining file -- this is
    what stops two unrelated classes that happen to share a name from
    cross-contaminating each other's channel."""
    for channel in channels:
        if len(channel) == 2:
            ch_class, ch_field = channel
            if ch_class == class_name and ch_field == field:
                return True
        else:
            ch_file, ch_class, ch_field = channel
            if (
                ch_class == class_name
                and ch_field == field
                and (defining_file is None or ch_file == defining_file)
            ):
                return True
    return False


def _collect_orm_write_channels(
    tree: ast.AST,
    file_path: str | None = None,
    import_graph: _ImportGraph | None = None,
    classes_by_file: dict[str, set[str]] | None = None,
) -> set[tuple[str, str]] | set[tuple[str, str, str]]:
    """Find `Model(field=tainted_value)` constructor calls where the keyword
    value traces back to a known taint source read earlier in the same
    function.

    Returns a `(ClassName, field)` pair when the class's defining file can't
    be resolved (no `file_path`/import-graph context supplied, e.g. a direct
    unit-test call, or the class genuinely isn't resolvable), or a
    `(defining_file, ClassName, field)` triple when it is -- scoping the
    channel to the specific class it was actually written on, so two
    unrelated models sharing a bare class name (`User` in two apps) don't
    share a taint channel. See `_channel_matches` for how a reader is
    matched against a mix of both shapes."""
    channels: set[tuple] = set()
    for func in ast.walk(tree):
        if not isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        source_vars = _local_source_vars(func)
        for node in ast.walk(func):
            if not (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and _is_pascal_case(node.func.id)
            ):
                continue
            for kw in node.keywords:
                if kw.arg is None:
                    continue
                if _expr_reads_source(kw.value) or any(
                    n in source_vars for n in _names_in(kw.value)
                ):
                    defining_file = _resolve_orm_class_file(
                        node.func.id, file_path, import_graph, classes_by_file
                    )
                    if defining_file is not None:
                        channels.add((defining_file, node.func.id, kw.arg))
                    else:
                        channels.add((node.func.id, kw.arg))
    return channels


# _DJANGO_MANAGER_READ_METHODS / _orm_read_class / _orm_classes_by_var now live
# in rowan.analysis.orm_reads and are imported above under their historical
# private names.


def _expr_reads_orm_channel(
    expr: ast.expr,
    classes_by_var: dict[str, str],
    orm_channels: set[tuple[str, str]] | set[tuple[str, str, str]],
    file_path: str | None,
    import_graph: _ImportGraph | None,
    classes_by_file: dict[str, set[str]] | None,
) -> bool:
    """True if `expr` contains an attribute access (`u.email`) on a locally
    ORM-read variable (`classes_by_var`) whose (class, field) matches a known
    second-order taint write channel -- the per-EXPRESSION form of the check
    `_function_reads_orm_channel` performs across a function's WHOLE body."""
    if not orm_channels:
        return False
    for node in ast.walk(expr):
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
            cls = classes_by_var.get(node.value.id)
            if cls is None:
                continue
            defining_file = _resolve_orm_class_file(cls, file_path, import_graph, classes_by_file)
            if _channel_matches(cls, node.attr, defining_file, orm_channels):
                return True
    return False


def _orm_channel_vars(
    func_node: ast.FunctionDef | ast.AsyncFunctionDef,
    classes_by_var: dict[str, str],
    orm_channels: set[tuple],
    file_path: str,
    import_graph: _ImportGraph | None,
    classes_by_file: dict[str, set[str]] | None,
) -> set[str]:
    """Local names derived from a persisted ORM channel value.

    This is intentionally separate from ordinary source/parameter taint.  A
    previous implementation combined the two and could pair an unrelated
    trusted URL parameter with an ORM read elsewhere in the function.
    """
    derived: set[str] = set()
    changed = True
    while changed:
        changed = False
        for stmt in _iter_body_statements(func_node.body):
            if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
                mutation = stmt.value
                if (
                    isinstance(mutation.func, ast.Attribute)
                    and isinstance(mutation.func.value, ast.Name)
                    and mutation.func.attr in {"append", "extend", "insert", "update"}
                    and any(
                        _expr_reads_orm_channel(
                            arg,
                            classes_by_var,
                            orm_channels,
                            file_path,
                            import_graph,
                            classes_by_file,
                        )
                        or bool(set(_names_in(arg)) & derived)
                        for arg in mutation.args
                    )
                    and mutation.func.value.id not in derived
                ):
                    derived.add(mutation.func.value.id)
                    changed = True
                continue
            if not isinstance(stmt, (ast.Assign, ast.AnnAssign)) or stmt.value is None:
                continue
            targets = stmt.targets if isinstance(stmt, ast.Assign) else [stmt.target]
            names: set[str] = set()
            for target in targets:
                names |= _bound_names(target)
            if not names:
                continue
            value = stmt.value
            is_channel = _expr_reads_orm_channel(
                value, classes_by_var, orm_channels, file_path, import_graph, classes_by_file
            ) or bool(set(_names_in(value)) & derived)
            if is_channel and not names <= derived:
                derived |= names
                changed = True
    return derived


def _expr_reads_persistent_channel(
    expr: ast.expr,
    classes_by_var: dict[str, str],
    derived_vars: set[str],
    orm_channels: set[tuple],
    file_path: str,
    import_graph: _ImportGraph | None,
    classes_by_file: dict[str, set[str]] | None,
) -> bool:
    return _expr_reads_orm_channel(
        expr, classes_by_var, orm_channels, file_path, import_graph, classes_by_file
    ) or bool(set(_names_in(expr)) & derived_vars)


def _function_reads_orm_channel(
    func_node: ast.FunctionDef | ast.AsyncFunctionDef,
    orm_channels: set[tuple[str, str]] | set[tuple[str, str, str]],
    file_path: str | None = None,
    import_graph: _ImportGraph | None = None,
    classes_by_file: dict[str, set[str]] | None = None,
) -> bool:
    if not orm_channels:
        return False
    classes_by_var = _orm_classes_by_var(func_node)
    for node in ast.walk(func_node):
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
            cls = classes_by_var.get(node.value.id)
            if cls is None:
                continue
            defining_file = _resolve_orm_class_file(cls, file_path, import_graph, classes_by_file)
            if _channel_matches(cls, node.attr, defining_file, orm_channels):
                return True
    return False


# ---------------------------------------------------------------------------
# Second-order taint through vector-store / RAG persistence (#156).
#
# The ORM channel above generalizes: any store where one function WRITES
# untrusted data and a DIFFERENT function READS it back with no call edge
# between them is a second-order taint channel. A retrieval-augmented (RAG)
# app is the highest-value instance -- a handler ingests attacker-supplied
# documents into a vector store (`collection.add_documents([user_doc])`), and
# a separate function later retrieves them (`store.similarity_search(q)`) and
# feeds the retrieved text into an LLM prompt or another sink. This is the
# "embedding-space / index poisoning -> prompt injection" surface.
#
# Unlike the ORM channel, a vector store has no AST-stable cross-file identity
# (no `(class, field)` key), so this uses a deliberately coarse but
# tainted-write-GATED model: the channel is "armed" only if SOME recognized
# vector write is fed a value tracing to a known source anywhere in the
# project; while armed, any recognized vector READ is treated as a source.
# The arming gate is what keeps this precise in practice -- framework code
# (langchain/llamaindex internals) writes function parameters, not
# request.args, into these methods, so it never arms; only a real app that
# ingests genuinely untrusted data does. Method names are chosen to be
# vector-store-specific (`upsert`/`add_texts`/`similarity_search`/...) so the
# recognizer doesn't fire on an unrelated `.add()`/`.query()`. Follow-ups for
# the remaining #156 channels (agent memory, KV cache set/get, file write/
# read, precise Celery arg pairing) follow this same write-recognizer /
# read-recognizer / armed-channel shape.
# ---------------------------------------------------------------------------

_VECTOR_WRITE_METHODS = frozenset(
    {
        "upsert",
        "add_texts",
        "add_documents",
        "add_embeddings",
        "from_texts",
        "from_documents",
        "aadd_texts",
        "aadd_documents",
        "aadd_embeddings",
        "aupsert",
    }
)
_VECTOR_READ_METHODS = frozenset(
    {
        "similarity_search",
        "similarity_search_with_score",
        "similarity_search_by_vector",
        "max_marginal_relevance_search",
        "get_relevant_documents",
        "aget_relevant_documents",
        "asimilarity_search",
        "similarity_search_with_relevance_scores",
    }
)
#: `query`/`search` are too generic to stand alone; recognized as a vector
#: read ONLY when the receiver name hints at a vector store / index / retriever.
_VECTOR_GENERIC_READ_METHODS = frozenset({"query", "search", "aquery", "asearch"})
#: Same idea for writes (STaint, ASE 2025, arxiv doi 10.1109/ASE63991.2025.00347
#: -- the motivating case is a custom/unfamiliar persistence-API wrapper class
#: that doesn't happen to use one of LangChain's exact method names above,
#: e.g. a project's own `VectorStore.save(doc)`/`.persist(doc)`/`.ingest(doc)`
#: helper). Generic write-shaped verbs, gated on the SAME receiver-name hint
#: as the generic reads above, so this doesn't fire on an unrelated `.save()`/
#: `.insert()` on some other kind of object.
_VECTOR_GENERIC_WRITE_METHODS = frozenset(
    {
        "save",
        "asave",
        "persist",
        "apersist",
        "insert",
        "ainsert",
        "index",
        "aindex",
        "ingest",
        "aingest",
        "put",
        "aput",
    }
)
_VECTOR_RECEIVER_HINT_RE = re.compile(
    r"(?:^|_)(?:vector|vectorstore|vector_store|collection|index|retriever|store|db|chroma|faiss|pinecone|weaviate|qdrant|milvus)s?$",
    re.IGNORECASE,
)

_VECTOR_CHANNEL_PREFIX = "__vector__"
#: Retained as a public compatibility constant for callers that need the
#: prefix. Concrete channels prefer a stable backing-resource identity and
#: fall back to the local receiver when resource configuration is dynamic.
_VECTOR_CHANNEL_KEY = (_VECTOR_CHANNEL_PREFIX,)


def _state_receiver(node: ast.expr) -> str | None:
    """Return a stable dotted receiver for a method call or subscript."""
    receiver: ast.expr | None = None
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        receiver = node.func.value
    elif isinstance(node, ast.Subscript):
        receiver = node.value
    if receiver is None:
        return None
    return _dotted_name(receiver)


def _vector_store_identities(tree: ast.AST) -> dict[str, tuple[str, ...]]:
    """Resolve Chroma variables to stable backing-resource identities.

    Receiver spelling is only a fallback. When both the persistent client
    location and collection name are literal, the same store can be paired
    across files even when each module chooses a different local variable.
    """
    body = tree.body if isinstance(tree, ast.Module) else []
    binding_counts: dict[str, int] = {}
    for stmt in body:
        targets = stmt.targets if isinstance(stmt, ast.Assign) else []
        if isinstance(stmt, (ast.AnnAssign, ast.AugAssign)):
            targets = [stmt.target]
        for target in targets:
            for name in _bound_names(target):
                binding_counts[name] = binding_counts.get(name, 0) + 1
    clients: dict[str, str] = {}
    for stmt in body:
        if not (
            isinstance(stmt, ast.Assign)
            and len(stmt.targets) == 1
            and isinstance(stmt.targets[0], ast.Name)
            and binding_counts.get(stmt.targets[0].id) == 1
            and isinstance(stmt.value, ast.Call)
            and (_dotted_name(stmt.value.func) or "").split(".")[-1] == "PersistentClient"
        ):
            continue
        path_expr = next(
            (kw.value for kw in stmt.value.keywords if kw.arg == "path"),
            stmt.value.args[0] if stmt.value.args else None,
        )
        path = _string_literal(path_expr)
        if path is not None:
            clients[stmt.targets[0].id] = path

    identities: dict[str, tuple[str, ...]] = {}
    for stmt in body:
        if not (
            isinstance(stmt, ast.Assign)
            and len(stmt.targets) == 1
            and isinstance(stmt.targets[0], ast.Name)
            and binding_counts.get(stmt.targets[0].id) == 1
            and isinstance(stmt.value, ast.Call)
        ):
            continue
        target = stmt.targets[0].id
        call = stmt.value
        call_name = _dotted_name(call.func) or ""
        collection_expr: ast.expr | None = None
        client_path: str | None = None
        if call_name.split(".")[-1] == "Chroma":
            collection_expr = next(
                (kw.value for kw in call.keywords if kw.arg == "collection_name"), None
            )
            client_expr = next((kw.value for kw in call.keywords if kw.arg == "client"), None)
            if isinstance(client_expr, ast.Name):
                client_path = clients.get(client_expr.id)
            if client_path is None:
                persist_expr = next(
                    (kw.value for kw in call.keywords if kw.arg == "persist_directory"), None
                )
                client_path = _string_literal(persist_expr)
        elif (
            isinstance(call.func, ast.Attribute)
            and call.func.attr in {"get_collection", "get_or_create_collection"}
            and isinstance(call.func.value, ast.Name)
        ):
            client_path = clients.get(call.func.value.id)
            collection_expr = next(
                (kw.value for kw in call.keywords if kw.arg == "name"),
                call.args[0] if call.args else None,
            )
        collection_name = _string_literal(collection_expr)
        if client_path is not None and collection_name is not None:
            identities[target] = (
                _VECTOR_CHANNEL_PREFIX,
                "chroma",
                client_path,
                collection_name,
            )
    return identities


def _vector_channel(
    node: ast.expr,
    vector_identities: dict[str, tuple[str, ...]] | None = None,
) -> tuple[str, ...] | None:
    receiver = _state_receiver(node)
    if receiver and vector_identities and receiver in vector_identities:
        return vector_identities[receiver]
    return (_VECTOR_CHANNEL_PREFIX, receiver) if receiver else None


def _vector_call_receiver_name(node: ast.Call) -> str | None:
    recv = node.func.value  # type: ignore[union-attr]
    return (
        recv.id
        if isinstance(recv, ast.Name)
        else (recv.attr if isinstance(recv, ast.Attribute) else None)
    )


def _is_vector_read_call(node: ast.expr) -> bool:
    """True if `node` is a recognized vector-store retrieval call."""
    if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)):
        return False
    method = node.func.attr
    if method in _VECTOR_READ_METHODS:
        return True
    if method in _VECTOR_GENERIC_READ_METHODS:
        recv_name = _vector_call_receiver_name(node)
        return bool(recv_name and _VECTOR_RECEIVER_HINT_RE.search(recv_name))
    return False


def _is_vector_write_call(node: ast.expr) -> bool:
    """True if `node` is a recognized vector-store persistence call --
    either an exact known-SDK write method name, or a generic write-shaped
    verb on a receiver whose name hints at a vector store (#156 follow-up,
    STaint-motivated: catches custom wrapper classes the exact-name list
    can't)."""
    if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)):
        return False
    method = node.func.attr
    if method in _VECTOR_WRITE_METHODS:
        return True
    if method in _VECTOR_GENERIC_WRITE_METHODS:
        recv_name = _vector_call_receiver_name(node)
        return bool(recv_name and _VECTOR_RECEIVER_HINT_RE.search(recv_name))
    return False


def _collect_vector_write_channels(tree: ast.AST) -> set[tuple[str, ...]]:
    """Return resource- or receiver-scoped channels for tainted vector writes."""
    channels: set[tuple[str, ...]] = set()
    vector_identities = _vector_store_identities(tree)
    for func in ast.walk(tree):
        if not isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        source_vars = _local_source_vars(func)
        for node in ast.walk(func):
            if not (isinstance(node, ast.Call) and _is_vector_write_call(node)):
                continue
            for arg in (*node.args, *(kw.value for kw in node.keywords)):
                if _expr_reads_source(arg) or any(n in source_vars for n in _names_in(arg)):
                    channel = _vector_channel(node, vector_identities)
                    if channel is not None:
                        channels.add(channel)
    return channels


def _vector_read_vars(
    func_node: ast.FunctionDef | ast.AsyncFunctionDef,
    vector_channels: set[tuple[str, ...]],
    vector_identities: dict[str, tuple[str, ...]] | None = None,
) -> set[str]:
    """Local variable names assigned from a recognized vector-store read --
    `docs = store.similarity_search(q)` -> {"docs"}. Whole-value tainted (the
    retrieved text is the untrusted content), so no per-field matching, unlike
    ORM."""
    read_vars: set[str] = set()
    for stmt in _iter_body_statements(func_node.body):
        if (
            isinstance(stmt, ast.Assign)
            and len(stmt.targets) == 1
            and isinstance(stmt.targets[0], ast.Name)
            and _is_vector_read_call(stmt.value)
            and _vector_channel(stmt.value, vector_identities) in vector_channels
        ):
            read_vars.add(stmt.targets[0].id)
    return read_vars


# ---------------------------------------------------------------------------
# Second-order taint through object / key-value state (#300). This is the
# "KV cache set/get" follow-up the vector-store comment above names.
#
# One function writes untrusted data into a plain object's state under a key
# (`store.set("report_cmd", request.args.get("cmd"))`), and a different
# function in a different file reads it back (`store.get("report_cmd")`) and
# sinks it. No call edge between them, no ORM model, no vector store, so none
# of the channels above see it.
#
# `set`/`get` are far too generic for the vector channel's coarse project-wide
# "armed" bit: every dict in Python has `.get()`. So this channel is keyed on
# the LITERAL key string, which is AST-stable across files and connects a read
# only to a write that provably used the same key. A write whose key is a
# variable arms nothing, and a read whose key is a variable matches nothing:
# both deliberate, since a variable key can't be proven equal across files
# without real value tracking. The write must also carry a value tracing to a
# real source, the same arming gate the vector channel relies on.
#
# NOT covered here: attribute-style state (`obj.attr = tainted` written in one
# file, `obj.attr` read in another). That shape is closer to the ORM channel's
# `(class, field)` key and needs receiver-class resolution to avoid connecting
# unrelated objects that happen to share an attribute name.
# ---------------------------------------------------------------------------

_OBJSTATE_WRITE_METHODS = frozenset(
    {
        "set",
        "put",
        "store",
        "write",
        "cache",
        "save",
        "setex",
        "hset",
        "aset",
        "aput",
        "asave",
    }
)
_OBJSTATE_READ_METHODS = frozenset(
    {
        "get",
        "fetch",
        "load",
        "read",
        "lookup",
        "retrieve",
        "hget",
        "aget",
        "afetch",
        "aload",
    }
)
#: Channel keys are `("__objstate__", <receiver>, <literal key>)`.
_OBJSTATE_PREFIX = "__objstate__"


def _string_literal(node: ast.expr | None) -> str | None:
    """The value of `node` if it is a plain string literal, else None."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _objstate_write_key(node: ast.expr) -> str | None:
    """The literal key a recognized object-state WRITE writes under.

    Two shapes: a method call whose first positional argument is a string
    literal (`store.set("k", v)`, `cache.setex("k", 300, v)`), and a subscript
    assignment's key (`store["k"] = v`, handled by the caller since the target
    lives on the statement, not the value)."""
    if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)):
        return None
    if node.func.attr not in _OBJSTATE_WRITE_METHODS:
        return None
    if not node.args:
        return None
    return _string_literal(node.args[0])


def _objstate_read_key(node: ast.expr) -> str | None:
    """The literal key a recognized object-state READ reads, for both the
    method-call shape (`store.get("k")`) and the subscript shape
    (`store["k"]`)."""
    if isinstance(node, ast.Subscript):
        return _string_literal(node.slice)
    if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)):
        return None
    if node.func.attr not in _OBJSTATE_READ_METHODS:
        return None
    if not node.args:
        return None
    return _string_literal(node.args[0])


def _collect_objstate_write_channels(tree: ast.AST) -> set[tuple[str, str, str]]:
    """Arm receiver/key channels for source-tracing object-state writes."""
    channels: set[tuple[str, str, str]] = set()
    for func in ast.walk(tree):
        if not isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        source_vars = _local_source_vars(func)
        for stmt in _iter_body_statements(func.body):
            # store["k"] = tainted
            if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1:
                target = stmt.targets[0]
                if isinstance(target, ast.Subscript):
                    key = _string_literal(target.slice)
                    if key is not None and (
                        _expr_reads_source(stmt.value)
                        or any(n in source_vars for n in _names_in(stmt.value))
                    ):
                        receiver = _state_receiver(target)
                        if receiver is not None:
                            channels.add((_OBJSTATE_PREFIX, receiver, key))
            for node in ast.walk(stmt):
                if not isinstance(node, ast.Call):
                    continue
                key = _objstate_write_key(node)
                if key is None:
                    continue
                # The key itself doesn't arm the channel, a tainted VALUE in
                # any other argument position does.
                for arg in (*node.args[1:], *(kw.value for kw in node.keywords)):
                    if _expr_reads_source(arg) or any(n in source_vars for n in _names_in(arg)):
                        receiver = _state_receiver(node)
                        if receiver is not None:
                            channels.add((_OBJSTATE_PREFIX, receiver, key))
                        break
    return channels


def _expr_reads_objstate_channel(
    expr: ast.expr, objstate_channels: set[tuple[str, str, str]]
) -> bool:
    """True if `expr` contains a recognized object-state read whose literal key
    is armed by a tainted write elsewhere in the project (#300)."""
    if not objstate_channels:
        return False
    for node in ast.walk(expr):
        if not isinstance(node, (ast.Call, ast.Subscript)):
            continue
        key = _objstate_read_key(node)
        receiver = _state_receiver(node)
        if (
            key is not None
            and receiver is not None
            and (_OBJSTATE_PREFIX, receiver, key) in objstate_channels
        ):
            return True
    return False


def _function_reads_objstate_channel(
    func_node: ast.FunctionDef | ast.AsyncFunctionDef,
    objstate_channels: set[tuple[str, str, str]],
) -> bool:
    """Whole-body form of `_expr_reads_objstate_channel` (#300)."""
    if not objstate_channels:
        return False
    for node in ast.walk(func_node):
        if not isinstance(node, (ast.Call, ast.Subscript)):
            continue
        key = _objstate_read_key(node)
        receiver = _state_receiver(node)
        if (
            key is not None
            and receiver is not None
            and (_OBJSTATE_PREFIX, receiver, key) in objstate_channels
        ):
            return True
    return False


def _objstate_read_vars(
    func_node: ast.FunctionDef | ast.AsyncFunctionDef,
    objstate_channels: set[tuple[str, str, str]],
) -> set[str]:
    """Local variables assigned from an armed object-state read --
    `cmd = store.get("report_cmd")` -> {"cmd"}. Whole-value tainted, same as
    the vector channel (#300)."""
    if not objstate_channels:
        return set()
    read_vars: set[str] = set()
    for stmt in _iter_body_statements(func_node.body):
        if (
            isinstance(stmt, ast.Assign)
            and len(stmt.targets) == 1
            and isinstance(stmt.targets[0], ast.Name)
            and _expr_reads_objstate_channel(stmt.value, objstate_channels)
        ):
            read_vars.add(stmt.targets[0].id)
    return read_vars


def _function_reads_vector_channel(
    func_node: ast.FunctionDef | ast.AsyncFunctionDef,
    vector_channels: set[tuple[str, ...]],
    vector_identities: dict[str, tuple[str, ...]] | None = None,
) -> bool:
    """True if the vector channel is armed and this function performs a
    recognized vector-store read anywhere in its body (#156)."""
    return any(
        _is_vector_read_call(n) and _vector_channel(n, vector_identities) in vector_channels
        for n in ast.walk(func_node)
    )


def _expr_reads_vector_channel(
    expr: ast.expr,
    vector_read_vars: set[str],
    vector_channels: set[tuple[str, ...]],
    vector_identities: dict[str, tuple[str, ...]] | None = None,
) -> bool:
    """Per-expression vector-channel check for #119 argument binding: the
    expression is (or names a variable assigned from) a vector read, and the
    channel is armed."""
    if any(
        _is_vector_read_call(n)
        and _vector_channel(n, vector_identities) in vector_channels
        for n in ast.walk(expr)
    ):
        return True
    return any(n in vector_read_vars for n in _names_in(expr))


def _arg_expr_is_caller_tainted(
    expr: ast.expr,
    caller_taint_candidates: set[str],
    orm_classes_by_var: dict[str, str],
    orm_channels: set[tuple[str, str]] | set[tuple[str, str, str]],
    file_path: str | None,
    import_graph: _ImportGraph | None,
    classes_by_file: dict[str, set[str]] | None,
    vector_read_vars: set[str] | None = None,
    vector_channels: set[tuple[str, ...]] | None = None,
    vector_identities: dict[str, tuple[str, ...]] | None = None,
    objstate_read_vars: set[str] | None = None,
    objstate_channels: set[tuple[str, str, str]] | None = None,
) -> bool:
    """(#119) True if a call-site argument expression is tainted from the
    CALLING function's own perspective -- the union of every signal
    `has_source` is already built from at the function level, applied to one
    expression instead of a whole body: a direct known-source read inline
    (`_expr_reads_source`, e.g. `f(request.args.get('x'))` with no
    intermediate variable), a reference to a name this caller already
    considers tainted (`caller_taint_candidates` -- source-derived locals
    from `_local_source_vars`, UNION the caller's own parameters), an
    ORM-channel-matched attribute read (`u.email` after `u =
    User.query...first()`), or a vector-store retrieval (#156)."""
    if _expr_reads_source(expr):
        return True
    if any(n in caller_taint_candidates for n in _names_in(expr)):
        return True
    if _expr_reads_orm_channel(
        expr, orm_classes_by_var, orm_channels, file_path, import_graph, classes_by_file
    ):
        return True
    if vector_channels and _expr_reads_vector_channel(
        expr, vector_read_vars or set(), vector_channels, vector_identities
    ):
        return True
    # #300: an armed object-state read inline (`f(store.get("k"))`), or a
    # local already assigned from one.
    if objstate_channels:
        if _expr_reads_objstate_channel(expr, objstate_channels):
            return True
        if objstate_read_vars and any(n in objstate_read_vars for n in _names_in(expr)):
            return True
    return False


# ---------------------------------------------------------------------------
# Structural path-write/read sink detection.
#
# NS-PATH-001 only fires when `request.args`/`request.form`/`request.json`
# appears on the SAME line as `open(...)`. Real path-traversal sinks are
# usually a service-layer function or two away from the framework boundary:
# a helper receives an already-untrusted parameter, joins it onto a base
# directory constant, and opens/writes/removes the result several lines
# later. Detecting that shape directly from the AST lets it feed the same
# has_sink/has_source cross-file propagation below -- so it only surfaces
# when a real caller elsewhere threads request data into the parameter,
# same precision bar as every other sink kind here.
# ---------------------------------------------------------------------------

_SINK_FUNC_NAMES = frozenset(
    {
        "open",
        "makedirs",
        "remove",
        "rmtree",
        "unlink",
        "move",
        "copyfile",
        "rename",
        "load_workbook",  # openpyxl opens the path it is given
    }
)
_BASE_DIR_NAME_RE = re.compile(r"(DIR|ROOT|BASE|_HOME|STORAGE)$")
_TRAVERSAL_LITERALS = ("../", "..\\", "..")
_CONTAINMENT_ATTRS = (
    "realpath",
    "abspath",
    "resolve",
    "commonpath",
    "commonprefix",
    "is_relative_to",
)
# Subset of _CONTAINMENT_ATTRS that only *normalize* a path (realpath/abspath/
# resolve/commonpath/commonprefix) -- their result still has to feed an actual
# comparison against a base directory to constitute a containment check.
# is_relative_to() is excluded: unlike the others, its own return value IS
# the check (a bool), so its mere presence as a call is sufficient.
_CONTAINMENT_NORMALIZE_ATTRS = ("realpath", "abspath", "resolve", "commonpath", "commonprefix")

# ---------------------------------------------------------------------------
# Agentic tool-abuse sources.
#
# LangChain/CrewAI/AutoGen-style "tool" functions -- a BaseTool subclass's
# _run/run/_arun/arun method (or Dify/LangChain-Runnable-style _invoke/
# invoke/ainvoke), or a bare function decorated with @tool -- are invoked
# with arguments an LLM chooses at runtime. If that LLM's own instructions
# were influenced by untrusted content (direct or indirect prompt
# injection), the tool's arguments are effectively attacker-controlled, the
# same way request.args is -- but nothing upstream of the tool call ever
# reads a KNOWN_SOURCE_PREFIXES attribute, so this needs its own
# recognition rather than falling out of _function_reads_source.
# ---------------------------------------------------------------------------

_TOOL_METHOD_NAMES = frozenset({"_run", "run", "_arun", "arun", "_invoke", "invoke", "ainvoke"})
_TOOL_BASE_HINT_RE = re.compile(r"Tool$")
# `tool` covers LangChain `@tool` and FastMCP `@mcp.tool()`; `call_tool` is
# the low-level MCP server's `@server.call_tool()` handler.
_TOOL_DECORATOR_NAMES = frozenset({"tool", "call_tool"})

# ---------------------------------------------------------------------------
# Other structural trust boundaries (GitHub issue #122).
#
# The agent-tool insight generalizes: any boundary where a function's own
# arguments are attacker-influenced is a structural source, whether or not
# anything upstream reads a KNOWN_SOURCE_PREFIXES attribute like request.args.
# Celery/RQ task bodies, gRPC servicer methods, GraphQL resolvers, and
# webhook handlers are the same shape -- the caller (a queue broker, an RPC
# client, a GraphQL client, an external webhook sender) is untrusted, and the
# framework hands its payload straight to the function's parameters.
# ---------------------------------------------------------------------------

# Celery's @app.task/@celery.task/@shared_task decorate the task body itself;
# RQ has no equivalent decorator convention (a plain function passed to
# queue.enqueue(func, ...) at the call site) so it isn't structurally
# recognizable this way -- out of scope for this pass, same tradeoff as
# agent-tool recognition only covering @tool/BaseTool and not every possible
# LLM-tool-calling convention.
_TASK_QUEUE_DECORATOR_NAMES = frozenset({"task", "shared_task"})

# grpcio-tools generates a `<Service>Servicer` base class per .proto service;
# every public method on a subclass is an RPC handler invoked with a
# client-controlled request message.
_GRPC_SERVICER_BASE_HINT_RE = re.compile(r"Servicer$")

# graphene's convention: a resolve_<field> method, but ONLY on a class that
# itself looks GraphQL-related (an ObjectType/Interface/Mutation subclass,
# or a class named ...Query/...Mutation/...Type/...Schema) -- "resolve_"
# alone is much too common a prefix for an arbitrary utility function
# (confirmed empirically: llama-index's own resolve_binary() is an unrelated
# HTTP-fetch helper, not a GraphQL resolver, and would have been misflagged
# without this class-context gate).
_GRAPHQL_RESOLVER_METHOD_RE = re.compile(r"^resolve_")
_GRAPHQL_CLASS_HINT_RE = re.compile(r"(ObjectType|Interface|Mutation|Query|Type|Schema)$")
# strawberry/ariadne: @strawberry.field or @<query|mutation>.field(...) --
# also gated on the decorator's own qualifier hinting at GraphQL, since a
# bare ".field" attribute is otherwise a plausible name in unrelated code.
_GRAPHQL_RESOLVER_DECORATOR_NAMES = frozenset({"field"})
_GRAPHQL_DECORATOR_QUALIFIER_RE = re.compile(r"strawberry|query|mutation", re.IGNORECASE)

# A route whose own path/name mentions "webhook" -- the actual payload-typed
# parameter convention varies by framework (FastAPI's Pydantic-model body
# injection, Django views, raw Lambda-style handler(event, context)).  A bare
# function name is not boundary evidence: compiler callback registries and GUI
# callbacks use the same vocabulary.  Recognition therefore requires an HTTP
# route decorator or an explicit route-registration call as well as the hint.
_WEBHOOK_HINT_RE = re.compile(r"webhook|callback", re.IGNORECASE)
_HTTP_ROUTE_DECORATOR_NAMES = frozenset(
    {
        "route",
        "get",
        "post",
        "put",
        "patch",
        "delete",
        "options",
        "head",
        "websocket",
    }
)


def _decorator_call_string_args(dec: ast.expr) -> list[str]:
    if isinstance(dec, ast.Call):
        return [
            a.value for a in dec.args if isinstance(a, ast.Constant) and isinstance(a.value, str)
        ]
    return []


def _collect_task_queue_nodes(tree: ast.AST) -> set[int]:
    """Celery-style @task/@shared_task-decorated function bodies -- the
    task's own parameters are attacker-influenced whenever anything
    upstream of the .delay()/.apply_async() call site is (a common shape
    for webhook-triggered or user-submitted background work)."""
    task_nodes: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and any(
            _decorator_ref_name(dec) in _TASK_QUEUE_DECORATOR_NAMES for dec in node.decorator_list
        ):
            task_nodes.add(id(node))
    return task_nodes


def _collect_grpc_servicer_nodes(tree: ast.AST) -> set[int]:
    """Public methods on a grpcio-generated `*Servicer` subclass -- each one
    is an RPC handler invoked with a client-controlled request message."""
    servicer_nodes: set[int] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.ClassDef):
            continue
        if not any(
            (name := _base_ref_name(base)) and _GRPC_SERVICER_BASE_HINT_RE.search(name)
            for base in node.bases
        ):
            continue
        for item in node.body:
            if isinstance(
                item, (ast.FunctionDef, ast.AsyncFunctionDef)
            ) and not item.name.startswith("_"):
                servicer_nodes.add(id(item))
    return servicer_nodes


def _decorator_qualifier_name(dec: ast.expr) -> str | None:
    """The name before the final .attr in a decorator, e.g. 'strawberry' in
    @strawberry.field or 'query' in @query.field(...)."""
    target = dec.func if isinstance(dec, ast.Call) else dec
    return _base_ref_name(target.value) if isinstance(target, ast.Attribute) else None


def _collect_graphql_resolver_nodes(tree: ast.AST) -> set[int]:
    """graphene's resolve_<field> convention (only on a class that itself
    looks GraphQL-related), or a strawberry/ariadne @<...>.field(...)-
    decorated resolver (only when the decorator's own qualifier hints at
    GraphQL) -- a GraphQL client controls every argument passed to a
    resolver."""
    resolver_nodes: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            class_looks_graphql = _GRAPHQL_CLASS_HINT_RE.search(node.name) or any(
                (name := _base_ref_name(base)) and _GRAPHQL_CLASS_HINT_RE.search(name)
                for base in node.bases
            )
            if not class_looks_graphql:
                continue
            for item in node.body:
                if isinstance(
                    item, (ast.FunctionDef, ast.AsyncFunctionDef)
                ) and _GRAPHQL_RESOLVER_METHOD_RE.match(item.name):
                    resolver_nodes.add(id(item))
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for dec in node.decorator_list:
                if _decorator_ref_name(dec) not in _GRAPHQL_RESOLVER_DECORATOR_NAMES:
                    continue
                qualifier = _decorator_qualifier_name(dec)
                if qualifier and _GRAPHQL_DECORATOR_QUALIFIER_RE.search(qualifier):
                    resolver_nodes.add(id(node))
                    break
    return resolver_nodes


def _collect_webhook_handler_nodes(tree: ast.AST) -> set[int]:
    """HTTP-registered handlers whose route or name says webhook/callback.

    The route/registration is the trust-boundary evidence.  The name is only
    a hint once that evidence exists; treating every ``*_callback`` helper as
    externally reachable made ordinary in-process callback registries High.
    """
    webhook_nodes: set[int] = set()
    functions_by_name = {
        node.name: node
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for dec in node.decorator_list:
            if _decorator_ref_name(dec) not in _HTTP_ROUTE_DECORATOR_NAMES:
                continue
            paths = [s for s in _decorator_call_string_args(dec) if s.startswith("/")]
            if _WEBHOOK_HINT_RE.search(node.name) or any(
                _WEBHOOK_HINT_RE.search(path) for path in paths
            ):
                webhook_nodes.add(id(node))
                break

    # Flask/FastAPI/Starlette registration forms for named handlers, e.g.
    # app.add_url_rule("/webhook", view_func=github_webhook) and
    # router.add_api_route("/callback", handler).  Both a route-like path and
    # a statically named in-repo handler are required.
    registration_methods = {"add_url_rule", "add_api_route", "add_route"}
    for call in (node for node in ast.walk(tree) if isinstance(node, ast.Call)):
        if not isinstance(call.func, ast.Attribute) or call.func.attr not in registration_methods:
            continue
        paths = [
            arg.value
            for arg in call.args
            if isinstance(arg, ast.Constant)
            and isinstance(arg.value, str)
            and arg.value.startswith("/")
        ]
        if not any(_WEBHOOK_HINT_RE.search(path) for path in paths):
            continue
        handler_expr: ast.expr | None = None
        for keyword in call.keywords:
            if keyword.arg in {"view_func", "endpoint", "handler"}:
                handler_expr = keyword.value
                break
        if handler_expr is None and len(call.args) >= 2:
            handler_expr = call.args[1]
        if isinstance(handler_expr, ast.Name) and handler_expr.id in functions_by_name:
            webhook_nodes.add(id(functions_by_name[handler_expr.id]))
    return webhook_nodes


def _collect_http_route_nodes(tree: ast.AST) -> set[int]:
    """Flask/FastAPI-style decorated route functions.

    Their path parameters and ``**kwargs`` are populated from the request
    boundary even when the body never reads a global ``request`` object.
    """
    return {
        id(node)
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and any(
            _decorator_ref_name(dec) in _HTTP_ROUTE_DECORATOR_NAMES
            and any(path.startswith("/") for path in _decorator_call_string_args(dec))
            for dec in node.decorator_list
        )
    }


# rule_id/label for each boundary kind's standalone same-file finding, in
# the same spirit as AGENT-TOOL-001 -- the vulnerability doesn't need to
# cross a file boundary to be real, since the "caller" here is an external
# broker/client, not trusted in-repo code.
_BOUNDARY_RULE_IDS: dict[str, tuple[str, str]] = {
    "agent_tool": ("AGENT-TOOL-001", "Agent tool"),
    "task_queue": ("TASK-QUEUE-001", "Task queue handler"),
    "grpc": ("GRPC-001", "gRPC servicer method"),
    "graphql": ("GRAPHQL-001", "GraphQL resolver"),
    "webhook": ("WEBHOOK-001", "Webhook handler"),
    "http_route": ("HTTP-ROUTE-001", "HTTP route"),
}

# Sink calls that only count in agent-tool mode, where any direct use of a
# tool argument is inherently suspicious (no base-dir-join gate needed --
# the whole point of the tool boundary is that the argument is untrusted).
# Qualified so generic method names (run/get/call) don't fire project-wide.
_TOOL_QUALIFIED_SINKS: dict[str, frozenset[str]] = {
    "os": frozenset({"system", "popen"}),
    "subprocess": frozenset({"run", "Popen", "call", "check_output", "check_call"}),
    "requests": frozenset({"get", "post", "put", "delete", "patch"}),
    "httpx": frozenset({"get", "post", "put", "delete", "patch"}),
    # SymPy evaluates string input as Python (GHSA-mw6r-2hvm-4rp2).
    "sympy": frozenset({"sympify", "parse_expr"}),
}
_TOOL_BARE_SINKS = frozenset({"eval", "exec", "sympify", "parse_expr"})


def _decorator_ref_name(node: ast.expr) -> str | None:
    if isinstance(node, ast.Call):
        return _decorator_ref_name(node.func)
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Name):
        return node.id
    return None


def _is_tool_class(class_def: ast.ClassDef) -> bool:
    for base in class_def.bases:
        name = _base_ref_name(base)
        if name and _TOOL_BASE_HINT_RE.search(name):
            return True
    return False


def _collect_agent_tool_nodes(tree: ast.AST) -> set[int]:
    """Identify _run/run/_arun/arun methods on BaseTool-style classes, and
    @tool-decorated bare functions. Returns id()s of the matching FunctionDef/
    AsyncFunctionDef nodes -- valid for the lifetime of this parsed tree,
    which CrossFilePass holds for the duration of a single scan."""
    tool_nodes: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and _is_tool_class(node):
            for item in node.body:
                if (
                    isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
                    and item.name in _TOOL_METHOD_NAMES
                ):
                    tool_nodes.add(id(item))
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if any(
                _decorator_ref_name(dec) in _TOOL_DECORATOR_NAMES for dec in node.decorator_list
            ):
                tool_nodes.add(id(node))
    return tool_nodes


_MODEL_TOOL_CALL_NAMES = frozenset(
    {
        "chat",
        "completion",
        "complete",
        "invoke",
        "generate",
    }
)
_PRINCIPAL_PARAM_RE = re.compile(
    r"^(?:(?:current_)?user(?:_id|_ctx|_context)?|owner(?:_id)?|tenant(?:_id)?|"
    r"principal|actor(?:_id)?|role|permissions?|policy|auth_context)$",
    re.IGNORECASE,
)
_POLICY_CALL_RE = re.compile(
    r"auth|authoriz|permission|policy|scope|can_|allowed|check_access", re.IGNORECASE
)


def _function_uses_principal_policy(func: ast.AST) -> bool:
    principal_names = (
        {arg.arg for arg in func.args.args if _PRINCIPAL_PARAM_RE.search(arg.arg)}
        if isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef))
        else set()
    )
    if not principal_names:
        return False
    return any(
        isinstance(node, ast.Call)
        and _POLICY_CALL_RE.search(_dotted_name(node.func))
        and any(
            set(_names_in(arg)) & principal_names
            for arg in (*node.args, *(kw.value for kw in node.keywords))
        )
        for node in ast.walk(func)
    )


def _agent_capabilities(func: ast.AST) -> dict[str, int]:
    """Dangerous capabilities exposed by a registered tool function."""
    capabilities: dict[str, int] = {}
    for call in (n for n in ast.walk(func) if isinstance(n, ast.Call)):
        dotted = _dotted_name(call.func).lower()
        line = getattr(call, "lineno", getattr(func, "lineno", 0))
        if dotted in {"eval", "exec", "sympify", "parse_expr", "sympy.sympify", "sympy.parse_expr"}:
            capabilities.setdefault("code execution", line)
        elif dotted == "open":
            capabilities.setdefault("filesystem access", line)
        elif dotted.startswith(("requests.", "httpx.")):
            capabilities.setdefault("network access", line)
        elif dotted.startswith("subprocess.") or dotted in {"os.system", "os.popen"}:
            if _is_dynamic_package_install(func, call):
                capabilities.setdefault("unpinned package supply chain execution", line)
            else:
                capabilities.setdefault("shell execution", line)
        elif dotted.endswith((".execute", ".executemany", ".exec_driver_sql")) and any(
            part in dotted for part in ("db.", "session.", "cursor.", "connection.")
        ):
            capabilities.setdefault("SQL execution", line)
        elif dotted.endswith((".delete", ".add", ".commit")) and "session" in dotted:
            capabilities.setdefault("database mutation", line)
    return capabilities


_PACKAGE_INSTALL_COMMANDS = frozenset({"pip", "pip3", "pipx", "npm", "pnpm", "yarn", "uv"})
_PACKAGE_INSTALL_VERBS = frozenset({"install", "add"})
_PACKAGE_OPTIONS_WITH_VALUES = frozenset(
    {
        "--target",
        "-t",
        "--prefix",
        "--root",
        "--cache-dir",
        "--index-url",
        "-i",
        "--extra-index-url",
        "--find-links",
        "-f",
        "--registry",
        "--python",
    }
)


def _is_dynamic_package_install(func: ast.AST, call: ast.Call) -> bool:
    """Whether a subprocess installs a caller/model-selected package.

    Literal requirements and values selected from a guarded, code-owned
    catalog are excluded. List-form subprocess invocation prevents shell
    injection but does not prevent install-time package code execution.
    """
    if not call.args or not isinstance(call.args[0], (ast.List, ast.Tuple)):
        return False
    argv = call.args[0].elts
    words = {
        value.value.lower()
        for value in argv
        if isinstance(value, ast.Constant) and isinstance(value.value, str)
    }
    if not (words & _PACKAGE_INSTALL_COMMANDS) or not (words & _PACKAGE_INSTALL_VERBS):
        return False

    verb_index = next(
        (
            index
            for index, value in enumerate(argv)
            if isinstance(value, ast.Constant)
            and isinstance(value.value, str)
            and value.value.lower() in _PACKAGE_INSTALL_VERBS
        ),
        None,
    )
    if verb_index is None:
        return False
    requirements: list[ast.expr] = []
    skip_option_value = False
    for value in argv[verb_index + 1 :]:
        literal = value.value if isinstance(value, ast.Constant) else None
        if skip_option_value:
            skip_option_value = False
            continue
        if isinstance(literal, str) and literal in _PACKAGE_OPTIONS_WITH_VALUES:
            skip_option_value = True
            continue
        if isinstance(literal, str) and literal.startswith("-"):
            continue
        requirements.append(value)

    dynamic_names = {
        node.id for value in requirements for node in ast.walk(value) if isinstance(node, ast.Name)
    }
    if not dynamic_names:
        return False

    guarded_catalog_values: set[str] = set()
    rejected_catalog_values: set[str] = set()
    for node in ast.walk(func):
        if isinstance(node, (ast.Assign, ast.AnnAssign)) and node.value is not None:
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            if isinstance(node.value, ast.Call) and _is_fixed_catalog_lookup(node.value):
                for target in targets:
                    guarded_catalog_values |= _bound_names(target)
        elif isinstance(node, ast.If) and any(
            isinstance(child, (ast.Raise, ast.Return, ast.Continue, ast.Break))
            for child in node.body
            for child in ast.walk(child)
        ):
            rejected_catalog_values |= set(_names_in(node.test))
    safe_values = guarded_catalog_values & rejected_catalog_values
    return bool(dynamic_names - safe_values)


def _collect_tool_registries(
    parsed: list[tuple[str, ast.AST]],
) -> dict[tuple[str, str], dict[str, tuple[str, int]]]:
    """Collect literal tool registries and summarize their function bodies."""
    functions: dict[tuple[str, str], ast.AST] = {}
    for file_path, tree in parsed:
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                functions[(file_path, node.name)] = node

    registries: dict[tuple[str, str], dict[str, tuple[str, int]]] = {}
    for file_path, tree in parsed:
        for node in ast.walk(tree):
            if not (
                isinstance(node, (ast.Assign, ast.AnnAssign)) and isinstance(node.value, ast.Dict)
            ):
                continue
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            names = {name for target in targets for name in _bound_names(target)}
            for registry_name in names:
                exposed: dict[str, tuple[str, int]] = {}
                for key, value in zip(node.value.keys, node.value.values, strict=True):
                    if not (
                        isinstance(key, ast.Constant)
                        and isinstance(key.value, str)
                        and isinstance(value, ast.Name)
                    ):
                        continue
                    func = functions.get((file_path, value.id))
                    if func is None:
                        continue
                    for capability, line in _agent_capabilities(func).items():
                        exposed.setdefault(capability, (value.id, line))
                if exposed:
                    registries[(file_path, registry_name)] = exposed
    return registries


def _is_model_tool_response_call(call: ast.Call) -> bool:
    if _call_returns_llm_output(call):
        return True
    callee = _dotted_name(call.func).lower()
    tail = callee.rsplit(".", 1)[-1]
    # A bare `chat(messages, tools=...)` wrapper is common in small agents and
    # is sufficiently specific only when it is explicitly given tool schemas.
    return tail in _MODEL_TOOL_CALL_NAMES and any(kw.arg == "tools" for kw in call.keywords)


def _has_tool_feedback_loop(func: ast.AST, callable_names: set[str]) -> bool:
    """True when a registered tool result is fed back into a repeated model call."""
    result_vars: set[str] = set()
    for stmt in ast.walk(func):
        if not isinstance(stmt, (ast.Assign, ast.AnnAssign)) or stmt.value is None:
            continue
        if not (
            isinstance(stmt.value, ast.Call)
            and isinstance(stmt.value.func, ast.Name)
            and stmt.value.func.id in callable_names
        ):
            continue
        targets = stmt.targets if isinstance(stmt, ast.Assign) else [stmt.target]
        for target in targets:
            result_vars |= _bound_names(target)
    if not result_vars:
        return False
    for loop in ast.walk(func):
        if not isinstance(loop, (ast.For, ast.AsyncFor, ast.While)):
            continue
        has_model_call = any(
            isinstance(node, ast.Call) and _is_model_tool_response_call(node)
            for node in ast.walk(loop)
        )
        feeds_result_back = any(
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr in {"append", "extend", "insert", "update"}
            and any(set(_names_in(arg)) & result_vars for arg in node.args)
            for node in ast.walk(loop)
        )
        if has_model_call and feeds_result_back:
            return True
    return False


def _collect_agent_capability_findings(
    parsed: list[tuple[str, ast.AST]],
    import_graph: _ImportGraph,
    registries: dict[tuple[str, str], dict[str, tuple[str, int]]],
) -> list[Finding]:
    """Find model-selected calls into registries exposing dangerous tools."""
    findings: list[Finding] = []
    for file_path, tree in parsed:
        for func in ast.walk(tree):
            if not isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            prompt_tainted = (
                _param_names(func) - _scalar_annotated_params(func)
            ) | _local_source_vars(func)
            prompt_changed = True
            while prompt_changed:
                prompt_changed = False
                for prompt_stmt in _iter_body_statements(func.body):
                    if (
                        isinstance(prompt_stmt, (ast.Assign, ast.AnnAssign))
                        and prompt_stmt.value is not None
                    ):
                        prompt_targets = (
                            prompt_stmt.targets
                            if isinstance(prompt_stmt, ast.Assign)
                            else [prompt_stmt.target]
                        )
                        if set(_names_in(prompt_stmt.value)) & prompt_tainted:
                            before = len(prompt_tainted)
                            for target in prompt_targets:
                                prompt_tainted |= _bound_names(target)
                            prompt_changed |= len(prompt_tainted) != before
                    elif isinstance(prompt_stmt, (ast.For, ast.AsyncFor)):
                        if set(_names_in(prompt_stmt.iter)) & prompt_tainted:
                            before = len(prompt_tainted)
                            prompt_tainted |= _bound_names(prompt_stmt.target)
                            prompt_changed |= len(prompt_tainted) != before
                    elif isinstance(prompt_stmt, ast.Expr) and isinstance(
                        prompt_stmt.value, ast.Call
                    ):
                        mutation = prompt_stmt.value
                        if (
                            isinstance(mutation.func, ast.Attribute)
                            and isinstance(mutation.func.value, ast.Name)
                            and mutation.func.attr in {"append", "extend", "insert", "update"}
                            and any(set(_names_in(arg)) & prompt_tainted for arg in mutation.args)
                            and mutation.func.value.id not in prompt_tainted
                        ):
                            prompt_tainted.add(mutation.func.value.id)
                            prompt_changed = True
            derived: set[str] = set()
            model_line = 0
            changed = True
            while changed:
                changed = False
                for stmt in _iter_body_statements(func.body):
                    if isinstance(stmt, (ast.Assign, ast.AnnAssign)) and stmt.value is not None:
                        targets = stmt.targets if isinstance(stmt, ast.Assign) else [stmt.target]
                        target_names = {n for target in targets for n in _bound_names(target)}
                        value = stmt.value
                        from_model = any(
                            _is_model_tool_response_call(n)
                            and any(
                                _expr_reads_source(arg)
                                or bool(set(_names_in(arg)) & prompt_tainted)
                                for arg in (
                                    *n.args,
                                    *(kw.value for kw in n.keywords if kw.arg != "tools"),
                                )
                            )
                            for n in ast.walk(value)
                            if isinstance(n, ast.Call)
                        )
                        if from_model and not model_line:
                            model_line = getattr(stmt, "lineno", func.lineno)
                        if from_model or set(_names_in(value)) & derived:
                            before = len(derived)
                            derived |= target_names
                            changed |= len(derived) != before
                    elif isinstance(stmt, (ast.For, ast.AsyncFor)):
                        if set(_names_in(stmt.iter)) & derived:
                            before = len(derived)
                            derived |= _bound_names(stmt.target)
                            changed |= len(derived) != before

            if not derived:
                continue
            invoked_names = {
                n.func.id
                for n in ast.walk(func)
                if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
            }
            for stmt in _iter_body_statements(func.body):
                if not isinstance(stmt, (ast.Assign, ast.AnnAssign)) or stmt.value is None:
                    continue
                targets = stmt.targets if isinstance(stmt, ast.Assign) else [stmt.target]
                bound = {n for target in targets for n in _bound_names(target)}
                if not (bound & invoked_names):
                    continue
                lookup = stmt.value
                registry_name: str | None = None
                selector: ast.expr | None = None
                if (
                    isinstance(lookup, ast.Call)
                    and isinstance(lookup.func, ast.Attribute)
                    and lookup.func.attr == "get"
                    and isinstance(lookup.func.value, ast.Name)
                    and lookup.args
                ):
                    registry_name, selector = lookup.func.value.id, lookup.args[0]
                elif isinstance(lookup, ast.Subscript) and isinstance(lookup.value, ast.Name):
                    registry_name, selector = lookup.value.id, lookup.slice
                if registry_name is None or selector is None:
                    continue
                if not (set(_names_in(selector)) & derived):
                    continue
                registry_file = file_path
                resolved_registry_name = registry_name
                imported = import_graph.name_to_def.get((file_path, registry_name))
                if imported is not None:
                    registry_file, resolved_registry_name = imported
                exposed = registries.get((registry_file, resolved_registry_name))
                if not exposed:
                    continue
                capability_text = ", ".join(sorted(exposed))
                sink_capability = sorted(exposed)[0]
                sink_func, sink_line = exposed[sink_capability]
                line = getattr(lookup, "lineno", func.lineno)
                tool_feedback_loop = _has_tool_feedback_loop(func, bound)
                cwe_ids = [284]
                if "unpinned package supply chain execution" in exposed:
                    cwe_ids.append(829)
                findings.append(
                    Finding(
                        rule_id="AGENT-CAPABILITY-001",
                        message=(
                            f"Model-selected tool dispatch in {func.name}() can invoke a registry "
                            f"exposing {capability_text}. Validate tool choice and arguments against "
                            "the current user's authorization before invocation."
                        ),
                        severity=Severity.HIGH,
                        category=Category.AI_ML,
                        file_path=file_path,
                        start_line=line,
                        confidence=BOUNDARY_SOURCE,
                        cwe_ids=cwe_ids,
                        engine="crossfile",
                        taint_flow=TaintFlow(
                            source=TaintNode(file_path=file_path, line=model_line or func.lineno),
                            sink=TaintNode(file_path=registry_file, line=sink_line),
                        ),
                        metadata={
                            "agent_capability_graph": True,
                            "registry": registry_name,
                            "capabilities": sorted(exposed),
                            "example_tool": sink_func,
                            "tool_feedback_loop": tool_feedback_loop,
                        },
                    )
                )
    return findings


def _collect_reflective_tool_findings(
    parsed: list[tuple[str, ast.AST]],
) -> list[Finding]:
    """Detect advertised tool surfaces bypassed by reflective dispatch."""
    findings: list[Finding] = []
    for file_path, tree in parsed:
        literal_surfaces: dict[str, set[str]] = {}
        instances: dict[str, str] = {}
        classes: dict[str, ast.ClassDef] = {}
        for node in getattr(tree, "body", []):
            if isinstance(node, ast.ClassDef):
                classes[node.name] = node
            elif isinstance(node, (ast.Assign, ast.AnnAssign)):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                names = {name for target in targets for name in _bound_names(target)}
                value = node.value
                if isinstance(value, (ast.Tuple, ast.List, ast.Set)) and all(
                    isinstance(item, ast.Constant) and isinstance(item.value, str)
                    for item in value.elts
                ):
                    for name in names:
                        literal_surfaces[name] = {item.value for item in value.elts}
                elif (
                    isinstance(value, ast.Call)
                    and isinstance(value.func, ast.Name)
                    and not value.args
                ):
                    for name in names:
                        instances[name] = value.func.id

        advertised = {
            surface
            for surface in literal_surfaces
            if any(
                isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef))
                and re.search(
                    r"(?:tool|action).*(?:schema|definition)|(?:schema|definition).*(?:tool|action)",
                    fn.name,
                    re.I,
                )
                and any(isinstance(item, ast.Name) and item.id == surface for item in ast.walk(fn))
                and any(
                    isinstance(item, ast.Constant) and item.value == "name" for item in ast.walk(fn)
                )
                for fn in getattr(tree, "body", [])
            )
        }
        if not advertised:
            continue
        public_names = set().union(*(literal_surfaces[name] for name in advertised))

        for fn in (
            node
            for node in getattr(tree, "body", [])
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        ):
            params = _param_names(fn)
            for call in (node for node in ast.walk(fn) if isinstance(node, ast.Call)):
                if not (
                    isinstance(call.func, ast.Name)
                    and call.func.id == "getattr"
                    and len(call.args) >= 2
                    and isinstance(call.args[0], ast.Name)
                    and isinstance(call.args[1], ast.Name)
                    and call.args[1].id in params
                ):
                    continue
                selector = call.args[1].id
                if _has_rejecting_surface_guard(fn, call, selector, advertised):
                    continue
                assigned = {
                    name
                    for statement in ast.walk(fn)
                    if isinstance(statement, (ast.Assign, ast.AnnAssign))
                    and statement.value is call
                    for target in (
                        statement.targets
                        if isinstance(statement, ast.Assign)
                        else [statement.target]
                    )
                    for name in _bound_names(target)
                }
                if not assigned or not any(
                    isinstance(invocation, ast.Call)
                    and isinstance(invocation.func, ast.Name)
                    and invocation.func.id in assigned
                    for invocation in ast.walk(fn)
                ):
                    continue
                class_name = instances.get(call.args[0].id)
                cls = classes.get(class_name or "")
                if cls is None:
                    continue
                hidden_capabilities: dict[str, int] = {}
                for method in cls.body:
                    if (
                        isinstance(method, (ast.FunctionDef, ast.AsyncFunctionDef))
                        and method.name not in public_names
                    ):
                        hidden_capabilities.update(_agent_capabilities(method))
                if not hidden_capabilities:
                    continue
                capability_text = ", ".join(sorted(hidden_capabilities))
                findings.append(
                    Finding(
                        rule_id="AGENT-REFLECTION-SURFACE-001",
                        message=(
                            f"Reflective tool dispatch in {fn.name}() passes a caller/model-selected "
                            f"name to getattr() without enforcing the advertised action surface. "
                            f"Unadvertised methods expose {capability_text}."
                        ),
                        severity=Severity.HIGH,
                        category=Category.AI_ML,
                        file_path=file_path,
                        start_line=call.lineno,
                        confidence=0.95,
                        cwe_ids=[470],
                        engine="crossfile",
                        taint_flow=TaintFlow(
                            source=TaintNode(file_path=file_path, line=fn.lineno),
                            sink=TaintNode(file_path=file_path, line=call.lineno),
                        ),
                        metadata={
                            "advertised_surface": sorted(public_names),
                            "hidden_capabilities": sorted(hidden_capabilities),
                            "receiver_class": class_name,
                        },
                    )
                )
    return findings


def _has_rejecting_surface_guard(
    fn: ast.AST,
    sink: ast.Call,
    selector: str,
    surfaces: set[str],
) -> bool:
    for node in ast.walk(fn):
        if not isinstance(node, ast.If) or node.lineno >= sink.lineno:
            continue
        names = {item.id for item in ast.walk(node.test) if isinstance(item, ast.Name)}
        if selector not in names or not (names & surfaces):
            continue
        if any(
            isinstance(item, (ast.Return, ast.Raise, ast.Continue, ast.Break))
            for statement in node.body
            for item in ast.walk(statement)
        ):
            return True
    return False


_CONFIRMATION_TEXT_RE = re.compile(r"confirm|approv|consent|authoriz", re.IGNORECASE)
_TRANSCRIPT_NAME_RE = re.compile(
    r"message|msgs|context|transcript|conversation|history|prompt|content|tool_result",
    re.IGNORECASE,
)


def _collect_confirmation_provenance_findings(
    parsed: list[tuple[str, ast.AST]],
) -> list[Finding]:
    """Detect approval decisions derived from attacker-influenceable text.

    Human approval must arrive as trusted application state. Searching prompt,
    context, or tool-result text for a marker lets that same content forge the
    approval and is unsafe even though a visible confirmation check exists.
    """
    findings: list[Finding] = []
    for file_path, tree in parsed:
        marker_names: set[str] = set()
        for stmt in getattr(tree, "body", []):
            if not isinstance(stmt, (ast.Assign, ast.AnnAssign)) or stmt.value is None:
                continue
            if not (
                isinstance(stmt.value, ast.Constant)
                and isinstance(stmt.value.value, str)
                and _CONFIRMATION_TEXT_RE.search(stmt.value.value)
            ):
                continue
            targets = stmt.targets if isinstance(stmt, ast.Assign) else [stmt.target]
            for target in targets:
                marker_names |= _bound_names(target)

        for func in ast.walk(tree):
            if not isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            function_context = (
                func.name
                + " "
                + " ".join(_dotted_name(n.func) for n in ast.walk(func) if isinstance(n, ast.Call))
            )
            if not re.search(r"agent|tool|guard|confirm|approv|execut", function_context, re.I):
                continue
            for compare in (n for n in ast.walk(func) if isinstance(n, ast.Compare)):
                operands: list[ast.expr] = [compare.left, *compare.comparators]
                marker_operand = any(
                    (
                        isinstance(operand, ast.Constant)
                        and isinstance(operand.value, str)
                        and _CONFIRMATION_TEXT_RE.search(operand.value)
                    )
                    or (isinstance(operand, ast.Name) and operand.id in marker_names)
                    for operand in operands
                )
                if not marker_operand:
                    continue
                transcript_operand = any(
                    _TRANSCRIPT_NAME_RE.search(name)
                    for operand in operands
                    for name in _names_in(operand)
                    if name not in marker_names
                )
                if not transcript_operand:
                    continue
                line = getattr(compare, "lineno", func.lineno)
                findings.append(
                    Finding(
                        rule_id="AGENT-CONFIRMATION-001",
                        message=(
                            "Agent authorization is inferred from a confirmation marker in prompt, "
                            "context, transcript, or tool-result text. That content can forge the "
                            "marker; bind approval to trusted application state and user identity."
                        ),
                        severity=Severity.HIGH,
                        category=Category.AI_ML,
                        file_path=file_path,
                        start_line=line,
                        confidence=BOUNDARY_SOURCE,
                        cwe_ids=[345],
                        engine="crossfile",
                        taint_flow=TaintFlow(
                            source=TaintNode(file_path=file_path, line=func.lineno),
                            sink=TaintNode(file_path=file_path, line=line),
                        ),
                        metadata={
                            "agent_capability_graph": True,
                            "confirmation_provenance": "transcript_text",
                        },
                    )
                )
    return findings


def _collect_boundary_nodes(tree: ast.AST) -> dict[int, str]:
    """Union of every recognized structural trust-boundary function in this
    file, mapped to its kind ("agent_tool"/"task_queue"/"grpc"/"graphql"/
    "webhook") -- id()s valid for the lifetime of this parsed tree, which
    CrossFilePass holds for the duration of a single scan. Later collectors
    win on overlap (rare in practice -- e.g. a GraphQL resolver would need
    to also be @tool-decorated); any single tag is enough to mark the
    function as a source and widen its sink detection."""
    kind_by_id: dict[int, str] = {}
    for node_id in _collect_agent_tool_nodes(tree):
        kind_by_id[node_id] = "agent_tool"
    for node_id in _collect_task_queue_nodes(tree):
        kind_by_id[node_id] = "task_queue"
    for node_id in _collect_grpc_servicer_nodes(tree):
        kind_by_id[node_id] = "grpc"
    for node_id in _collect_graphql_resolver_nodes(tree):
        kind_by_id[node_id] = "graphql"
    for node_id in _collect_webhook_handler_nodes(tree):
        kind_by_id[node_id] = "webhook"
    for node_id in _collect_http_route_nodes(tree):
        kind_by_id.setdefault(node_id, "http_route")
    return kind_by_id


def _is_url_fetch_call(call: ast.Call, http_clients: set[str] = frozenset()) -> bool:
    func = call.func
    return (
        isinstance(func, ast.Attribute)
        and isinstance(func.value, ast.Name)
        and (func.value.id in ("requests", "httpx") or func.value.id in http_clients)
    )


# Client objects whose request methods take a URL, and pathlib methods that
# touch the file a Path names.
_HTTP_CLIENT_FACTORIES = frozenset({
    "httpx.AsyncClient", "httpx.Client", "requests.Session", "requests.session",
    "aiohttp.ClientSession",
})
_HTTP_CLIENT_METHODS = frozenset({"get", "post", "put", "patch", "delete", "head", "request", "stream"})
_PATHLIB_SINK_METHODS = frozenset({
    "open", "read_text", "read_bytes", "write_text", "write_bytes", "unlink", "rmdir", "mkdir", "touch",
})
_PATH_CONSTRUCTORS = frozenset({"Path", "PurePath", "PosixPath", "WindowsPath"})


# A statement-form validator (`validate_public_url(url)`) raises on bad input,
# so the names it checks are clean afterwards; likewise a request hook with such
# a name guards every request an HTTP client makes.
_GUARD_NAME_RE = re.compile(
    r"^(?:validate|sanitize|assert|ensure|check_(?:safe|valid|allowed|public)|guard)"
    r"|_(?:ssrf_)?guard|(?:^|_)(?:safe|ssrf)_(?:guard|check)",
    re.IGNORECASE,
)


def _statement_guarded_names(stmt: ast.stmt) -> set[str]:
    """Names checked by `validate_x(name)` used as a bare statement."""
    if not isinstance(stmt, ast.Expr):
        return set()
    call = stmt.value.value if isinstance(stmt.value, ast.Await) else stmt.value
    if not isinstance(call, ast.Call):
        return set()
    func = call.func
    name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", "")
    if not _GUARD_NAME_RE.search(name):
        return set()
    return {a.id for a in call.args if isinstance(a, ast.Name)}


def _fullmatch_guarded_names(stmt: ast.If) -> set[str]:
    """Names checked by an allowlist that exits:
    `if not PATTERN.fullmatch(name): raise ...`."""
    test = stmt.test
    exits = bool(stmt.body) and isinstance(stmt.body[-1], (ast.Raise, ast.Return))
    if not (exits and isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not)):
        return set()
    call = test.operand
    if not (isinstance(call, ast.Call) and isinstance(call.func, ast.Attribute)
            and call.func.attr == "fullmatch"):
        return set()
    # `PATTERN.fullmatch(name)` or `re.fullmatch(pattern, name)`.
    subject = call.args[1] if _dotted_name(call.func) == "re.fullmatch" and len(call.args) > 1 else (
        call.args[0] if call.args else None
    )
    return {subject.id} if isinstance(subject, ast.Name) else set()


def _has_guard_hook(factory: ast.Call) -> bool:
    """`httpx.AsyncClient(event_hooks={"request": [ssrf_guard]})`."""
    return any(
        kw.arg == "event_hooks"
        and any(
            _GUARD_NAME_RE.search(n.id if isinstance(n, ast.Name) else n.attr)
            for n in ast.walk(kw.value)
            if isinstance(n, (ast.Name, ast.Attribute))
        )
        for kw in factory.keywords
    )


def _http_client_names(stmt: ast.stmt) -> set[str]:
    """Names bound to an HTTP client object: `with httpx.AsyncClient() as c`
    or `session = requests.Session()`."""
    bound: list[tuple[ast.expr, ast.expr | None]] = []
    if isinstance(stmt, (ast.With, ast.AsyncWith)):
        bound = [(item.context_expr, item.optional_vars) for item in stmt.items]
    elif isinstance(stmt, ast.Assign) and len(stmt.targets) == 1:
        bound = [(stmt.value, stmt.targets[0])]
    return {
        target.id
        for value, target in bound
        if isinstance(target, ast.Name)
        and isinstance(value, ast.Call)
        and _dotted_name(value.func) in _HTTP_CLIENT_FACTORIES
        and not _has_guard_hook(value)
    }


def _tool_object_sink_operands(call: ast.Call, http_clients: set[str]) -> list[ast.expr]:
    """The operand a model-chosen value must reach for a method-call sink:
    the URL of `client.get(url)`, or the path of `Path(p).read_text()`."""
    func = call.func
    if not isinstance(func, ast.Attribute):
        return []
    receiver = func.value
    if isinstance(receiver, ast.Name) and receiver.id in http_clients:
        return call.args[:1] if func.attr in _HTTP_CLIENT_METHODS else []
    if func.attr not in _PATHLIB_SINK_METHODS:
        return []
    if isinstance(receiver, ast.Call) and _base_ref_name(receiver.func) in _PATH_CONSTRUCTORS:
        return receiver.args[:1]
    return [receiver] if isinstance(receiver, (ast.Name, ast.BinOp)) else []


# String methods that return the same attacker-chosen text, reshaped.
_STR_TRANSFORMS = frozenset({
    "replace", "strip", "lstrip", "rstrip", "lower", "upper", "casefold",
    "title", "removeprefix", "removesuffix", "encode", "decode",
})


def _str_transform_source(expr: ast.expr) -> str | None:
    """`x` in `x.strip().replace("^", "**")`; None for anything else, and for
    a `.replace("..", "")` traversal strip, which is judged as a sanitizer."""
    while (
        isinstance(expr, ast.Call)
        and isinstance(expr.func, ast.Attribute)
        and expr.func.attr in _STR_TRANSFORMS
        and not _is_replace_traversal_call(expr)
    ):
        expr = expr.func.value
    return expr.id if isinstance(expr, ast.Name) else None


def _tool_string_arg_taint(
    arg: ast.expr, var_taint: dict[str, _VarTaint], host_only: bool
) -> _VarTaint | None:
    """Taint of a tool parameter inside `arguments["path"]`, an f-string or a
    `+` concatenation. For a URL fetch only the leading part can choose the
    host: `f"{API_BASE}/items/{item_id}"` is path-only, not SSRF."""
    if isinstance(arg, ast.Subscript):
        return var_taint.get(arg.value.id) if isinstance(arg.value, ast.Name) else None
    if isinstance(arg, ast.JoinedStr):
        parts = [v.value for v in arg.values if isinstance(v, ast.FormattedValue)]
        if host_only:
            first = arg.values[0] if arg.values else None
            parts = [first.value] if isinstance(first, ast.FormattedValue) else []
    elif isinstance(arg, ast.BinOp) and isinstance(arg.op, ast.Add):
        parts = [arg.left] if host_only else [arg.left, arg.right]
    else:
        return None
    for part in parts:
        if isinstance(part, ast.Name) and part.id in var_taint:
            return var_taint[part.id]
        if isinstance(part, (ast.Subscript, ast.JoinedStr, ast.BinOp)):
            state = _tool_string_arg_taint(part, var_taint, host_only)
            if state is not None:
                return state
    return None


def _is_tool_sink_call(call: ast.Call) -> bool:
    if _is_sink_call(call):
        return True
    func = call.func
    if isinstance(func, ast.Name):
        return func.id in _TOOL_BARE_SINKS
    if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
        allowed = _TOOL_QUALIFIED_SINKS.get(func.value.id)
        return bool(allowed) and func.attr in allowed
    return False


def _infer_agent_tool_category(message: str) -> Category:
    """Best-effort category for an agent-tool finding, from the sink name
    already embedded in its message (reaches eval()/os.system()/requests.get()/...)."""
    if any(f"{name}(" in message for name in ("eval", "exec", "sympify", "parse_expr")):
        return Category.INJECTION
    lower = message.lower()
    if any(kw in lower for kw in ("subprocess", "os.system(", "os.popen(", "shell command")):
        return Category.COMMAND_INJECTION
    if any(kw in lower for kw in ("requests.", "httpx.", "outbound http", "http client", "ssrf")):
        return Category.SSRF
    return Category.PATH_TRAVERSAL


_AGENT_TOOL_CWE = {
    Category.COMMAND_INJECTION: 78,
    Category.PATH_TRAVERSAL: 22,
    Category.SSRF: 918,
    Category.INJECTION: 95,
}


@dataclass
class _VarTaint:
    is_path: bool = False
    sanitizer: str | None = None


def _is_replace_traversal_call(node: ast.AST) -> bool:
    """True if `node` is a `<expr>.replace(<traversal literal>, ...)` call --
    a single-pass strip of a literal `../`/`..\\`/`..` sequence."""
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "replace"
        and any(
            isinstance(arg, ast.Constant) and arg.value in _TRAVERSAL_LITERALS for arg in node.args
        )
    )


def _expr_has_containment_normalize_call(expr: ast.AST) -> bool:
    """True if `expr` itself (or anything nested inside it) is a call to a
    path-normalizing function (realpath/abspath/resolve/commonpath/
    commonprefix)."""
    return any(
        isinstance(n, ast.Call)
        and isinstance(n.func, ast.Attribute)
        and n.func.attr in _CONTAINMENT_NORMALIZE_ATTRS
        for n in ast.walk(expr)
    )


def _stmt_own_check_exprs(stmt: ast.stmt) -> list[ast.expr]:
    """Expressions that belong to `stmt` itself, not to a nested block it
    introduces (those are visited as their own statements by
    `iter_body_statements`) -- used to attribute a containment-check node to
    the specific statement that must dominate the function's returns (issue
    #124), analogous to `_statement_own_calls` above but also covering
    `If`/`While`/`Assert` tests and `Raise` expressions, since a containment
    check very commonly lives in a guard test or a raise, not just an
    assignment/return value."""
    if isinstance(stmt, (ast.If, ast.While, ast.Assert)):
        return [stmt.test]
    if isinstance(stmt, (ast.For, ast.AsyncFor)):
        return [stmt.iter]
    if isinstance(stmt, (ast.With, ast.AsyncWith)):
        return [item.context_expr for item in stmt.items]
    if isinstance(stmt, ast.Raise):
        return [stmt.exc] if stmt.exc is not None else []
    if (
        isinstance(stmt, (ast.Return, ast.Assign, ast.AnnAssign, ast.AugAssign))
        and stmt.value is not None
    ):
        return [stmt.value]
    if isinstance(stmt, ast.Expr):
        return [stmt.value]
    return []


def _classify_path_sanitizer(func_def: ast.AST) -> str:
    """Classify a locally-defined function as a path-traversal sanitizer.

    Returns "strong" (a proper containment check via realpath/resolve +
    commonpath/is_relative_to, or a strip that repeats to a fixed point),
    "weak" (a single non-recursive strip of a literal traversal sequence --
    bypassable, e.g. "....//" collapses to "../" after one substitution
    pass), or "unknown" (doesn't look like a path sanitizer at all, e.g. a
    quote-escaper -- treated conservatively as safe to avoid flagging
    unrelated helper calls).

    A containment check only counts if the normalizing call's result (or a
    variable it was assigned to) actually feeds a comparison/containment
    idiom (`==`/`!=` against a base var, `.startswith(...)`, or
    `.is_relative_to(...)`, whose own return value IS the check) --
    otherwise a function that merely calls realpath()/abspath() as an
    incidental normalization step, with no actual containment check, was
    being misclassified as "strong" and suppressing a real finding. A loop
    only counts toward the fixed-point "strong" strip if its OWN body
    re-applies the same traversal-literal `.replace(...)` -- an unrelated
    loop elsewhere in the function no longer upgrades a single-pass strip.

    GitHub issue #124: a containment check only earns "strong" if it
    actually *dominates* every `return <value>` in the function -- not
    merely if it exists somewhere in the body. A check sitting in a branch
    that doesn't guard the function's actual return (e.g. behind an
    unrelated `if debug_mode:`, with the real return sitting unconditionally
    after that `if`) was previously classified "strong" even though it's
    dead code on the path that returns the "sanitized" value. This reuses
    `collect_dominating_candidates` (`rowan/analysis/dominance.py`,
    shared with `guard_clause.py`'s early-return guard fix) rather than a
    full CFG/dominator tree. Functions with no `return <value>` statement
    (bare `return`/implicit `None` only) have nothing for the check to
    dominate, so the dominance requirement is vacuously satisfied and
    behavior is unchanged for that shape.
    """
    # Variables assigned directly from a realpath/abspath/resolve/
    # commonpath/commonprefix call -- if the variable later feeds a
    # comparison, that still counts even though the call and the
    # comparison are on different lines.
    containment_result_vars: set[str] = set()
    for node in ast.walk(func_def):
        if (
            isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
            and _expr_has_containment_normalize_call(node.value)
        ):
            containment_result_vars.add(node.targets[0].id)

    def _feeds_containment_check(operand: ast.expr) -> bool:
        return _expr_has_containment_normalize_call(operand) or any(
            isinstance(n, ast.Name) and n.id in containment_result_vars for n in ast.walk(operand)
        )

    def _expr_has_containment_check(expr: ast.expr) -> bool:
        for node in ast.walk(expr):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "is_relative_to"
            ):
                # The call's own return value IS the containment check.
                return True
            if isinstance(node, ast.Compare) and any(
                isinstance(op, (ast.Eq, ast.NotEq)) for op in node.ops
            ):
                operands = [node.left, *node.comparators]
                if any(_feeds_containment_check(o) for o in operands):
                    return True
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "startswith"
            ):
                operands = [node.func.value, *node.args]
                if any(_feeds_containment_check(o) for o in operands):
                    return True
        return False

    has_containment_check = False
    has_replace_traversal = False
    has_fixed_point_loop = False
    checking_stmts: list[ast.stmt] = []
    for node in ast.walk(func_def):
        if isinstance(node, (ast.For, ast.While)):
            if any(_is_replace_traversal_call(n) for n in ast.walk(node)):
                has_fixed_point_loop = True
        elif _is_replace_traversal_call(node):
            has_replace_traversal = True

    if isinstance(func_def, (ast.FunctionDef, ast.AsyncFunctionDef)):
        for stmt in _iter_body_statements(func_def.body):
            if any(_expr_has_containment_check(e) for e in _stmt_own_check_exprs(stmt)):
                has_containment_check = True
                checking_stmts.append(stmt)

        return_lines = [
            stmt.lineno
            for stmt in _iter_body_statements(func_def.body)
            if isinstance(stmt, ast.Return) and stmt.value is not None
        ]
        if has_containment_check and return_lines:
            has_containment_check = any(
                all(
                    cstmt in _collect_dominating_candidates(func_def.body, rline)[1]
                    for rline in return_lines
                )
                for cstmt in checking_stmts
            )
    else:
        # No statement body to walk (shouldn't normally happen for a real
        # function def) -- fall back to the previous whole-subtree scan so
        # this degrades gracefully rather than silently classifying
        # "unknown".
        has_containment_check = _expr_has_containment_check(func_def)

    if has_containment_check:
        return "strong"
    if has_replace_traversal:
        return "strong" if has_fixed_point_loop else "weak"
    # `if os.path.isabs(name): return name` in a helper with no containment
    # check anywhere hands the input back unchanged: a path builder, not a
    # sanitizer. (A check that guards only some returns stays "unknown".)
    if isinstance(func_def, (ast.FunctionDef, ast.AsyncFunctionDef)) and not checking_stmts:
        params = set(_param_names(func_def))
        if any(
            isinstance(stmt, ast.Return) and isinstance(stmt.value, ast.Name) and stmt.value.id in params
            for stmt in _iter_body_statements(func_def.body)
        ):
            return "absent"
    return "unknown"


def _declared_params(func_node: ast.FunctionDef | ast.AsyncFunctionDef) -> list[ast.arg]:
    """Parameters in binding order: positional-only, regular, keyword-only.

    Positional indices stay valid for `edge_bindings`, and keyword-only names
    resolve through `params.index(name)`; a sink fed by `def run(*, cmd)` or
    `def run(cmd, /)` is otherwise invisible (XF-05).
    """
    args = func_node.args
    return [*args.posonlyargs, *args.args, *args.kwonlyargs]


def _param_names(func_node: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    args = func_node.args
    names = {a.arg for a in (*args.args, *args.posonlyargs, *args.kwonlyargs)}
    if args.vararg is not None:
        names.add(args.vararg.arg)
    if args.kwarg is not None:
        names.add(args.kwarg.arg)
    names -= _SELF_QUALIFIERS
    return names


#: Type annotations whose values structurally cannot carry a string-injection /
#: path-traversal / SQL / deserialization payload (#121). An `int`/`float`/
#: `bool`/`complex`-annotated value is a number, not attacker-controllable text
#: -- even if a caller passes something tainted, the developer's declared
#: contract is a scalar, and a real type checker would reject a str there. Note
#: `str`/`bytes`/`Any`/custom types are deliberately EXCLUDED: those absolutely
#: can carry a payload. `Optional[int]` / `int | None` count as safe (their only
#: non-int value is None), via `_annotation_class_name`'s unwrapping.
_SAFE_SCALAR_ANNOTATIONS = frozenset({"int", "float", "bool", "complex"})


def _scalar_annotated_params(func_node: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    """Parameter names annotated with a taint-incapable scalar type (#121).
    These are excluded from every taint-carrier set in this pass -- a value the
    author declared `: int` is treated as sanitized at the parameter boundary."""
    safe: set[str] = set()
    for a in (
        *func_node.args.args,
        *func_node.args.posonlyargs,
        *func_node.args.kwonlyargs,
    ):
        if a.arg in _SELF_QUALIFIERS:
            continue
        if _annotation_class_name(a.annotation) in _SAFE_SCALAR_ANNOTATIONS:
            safe.add(a.arg)
    return safe


# Builtins that reduce their argument to a content-independent scalar: a length,
# an identity/hash, a codepoint, a validated number/bool, or a type. The value
# they return does not carry the argument's injectable *content*, so a parameter
# that appears in the return only to be reduced this way is NOT propagated to
# callers as tainted. Without this, `return len(encoding.encode(s))` read as
# "returns s" and manufactured cross-file return-taint false positives on every
# count/parse/validate utility (e.g. ragflow's num_tokens_from_string()).
_TAINT_NEUTRALIZING_RETURN_BUILTINS = frozenset(
    {
        "len",
        "id",
        "hash",
        "ord",
        "bool",
        "int",
        "float",
        "isinstance",
        "type",
    }
)

_SECURITY_DECISION_CALLS = frozenset(
    {
        "compare_digest",
        "check_password",
        "verify_password",
        "verify_signature",
    }
)


def _is_taint_neutralizing_return(value: ast.expr) -> bool:
    """True if `value` is a direct call to a scalar-reducing builtin whose
    result is content-independent (see `_TAINT_NEUTRALIZING_RETURN_BUILTINS`).
    Conservative: only the outermost call is inspected, so a return that merely
    *contains* such a call among other tainted parts (a tuple, an f-string) is
    left to propagate normally."""
    if not isinstance(value, ast.Call):
        return False
    if isinstance(value.func, ast.Name):
        name = value.func.id
    elif isinstance(value.func, ast.Attribute):
        name = value.func.attr
    else:
        return False
    return name in _TAINT_NEUTRALIZING_RETURN_BUILTINS or name in _SECURITY_DECISION_CALLS


def _is_fixed_catalog_lookup(call: ast.Call) -> bool:
    """True for ``ALL_CAPS_MAP.get(user_key[, literal_default])``.

    This common allowlist/catalog idiom returns a code-owned value selected by
    untrusted input, rather than returning the input itself. Requiring an
    ALL_CAPS receiver and a literal/omitted default keeps ordinary mutable
    dictionaries and caller-controlled fallback values tainted.
    """
    return (
        isinstance(call.func, ast.Attribute)
        and call.func.attr == "get"
        and isinstance(call.func.value, ast.Name)
        and call.func.value.id.isupper()
        and len(call.args) in {1, 2}
        and (len(call.args) == 1 or isinstance(call.args[1], ast.Constant))
    )


def _looks_sanitized(call: ast.Call) -> bool:
    """True if `call`'s source text matches ANY registered sanitizer pattern,
    from ANY category (`rowan.rules_registry.SANITIZER_REGEX`, the
    Phase A shared registry, issue #159). Used only by `_summarize_params`
    (#119): a per-parameter procedure summary doesn't yet know which
    category's sink a value will ultimately reach, so it treats a value as
    sanitized once it passes through ANY recognized sanitizer call -- a
    deliberately conservative (favors NOT flagging over over-flagging)
    approximation, consistent with this codebase's precision-first bias."""
    if _is_fixed_catalog_lookup(call) or _is_taint_neutralizing_return(call):
        return True
    # Match the CALLEE and constant keyword arguments only. Searching the
    # whole unparsed call let the `int(` pattern match inside `hint("x")` and `print(`,
    # clearing taint on an unrelated argument (XF-03).
    try:
        callee = ast.unparse(call.func) + "("
        constant_kwargs = " ".join(
            ast.unparse(kw) for kw in call.keywords if isinstance(kw.value, ast.Constant)
        )
    except Exception:
        return False
    for category in Category:
        for s in call_sanitizers(category):
            if re.search(_anchor_callee_pattern(s.pattern), callee):
                return True
        if constant_kwargs:
            for s in shape_sanitizers(category):
                if s.search(constant_kwargs):
                    return True
    return False


def _anchor_callee_pattern(pat: str) -> str:
    """A registry pattern that starts with a name (the `int(` pattern) must
    not match the tail of a longer name (`print(`, `hint(`)."""
    return rf"(?<![\w.]){pat}" if pat and (pat[0].isalnum() or pat[0] == "_") else pat


def _summarize_params(
    func_node: ast.FunctionDef | ast.AsyncFunctionDef, sink_line: int
) -> tuple[frozenset[int], frozenset[int]]:
    """Compute a lightweight per-parameter procedure summary (#119):
    (sink_params, return_params), each a set of 0-based positional-parameter
    indices.

    `sink_params`: which parameters' values reach the function's own sink
    call, already resolved by the primary taint/neuroscan/structural-sink
    detectors at `sink_line` -- this does NOT re-detect what counts as a
    sink, only which parameter(s) feed the ALREADY-known one. Empty (but not
    None) when the sink call's arguments don't depend on any parameter at
    all (e.g. `os.system("ls")`) -- correctly meaning no caller can ever
    trigger a finding through this callee, since the sink is unconditional.

    `return_params`: which parameters' values reach an `ast.Return` --
    independent of `sink_line`/has_sink, this is the "does this function
    pass a parameter straight through" signal (`def passthru(p): return p`).

    Implementation: a small intra-procedural fixpoint tracking, per local
    variable name, the SET of parameter indices whose taint could have
    produced it (`origins`). An assignment's RHS names are looked up in
    `origins` and unioned onto the LHS name(s); this is monotonic (a name,
    once it acquires an origin, never loses it even if later reassigned to
    something clean) and iterates to a fixpoint, so taint threads through
    any number of local reassignments. A value assigned directly from a
    recognized sanitizer call (`_looks_sanitized`) does NOT propagate its
    argument's origins onto the target -- but per the same monotonic
    limitation, a LATER reassignment through a sanitizer does not retroactively
    clear an EARLIER taint already recorded for that name; this mirrors the
    existing accepted imprecision in `_local_source_vars` elsewhere in this
    file rather than inventing a new, more precise (and much larger) flow-
    sensitive model for this one helper.
    """
    param_index = {
        a.arg: i
        for i, a in enumerate(_declared_params(func_node))
        if a.arg not in _SELF_QUALIFIERS
    }
    if not param_index:
        return frozenset(), frozenset()

    # #121: a parameter the author annotated as a taint-incapable scalar
    # (`: int`/`float`/`bool`) is never seeded as a taint origin, so it can
    # never appear in sink_params/return_params -- the annotation is treated
    # as a sanitizing contract at the parameter boundary.
    safe_scalar = _scalar_annotated_params(func_node)
    origins: dict[str, frozenset[int]] = {
        name: frozenset({idx}) for name, idx in param_index.items() if name not in safe_scalar
    }

    def _spread(target_names: set[str], combined: set[int]) -> bool:
        moved = False
        for name in target_names:
            existing = origins.get(name, frozenset())
            merged = existing | combined
            if merged != existing:
                origins[name] = frozenset(merged)
                moved = True
        return moved

    changed = True
    while changed:
        changed = False
        for stmt in _iter_body_statements(func_node.body):
            # Iterating a tainted collection taints the loop target. Batch
            # loops over model responses (`for out in llm.generate(...)`,
            # `for k, v in parsed.items()`) are the norm in AI/ML pipelines,
            # and stopping at the loop boundary broke the summary for every
            # callee that consumes its parameter that way.
            if isinstance(stmt, (ast.For, ast.AsyncFor)):
                combined = set()
                for n in _names_in(stmt.iter):
                    combined |= origins.get(n, frozenset())
                if combined and _spread(_bound_names(stmt.target), combined):
                    changed = True
                continue
            # Mutating a prompt/context collection carries the appended
            # parameter origins into the collection itself. Agent loops
            # commonly build `messages` this way before passing it to chat().
            if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
                mutation = stmt.value
                if (
                    isinstance(mutation.func, ast.Attribute)
                    and isinstance(mutation.func.value, ast.Name)
                    and mutation.func.attr in {"append", "extend", "insert", "update"}
                ):
                    combined = set()
                    for arg in mutation.args:
                        for name in _names_in(arg):
                            combined |= origins.get(name, frozenset())
                    if combined and _spread({mutation.func.value.id}, combined):
                        changed = True
                continue
            if not (isinstance(stmt, (ast.Assign, ast.AnnAssign)) and stmt.value is not None):
                continue
            targets = stmt.targets if isinstance(stmt, ast.Assign) else [stmt.target]
            target_names: set[str] = set()
            for t in targets:
                if isinstance(t, (ast.Name, ast.Tuple, ast.List)):
                    target_names |= _bound_names(t)
            if not target_names:
                continue
            value = stmt.value
            if isinstance(value, ast.Call) and _looks_sanitized(value):
                continue
            combined = set()
            for n in _names_in(value):
                combined |= origins.get(n, frozenset())
            if not combined:
                continue
            if _spread(target_names, combined):
                changed = True

    sink_params: set[int] = set()
    return_params: set[int] = set()

    for stmt in _iter_body_statements(func_node.body):
        if isinstance(stmt, ast.Return) and stmt.value is not None:
            if _is_taint_neutralizing_return(stmt.value):
                continue
            for n in _names_in(stmt.value):
                return_params |= origins.get(n, frozenset())

    if sink_line:
        # The sink finding may sit on any line of a multi-line call (a regex
        # rule matching the `shell=True` kwarg line), so match by span and
        # take the outermost enclosing call (XF-01).
        spanning = [
            call
            for call in ast.walk(func_node)
            if isinstance(call, ast.Call)
            and getattr(call, "lineno", 0) <= sink_line <= _call_end_line(call)
        ]
        if spanning:
            call = min(spanning, key=lambda c: (c.lineno, -_call_end_line(c)))
            for arg in (*call.args, *(kw.value for kw in call.keywords)):
                for n in _names_in(arg):
                    sink_params |= origins.get(n, frozenset())

    return frozenset(sink_params), frozenset(return_params)


def _call_end_line(call: ast.Call) -> int:
    return getattr(call, "end_lineno", None) or getattr(call, "lineno", 0)


def _looks_like_base_dir(node: ast.expr) -> bool:
    """True if a join argument looks like a configured base directory
    (ALL_CAPS constant or a DIR/ROOT/BASE-suffixed name), not a user part."""
    if isinstance(node, ast.Call) and len(node.args) == 1:
        return _looks_like_base_dir(node.args[0])  # unwrap str(BASE_DIR) etc.
    name = _base_ref_name(node)
    if not name:
        return False
    return name.isupper() or bool(_BASE_DIR_NAME_RE.search(name))


def _base_ref_name(node: ast.expr) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def _join_call_parts(call: ast.Call) -> tuple[bool, list[ast.expr]] | None:
    """If `call` is an os.path.join(...)-shaped call, return (has_dirlike_base, other_args)."""
    if not (isinstance(call.func, ast.Attribute) and call.func.attr == "join") or not call.args:
        return None
    base, *rest = call.args
    return (_looks_like_base_dir(base), rest)


def _names_in(expr: ast.expr) -> list[str]:
    return [n.id for n in ast.walk(expr) if isinstance(n, ast.Name)]


# Calls that reduce a value to one path component, so joining it under a base
# directory cannot climb out of it.
_PATH_COMPONENT_REDUCERS = frozenset({"basename", "secure_filename"})


def _names_outside_path_reducers(expr: ast.expr) -> list[str]:
    """`_names_in`, skipping values passed through `os.path.basename(...)` or
    `secure_filename(...)`: `join(BASE, basename(x))` stays under BASE."""
    if isinstance(expr, ast.Call):
        func = expr.func
        tail = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", "")
        if tail in _PATH_COMPONENT_REDUCERS:
            return []
    # `Path(p).name` / `.stem` is one path component, like basename(p).
    if (
        isinstance(expr, ast.Attribute)
        and expr.attr in ("name", "stem")
        and isinstance(expr.value, ast.Call)
        and _base_ref_name(expr.value.func) in _PATH_CONSTRUCTORS
    ):
        return []
    if isinstance(expr, ast.Name):
        return [expr.id]
    return [name for child in ast.iter_child_nodes(expr) for name in _names_outside_path_reducers(child)]


def _expr_path_taint(expr: ast.expr, var_taint: dict[str, _VarTaint]) -> _VarTaint | None:
    """Resolve an expression to a _VarTaint if it names, or structurally
    builds, a path derived from a base-dir join with a tainted part."""
    if isinstance(expr, ast.Name):
        state = var_taint.get(expr.id)
        return state if state and state.is_path else None
    if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Div):
        if _looks_like_base_dir(expr.left):
            for name in _names_outside_path_reducers(expr.right):
                state = var_taint.get(name)
                if state:
                    return _VarTaint(is_path=True, sanitizer=state.sanitizer)
        return None
    if isinstance(expr, ast.Call):
        joined = _join_call_parts(expr)
        if joined is not None:
            has_base, rest = joined
            if has_base:
                for part in rest:
                    for name in _names_outside_path_reducers(part):
                        state = var_taint.get(name)
                        if state:
                            return _VarTaint(is_path=True, sanitizer=state.sanitizer)
            return None
        for arg in (*expr.args, *(kw.value for kw in expr.keywords)):
            found = _expr_path_taint(arg, var_taint)
            if found is not None:
                return found
        return None
    return None


def _statement_own_calls(stmt: ast.stmt) -> list[ast.Call]:
    """Call expressions on a statement's own line -- not ones nested inside
    a block it introduces (those are visited as their own statements)."""
    if isinstance(stmt, (ast.With, ast.AsyncWith)):
        exprs = [item.context_expr for item in stmt.items]
    elif (
        isinstance(stmt, (ast.Return, ast.Assign, ast.AnnAssign)) and stmt.value is not None
    ) or isinstance(stmt, ast.Expr):
        exprs = [stmt.value]
    else:
        exprs = []
    return [n for e in exprs for n in ast.walk(e) if isinstance(n, ast.Call)]


def _is_sink_call(call: ast.Call) -> bool:
    func = call.func
    if isinstance(func, ast.Name):
        return func.id in _SINK_FUNC_NAMES
    if isinstance(func, ast.Attribute):
        return func.attr in _SINK_FUNC_NAMES
    return False


# Ranking of sanitizer classifications for suppression purposes, weakest
# first: "weak" keeps the finding (a bypassable single-pass strip is still
# reachable), "unknown"/"strong" suppress it. When a bare sanitizer name
# resolves to more than one ambiguous candidate (no import-graph/same-file
# resolution available to pick the right one), classifying all of them and
# taking the weakest verdict is the conservative choice -- consistent with
# this codebase's "precision-first, but no silent false negatives" stance
# (docs/taint-sanitizer-audit.md): it's better to keep a finding that a
# strong sanitizer elsewhere would have suppressed than to drop one that
# actually went through the weak implementation.
_SANITIZER_STRENGTH_RANK: dict[str, int] = {"absent": -1, "weak": 0, "unknown": 1, "strong": 2}


def _classify_sanitizer_by_name(
    fname: str,
    def_nodes: dict[str, ast.AST] | dict[tuple[str, str], ast.AST],
    file_path: str | None,
    import_graph: _ImportGraph | None,
    def_nodes_by_name: dict[str, list[tuple[str, ast.AST]]] | None,
) -> str:
    """Resolve a sanitizer call's bare name to the AST node(s) it could
    refer to and classify it.

    `def_nodes` can be in either of two shapes:
    - Legacy: a project-wide `dict[str, ast.AST]` bare-name map (used by
      unit tests that call `_structural_path_sink` directly with no file/
      import-graph context) -- classifies whatever single node is there,
      same as before this fix.
    - `dict[(file, name), ast.AST]` (built by `CrossFilePass.run`) -- first
      tries the caller's OWN file (a same-file `def sanitize(...):`), then
      resolves through the caller's import graph (`import_graph.name_to_def`)
      to a specific `(file, name)`. Only when neither resolves does it fall
      back to `def_nodes_by_name[fname]` -- every same-named candidate
      project-wide -- and classify all of them, taking the weakest verdict.
    """
    if not def_nodes or not isinstance(next(iter(def_nodes)), tuple):
        # Legacy bare-name shape (or empty dict): single project-wide
        # lookup, exactly the pre-fix behavior.
        target = def_nodes.get(fname) if def_nodes else None
        return _classify_path_sanitizer(target) if target is not None else "unknown"

    if file_path is not None and (file_path, fname) in def_nodes:
        return _classify_path_sanitizer(def_nodes[(file_path, fname)])

    if file_path is not None and import_graph is not None:
        resolved = import_graph.name_to_def.get((file_path, fname))
        if resolved is not None:
            target = def_nodes.get(resolved)
            if target is not None:
                return _classify_path_sanitizer(target)

    candidates = [node for _f, node in (def_nodes_by_name or {}).get(fname, [])]
    if not candidates:
        return "unknown"
    verdicts = [_classify_path_sanitizer(c) for c in candidates]
    return min(verdicts, key=lambda v: _SANITIZER_STRENGTH_RANK[v])


def _structural_path_sink(
    func_node: ast.FunctionDef | ast.AsyncFunctionDef,
    def_nodes: dict[str, ast.AST] | dict[tuple[str, str], ast.AST],
    is_agent_tool: bool = False,
    file_path: str | None = None,
    import_graph: _ImportGraph | None = None,
    def_nodes_by_name: dict[str, list[tuple[str, ast.AST]]] | None = None,
    seed_params: set[str] | None = None,
) -> tuple[bool, str, int]:
    """Detect a path built from a function parameter via a base-dir join
    reaching a file write/remove/read call, and classify any locally-defined
    sanitizer applied along the way. A "weak" sanitizer (single-pass strip)
    still lets the finding through; "strong" or unresolvable/unrelated
    sanitizers suppress it, matching this codebase's precision-first bias.

    When `is_agent_tool` is set (this function is a recognized LangChain/
    CrewAI/AutoGen-style tool method), the base-dir-join requirement is
    dropped and the sink set is broadened (eval/exec/subprocess/requests):
    a tool's arguments are chosen by an LLM, which may itself be manipulated
    via prompt injection, so any direct use of one in a sensitive call is
    inherently suspicious -- unlike an ordinary function, there's no
    "trusted caller" assumption to lean on here."""
    params = _param_names(func_node)
    if not params:
        return False, "", 0

    # `seed_params` restricts the untrusted parameters to the ones a caller
    # actually passed tainted data into (see `_tool_helper_findings`).
    var_taint: dict[str, _VarTaint] = {
        p: _VarTaint() for p in params if seed_params is None or p in seed_params
    }
    classified: dict[str, str] = {}

    def classify(fname: str) -> str:
        if fname not in classified:
            classified[fname] = _classify_sanitizer_by_name(
                fname, def_nodes, file_path, import_graph, def_nodes_by_name
            )
        return classified[fname]

    def resolve(value: ast.expr) -> _VarTaint | None:
        """Best-effort one-hop dataflow: dict-get, sanitizer-call, base-dir
        join, or an `or`-chained combination of these (e.g.
        `meta.get("x") or default` -- common for optional metadata fields)."""
        if isinstance(value, ast.BoolOp):
            for sub in value.values:
                found = resolve(sub)
                if found is not None:
                    return found
            return None
        if (
            isinstance(value, ast.Call)
            and isinstance(value.func, ast.Attribute)
            and value.func.attr == "get"
            and isinstance(value.func.value, ast.Name)
            and value.func.value.id in var_taint
        ):
            return var_taint[value.func.value.id]
        if (
            isinstance(value, ast.Call)
            and isinstance(value.func, ast.Name)
            and len(value.args) == 1
            and isinstance(value.args[0], ast.Name)
            and value.args[0].id in var_taint
        ):
            src = var_taint[value.args[0].id]
            # `Path(p)` / `str(p)` re-wrap the same value; they validate nothing.
            if value.func.id in _PATH_CONSTRUCTORS or value.func.id in ("str", "fspath"):
                return src
            return _VarTaint(is_path=src.is_path, sanitizer=value.func.id)
        return _expr_path_taint(value, var_taint)

    http_clients: set[str] = set()
    for stmt in _iter_body_statements(func_node.body):
        if (
            isinstance(stmt, ast.Assign)
            and len(stmt.targets) == 1
            and isinstance(stmt.targets[0], ast.Name)
        ):
            found = resolve(stmt.value)
            if found is None and is_agent_tool:
                found = var_taint.get(_str_transform_source(stmt.value) or "")
            if found is not None:
                var_taint[stmt.targets[0].id] = found
        if is_agent_tool:
            http_clients |= _http_client_names(stmt)
        guarded = _statement_guarded_names(stmt)
        # Only a top-level allowlist runs before everything after it.
        if isinstance(stmt, ast.If) and any(stmt is top for top in func_node.body):
            guarded |= _fullmatch_guarded_names(stmt)
        for name in guarded:
            var_taint.pop(name, None)

        for call in _statement_own_calls(stmt):
            is_sink = _is_tool_sink_call(call) if is_agent_tool else _is_sink_call(call)
            operands: list[ast.expr] = list(call.args) if is_sink else []
            if is_agent_tool:
                # `Path(p).open()` matches the `open` sink by name but carries
                # the path in its receiver, not its arguments.
                operands += _tool_object_sink_operands(call, http_clients)
            for arg in operands:
                state = _expr_path_taint(arg, var_taint)
                direct = state is None
                if state is None and is_agent_tool:
                    if isinstance(arg, ast.Name):
                        state = var_taint.get(arg.id)
                    elif isinstance(arg, ast.Attribute) and isinstance(arg.value, ast.Name):
                        # A boundary source's request/context object (gRPC's
                        # `request`, a GraphQL resolver's `info`, ...) is
                        # itself untrusted -- any attribute read off a
                        # tainted parameter is just as attacker-controlled
                        # as the parameter itself would be if passed bare.
                        state = var_taint.get(arg.value.id)
                    elif (
                        isinstance(arg, ast.Call)
                        and isinstance(arg.func, ast.Attribute)
                        and arg.func.attr == "get"
                        and isinstance(arg.func.value, ast.Name)
                    ):
                        state = var_taint.get(arg.func.value.id)
                    elif isinstance(arg, (ast.Subscript, ast.JoinedStr, ast.BinOp)):
                        state = _tool_string_arg_taint(
                            arg, var_taint, _is_url_fetch_call(call, http_clients)
                        )
                    elif isinstance(arg, ast.Call):
                        state = var_taint.get(_str_transform_source(arg) or "")
                if state is None:
                    continue
                status = classify(state.sanitizer) if state.sanitizer else "absent"
                call_name = (
                    _dotted_name(call.func)
                    if isinstance(call.func, ast.Attribute)
                    else _base_ref_name(call.func) or "<call>"
                )
                if _is_url_fetch_call(call, http_clients) and not is_sink:
                    call_name = f"the HTTP client request {call_name}"
                line = getattr(call, "lineno", func_node.lineno)
                if status == "absent":
                    if direct:
                        return (
                            True,
                            (
                                f"external boundary argument reaches {call_name}() directly with no "
                                "sanitizer applied."
                            ),
                            line,
                        )
                    return (
                        True,
                        (
                            "Path built from a base-dir join with a function parameter reaches "
                            f"{call_name}() with no sanitizer applied -- arbitrary file path "
                            "traversal / unsanitized path write is possible."
                        ),
                        line,
                    )
                if status == "weak":
                    return (
                        True,
                        (
                            f"path traversal: path is passed through {state.sanitizer}(), but its "
                            "implementation does a single non-recursive strip of a literal "
                            "traversal sequence, which is bypassable (e.g. '....//' collapses to "
                            f"'../' after one pass) -- {call_name}() should be treated as reachable."
                        ),
                        line,
                    )
    return False, "", 0


# ---------------------------------------------------------------------------
# Internal types
# ---------------------------------------------------------------------------


#: Sentinel `end_line` for a `_FunctionSig` built without a real body span
#: (e.g. hand-constructed in a unit test that feeds `_propagate_cross_file`
#: directly rather than going through `_extract_functions`) -- treated as
#: "unbounded" so the `func.line <= finding_line <= func.end_line` span
#: check in `_match_findings_to_functions` doesn't reject a legitimate
#: finding just because the test never populated a real end line.
_UNBOUNDED_END_LINE = 2**31


@dataclass
class _FunctionSig:
    """Summary of a single function extracted from AST."""

    name: str
    file: str
    line: int
    params: list[str]
    calls: list[tuple]
    """(callee_name, module_qualifier | None, has_args, call_lineno,
    resolved_file | None). The call_lineno is the line of the call expression
    itself (not the enclosing `def`) -- needed so a cross-file finding can be
    anchored at the actual call site (issue #154 Defect 2) rather than the
    caller's function signature. `resolved_file` (issue #158) is the callee's
    defining file when receiver type inference resolved a method call
    confidently; None means resolve by name/qualifier as before. Hand-built
    `_FunctionSig`s (unit tests that feed `_propagate_cross_file` directly) may
    still pass shorter 2-/3-/4-tuples; `_propagate_cross_file` fills the missing
    trailing elements with their defaults (has_args=True, lineno=caller line,
    resolved_file=None)."""
    qualname: str | None = None
    """`Class.method` for a method whose enclosing class the class model
    knows; None for free functions and for hand-built signatures. Two same-
    named methods in one file (`Shell.run`, `Safe.run`) must be distinct
    call-graph nodes, or whichever is defined last masks the other (XF-02)."""
    end_line: int = _UNBOUNDED_END_LINE
    """Last line of the function's own body span (`ast.FunctionDef.end_lineno`
    for Python, a tree-sitter node's `end_point` row for JS/TS). Used to
    bound finding-to-function attribution so a module-level statement below
    the last `def` in a file isn't misattributed to that function."""
    has_sink: bool = False
    sink_detail: str = ""
    sink_rule_id: str = ""
    """Rule that proved the concrete terminal used by propagated findings."""
    sink_symbol: str = ""
    """Concrete terminal call symbol; empty when it cannot be resolved safely."""
    sink_cwe: list[int] = field(default_factory=list)
    """CWE ids of the originating sink finding, propagated so a cross-file
    finding can reflect the sink's real risk class -- e.g. a taint flow into a
    log statement (CWE-117 log forging) is emitted MEDIUM, not HIGH, matching
    how the intra-file log rules are rated (they are log poisoning, not RCE)."""
    sink_category: Category | None = None
    """Category of the originating sink finding, propagated so crossing a
    function boundary does not flatten a specific vulnerability to GENERAL."""
    sink_line: int = 0
    """Precise source line of the real sink this function was marked with --
    either the opengrep/neuroscan finding's own line (`_match_findings_to_
    functions`) or the structural path-sink's call-site line
    (`_structural_path_sink`). 0 when unset (falls back to `line`, the `def`
    line, at TaintFlow-construction time). Distinct from `line` so a
    cross-file TaintFlow's sink node (issue #154 Defect 1) can point at the
    actual sink call instead of the containing function's signature."""
    has_source: bool = False
    has_return_taint: bool = False
    """True if this function returns tainted data (propagates upward to callers)."""
    calls_propagator: bool = False
    """True if this function calls a known taint propagator (hf_hub_download etc)."""
    boundary_finding: tuple[int, str, str] | None = None
    """(line, message, boundary_kind) set when this is a recognized
    structural trust-boundary function (agent tool, Celery/RQ task, gRPC
    servicer method, GraphQL resolver, webhook handler) whose own body
    reaches a sink on one of its arguments -- emitted as a standalone
    same-file Finding, since the vulnerability doesn't need to cross a file
    boundary (unlike the ordinary cross-file has_sink/has_source path)."""
    agent_capability_sink: bool = False
    """True when this function performs model-selected dispatch into a tool
    registry that exposes at least one privileged capability."""
    agent_tool_feedback_loop: bool = False
    """A registered tool result is appended to context inside a repeated
    model/tool loop, allowing fetched content to choose a later tool."""
    authenticated_boundary: bool = False
    """The function is decorated as an authenticated route or handler."""
    principal_policy_used: bool = False
    """A caller principal parameter feeds an authorization/policy decision."""
    sink_params: frozenset[int] | None = None
    """(#119) 0-based positional-parameter indices whose value reaches this
    function's own sink call (at `sink_line`). None means "not computed" --
    every hand-built test `_FunctionSig` and every function with has_sink=False
    defaults here, and the propagator falls back to the old any-argument gate
    exactly as before. An empty frozenset (computed, but no parameter reaches
    the sink -- e.g. the sink call's arguments are all literals) correctly
    suppresses every caller's finding on this callee, since the sink demonstrably
    doesn't depend on anything the caller could pass in."""
    return_params: frozenset[int] | None = None
    """(#119) 0-based positional-parameter indices whose value reaches an
    `ast.Return` statement in this function's own body -- the "passthru"
    signal used to gate the return-taint direction per-parameter instead of
    unconditionally. Deliberately single-hop/direct in this pass: unlike
    `sink_params` (which only narrows an already-existing multi-hop BFS
    membership check), a function's return_params is consulted only against
    its DIRECT callers' edge bindings, not propagated further up the call
    chain -- composing it transitively is future work (see the "also worth
    doing" note in the #119 implementation)."""
    source_line: int = 0
    """(XF-16) Line of the first statement that reads a source, so a flow's
    source node points at the read rather than the call or `def` line."""
    sink_strength: tuple[bool, int] = (False, -1)
    """(XF-15) `_sink_strength` of the finding that set `sink_detail`."""
    returned_calls: frozenset[str] | None = None
    """(XF-07) Names of calls whose results reach one of this function's
    `return` values, directly or through locals. None means "not computed"
    (any call relays a tainted return, the old behaviour)."""
    sink_calls: frozenset[str] | None = None
    """(XF-07) Names of calls whose results reach the arguments of the sink
    call at `sink_line`. None means "not computed" (any captured return
    counts as reaching the sink, the old behaviour)."""


@dataclass
class _ImportGraph:
    """Cross-file import resolution."""

    # (caller_file, imported_name) -> (target_file, target_name)
    name_to_def: dict[tuple[str, str], tuple[str, str]] = field(default_factory=dict)
    # (caller_file, module_alias) -> target_file
    module_to_file: dict[tuple[str, str], str] = field(default_factory=dict)


@dataclass
class _ClassInfo:
    """Lightweight model of a class definition, for receiver type inference
    (#158). Just enough to resolve `obj.method()` / `self.attr.method()` to the
    file that actually defines `method`, including via base classes -- without
    a full type system."""

    name: str
    file: str
    bases: list[str]
    """Base-class names *as written* (`class C(Base)` -> ["Base"];
    `class C(pkg.Base)` -> ["Base"]). Resolved against `class_by_name` when
    walking for inherited methods, so a base defined in another file still
    resolves (recall-preserving fallback, same spirit as `def_nodes_by_name`)."""
    methods: set[str]
    """Method names defined directly on this class."""
    attr_types: dict[str, str] = field(default_factory=dict)
    """`self.<attr> = ClassName(...)` in __init__ -> {attr: "ClassName"}. Used to
    type `self.attr.method()` receivers."""


@dataclass
class _ClassModel:
    """Project-wide class index built once in Phase 1 and threaded into
    `_extract_functions` for receiver type inference."""

    registry: dict[tuple[str, str], _ClassInfo] = field(default_factory=dict)
    """(file, class_name) -> _ClassInfo."""
    by_name: dict[str, list[_ClassInfo]] = field(default_factory=dict)
    """class_name -> every _ClassInfo with that name (cross-file base/annotation
    resolution when the defining file isn't locally known)."""
    enclosing_class: dict[int, str] = field(default_factory=dict)
    """id(FunctionDef|AsyncFunctionDef) -> the name of the class it's a method
    of, so `_extract_functions` can type a `self`/`cls` receiver."""


# ---------------------------------------------------------------------------
# AST extraction
# ---------------------------------------------------------------------------


def _collect_python_files(
    root: Path,
    ignore_patterns: list[str] | None = None,
    *,
    candidates: Iterable[Path] | None = None,
) -> list[Path]:
    """Scoped Python files, using the shared discovery policy (CN-01)."""
    source_paths = iter_within_root(root, "*.py") if candidates is None else candidates
    return list(filter_python_paths(root, source_paths, ignore_patterns or [], skip_tests=False))


def _extract_imports(file_path: str, tree: ast.AST) -> _ImportGraph:
    """Extract import statements from a single file's AST."""
    graph = _ImportGraph()
    caller_dir = str(Path(file_path).parent)

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                mod_name = alias.name
                target = _resolve_module_path(caller_dir, mod_name)
                if not target:
                    continue
                graph.module_to_file[(file_path, mod_name)] = target
                if alias.asname:
                    graph.module_to_file[(file_path, alias.asname)] = target
                elif "." in mod_name:
                    # `import a.b` binds the name `a` to package `a` (XF-10).
                    root = mod_name.split(".")[0]
                    package = _resolve_module_path(caller_dir, root)
                    if package:
                        graph.module_to_file[(file_path, root)] = package

        elif isinstance(node, ast.ImportFrom):
            if node.module is None:
                continue
            mod_name = node.module
            level = node.level  # 0=absolute, 1=., 2=..
            if level > 0:
                target = _resolve_relative_module(caller_dir, mod_name, level)
            else:
                target = _resolve_module_path(caller_dir, mod_name)

            # `target` is `mod_name`'s own file, which for a package is its
            # __init__.py -- but `from package import submodule` names a
            # *file inside that package*, not a symbol defined in __init__.py.
            # Resolving those two the same way silently dropped every
            # from-package-import-submodule edge (e.g. `from ..services
            # import registry` in a Flask-style `api/`+`services/` layout),
            # since callee resolution only ever consulted module_to_file.
            package_dir = (
                Path(target).parent if target and Path(target).name == "__init__.py" else None
            )

            for alias in node.names:
                imported = alias.name
                local = alias.asname or imported
                if imported == "*":
                    if target:
                        # One key per star target; expanded once every file
                        # is parsed (`_resolve_import_indirection`).
                        graph.module_to_file[(file_path, "*" + target)] = target
                    continue
                submodule = (
                    _resolve_module_path(str(package_dir), imported) if package_dir else None
                )
                if submodule:
                    graph.module_to_file[(file_path, local)] = submodule
                elif target:
                    graph.name_to_def[(file_path, local)] = (target, imported)

    return graph


def _resolve_import_indirection(
    imports: _ImportGraph,
    def_nodes: dict[tuple[str, str], ast.AST],
    top_level_defs: dict[str, set[str]],
) -> None:
    """Expand `from m import *` into named imports of m's public top-level
    functions, then follow re-exports (`pkg/__init__.py` doing
    `from .impl import helper`) to the file that defines the name (XF-10)."""
    for (file_path, key), target in list(imports.module_to_file.items()):
        if key.startswith("*"):
            for name in top_level_defs.get(target, ()):
                if not name.startswith("_"):
                    imports.name_to_def.setdefault((file_path, name), (target, name))
    for key, (target, name) in list(imports.name_to_def.items()):
        seen: set[tuple[str, str]] = set()
        while (
            (target, name) not in def_nodes
            and (target, name) in imports.name_to_def
            and (target, name) not in seen
            and len(seen) < 5
        ):
            seen.add((target, name))
            target, name = imports.name_to_def[(target, name)]
        imports.name_to_def[key] = (target, name)


def _resolve_module_path(caller_dir: str, mod_name: str) -> str | None:
    """Resolve a Python module name to a file path."""
    parts = mod_name.split(".")
    # Search from the caller directory first (for flat/sibling imports),
    # then from parent (for package-style imports)
    search_dirs = [Path(caller_dir), *Path(caller_dir).parents]

    for search_dir in search_dirs:
        # Try: <search_dir>/<p0>/<p1>/.../<pN>.py
        candidate = search_dir
        for p in parts[:-1]:
            candidate = candidate / p
        candidate = candidate / (parts[-1] + ".py")
        if candidate.exists():
            return str(candidate.resolve())

        # Try: <search_dir>/<p0>/.../<pN>/__init__.py
        candidate = search_dir
        for p in parts:
            candidate = candidate / p
        candidate = candidate / "__init__.py"
        if candidate.exists():
            return str(candidate.resolve())
    return None


def _resolve_relative_module(caller_dir: str, mod_name: str, level: int) -> str | None:
    """Resolve a relative import to a file path.

    `caller_dir` is already the directory of the importing module, which IS
    the target of a single-dot import (level=1: "from . import x" means "from
    this same package"). Each additional dot climbs one more package level, so
    the walk is `level - 1` parent hops, not `level` -- the off-by-one here
    silently failed to resolve every `.`/`..`-style relative import in any
    real package (confirmed: `from ..core.db import db` and `from . import a`
    both returned None against files that exist on disk), which starved
    CrossFilePass's import graph on any codebase using relative imports.
    """
    base = Path(caller_dir)
    for _ in range(max(level - 1, 0)):
        base = base.parent
    parts = mod_name.split(".") if mod_name else []
    candidate_py = base / ("/".join(parts) + ".py") if parts else base / "__init__.py"
    candidate_init = base / "/".join(parts) / "__init__.py" if parts else None
    if candidate_py.exists():
        return str(candidate_py.resolve())
    if candidate_init and candidate_init.exists():
        return str(candidate_init.resolve())
    return None


def _extract_functions(
    file_path: str,
    tree: ast.AST,
    def_nodes: dict[str, ast.AST] | dict[tuple[str, str], ast.AST] | None = None,
    orm_channels: set[tuple[str, str]] | set[tuple[str, str, str]] | None = None,
    boundary_kind_by_id: dict[int, str] | None = None,
    import_graph: _ImportGraph | None = None,
    classes_by_file: dict[str, set[str]] | None = None,
    def_nodes_by_name: dict[str, list[tuple[str, ast.AST]]] | None = None,
    class_model: _ClassModel | None = None,
    vector_channels: set[tuple[str, ...]] | None = None,
    objstate_channels: set[tuple[str, str, str]] | None = None,
) -> list[_FunctionSig]:
    """Extract function definitions and their call sites from an AST."""
    funcs: list[_FunctionSig] = []
    vector_channels = vector_channels or set()
    vector_identities = _vector_store_identities(tree)
    objstate_channels = objstate_channels or set()
    module_var_types = _module_var_types(tree) if class_model is not None else {}

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            params = [a.arg for a in _declared_params(node)]
            # calls is a list of (callee_name, module_qual, has_args, lineno,
            # resolved_file|None, tainted_arg_slots, persistent_arg_slots,
            # resolved_qualname|None) 8-tuples. `resolved_file`
            # is set only when receiver type inference (#158) confidently
            # resolved a method call to its defining file; None means "let
            # _resolve_callee_file guess by name/qualifier as before" (the
            # behavior for every call when no class_model is supplied, e.g.
            # direct unit-test call sites). `tainted_arg_slots` (#119) is a
            # frozenset of int (positional index) / str (keyword name)
            # identifying which of THIS call's own arguments reference a
            # name this CALLER function considers tainted -- resolved into
            # the callee's parameter INDICES later, in
            # `_propagate_cross_file`, once the callee's own `params` list is
            # known via `func_index`.
            calls: list[tuple] = []

            enclosing_class = (
                class_model.enclosing_class.get(id(node)) if class_model is not None else None
            )
            var_types = (
                {**module_var_types, **_infer_var_types(node, enclosing_class)}
                if class_model is not None
                else {}
            )

            # Caller-side taint candidates for #119's per-call-site argument
            # binding: local vars provably derived from a known source read
            # (`_local_source_vars`, the same notion `has_source` already
            # uses) UNION this function's own parameter names. Including the
            # caller's own parameters -- unconditionally, not gated on
            # whether THIS caller is itself currently known to be
            # source-seeded -- is what lets a multi-hop chain (an
            # intermediate function that just forwards one of its own
            # parameters into a deeper sink-bearing call) compose correctly:
            # the resulting `edge_bindings` fact ("caller's param X feeds
            # callee's param Y") is recorded regardless of whether X turns
            # out to be tainted from THIS caller's own callers -- that's
            # still gated separately by the existing `source_seeded`
            # membership check at emission time, so this doesn't loosen
            # anything, only lets the per-parameter precision propagate
            # through more than one hop.
            # #121: a caller's OWN scalar-annotated parameter (`def
            # relay(n: int)`) can't carry a payload either, so it isn't a
            # taint candidate when deciding which of THIS call's arguments to
            # bind -- symmetric with excluding it from the callee's
            # sink_params in `_summarize_params`.
            caller_taint_candidates = (
                _local_source_vars(node) | _param_names(node)
            ) - _scalar_annotated_params(node)
            # ORM-channel-derived taint (`u.email` after `u =
            # User.query...first()`) isn't a NAME in caller_taint_candidates
            # at all -- it's an ATTRIBUTE match against a write channel, so
            # it needs its own per-expression check (`_arg_expr_is_caller_
            # tainted`) rather than a plain name-set intersection.
            orm_classes_by_var = _orm_classes_by_var(node) if orm_channels else {}
            orm_channel_vars = (
                _orm_channel_vars(
                    node,
                    orm_classes_by_var,
                    orm_channels or set(),
                    file_path,
                    import_graph,
                    classes_by_file,
                )
                if orm_channels
                else set()
            )
            # #156: vector-store retrieval results are whole-value tainted
            # while the channel is armed -- tracked as their own var set,
            # same role orm_classes_by_var plays for ORM reads.
            vector_read_vars = (
                _vector_read_vars(node, vector_channels, vector_identities)
                if vector_channels
                else set()
            )
            # #300: same role again for armed object/KV-state reads.
            objstate_read_vars = _objstate_read_vars(node, objstate_channels)

            for child in ast.walk(node):
                if isinstance(child, ast.Call):
                    callee_name, module_qual = _resolve_call_target(child)
                    if callee_name:
                        has_args = bool(child.args) or bool(child.keywords)
                        call_lineno = getattr(child, "lineno", node.lineno)
                        resolved_file: str | None = None
                        resolved_qualname: str | None = None
                        if (
                            module_qual == _UNRESOLVED_QUALIFIER
                            and import_graph is not None
                            and isinstance(child.func, ast.Attribute)
                        ):
                            # `pkg.impl.run_it()` after `import pkg.impl` (XF-10).
                            resolved_file = import_graph.module_to_file.get(
                                (file_path, _dotted_name(child.func.value))
                            )
                        if class_model is not None and resolved_file is None:
                            recv_class = _infer_receiver_class(child, var_types, class_model)
                            if recv_class is not None:
                                owner = _resolve_method_owner(recv_class, callee_name, class_model)
                                if owner is not None:
                                    resolved_file = owner[0]
                                    resolved_qualname = f"{owner[1]}.{callee_name}"
                            elif module_qual is None and _is_pascal_case(callee_name):
                                # `Job(q)` runs `Job.__init__`: only for a class this
                                # file defines or imports, and only its own __init__.
                                cls_file = _resolve_orm_class_file(
                                    callee_name, file_path, import_graph, classes_by_file
                                )
                                if cls_file is not None and any(
                                    info.file == cls_file and "__init__" in info.methods
                                    for info in class_model.by_name.get(callee_name, [])
                                ):
                                    resolved_file = cls_file
                                    resolved_qualname = f"{callee_name}.__init__"
                        tainted_slots: set[int | str] = set()
                        persistent_slots: set[int | str] = set()
                        for i, arg in enumerate(child.args):
                            if _arg_expr_is_caller_tainted(
                                arg,
                                caller_taint_candidates,
                                orm_classes_by_var,
                                orm_channels or set(),
                                file_path,
                                import_graph,
                                classes_by_file,
                                vector_read_vars,
                                vector_channels,
                                vector_identities,
                                objstate_read_vars,
                                objstate_channels,
                            ):
                                tainted_slots.add(i)
                            if (
                                _expr_reads_persistent_channel(
                                    arg,
                                    orm_classes_by_var,
                                    orm_channel_vars,
                                    orm_channels or set(),
                                    file_path,
                                    import_graph,
                                    classes_by_file,
                                )
                                or _expr_reads_vector_channel(
                                    arg,
                                    vector_read_vars,
                                    vector_channels,
                                    vector_identities,
                                )
                                or _expr_reads_objstate_channel(arg, objstate_channels)
                                or bool(set(_names_in(arg)) & objstate_read_vars)
                            ):
                                persistent_slots.add(i)
                        for kw in child.keywords:
                            if kw.arg is None:
                                continue
                            if _arg_expr_is_caller_tainted(
                                kw.value,
                                caller_taint_candidates,
                                orm_classes_by_var,
                                orm_channels or set(),
                                file_path,
                                import_graph,
                                classes_by_file,
                                vector_read_vars,
                                vector_channels,
                                vector_identities,
                                objstate_read_vars,
                                objstate_channels,
                            ):
                                tainted_slots.add(kw.arg)
                            if (
                                _expr_reads_persistent_channel(
                                    kw.value,
                                    orm_classes_by_var,
                                    orm_channel_vars,
                                    orm_channels or set(),
                                    file_path,
                                    import_graph,
                                    classes_by_file,
                                )
                                or _expr_reads_vector_channel(
                                    kw.value,
                                    vector_read_vars,
                                    vector_channels,
                                    vector_identities,
                                )
                                or _expr_reads_objstate_channel(kw.value, objstate_channels)
                                or bool(set(_names_in(kw.value)) & objstate_read_vars)
                            ):
                                persistent_slots.add(kw.arg)
                        calls.append(
                            (
                                callee_name,
                                module_qual,
                                has_args,
                                call_lineno,
                                resolved_file,
                                frozenset(tainted_slots),
                                frozenset(persistent_slots),
                                resolved_qualname,
                            )
                        )

            # Mark if this function calls known propagators
            calls_propagator = any(
                cn in KNOWN_PROPAGATORS or (mq is not None and f"{mq}.{cn}" in KNOWN_PROPAGATORS)
                for cn, mq, *_rest in calls
            )

            boundary_kind = (
                boundary_kind_by_id.get(id(node)) if boundary_kind_by_id is not None else None
            )
            authenticated_boundary = any(
                (name := _decorator_ref_name(dec)) is not None
                and re.search(r"auth|login|required|permission", name, re.IGNORECASE)
                for dec in node.decorator_list
            )
            is_boundary_source = boundary_kind is not None
            has_sink, sink_detail, sink_line = (
                _structural_path_sink(
                    node, def_nodes, is_boundary_source, file_path, import_graph, def_nodes_by_name
                )
                if def_nodes is not None
                else (False, "", 0)
            )
            has_source = (
                _function_reads_source(node)
                or (
                    orm_channels is not None
                    and _function_reads_orm_channel(
                        node, orm_channels, file_path, import_graph, classes_by_file
                    )
                )
                or _function_reads_vector_channel(node, vector_channels, vector_identities)
                or _function_reads_objstate_channel(node, objstate_channels)
                or is_boundary_source
            )
            has_return_taint = _function_returns_source(node)
            boundary_finding = (
                (sink_line, sink_detail, boundary_kind)
                if is_boundary_source and has_sink and sink_line
                else None
            )

            funcs.append(
                _FunctionSig(
                    name=node.name,
                    qualname=f"{enclosing_class}.{node.name}" if enclosing_class else None,
                    file=file_path,
                    line=node.lineno,
                    end_line=getattr(node, "end_lineno", None) or node.lineno,
                    params=params,
                    calls=calls,
                    calls_propagator=calls_propagator,
                    has_source=has_source,
                    source_line=_first_source_read_line(node) if has_source else 0,
                    has_return_taint=has_return_taint,
                    has_sink=has_sink,
                    sink_detail=sink_detail,
                    sink_line=sink_line,
                    # Outside an agent tool the structural sink is a path
                    # built from a parameter: path traversal, CWE-22 (RT-12).
                    sink_category=(
                        Category.PATH_TRAVERSAL if has_sink and not is_boundary_source else None
                    ),
                    sink_cwe=[22] if has_sink and not is_boundary_source else [],
                    boundary_finding=boundary_finding,
                    authenticated_boundary=authenticated_boundary,
                    principal_policy_used=_function_uses_principal_policy(node),
                )
            )

    return funcs


def _annotation_class_name(annotation: ast.expr | None) -> str | None:
    """Extract a simple class name from a parameter/variable annotation.

    Handles the common shapes only: `Config`, `pkg.Config`, `Optional[Config]`,
    and `Config | None`. Anything more exotic (generics with multiple args,
    string forward-refs, unions of two real types) returns None -- receiver
    typing is a precision aid, so an unrecognized annotation just falls back to
    today's name-based resolution, never a wrong guess."""
    node = annotation
    if node is None:
        return None
    # Optional[X] / typing.Optional[X]
    if isinstance(node, ast.Subscript):
        base = node.value
        base_name = base.attr if isinstance(base, ast.Attribute) else getattr(base, "id", None)
        if base_name == "Optional":
            return _annotation_class_name(node.slice)
        return None
    # X | None  /  None | X
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
        left = _annotation_class_name(node.left)
        right = _annotation_class_name(node.right)
        return left or right
    if isinstance(node, ast.Constant) and node.value is None:
        return None  # the `None` half of an Optional union
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def _build_class_model(parsed: list[tuple[str, ast.AST]]) -> _ClassModel:
    """Scan every parsed file for class definitions and build the project-wide
    `_ClassModel` used for receiver type inference (#158)."""
    model = _ClassModel()
    for file_str, tree in parsed:
        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef):
                continue
            bases = [
                b.attr if isinstance(b, ast.Attribute) else b.id
                for b in node.bases
                if isinstance(b, (ast.Name, ast.Attribute))
            ]
            methods: set[str] = set()
            attr_types: dict[str, str] = {}
            for stmt in node.body:
                if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    methods.add(stmt.name)
                    model.enclosing_class[id(stmt)] = node.name
                    if stmt.name == "__init__":
                        attr_types.update(_collect_self_attr_types(stmt))
            info = _ClassInfo(
                name=node.name, file=file_str, bases=bases, methods=methods, attr_types=attr_types
            )
            model.registry[(file_str, node.name)] = info
            model.by_name.setdefault(node.name, []).append(info)
    return model


def _collect_self_attr_types(init_node: ast.FunctionDef | ast.AsyncFunctionDef) -> dict[str, str]:
    """From an __init__ body, map `self.<attr> = ClassName(...)`, and
    `self.<attr> = param` where `param: ClassName`, to {attr: ClassName}."""
    attr_types: dict[str, str] = {}
    param_types = {
        arg.arg: cls
        for arg in (*init_node.args.args, *init_node.args.posonlyargs, *init_node.args.kwonlyargs)
        if (cls := _annotation_class_name(arg.annotation))
    }
    for stmt in ast.walk(init_node):
        if not (isinstance(stmt, ast.Assign) and len(stmt.targets) == 1):
            continue
        target = stmt.targets[0]
        if not (
            isinstance(target, ast.Attribute)
            and isinstance(target.value, ast.Name)
            and target.value.id in _SELF_QUALIFIERS
        ):
            continue
        value = stmt.value
        if (
            isinstance(value, ast.Call)
            and isinstance(value.func, ast.Name)
            and _is_pascal_case(value.func.id)
        ):
            attr_types[target.attr] = value.func.id
        elif isinstance(value, ast.Name) and value.id in param_types:
            attr_types[target.attr] = param_types[value.id]
    return attr_types


def _module_var_types(tree: ast.AST) -> dict[str, str]:
    """Module-level `svc = ClassName(...)` bindings, visible to every function
    in the file (a local binding of the same name takes precedence)."""
    var_types: dict[str, str] = {}
    for stmt in getattr(tree, "body", []):
        if (
            isinstance(stmt, ast.Assign)
            and len(stmt.targets) == 1
            and isinstance(stmt.targets[0], ast.Name)
            and isinstance(stmt.value, ast.Call)
            and isinstance(stmt.value.func, ast.Name)
            and _is_pascal_case(stmt.value.func.id)
        ):
            var_types[stmt.targets[0].id] = stmt.value.func.id
    return var_types


def _infer_var_types(
    func_node: ast.FunctionDef | ast.AsyncFunctionDef, enclosing_class: str | None
) -> dict[str, str]:
    """Build a local `variable -> class name` map for one function body:
    parameter annotations, `x = ClassName(...)` assignments, and self/cls."""
    var_types: dict[str, str] = {}
    if enclosing_class is not None:
        for q in _SELF_QUALIFIERS:
            var_types[q] = enclosing_class
    for arg in (*func_node.args.args, *func_node.args.posonlyargs, *func_node.args.kwonlyargs):
        cls = _annotation_class_name(arg.annotation)
        if cls:
            var_types[arg.arg] = cls
    for stmt in ast.walk(func_node):
        if (
            isinstance(stmt, ast.Assign)
            and len(stmt.targets) == 1
            and isinstance(stmt.targets[0], ast.Name)
            and isinstance(stmt.value, ast.Call)
            and isinstance(stmt.value.func, ast.Name)
            and _is_pascal_case(stmt.value.func.id)
        ):
            var_types[stmt.targets[0].id] = stmt.value.func.id
    return var_types


def _infer_receiver_class(
    call_node: ast.Call, var_types: dict[str, str], class_model: _ClassModel
) -> str | None:
    """Infer the class of a method call's receiver, for `obj.method()` and
    `self.attr.method()`. Returns None when the receiver can't be typed (falls
    back to today's name-based resolution)."""
    func = call_node.func
    if not isinstance(func, ast.Attribute):
        return None
    recv = func.value
    # obj.method() / self.method()  -- receiver is a bare name we may have typed
    if isinstance(recv, ast.Name):
        return var_types.get(recv.id)
    # Cls().method()  -- the receiver is a constructor call of a known class
    if (
        isinstance(recv, ast.Call)
        and isinstance(recv.func, ast.Name)
        and _is_pascal_case(recv.func.id)
        and recv.func.id in class_model.by_name
    ):
        return recv.func.id
    # self.attr.method()  -- type self, then read attr off its class
    if (
        isinstance(recv, ast.Attribute)
        and isinstance(recv.value, ast.Name)
        and recv.value.id in _SELF_QUALIFIERS
    ):
        self_class = var_types.get(recv.value.id)
        if self_class is None:
            return None
        for info in class_model.by_name.get(self_class, []):
            attr_class = info.attr_types.get(recv.attr)
            if attr_class:
                return attr_class
    return None


def _resolve_method_owner(
    class_name: str, method: str, class_model: _ClassModel
) -> tuple[str, str] | None:
    """Resolve `(file, defining_class)` for `method` on `class_name`, walking
    base classes left-to-right (MRO-ish) for inherited methods. Returns None
    if unresolved."""
    stack: list[str] = [class_name]
    visited: set[str] = set()
    while stack:
        name = stack.pop(0)
        if name in visited:
            continue
        visited.add(name)
        for info in class_model.by_name.get(name, []):
            if method in info.methods:
                return info.file, name
            # queue bases (preserve left-to-right order after this node)
            stack = list(info.bases) + stack
    return None


def _resolve_method_file(class_name: str, method: str, class_model: _ClassModel) -> str | None:
    """Resolve which file defines `method` on `class_name`."""
    owner = _resolve_method_owner(class_name, method, class_model)
    return owner[0] if owner else None


#: Marks a call whose qualifier is a chained/complex attribute access
#: (``a.b.foo()``) that couldn't be confidently attributed to any single
#: name. Distinct from ``None`` (a genuinely unqualified ``foo()`` call, for
#: which same-file resolution is a reasonable default) -- treating both the
#: same let a same-named function anywhere in the caller's file get guessed
#: as the target of an unrelated chained call.
_UNRESOLVED_QUALIFIER = "<unresolved>"

#: Qualifiers that name the current instance/class rather than an imported
#: module -- self.foo()/cls.foo() (Python) and this.foo() (JS/TS, shares this
#: propagation core) are method calls, not the never-matching "module named
#: self/cls/this" that a naive import lookup would look for.
_SELF_QUALIFIERS = frozenset({"self", "cls", "this"})


def _resolve_call_target(call_node: ast.Call) -> tuple[str | None, str | None]:
    """Resolve a call expression to (function_name, module_qualifier | None)."""
    func = call_node.func
    if isinstance(func, ast.Name):
        return (func.id, None)
    if isinstance(func, ast.Attribute):
        if isinstance(func.value, ast.Name):
            return (func.attr, func.value.id)
        if (
            isinstance(func.value, ast.Attribute)
            and isinstance(func.value.value, ast.Name)
            and func.value.value.id in _SELF_QUALIFIERS
        ):
            # self.db.query(...) / self.session.add(...) -- one level of
            # attribute chaining off self/cls/this (an ORM session/manager
            # attribute this pass doesn't otherwise track). The method name
            # alone is still resolvable the same way a bare self.<method>()
            # call is below (same imprecision already accepted there),
            # since self/cls/this are a strong signal the method is defined
            # somewhere reachable from this class. A chain rooted in an
            # arbitrary non-self name (e.g. a.b.foo()) stays
            # _UNRESOLVED_QUALIFIER: there's no such signal for an ordinary
            # instance variable, so guessing there would fabricate edges
            # more often than it finds real ones.
            return (func.attr, func.value.value.id)
        return (func.attr, _UNRESOLVED_QUALIFIER)
    return (None, None)


# ---------------------------------------------------------------------------
# Cross-file taint propagation
# ---------------------------------------------------------------------------


def _compute_param_summaries(
    funcs: list[_FunctionSig],
    def_nodes: dict[tuple[str, str], ast.AST],
    def_nodes_by_line: dict[tuple[str, str, int], ast.AST] | None = None,
) -> None:
    """Populate `sink_params`/`return_params` on every function whose real AST
    node is available (#119). Must run AFTER `_match_findings_to_functions`,
    since most functions' `has_sink`/`sink_line` are only known once findings
    from the primary opengrep/neuroscan engines have been matched -- computing
    a summary any earlier would only see the narrower, structural-path-sink
    subset of sinks `_extract_functions` can detect on its own.

    Mutates `funcs` in place. A function whose AST node isn't in `def_nodes`
    (hand-built test `_FunctionSig`s never populate this) is left with both
    fields at their default `None`, which is exactly the "not computed, use
    the old any-argument fallback" signal `_propagate_cross_file` checks for.
    """
    for f in funcs:
        # Prefer the def at this signature's OWN line. `def_nodes` is keyed by
        # (file, name) and populated with `setdefault`, so when a file defines
        # the same method name twice -- a subclass overriding its base, which
        # is ordinary in framework code -- the FIRST def wins there while
        # `func_index` keeps the LAST. The override would then be summarized
        # against the base's AST and come back with an empty `sink_params`,
        # which reads as "no caller can reach this sink" and silently kills
        # every edge into it. flashrag's `AgentUtils.postprocess_agent_response`
        # (the override that reaches `eval`) was invisible for exactly this
        # reason.
        node = None
        if def_nodes_by_line is not None:
            node = def_nodes_by_line.get((f.file, f.name, f.line))
        if node is None:
            node = def_nodes.get((f.file, f.name))
        if node is None or not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        sink_params, return_params = _summarize_params(node, f.sink_line if f.has_sink else 0)
        f.sink_params = sink_params
        f.return_params = return_params
        f.returned_calls = _call_results_reaching(
            node,
            [
                stmt.value
                for stmt in _iter_body_statements(node.body)
                if isinstance(stmt, ast.Return) and stmt.value is not None
            ],
        )
        sink_call_nodes = [
            n for n in ast.walk(node)
            if isinstance(n, ast.Call) and f.has_sink and getattr(n, "lineno", 0) == f.sink_line
        ]
        if sink_call_nodes:
            f.sink_calls = _call_results_reaching(
                node,
                [a for c in sink_call_nodes for a in (*c.args, *(k.value for k in c.keywords))],
            )


def _call_results_reaching(func_node: ast.AST, targets: list[ast.expr]) -> frozenset[str]:
    """Names of calls whose results reach any of `targets`, either inside the
    expression itself or through locals assigned from them (`n = relay()`)."""
    origins: dict[str, set[str]] = {}

    def calls_in(expr: ast.AST) -> set[str]:
        found: set[str] = set()
        for n in ast.walk(expr):
            if isinstance(n, ast.Call):
                name, _qual = _resolve_call_target(n)
                if name:
                    found.add(name)
            elif isinstance(n, ast.Name) and n.id in origins:
                found |= origins[n.id]
        return found

    for _ in range(3):  # a few passes settle chains like `a = f(); b = a`
        for stmt in _iter_body_statements(func_node.body):
            if isinstance(stmt, (ast.Assign, ast.AnnAssign)) and stmt.value is not None:
                calls = calls_in(stmt.value)
                if calls:
                    for target in stmt.targets if isinstance(stmt, ast.Assign) else [stmt.target]:
                        for name in _bound_names(target):
                            origins.setdefault(name, set()).update(calls)
    result: set[str] = set()
    for target in targets:
        result |= calls_in(target)
    return frozenset(result)


def _innermost_function(
    by_file: dict[str, list[_FunctionSig]], file_path: str, line: int
) -> _FunctionSig | None:
    """The innermost function in `file_path` whose body spans `line`.

    Looked up per file, so matching is linear in findings rather than
    findings x functions (XF-17).
    """
    best = None
    for func in by_file.get(file_path, ()):
        if func.line <= line <= func.end_line and (best is None or func.line > best.line):
            best = func
    return best


def _match_findings_to_functions(
    findings: list[Finding],
    funcs: list[_FunctionSig],
    rule_map: dict[str, dict] | None = None,
    def_nodes_by_line: dict[tuple[str, str, int], ast.AST] | None = None,
) -> list[_FunctionSig]:
    """Annotate function signatures with source/sink info from per-file findings.

    Handles both TaintPass findings (with taint_flow) and neuroscan findings
    (without taint_flow: regex matches act as sink markers).

    `rule_map` (from the converter manifest, see `_is_sink_rule`) is threaded
    through so the regex-finding branch below can classify sink-ness from
    each rule's declared category instead of the hand-maintained prefix list.
    `def_nodes_by_line` lets it drop CWE-78 regex hits on safe list-form
    subprocess calls (XF-26) and SQL-keyword hits on log messages;
    without it every hit is kept.
    """
    by_file: dict[str, list[_FunctionSig]] = {}
    log_message_lines: dict[tuple[str, str, int], set[int]] = {}
    for func in funcs:
        by_file.setdefault(func.file, []).append(func)

    for finding in findings:
        # TaintPass findings: have full source→sink taint flow
        if finding.taint_flow:
            tf = finding.taint_flow

            # Mark sink function: the closest containing function whose
            # body span actually contains the finding's line. Without the
            # upper bound (func.line <= line <= func.end_line), a
            # module-level sink below the last `def` in a file matched
            # "closest def with line <= finding_line" with no ceiling at
            # all, misattributing it to that unrelated function.
            if tf.sink:
                best = _innermost_function(by_file, tf.sink.file_path, tf.sink.line)
                if best is not None:
                    _record_sink(best, finding, tf.sink.line)

            # Mark source function: closest containing function only,
            # bounded by the same body-span check.
            if tf.source:
                best = _innermost_function(by_file, tf.source.file_path, tf.source.line)
                if best is not None:
                    best.has_source = True
                    if not best.source_line or tf.source.line < best.source_line:
                        best.source_line = tf.source.line
                    if finding.rule_id == "AGENT-CAPABILITY-001":
                        # The model response is the control-transfer source in
                        # this finding, but for interprocedural propagation the
                        # dispatching function is also the capability sink its
                        # callers feed through prompt/context parameters.
                        best.has_sink = True
                        best.agent_capability_sink = True
                        best.agent_tool_feedback_loop = bool(
                            finding.metadata.get("tool_feedback_loop")
                        )
                        _record_sink(best, finding, finding.start_line)

        # Regex (NeuroScan) sink-rule matches without taint_flow: treat as sink
        # markers for cross-file propagation. Match on the rule-id namespace, NOT the
        # engine tag: in the default path these run *through* OpenGrep and are tagged
        # engine="opengrep", so gating on engine=="neuroscan" silently dropped them.
        elif _is_sink_rule(finding.rule_id, rule_map):
            best = _innermost_function(by_file, finding.file_path, finding.start_line)
            if best is None:
                continue
            if finding.rule_id == "NS-SQLI-005" and def_nodes_by_line is not None:
                key = (best.file, best.name, best.line)
                if key not in log_message_lines:
                    node = def_nodes_by_line.get(key)
                    log_message_lines[key] = (
                        logging_fstring_lines(node) - fstring_assignment_lines(node)
                        if node is not None else set()
                    )
                if finding.start_line in log_message_lines[key]:
                    continue
            # Presence rules like ns-aiml-076 match any subprocess call. A
            # list-form call to a fixed, non-shell program cannot inject a
            # command, so it is not a CWE-78 sink for its callers (XF-26).
            if 78 in finding.cwe_ids and def_nodes_by_line is not None:
                node = def_nodes_by_line.get((best.file, best.name, best.line))
                if node is not None and _is_list_form_exec_at(node, finding.start_line):
                    continue
            _record_sink(best, finding, finding.start_line)

    return funcs


#: Programs that turn an argv element back into code (`sh -c`, `python -c`)
#: or run another command from their argv (`sudo`, `ssh`, `xargs`), so a
#: list-form call to one of them is still an injection sink. Matched after
#: dropping the directory, `.exe` and a version suffix (`python3.11`).
_CODE_INTERPRETERS = frozenset(
    {
        "sh", "bash", "zsh", "dash", "ksh", "csh", "tcsh", "fish", "busybox",
        "cmd", "powershell", "pwsh",
        "python", "node", "perl", "ruby", "php", "env",
        "sudo", "su", "doas", "ssh", "xargs", "timeout", "nice", "nohup",
        "docker", "kubectl",
    }
)  # fmt: skip


def _is_list_form_exec_at(func_node: ast.AST, line: int) -> bool:
    """True when the outermost call spanning `line` is `subprocess.*([...])`
    with a literal, non-interpreter program and no truthy `shell=` kwarg."""
    spanning = [
        call
        for call in ast.walk(func_node)
        if isinstance(call, ast.Call) and getattr(call, "lineno", 0) <= line <= _call_end_line(call)
    ]
    if not spanning:
        return False
    call = min(spanning, key=lambda c: (c.lineno, -_call_end_line(c)))
    if not _dotted_name(call.func).startswith("subprocess."):
        return False
    argv = call.args[0] if call.args else None
    if not isinstance(argv, (ast.List, ast.Tuple)) or not argv.elts:
        return False
    program = argv.elts[0]
    if not (isinstance(program, ast.Constant) and isinstance(program.value, str)):
        return False
    name = re.split(r"[/\\]", program.value)[-1].lower().removesuffix(".exe")
    if name.rstrip("0123456789.") in _CODE_INTERPRETERS:
        return False
    for kw in call.keywords:
        # `**kwargs` may carry shell=True.
        if kw.arg is None:
            return False
        if kw.arg == "shell" and not (isinstance(kw.value, ast.Constant) and not kw.value.value):
            return False
    return True


_SEVERITY_RANK = {s: i for i, s in enumerate(reversed(list(Severity)))}


def _sink_strength(finding: Finding) -> tuple[bool, int]:
    """A vulnerability-category rule beats a presence rule, then severity."""
    return finding.category.value in _SINK_CATEGORIES, _SEVERITY_RANK.get(finding.severity, 0)


def _record_sink(sig: _FunctionSig, finding: Finding, line: int) -> None:
    """Mark `sig` as sink-bearing at `line`; the earliest line wins.

    Several rules commonly hit one call: the call head and, for a multi-line
    call, a later kwarg line. Last-writer-wins put `sink_line` on the kwarg
    line where no Call starts, so `_summarize_params` found nothing and every
    caller was suppressed (XF-01). The detail, CWE and category travel with
    the line that is kept so the emitted message describes that sink.
    """
    sig.has_sink = True
    if sig.sink_line and sig.sink_line < line:
        return
    # Same line: keep the stronger claim, so an agent-safety presence rule
    # does not replace a command-injection rule's message and CWE (XF-15).
    if sig.sink_line == line and _sink_strength(finding) <= sig.sink_strength:
        return
    sig.sink_strength = _sink_strength(finding)
    sig.sink_line = line
    sig.sink_detail = finding.message
    sig.sink_rule_id = finding.rule_id
    snippet = finding.taint_flow.sink.snippet if finding.taint_flow and finding.taint_flow.sink else ""
    sig.sink_symbol = concrete_sink_symbol(snippet)
    if not sig.sink_symbol:
        try:
            source_line = Path(finding.file_path).read_text(encoding="utf-8").splitlines()[line - 1]
        except (OSError, UnicodeError, IndexError):
            source_line = ""
        sig.sink_symbol = concrete_sink_symbol(source_line)
    sig.sink_cwe = list(finding.cwe_ids)
    sig.sink_category = finding.category


# Rule *categories* (from rules/converted/_manifest.json, `metadata.category`
# on the source YAML) that indicate a genuine sink pattern -- i.e. a regex hit
# worth propagating across files -- as opposed to a config/secrets/crypto misc
# warning. This is the authoritative classifier; see `_is_sink_rule`.
#
# This exact set was derived by taking every category that at least one rule
# in the old `_SINK_RULE_PREFIXES` list below already belonged to -- so the
# switchover is monotonic: every rule that used to test as a sink still does
# (same categories, just resolved via metadata instead of a fragile ID
# prefix), plus every other rule that shares one of those categories but
# fell outside the hand-enumerated prefixes/ID-range now correctly does too.
# Rule categories are validated against `Category` (tests/test_rule_categories.py),
# so only enum values belong here. ai_ml, prompt_injection, config, auth,
# crypto, secrets, and general are deliberately NOT included here --
# broadening cross-file sink status to those categories is a separate,
# not-yet-made decision.
_SINK_CATEGORIES: frozenset[str] = frozenset(
    {
        "command_injection",
        "deserialization",
        "injection",
        "path_traversal",
        "ssrf",
        "ssti",
        "xss",
        "nosql_injection",
        "prototype_pollution",
        "supply_chain",
    }
)

# NeuroScan rule IDs that indicate sink patterns (not config/secrets/crypto warnings).
#
# Kept as a fallback, NOT dead code: this hand-enumerated prefix list is the
# only classifier available when `_is_sink_rule` is called without a
# `rule_map` -- i.e. when the conversion manifest fails to load (see
# `Pipeline._load_conversion_manifest`, which degrades to a warning + no
# manifest on any read/parse error) and in `--legacy-neuroscan` mode, which
# never populates `context.metadata["conversion_manifest"]` at all. Do not
# delete this just because the category-based path above covers the common
# case.
_SINK_RULE_PREFIXES: tuple[str, ...] = (
    "NS-DESER",
    "NS-INJECT",
    "NS-CMDI",
    "NS-SQLI",
    "NS-SSTI",
    "NS-SSRF",
    "NS-PATH",
    "NS-NOSQL",
    "NS-PROTO",
    "NS-XSS",
    "ns-aiml-030",
    "ns-aiml-031",
    "ns-aiml-032",
    "ns-aiml-033",
    "ns-aiml-034",
    "ns-aiml-035",
    "ns-aiml-036",
    "ns-aiml-037",
    "ns-aiml-038",
    "ns-aiml-039",
    "ns-aiml-040",
    "ns-aiml-041",
    "ns-aiml-042",
    "ns-aiml-043",
    "ns-aiml-044",
    "ns-aiml-045",
    "ns-aiml-046",
    "ns-aiml-047",
    "ns-aiml-048",
    "ns-aiml-049",
    "ns-aiml-050",
    "ns-aiml-051",
    "ns-aiml-057",
    "ns-aiml-058",
    "ns-aiml-059",
    "ns-aiml-060",
    "ns-aiml-061",
    "ns-aiml-062",
    "ns-aiml-063",
    "ns-aiml-064",
    "ns-aiml-065",
    "ns-aiml-066",
    "ns-aiml-067",
    "ns-aiml-068",
    "ns-aiml-072",
    "ns-aiml-073",
    "ns-aiml-074",
    "ns-aiml-075",
    "ns-aiml-076",
    "ns-aiml-077",
    # JS/TS NeuroScan rules (rules/javascript.yaml) -- TypeScript shares this
    # prefix, there is no separate TS- family. Additive: Python files never
    # produce JS- rule hits, so this can't introduce false sinks for Python.
    "JS-DESER",
    "JS-INJECT",
    "JS-PATH",
    "JS-SSRF",
    "JS-XSS",
)


def _is_sink_rule(rule_id: str, rule_map: dict[str, dict] | None = None) -> bool:
    """Check if a rule ID indicates a sink (source→sink flow relevant), vs a
    config/secrets/crypto misc warning.

    Authoritative path: if `rule_map` (the converter manifest's id -> rule
    dict) is available and has an entry for `rule_id` with a truthy
    `category`, classify by category membership in `_SINK_CATEGORIES`. This
    replaces the old hand-enumerated ID-prefix check, which silently stopped
    tracking new rule IDs above ns-aiml-077 and never recognized the
    uppercase NS-AIML- family at all -- see the module docstring/comment
    above `_SINK_RULE_PREFIXES` for why that list is still kept as a
    fallback rather than deleted.
    """
    if rule_map:
        info = rule_map.get(rule_id)
        if info and info.get("category"):
            return info["category"] in _SINK_CATEGORIES
    return any(rule_id.startswith(prefix) for prefix in _SINK_RULE_PREFIXES)


#: A propagation-graph node: (file, function_name).
_Node = tuple[str, str]


def _binding_misses_sink(
    callee: _FunctionSig | None, carries_taint: bool | None, bound: set[int]
) -> bool:
    """True when a call's tainted arguments provably miss the callee's sink.

    Needs both sides: a per-parameter sink summary on the callee and taint
    slots recorded for the call (`carries_taint` is None without them).
    """
    return bool(
        callee is not None
        and callee.sink_params is not None
        and carries_taint is not None
        and not (bound & callee.sink_params)
    )


def _bfs_taint_upward(
    seeds: set[_Node],
    reverse_graph: dict[_Node, set[_Node]],
    edge_call_line: dict[tuple[_Node, _Node], int],
) -> tuple[dict[_Node, int], dict[_Node, tuple[_Node, int]]]:
    """BFS taint-status propagation from `seeds` following `reverse_graph`
    edges (callee -> its callers), computing the TRUE shortest hop distance to
    every reachable node plus a predecessor map for chain reconstruction
    (issue #163).

    Replaces the old fixed 50-sweep fixpoint. A plain BFS over a finite graph
    always terminates -- no convergence cap needed -- and because each layer
    is expanded in full before the next begins, the first time a node is
    visited is provably via a shortest path. So `dist` is the real call-chain
    distance (not a sweep index that happened to coincide with it, which is
    what the old algorithm reported as `hop_depth`), and the predecessor map
    always reconstructs the SHORTEST source->sink chain.

    Deterministic: nodes are expanded in sorted order within each BFS layer,
    and `dist`/`pred` are recorded via `setdefault` (first write wins), so
    re-running on the same graph always produces identical distances and
    chains regardless of the sets' internal iteration order.
    """
    dist: dict[_Node, int] = {s: 0 for s in seeds}
    pred: dict[_Node, tuple[_Node, int]] = {}
    frontier = sorted(seeds)
    depth = 0
    while frontier:
        next_frontier: set[_Node] = set()
        for node in frontier:
            for caller_key in sorted(reverse_graph.get(node, ())):
                if caller_key in dist:
                    continue
                dist[caller_key] = depth + 1
                call_line = edge_call_line.get((caller_key, node))
                if call_line is not None:
                    pred.setdefault(caller_key, (node, call_line))
                next_frontier.add(caller_key)
        frontier = sorted(next_frontier)
        depth += 1
    return dist, pred


def _bfs_reachable_forward(seeds: set[_Node], forward_graph: dict[_Node, set[_Node]]) -> set[_Node]:
    """Plain reachability BFS from `seeds` following `forward_graph` edges
    (caller -> callee, i.e. the opposite direction of `_bfs_taint_upward`).
    Used for source-taint propagation, which only ever needs set membership
    -- unlike the sink/return direction, no chain is ever reconstructed
    starting from a source, so no predecessor map is needed here."""
    visited = set(seeds)
    frontier = sorted(seeds)
    while frontier:
        next_frontier: set[_Node] = set()
        for node in frontier:
            for nxt in sorted(forward_graph.get(node, ())):
                if nxt not in visited:
                    visited.add(nxt)
                    next_frontier.add(nxt)
        frontier = sorted(next_frontier)
    return visited


def _node_key(sig: _FunctionSig) -> tuple[str, str]:
    """Call-graph node identity: `(file, Class.method)` for a typed method,
    `(file, name)` otherwise."""
    return (sig.file, sig.qualname or sig.name)


def _propagate_cross_file(
    funcs: list[_FunctionSig],
    import_graph: _ImportGraph,
    findings: list[Finding],
    root: Path,
) -> list[Finding]:
    """Propagate taint across file boundaries via BFS (issue #163).

    1. Build the reverse call graph (callee -> callers).
    2. Seed sink/return/source status sets from each function's own
       properties.
    3. Run three independent BFS closures (`_bfs_taint_upward` x2,
       `_bfs_reachable_forward` x1) to grow each status set to its full
       reachable closure, with true shortest hop distances and predecessor
       chains for the two directions that need chain reconstruction.
    4. Emit a finding for every caller/callee pair whose join condition
       (sink-tainted callee + source-seeded caller, or return-tainted callee
       + sink-bearing caller) holds in the fully-converged sets.
    """
    new_findings: list[Finding] = []
    seen_keys: set[tuple[str, str, str, str, str]] = set()

    # Index functions
    func_index: dict[tuple[str, str], _FunctionSig] = {}
    for f in funcs:
        func_index[_node_key(f)] = f
    for f in funcs:
        # Calls the class model could not type resolve by bare name; keep
        # that deterministic (first definition) rather than last-def-wins.
        func_index.setdefault((f.file, f.name), f)

    # Build reverse call graph: (callee_file, callee_name) -> set of (caller_file, caller_name)
    # Also track, per (caller, callee) edge, whether ANY call site on that
    # edge passes at least one argument -- `_FunctionSig.calls` entries are
    # (callee_name, module_qualifier, has_args, call_lineno) from real
    # extraction, but a hand-built 2- or 3-tuple (name, qualifier[, has_args])
    # from a test that constructs `_FunctionSig` directly is still accepted:
    # missing has_args defaults to True (the old, unconditional-propagation
    # behavior, since such tests aren't exercising the argument-gating logic),
    # and a missing lineno falls back to the caller's own `line`.
    #
    # `edge_call_line` records, per (caller, callee) edge, the call site line
    # used to anchor a cross-file finding (issue #154 Defect 2) -- the
    # earliest call site when a caller invokes the same callee more than
    # once, for determinism.
    #
    # `edge_bindings` (#119) is the per-parameter refinement of `edge_has_args`:
    # the set of CALLEE parameter INDICES that receive a caller-tainted
    # argument on this edge (aggregated across all call sites the same way
    # `edge_has_args` is). A call's own `tainted_arg_slots` (positional index
    # or keyword name, computed in `_extract_functions`) is resolved into a
    # callee parameter index here -- not there -- because only here do we have
    # `func_index`, and therefore the callee's actual `params` list, to resolve
    # a keyword name against.
    reverse_graph: dict[tuple[str, str], set[tuple[str, str]]] = {}
    edge_has_args: dict[tuple[tuple[str, str], tuple[str, str]], bool] = {}
    # Per edge: did any call site pass an argument the CALLER considers
    # tainted (a local source var, its own parameter, or a persistent-channel
    # read)? None when no call on the edge carried slot information at all
    # (hand-built 2-/3-/4-/5-tuples), in which case `edge_has_args` is the
    # only gate available. A constant argument (`relay("x")`) must not carry
    # source status into the callee (XF-06).
    edge_carries_taint: dict[tuple[tuple[str, str], tuple[str, str]], bool | None] = {}
    edge_call_line: dict[tuple[tuple[str, str], tuple[str, str]], int] = {}
    edge_bindings: dict[tuple[tuple[str, str], tuple[str, str]], set[int]] = {}
    persistent_edge_bindings: dict[tuple[tuple[str, str], tuple[str, str]], set[int]] = {}
    for caller in funcs:
        caller_key = _node_key(caller)
        for call in caller.calls:
            resolved_file: str | None = None
            resolved_qualname: str | None = None
            tainted_slots: frozenset = frozenset()
            persistent_slots: frozenset = frozenset()
            if len(call) >= 8:
                resolved_qualname = call[7]
            if len(call) >= 7:
                (
                    callee_name,
                    module_qual,
                    has_args,
                    call_line,
                    resolved_file,
                    tainted_slots,
                    persistent_slots,
                ) = (call[0], call[1], bool(call[2]), int(call[3]), call[4], call[5], call[6])
            elif len(call) >= 6:
                callee_name, module_qual, has_args, call_line, resolved_file, tainted_slots = (
                    call[0],
                    call[1],
                    bool(call[2]),
                    int(call[3]),
                    call[4],
                    call[5],
                )
            elif len(call) == 5:
                callee_name, module_qual, has_args, call_line, resolved_file = (
                    call[0],
                    call[1],
                    bool(call[2]),
                    int(call[3]),
                    call[4],
                )
            elif len(call) == 4:
                callee_name, module_qual, has_args, call_line = (
                    call[0],
                    call[1],
                    bool(call[2]),
                    int(call[3]),
                )
            elif len(call) == 3:
                callee_name, module_qual, has_args = call
                call_line = caller.line
            else:
                callee_name, module_qual = call
                has_args = True
                call_line = caller.line
            # Receiver type inference (#158) wins when it resolved a method
            # call to a concrete defining file; otherwise fall back to the
            # name/qualifier import-graph guess.
            if resolved_file:
                callee_file, target_name = resolved_file, resolved_qualname or callee_name
            else:
                resolved = _resolve_callee(caller.file, callee_name, module_qual, import_graph)
                if resolved is None:
                    continue
                callee_file, target_name = resolved
            key = (callee_file, target_name)
            reverse_graph.setdefault(key, set()).add(caller_key)
            edge_has_args[(caller_key, key)] = (
                edge_has_args.get((caller_key, key), False) or has_args
            )
            if len(call) >= 6:
                edge_carries_taint[(caller_key, key)] = bool(
                    edge_carries_taint.get((caller_key, key)) or tainted_slots or persistent_slots
                )
            else:
                edge_carries_taint.setdefault((caller_key, key), None)
            existing_line = edge_call_line.get((caller_key, key))
            edge_call_line[(caller_key, key)] = (
                call_line if existing_line is None else min(existing_line, call_line)
            )
            if tainted_slots:
                callee_sig_for_binding = func_index.get(key)
                callee_params = callee_sig_for_binding.params if callee_sig_for_binding else []
                # A method definition's first parameter (self/cls/this) is
                # never present in a bound call's own `call.args` -- e.g.
                # `obj.method(x)`'s `x` is `call.args[0]`, but it binds to
                # the method's SECOND declared parameter. Offset positional
                # indices by 1 when the callee's own definition starts with
                # such a parameter, so `edge_bindings` indices land in the
                # SAME parameter-index space `_summarize_params` used to
                # compute sink_params/return_params (which counts self/cls/
                # this as occupying index 0, since it comes straight from
                # `func_node.args.args`).
                offset = 1 if callee_params and callee_params[0] in _SELF_QUALIFIERS else 0
                resolved_indices: set[int] = set()
                for slot in tainted_slots:
                    if isinstance(slot, int):
                        resolved_indices.add(slot + offset)
                    elif slot in callee_params:
                        resolved_indices.add(callee_params.index(slot))
                if resolved_indices:
                    edge_bindings.setdefault((caller_key, key), set()).update(resolved_indices)
            if persistent_slots:
                callee_sig_for_binding = func_index.get(key)
                callee_params = callee_sig_for_binding.params if callee_sig_for_binding else []
                offset = 1 if callee_params and callee_params[0] in _SELF_QUALIFIERS else 0
                resolved_indices: set[int] = set()
                for slot in persistent_slots:
                    if isinstance(slot, int):
                        resolved_indices.add(slot + offset)
                    elif slot in callee_params:
                        resolved_indices.add(callee_params.index(slot))
                if resolved_indices:
                    persistent_edge_bindings.setdefault((caller_key, key), set()).update(
                        resolved_indices
                    )

    # Seed: functions with direct sinks propagate UP the call chain (any
    # caller that reaches them is itself "leads to a sink"). Functions with
    # return taint propagate the same direction -- a caller that captures a
    # tainted return becomes return-tainted itself. Functions with a source
    # propagate DOWN the call chain (into the callees they pass data to).
    sink_seeds: set[_Node] = {_node_key(f) for f in funcs if f.has_sink}
    return_seeds: set[_Node] = {
        _node_key(f)
        for f in funcs
        # Propagator + sink = confirmed multi-step taint chain carrier, even
        # when the function has no `return` statement of its own that reads
        # a source directly.
        if f.has_return_taint or (f.calls_propagator and f.has_sink)
    }
    source_seeds: set[_Node] = {_node_key(f) for f in funcs if f.has_source}

    # Forward graph (caller -> callees), restricted to edges that actually
    # pass at least one argument -- source taint can only cross an edge that
    # hands the callee a value at all. Derived from reverse_graph rather than
    # built in the earlier edge-collection loop so there is exactly one
    # place that defines "what counts as an edge" for both directions.
    def _edge_passes_taint(edge: tuple[_Node, _Node]) -> bool:
        carries = edge_carries_taint.get(edge)
        if carries is None:
            return edge_has_args.get(edge, False)
        return carries

    forward_graph: dict[_Node, set[_Node]] = {}
    for callee_key, callers in reverse_graph.items():
        for caller_key in callers:
            if _edge_passes_taint((caller_key, callee_key)):
                forward_graph.setdefault(caller_key, set()).add(callee_key)

    # Three independent BFS closures (issue #163). Each status set's growth
    # rule depends only on its own seeds and its own graph/gating -- not on
    # the other two sets -- so they can be computed as three separate
    # shortest-path problems instead of one interleaved sweep. `sink_dist`/
    # `return_dist` double as the TRUE hop distance used for both the
    # reported `hop_depth` and the confidence decay (previously the sweep
    # index, which only coincidentally matched the real chain length).
    #
    # pred_sink[caller_key] = (callee_key, call_line) records that
    # caller_key became sink-tainted because it calls callee_key (closer to
    # the seed) at call_line -- walking this chain from a finding's own
    # direct callee toward a node with no entry (an originally-seeded sink)
    # reconstructs the full hop-by-hop path to the real sink. pred_return is
    # the same idea for the upward return-taint chain. Both maps are built
    # by `_bfs_taint_upward`, which guarantees they encode the SHORTEST such
    # chain (issue #163) -- the old sweep-based `pred_*.setdefault` only
    # guaranteed "first sweep that reached it", which was the shortest path
    # in practice but for the wrong reason (sweep order, not distance).
    # A caller relays a seeded sink only if what it passes binds to a
    # parameter that reaches the sink: the same per-parameter gate the
    # emission loop applies to a direct edge, applied to the first hop of the
    # relay chain. Callees without a summary (`sink_params is None`) and
    # calls without argument bindings keep the any-argument behaviour.
    sink_reverse_graph = {
        callee_key: {
            caller_key
            for caller_key in callers
            if not _binding_misses_sink(
                func_index.get(callee_key),
                edge_carries_taint.get((caller_key, callee_key)),
                edge_bindings.get((caller_key, callee_key), set())
                | persistent_edge_bindings.get((caller_key, callee_key), set()),
            )
        }
        if callee_key in sink_seeds
        else callers
        for callee_key, callers in reverse_graph.items()
    }
    sink_dist, pred_sink = _bfs_taint_upward(sink_seeds, sink_reverse_graph, edge_call_line)
    # A caller relays a tainted return only if it returns that call's result
    # (XF-07); calling the function and returning something else does not.
    def _returns_result_of(caller_key: _Node, callee_key: _Node) -> bool:
        caller_sig = func_index.get(caller_key)
        callee_sig = func_index.get(callee_key)
        if caller_sig is None or callee_sig is None or caller_sig.returned_calls is None:
            return True
        return callee_sig.name in caller_sig.returned_calls

    return_reverse_graph = {
        callee_key: {c for c in callers if _returns_result_of(c, callee_key)}
        for callee_key, callers in reverse_graph.items()
    }
    return_dist, pred_return = _bfs_taint_upward(return_seeds, return_reverse_graph, edge_call_line)
    source_seeded = _bfs_reachable_forward(source_seeds, forward_graph)

    # Emission: a single pass over the now fully-converged sets. Because BFS
    # runs each closure to completion before emission starts, there's no
    # "caller became sink-tainted before it had a source" ordering hazard to
    # special-case (the old sweep loop needed a duplicate elif branch for
    # exactly this) -- every join condition is just checked once, and
    # `_emit_cross_file_finding`'s own dedup key handles the rest.
    #
    # "sink" direction: a caller with a (converged) source calls a
    # sink-tainted callee across an edge that passes at least one argument.
    # #119: the precise per-parameter gate only applies on the DIRECT edge
    # into a function that IS ITSELF the sink (sink_dist[callee_key] == 0,
    # i.e. callee.has_sink) -- `sink_params` only describes reachability to
    # THIS callee's OWN sink call, so it says nothing about an intermediate
    # relay function (has_sink=False, sink_dist > 0 via pure propagation)
    # that merely forwards its argument to a DEEPER call; gating those edges
    # on the (necessarily empty) local sink_params would wrongly kill every
    # multi-hop chain. Every non-direct edge keeps the old any-argument gate
    # unchanged, same as a callee with no summary at all (has_sink=False, a
    # hand-built test `_FunctionSig`, or a summary that failed to resolve).
    for callee_key in sorted(sink_dist, key=lambda k: (sink_dist[k], k)):
        callee_sig = func_index.get(callee_key)
        for caller_key in sorted(reverse_graph.get(callee_key, ())):
            if caller_key not in source_seeded:
                continue
            edge = (caller_key, callee_key)
            if (
                sink_dist[callee_key] == 0
                and callee_sig is not None
                and callee_sig.sink_params is not None
            ):
                bound_params = edge_bindings.get(edge, set()) | persistent_edge_bindings.get(
                    edge, set()
                )
                if not (bound_params & callee_sig.sink_params):
                    continue
            elif not _edge_passes_taint(edge):
                continue
            caller_sig = func_index.get(caller_key)
            if caller_sig is None:
                continue
            call_line = edge_call_line.get(edge)
            indirect_agent_context = bool(
                callee_sig is not None
                and callee_sig.agent_capability_sink
                and callee_sig.sink_params
                and persistent_edge_bindings.get(edge, set()) & callee_sig.sink_params
            )
            _emit_cross_file_finding(
                new_findings,
                seen_keys,
                caller_sig,
                callee_sig,
                callee_key,
                sink_dist[callee_key],
                "sink",
                call_line,
                pred_sink,
                pred_return,
                func_index,
                indirect_agent_context=indirect_agent_context,
            )

    # "return" direction, part 1 (unchanged): a caller with its own local
    # sink calls a return-tainted callee (no args/source gating -- capturing
    # a tainted return value doesn't require passing anything TO the callee;
    # a propagator-style function like hf_hub_download produces tainted
    # output regardless of its specific arguments).
    for callee_key in sorted(return_dist, key=lambda k: (return_dist[k], k)):
        callee_sig = func_index.get(callee_key)
        for caller_key in sorted(reverse_graph.get(callee_key, ())):
            caller_sig = func_index.get(caller_key)
            if caller_sig is None or not caller_sig.has_sink:
                continue
            # The captured return must reach the caller's sink (XF-07).
            if (
                caller_sig.sink_calls is not None
                and callee_sig is not None
                and callee_sig.name not in caller_sig.sink_calls
            ):
                continue
            call_line = edge_call_line.get((caller_key, callee_key))
            _emit_cross_file_finding(
                new_findings,
                seen_keys,
                caller_sig,
                callee_sig,
                callee_key,
                return_dist[callee_key],
                "return",
                call_line,
                pred_sink,
                pred_return,
                func_index,
            )

    # "return" direction, part 2 (#119, additive): the "passthru" pattern --
    # a caller with its own local sink passes a tainted argument DIRECTLY
    # into a parameter the callee returns unchanged (`return_params`), even
    # when the callee has no `has_return_taint`/propagator signal of its own
    # (e.g. `def passthru(p): return p`, which reads no known source and
    # calls no propagator, so `return_seeds` never includes it). Deliberately
    # direct/single-hop only -- see `_FunctionSig.return_params`'s docstring
    # -- so this is a plain pass over every edge, not a BFS: there is no
    # multi-hop chain to reconstruct here, `depth=0` always (a direct call),
    # and `_emit_cross_file_finding`'s dedup key means this is a no-op for any
    # edge part 1 already emitted for.
    for callee_key in sorted(reverse_graph):
        callee_sig = func_index.get(callee_key)
        if callee_sig is None or not callee_sig.return_params:
            continue
        for caller_key in sorted(reverse_graph[callee_key]):
            caller_sig = func_index.get(caller_key)
            if caller_sig is None or not caller_sig.has_sink:
                continue
            edge = (caller_key, callee_key)
            if not (edge_bindings.get(edge, set()) & callee_sig.return_params):
                continue
            call_line = edge_call_line.get(edge)
            _emit_cross_file_finding(
                new_findings,
                seen_keys,
                caller_sig,
                callee_sig,
                callee_key,
                0,
                "return",
                call_line,
                pred_sink,
                pred_return,
                func_index,
            )

    # A persisted value can be reloaded and handed to a helper in the same
    # module.  Emit only when that exact channel-derived argument binds to a
    # parameter proven to reach the helper's own sink.
    for edge, bound_params in sorted(persistent_edge_bindings.items()):
        caller_key, callee_key = edge
        caller_sig = func_index.get(caller_key)
        callee_sig = func_index.get(callee_key)
        if (
            caller_sig is None
            or callee_sig is None
            or caller_sig.file != callee_sig.file
            or not callee_sig.has_sink
            or callee_sig.sink_params is None
            or not (bound_params & callee_sig.sink_params)
        ):
            continue
        _emit_cross_file_finding(
            new_findings,
            seen_keys,
            caller_sig,
            callee_sig,
            callee_key,
            0,
            "sink",
            edge_call_line.get(edge),
            pred_sink,
            pred_return,
            func_index,
            allow_same_file=True,
        )

    return _merge_direction_pairs(new_findings)


def _merge_direction_pairs(findings: list[Finding]) -> list[Finding]:
    """Collapse a CF-SINK-001/CF-RETURN-001 pair describing one flow (#264).

    The two directions are genuinely different traversals -- downward to a
    sink, upward through a tainted return -- and the fixpoint must keep them
    apart to terminate. But when both land on the same caller, callee and
    line, they are two views of a single flow, and reporting them as two
    findings doubles the apparent volume of the highest-trust engine we
    have: the letta audit found 18 cross-file highs describing about 6
    distinct claims.

    The survivor is the sink-direction finding (it names where the taint
    ends up, which is what a reviewer acts on); the merge is recorded in
    `metadata["directions"]` and the RETURN id is preserved in
    `metadata["merged_rule_ids"]` so a baseline entry for either id can
    still be matched.
    """
    by_key: dict[tuple[str, int, str, str], list[Finding]] = {}
    for f in findings:
        key = (
            f.file_path,
            f.start_line,
            str(f.metadata.get("caller", "")),
            str(f.metadata.get("callee_name", "")),
        )
        by_key.setdefault(key, []).append(f)

    merged: list[Finding] = []
    for group in by_key.values():
        if len(group) == 1:
            merged.append(group[0])
            continue
        sink_findings = [f for f in group if f.rule_id == "CF-SINK-001"]
        return_findings = [f for f in group if f.rule_id == "CF-RETURN-001"]
        if not sink_findings or not return_findings:
            merged.extend(group)
            continue
        survivor = max(sink_findings, key=lambda f: f.confidence)
        others = [f for f in group if f is not survivor]
        survivor.metadata["directions"] = ["sink", "return"]
        survivor.metadata["merged_rule_ids"] = sorted(
            {f.rule_id for f in others} | {survivor.rule_id}
        )
        # Keep the most confident evidence available for the merged claim.
        if survivor.taint_flow is None:
            for other in others:
                if other.taint_flow is not None:
                    survivor.taint_flow = other.taint_flow
                    break
        survivor.confidence = max(f.confidence for f in group)
        merged.append(survivor)

    # Preserve the caller's original ordering rather than dict order.
    order = {id(f): i for i, f in enumerate(findings)}
    merged.sort(key=lambda f: order[id(f)])
    return merged


#: Fixed rule-id family for cross-file findings (issue #154 Defect 3),
#: replacing the old unbounded `CF-{callee_name}` per-callee scheme. Two
#: ids only -- one per propagation direction -- so baselining/`.rowanignore`
#: suppression by rule id survives a callee rename, and per-rule metrics
#: don't treat every helper function name as its own rule. The callee is
#: still fully identified via `metadata["callee_name"]` and the message.
_CF_RULE_IDS: dict[str, str] = {"sink": "CF-SINK-001", "return": "CF-RETURN-001"}

# Log forging (CWE-117): a cross-file taint into a log statement is real but is
# log poisoning, not RCE, so it is emitted MEDIUM rather than HIGH.
_CF_LOG_FORGING_CWE = 117


def _build_cross_file_taint_flow(
    caller_sig: _FunctionSig,
    callee_sig: _FunctionSig | None,
    callee_key: tuple[str, str],
    direction: str,
    call_line: int,
    pred_sink: dict[tuple[str, str], tuple[tuple[str, str], int]],
    pred_return: dict[tuple[str, str], tuple[tuple[str, str], int]],
    func_index: dict[tuple[str, str], _FunctionSig],
) -> TaintFlow | None:
    """Reconstruct the full source->sink hop chain for a cross-file finding
    (issue #154 Defect 1), so SARIF `codeFlows`/the text report's `Taint:`
    line carry the real multi-file narrative instead of a bare location.

    "sink" direction: the finding's caller reads a source and calls
    `callee_key`, which is itself either the real sink (already seeded) or
    another hop that eventually reaches one. Walking `pred_sink` forward
    from `callee_key` follows the SAME call direction (X calls Y calls
    Z ... calls the seed), so the chain is already in source->sink order
    with no reversal needed. Each hop's line is the call site where THAT
    hop calls onward, matching Defect 2's call-site anchoring.

    "return" direction: the finding's caller already has its own sink and
    captures `callee_key`'s (tainted) return value. Walking `pred_return`
    forward from `callee_key` goes from the immediate callee BACK toward
    the deep function that originally read the source and returned it, so
    the chain is reversed before use to restore source->sink order.
    """
    if direction == "sink":
        pred_map = pred_sink
    elif direction == "return":
        pred_map = pred_return
    else:
        return None

    chain: list[TaintNode] = []
    current = callee_key
    visited = {current}
    while current in pred_map:
        next_key, line = pred_map[current]
        sig = func_index.get(current)
        if sig is not None:
            chain.append(TaintNode(file_path=sig.file, line=line))
        if next_key in visited:
            break  # defensive cycle guard; the fixpoint shouldn't produce one
        visited.add(next_key)
        current = next_key
    origin_sig = func_index.get(current) or callee_sig

    if direction == "sink":
        source_node = TaintNode(file_path=caller_sig.file, line=caller_sig.source_line or call_line)
        sink_node = None
        if origin_sig is not None:
            sink_node = TaintNode(
                file_path=origin_sig.file, line=origin_sig.sink_line or origin_sig.line
            )
        return TaintFlow(source=source_node, sink=sink_node, intermediate=chain)

    # "return": reverse so the chain reads deep-origin -> ... -> immediate
    # callee, i.e. source-to-sink order.
    chain.reverse()
    source_node = None
    if origin_sig is not None:
        source_node = TaintNode(file_path=origin_sig.file, line=origin_sig.source_line or origin_sig.line)
    sink_node = TaintNode(file_path=caller_sig.file, line=caller_sig.sink_line or call_line)
    return TaintFlow(source=source_node, sink=sink_node, intermediate=chain)


def _drop_test_anchored(result: ScanResult, target_path: Path) -> int:
    """Drop findings anchored in test/example code. Returns how many were removed.

    A cross-file finding anchors at the CALLER -- the entry point the flow
    starts from -- and a test function is not one: nobody controls a test file
    at runtime. Emitting them is pure noise. After LLM output was added as a
    cross-file source, an A/B over 17 AI/ML repos showed 200 of 226 new
    findings (88%) anchored in test files, and 121 of 121 in langchain, because
    test suites call `llm.invoke()` / `model.generate()` constantly and every
    one matched the model-receiver heuristic. `EnrichmentPass._suppress_test_
    findings` only downgrades to MEDIUM/0.4, which still buries the real ones.

    The path is made relative to the scan root first. Testing the absolute path
    would match any repository that merely happens to live under a directory
    named `test`, `examples`, `fixtures`, ... -- including every pytest
    `tmp_path`, which is how this was caught.
    """
    kept: list[Finding] = []
    dropped = 0
    for f in result.findings:
        try:
            rel = str(Path(f.file_path).resolve().relative_to(Path(target_path).resolve()))
        except (ValueError, OSError):
            rel = Path(f.file_path).name  # outside the root: judge on filename alone
        if _is_test_path(rel):
            dropped += 1
            continue
        kept.append(f)
    result.findings = kept
    return dropped


def _sink_description(callee_sig: _FunctionSig | None, taint_flow: TaintFlow | None) -> str:
    """Describe the sink this finding claims to reach (issue #264).

    A cross-file finding asserts "reaches a sink" -- so it has to say which
    sink. `sink_detail` (the originating rule's own message) is the best
    description when the callee carries one, but it is empty whenever the
    sink was found structurally rather than by a rule, which left messages
    ending at "...via get_or_create_agent() from helpers.py." and nothing
    else. The reconstructed TaintFlow already knows where the sink is, so
    fall back to quoting it.
    """
    if callee_sig is not None and callee_sig.sink_detail:
        return callee_sig.sink_detail
    sink = taint_flow.sink if taint_flow else None
    if sink is None:
        return ""
    snippet = (sink.snippet or "").strip()
    location = f"{Path(sink.file_path).name}:{sink.line}"
    if snippet:
        return f"Sink at {location}: `{snippet}`."
    return f"Sink at {location}."


def _emit_cross_file_finding(
    new_findings: list[Finding],
    seen_keys: set[tuple[str, str, str, str, str]],
    caller_sig: _FunctionSig,
    callee_sig: _FunctionSig | None,
    callee_key: tuple[str, str],
    depth: int,
    direction: str,
    call_line: int | None = None,
    pred_sink: dict[tuple[str, str], tuple[tuple[str, str], int]] | None = None,
    pred_return: dict[tuple[str, str], tuple[tuple[str, str], int]] | None = None,
    func_index: dict[tuple[str, str], _FunctionSig] | None = None,
    allow_same_file: bool = False,
    indirect_agent_context: bool = False,
) -> None:
    """Emit a cross-file finding if the call crosses file boundaries.

    `call_line`/`pred_sink`/`pred_return`/`func_index` are optional so unit
    tests that construct `_FunctionSig`s directly and call this helper
    without going through `_propagate_cross_file`'s fixpoint keep working:
    `call_line` falls back to the caller's own `line` (the old, def-line
    anchoring), and empty predecessor maps yield a `TaintFlow` with no
    intermediate hops instead of raising.
    """
    if caller_sig.file == callee_key[0] and not allow_same_file:
        return  # same-file, skip
    # direction is part of the key: a "sink" finding and a "return" finding
    # on the same caller->callee edge are two distinct taint narratives, not
    # duplicates -- omitting it let whichever direction ran first (sink is
    # checked before return each iteration) silently swallow the other.
    dedup_key = (caller_sig.file, caller_sig.name, callee_key[0], callee_key[1], direction)
    if dedup_key in seen_keys:
        return
    seen_keys.add(dedup_key)

    line = call_line if call_line is not None else caller_sig.line
    pred_sink = pred_sink if pred_sink is not None else {}
    pred_return = pred_return if pred_return is not None else {}
    func_index = func_index if func_index is not None else {}

    # ``callee_sig`` can be an intermediate relay on a multi-hop path. Walk
    # the predecessor chain to the actual sink summary before inheriting its
    # classification and description.
    sink_sig = callee_sig
    sink_key = callee_key
    seen_sink_keys: set[tuple[str, str]] = set()
    if direction == "sink":
        while sink_key in pred_sink and sink_key not in seen_sink_keys:
            seen_sink_keys.add(sink_key)
            sink_key = pred_sink[sink_key][0]
            sink_sig = func_index.get(sink_key, sink_sig)

    direction_label = {
        "sink": f"reaches a sink via {callee_key[1]}()",
        "return": f"captures tainted return from {callee_key[1]}()",
    }.get(direction, f"taint flow via {callee_key[1]}()")

    hop_label = "direct" if depth == 0 else f"transitive({depth + 1}-hop)"

    taint_flow = _build_cross_file_taint_flow(
        caller_sig,
        callee_sig,
        callee_key,
        direction,
        line,
        pred_sink,
        pred_return,
        func_index,
    )

    # A cross-file taint into a log statement is log forging (CWE-117): real,
    # but log poisoning, not the RCE a HIGH cross-file finding implies. Reflect
    # the sink's real risk class (propagated as sink_cwe) so it lands MEDIUM,
    # matching how the intra-file log rules are rated. Any other sink stays HIGH.
    sink_cwe = sink_sig.sink_cwe if sink_sig is not None else []
    unclassified_return = bool(
        direction == "return"
        and not sink_cwe
        and (sink_sig is None or not sink_sig.sink_detail)
        and (sink_sig is None or sink_sig.sink_category is None)
    )
    severity = (
        Severity.LOW
        if unclassified_return
        else Severity.MEDIUM
        if _CF_LOG_FORGING_CWE in sink_cwe
        else Severity.HIGH
    )
    flow_label = (
        "Persistent-data"
        if allow_same_file
        else "Indirect-context capability"
        if indirect_agent_context
        else "Cross-file"
    )
    feedback_detail = (
        " A tool result is fed back into the repeated model loop and can select a later tool."
        if indirect_agent_context and callee_sig is not None and callee_sig.agent_tool_feedback_loop
        else ""
    )
    ambient_authority = bool(
        callee_sig is not None
        and callee_sig.agent_capability_sink
        and caller_sig.authenticated_boundary
        and not callee_sig.principal_policy_used
    )
    authority_detail = (
        " The authenticated caller's user, tenant, role, or policy context is not passed "
        "to the agent executor, so tools run with the server process's broader authority."
        if ambient_authority
        else ""
    )

    finding = Finding(
        rule_id=(
            "PERSISTENT-TAINT-001"
            if allow_same_file
            else "AGENT-CAPABILITY-003"
            if (
                indirect_agent_context
                and callee_sig is not None
                and callee_sig.agent_tool_feedback_loop
            )
            else "AGENT-CAPABILITY-002"
            if callee_sig is not None and callee_sig.agent_capability_sink
            else _CF_RULE_IDS.get(direction, "CF-SINK-001")
        ),
        message=(
            f"{flow_label} taint "
            f"[{hop_label}, {direction}]: "
            f"{caller_sig.name}() in {Path(caller_sig.file).name} "
            f"{direction_label} from {Path(callee_key[0]).name}. "
            f"{_sink_description(sink_sig, taint_flow)}{feedback_detail}{authority_detail}"
        ),
        severity=severity,
        category=(
            _infer_agent_tool_category(callee_sig.sink_detail)
            if allow_same_file and callee_sig is not None
            else Category.AI_ML
            if callee_sig is not None and callee_sig.agent_capability_sink
            else sink_sig.sink_category
            if sink_sig is not None and sink_sig.sink_category is not None
            else Category.GENERAL
        ),
        file_path=caller_sig.file,
        start_line=line,
        confidence=CROSSFILE_TAINT(depth),
        cwe_ids=list(sink_cwe),
        engine="crossfile",
        taint_flow=taint_flow,
        metadata={
            "cross_file": not allow_same_file,
            "caller": caller_sig.name,
            "callee_file": callee_key[0],
            "callee_name": callee_key[1],
            "hop_depth": depth + 1,
            "direction": direction,
            "persistent_channel": allow_same_file,
            "agent_capability_graph": bool(
                callee_sig is not None and callee_sig.agent_capability_sink
            ),
            "indirect_context": indirect_agent_context,
            "tool_feedback_loop": bool(
                callee_sig is not None and callee_sig.agent_tool_feedback_loop
            ),
            "ambient_authority": ambient_authority,
            "unclassified_return_lead": unclassified_return,
            "sink_rule_id": sink_sig.sink_rule_id if sink_sig is not None else "",
            "sink_symbol": sink_sig.sink_symbol if sink_sig is not None else "",
        },
    )
    new_findings.append(finding)


def _resolve_callee(
    caller_file: str,
    callee_name: str,
    module_qual: str | None,
    import_graph: _ImportGraph,
) -> tuple[str, str] | None:
    """Resolve a callee to `(defining_file, name_in_that_file)`.

    The second element differs from `callee_name` for aliased imports
    (`from c import run_it as go`; `import runner from './shell.js'`), where
    the local name is not the name the callee is defined under (XF-04).
    """
    if module_qual == _UNRESOLVED_QUALIFIER:
        # a.b.foo() -- the qualifier chain wasn't attributable to any single
        # name. Don't fabricate a same-file edge just because a same-named
        # function happens to exist somewhere; drop the edge instead.
        return None
    if module_qual and module_qual not in _SELF_QUALIFIERS:
        target = import_graph.module_to_file.get((caller_file, module_qual))
        return (target, callee_name) if target else None
    # self.foo()/cls.foo(), or a genuinely unqualified foo() call.
    resolved = import_graph.name_to_def.get((caller_file, callee_name))
    if resolved:
        return resolved[0], resolved[1]
    # Same-file call
    return caller_file, callee_name


def _resolve_callee_file(
    caller_file: str,
    callee_name: str,
    module_qual: str | None,
    import_graph: _ImportGraph,
) -> str | None:
    """Resolve a callee to its defining file."""
    resolved = _resolve_callee(caller_file, callee_name, module_qual, import_graph)
    return resolved[0] if resolved else None


# ---------------------------------------------------------------------------
# Pass
# ---------------------------------------------------------------------------


_TOOL_HELPER_MAX_HOPS = 4


def _reads_tainted(expr: ast.expr, tainted: set[str]) -> bool:
    return any(name in tainted for name in _names_outside_path_reducers(expr))


def _tainted_locals(func_node: ast.AST, seeds: set[str]) -> set[str]:
    """`seeds` plus names assigned from them, including `for` targets and
    comprehension variables over a tainted iterable."""
    guarded = {
        name for n in ast.walk(func_node) if isinstance(n, ast.stmt)
        for name in _statement_guarded_names(n)
    }
    tainted = set(seeds) - guarded
    for _ in range(4):
        before = len(tainted)
        for n in ast.walk(func_node):
            if isinstance(n, (ast.Assign, ast.AnnAssign)) and n.value is not None:
                if _reads_tainted(n.value, tainted):
                    targets = n.targets if isinstance(n, ast.Assign) else [n.target]
                    tainted.update(x.id for tgt in targets for x in ast.walk(tgt) if isinstance(x, ast.Name))
            elif isinstance(n, (ast.For, ast.AsyncFor, ast.comprehension)):
                if _reads_tainted(n.iter, tainted):
                    tainted.update(x.id for x in ast.walk(n.target) if isinstance(x, ast.Name))
        if len(tainted) == before:
            break
    return tainted


def _resolve_helper(
    call: ast.Call,
    caller_file: str,
    def_nodes: dict[tuple[str, str], ast.AST],
    import_graph: _ImportGraph,
) -> tuple[str, ast.AST] | None:
    """A same-file function, `self.`/`cls.` method, or imported function."""
    func = call.func
    if isinstance(func, ast.Name):
        name, qualifier = func.id, None
    elif isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
        name, qualifier = func.attr, func.value.id
    else:
        return None
    if qualifier in (None, *_SELF_QUALIFIERS) and (caller_file, name) in def_nodes:
        return caller_file, def_nodes[(caller_file, name)]
    resolved = _resolve_callee(
        caller_file, name, None if qualifier in _SELF_QUALIFIERS else qualifier, import_graph
    )
    if resolved is not None and resolved in def_nodes:
        return resolved[0], def_nodes[resolved]
    return None


def _bound_params(call: ast.Call, callee: ast.AST, tainted: set[str]) -> set[str]:
    """Callee parameters that receive a tainted argument at `call`."""
    if not isinstance(callee, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return set()
    args = callee.args
    positional = [a.arg for a in (*args.posonlyargs, *args.args)]
    if positional and positional[0] in _SELF_QUALIFIERS:
        positional = positional[1:]
    bound = {
        positional[i]
        for i, arg in enumerate(call.args)
        if i < len(positional) and not isinstance(arg, ast.Starred) and _reads_tainted(arg, tainted)
    }
    named = {a.arg for a in (*args.args, *args.kwonlyargs)}
    bound |= {kw.arg for kw in call.keywords if kw.arg in named and _reads_tainted(kw.value, tainted)}
    return bound


def _tool_helper_findings(
    parsed: list[tuple[str, ast.AST]],
    boundary_kind_by_id: dict[int, str],
    def_nodes: dict[tuple[str, str], ast.AST],
    import_graph: _ImportGraph,
    def_nodes_by_name: dict[str, list[tuple[str, ast.AST]]],
) -> list[Finding]:
    """Agent tool argument -> helper chain -> sink.

    A tool's own body is checked by the boundary pass; real MCP servers pass
    the argument to a helper (same file, `self.` method or imported module)
    that does the file read, shell call or fetch. Walk those calls up to
    `_TOOL_HELPER_MAX_HOPS`, seeding each helper's sink check with only the
    parameters that received the tool's data.
    """
    findings: list[Finding] = []
    for file_str, tree in parsed:
        for tool in ast.walk(tree):
            if boundary_kind_by_id.get(id(tool)) != "agent_tool":
                continue
            frontier = [(file_str, tool, _param_names(tool), [])]
            seen = {(file_str, tool.name)}
            for _hop in range(_TOOL_HELPER_MAX_HOPS):
                next_frontier = []
                for caller_file, caller, seeds, path in frontier:
                    tainted = _tainted_locals(caller, seeds)
                    for call in ast.walk(caller):
                        if not isinstance(call, ast.Call):
                            continue
                        target = _resolve_helper(call, caller_file, def_nodes, import_graph)
                        if target is None or target[1] is caller:
                            continue
                        callee_file, callee = target
                        bound = _bound_params(call, callee, tainted)
                        if not bound:
                            continue
                        hops = [*path, TaintNode(file_path=caller_file, line=call.lineno)]
                        has_sink, detail, line = _structural_path_sink(
                            callee, def_nodes, True, callee_file, import_graph,
                            def_nodes_by_name, seed_params=bound,
                        )
                        if has_sink:
                            category = _infer_agent_tool_category(detail)
                            findings.append(Finding(
                                rule_id="AGENT-TOOL-001",
                                message=(
                                    f"Agent tool '{tool.name}': its argument reaches "
                                    f"{callee.name}() ({Path(callee_file).name}:{line}) through "
                                    f"{len(hops)} call(s); {detail}"
                                ),
                                severity=Severity.HIGH,
                                category=category,
                                cwe_ids=[_AGENT_TOOL_CWE[category]] if category in _AGENT_TOOL_CWE else [],
                                # Anchored at the tool's own call, like
                                # CF-SINK-001: one finding per entry point.
                                file_path=file_str,
                                start_line=hops[0].line,
                                confidence=BOUNDARY_SOURCE,
                                engine="crossfile",
                                taint_flow=TaintFlow(
                                    source=TaintNode(file_path=file_str, line=tool.lineno),
                                    sink=TaintNode(file_path=callee_file, line=line),
                                    intermediate=hops,
                                ),
                                metadata={
                                    "boundary_source": True,
                                    "boundary_kind": "agent_tool",
                                    "caller": tool.name,
                                    "callee_name": callee.name,
                                    "source_kind": "tool_param",
                                },
                            ))
                        key = (callee_file, callee.name)
                        if key not in seen:
                            seen.add(key)
                            next_frontier.append((callee_file, callee, bound, hops))
                frontier = next_frontier
    return findings


class CrossFilePass:
    name = "crossfile"

    def run(self, context: ScanContext) -> ScanResult:
        start = time.perf_counter()
        result = ScanResult()

        target = context.target_path
        if not target.exists():
            return result

        # One file that cannot be parsed is skipped by the iterator, never
        # allowed to abort the pass (XF-09).
        sources = list(iter_python_sources(context, owner=self.name, skip_tests=False))
        if not sources:
            logger.info("CrossFilePass: no Python files, skipping")
            return result

        # Single-file targets take the full path too: structural boundary
        # findings (an MCP tool argument reaching a sink) and persistent
        # channels are same-file by nature, and one-file MCP servers are common.
        # Phase 1: parse all files, extract imports + a per-(file, name) function
        # index (used to resolve a sanitizer call through the caller's own import
        # graph first -- same-file def, then name_to_def -- before falling back to
        # a project-wide bare-name scan of every same-named candidate; see
        # `_classify_sanitizer_by_name`). Also collect each file's own ClassDef
        # names, used the same way to resolve ORM model identity for the
        # second-order taint-channel matching below (`_resolve_orm_class_file`).
        all_imports = _ImportGraph()
        parsed: list[tuple[str, ast.AST]] = []
        def_nodes: dict[tuple[str, str], ast.AST] = {}
        def_nodes_by_line: dict[tuple[str, str, int], ast.AST] = {}
        def_nodes_by_name: dict[str, list[tuple[str, ast.AST]]] = {}
        classes_by_file: dict[str, set[str]] = {}
        top_level_defs: dict[str, set[str]] = {}

        for py_file, tree in sources:
            file_str = str(py_file.resolve())
            parsed.append((file_str, tree))

            file_imports = _extract_imports(file_str, tree)
            all_imports.name_to_def.update(file_imports.name_to_def)
            all_imports.module_to_file.update(file_imports.module_to_file)

            classes_here: set[str] = set()
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    def_nodes.setdefault((file_str, node.name), node)
                    def_nodes_by_line[(file_str, node.name, node.lineno)] = node
                    def_nodes_by_name.setdefault(node.name, []).append((file_str, node))
                elif isinstance(node, ast.ClassDef):
                    classes_here.add(node.name)
            classes_by_file[file_str] = classes_here
            top_level_defs[file_str] = {
                n.name for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
            }

        _resolve_import_indirection(all_imports, def_nodes, top_level_defs)

        orm_channels: set[tuple] = set()
        vector_channels: set[tuple[str, ...]] = set()
        objstate_channels: set[tuple[str, str, str]] = set()
        file_channels = _collect_file_write_channels(parsed)
        boundary_kind_by_id: dict[int, str] = {}
        for file_str, tree in parsed:
            orm_channels |= _collect_orm_write_channels(
                tree, file_str, all_imports, classes_by_file
            )
            # #156: prefer stable resource identity; fall back to receiver.
            vector_channels |= _collect_vector_write_channels(tree)
            # #300: object/KV state, armed per receiver and literal key.
            objstate_channels |= _collect_objstate_write_channels(tree)
            boundary_kind_by_id.update(_collect_boundary_nodes(tree))

        # Project-wide class model for receiver type inference (#158).
        class_model = _build_class_model(parsed)

        all_funcs: list[_FunctionSig] = []
        for file_str, tree in parsed:
            all_funcs.extend(
                _extract_functions(
                    file_str,
                    tree,
                    def_nodes,
                    orm_channels,
                    boundary_kind_by_id,
                    import_graph=all_imports,
                    classes_by_file=classes_by_file,
                    def_nodes_by_name=def_nodes_by_name,
                    class_model=class_model,
                    vector_channels=vector_channels,
                    objstate_channels=objstate_channels,
                )
            )

        logger.info(
            "CrossFilePass: %d files, %d functions, %d imports",
            len(sources),
            len(all_funcs),
            len(all_imports.name_to_def),
        )

        # Phase 2: match all findings to functions, both taint and neuroscan
        # NeuroScan regex hits mark sink functions; TaintPass hits add source info
        all_findings = [f for f in context.result.findings if f.engine in ("opengrep", "neuroscan")]
        tool_registries = _collect_tool_registries(parsed)
        agent_capability_findings = _collect_agent_capability_findings(
            parsed, all_imports, tool_registries
        )
        confirmation_findings = _collect_confirmation_provenance_findings(parsed)
        reflection_findings = _collect_reflective_tool_findings(parsed)
        all_findings.extend(agent_capability_findings)
        # Resolve sink-ness for regex findings from the converter manifest's
        # declared rule categories rather than the stale hand-maintained
        # ID-prefix list (see `_is_sink_rule`). Mirrors the same defensive
        # `.get(..., {})` chain enrichment.py uses for this same structure --
        # an absent/empty manifest (e.g. --legacy-neuroscan) degrades to
        # `{}`, which `_is_sink_rule` treats as "no rule_map" and falls back
        # to the prefix check, never raises.
        rule_map = context.metadata.get("conversion_manifest", {}).get("rule_map", {})
        all_funcs = _match_findings_to_functions(
            all_findings, all_funcs, rule_map=rule_map, def_nodes_by_line=def_nodes_by_line
        )

        # Phase 2b: per-parameter procedure summaries (#119), now that
        # has_sink/sink_line are finalized above for every function, not just
        # the structural-path-sink subset _extract_functions could see alone.
        _compute_param_summaries(all_funcs, def_nodes, def_nodes_by_line)

        # Phase 3: propagate across files
        new_findings = _propagate_cross_file(all_funcs, all_imports, all_findings, target)
        new_findings.extend(agent_capability_findings)
        new_findings.extend(confirmation_findings)
        new_findings.extend(reflection_findings)
        new_findings.extend(_file_channel_findings(parsed, file_channels))
        new_findings.extend(
            _tool_helper_findings(
                parsed, boundary_kind_by_id, def_nodes, all_imports, def_nodes_by_name
            )
        )

        for f in new_findings:
            result.add_finding(f)

        boundary_findings = 0
        for func in all_funcs:
            if func.boundary_finding is None:
                continue
            line, message, boundary_kind = func.boundary_finding
            rule_id, label = _BOUNDARY_RULE_IDS[boundary_kind]
            category = _infer_agent_tool_category(message)
            result.add_finding(
                Finding(
                    rule_id=rule_id,
                    message=f"{label} '{func.name}': {message}",
                    severity=Severity.HIGH,
                    category=category,
                    cwe_ids=[_AGENT_TOOL_CWE[category]] if category in _AGENT_TOOL_CWE else [],
                    file_path=func.file,
                    start_line=line,
                    confidence=BOUNDARY_SOURCE,
                    engine="crossfile",
                    metadata={
                        "boundary_source": True,
                        "boundary_kind": boundary_kind,
                        "caller": func.name,
                        # The model chooses a tool's arguments: file-level
                        # reachability guesses must not demote this finding.
                        **({"source_kind": "tool_param"} if boundary_kind == "agent_tool" else {}),
                    },
                )
            )
            boundary_findings += 1

        dropped = _drop_test_anchored(result, context.target_path)

        duration = time.perf_counter() - start
        scan_span(self.name, duration)
        logger.info(
            "CrossFilePass: %d cross-file findings, %d structural boundary findings "
            "(%d test-anchored dropped) in %.1fs",
            len(result.findings),
            boundary_findings,
            dropped,
            duration,
        )
        return result
