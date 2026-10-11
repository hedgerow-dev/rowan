"""AST-based taint source origin classifier.

Traces a taint flow's source variable back to its definition site using
the Python AST, then classifies the definition's right-hand side into
an origin category with a confidence score.

This is more precise than snippet-based regex classification because it
follows variable assignments and resolves chained origins.
"""

from __future__ import annotations

import ast
import logging
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from rowan.analysis.dominance import find_enclosing_function
from rowan.analysis.request_sources import route_input_names

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class SourceOrigin:
    label: str
    confidence: float


# ── origin labels ────────────────────────────────────────────────────────
ORIGIN_HTTP_INPUT = SourceOrigin("http_input", 1.0)
ORIGIN_CLI_INPUT = SourceOrigin("cli_input", 0.9)
ORIGIN_ENV_VARIABLE = SourceOrigin("env_variable", 0.7)
ORIGIN_FILE_CONTENTS = SourceOrigin("file_contents", 0.5)
ORIGIN_CONFIG_CONSTANT = SourceOrigin("config_constant", 0.4)
ORIGIN_FUNCTION_PARAM = SourceOrigin("function_param", 0.3)
ORIGIN_DB_RESULT = SourceOrigin("db_result", 0.25)
ORIGIN_UUID_GENERATED = SourceOrigin("uuid_generated", 0.2)
ORIGIN_MODEL_OUTPUT = SourceOrigin("model_output", 0.1)
ORIGIN_CONSTANT_LITERAL = SourceOrigin("constant_literal", 0.05)
ORIGIN_UNKNOWN = SourceOrigin("unknown", 0.0)


# ── classification helpers ────────────────────────────────────────────────

_HTTP_CALL_NAMES = frozenset({
    "get", "post", "put", "delete", "patch", "head",
})
_CONFIG_VAR_RE = __import__("re").compile(
    r"(?:_[Cc][Oo][Nn][Ff][Ii][Gg]|_settings|_URL|_ENDPOINT|_HOST"
    r"|MARKETPLACE|_KEY$|_SECRET$|_TOKEN$|_PASSWORD$|ADMIN_"
    r"|INTERNAL_|PREFECT_|REDIS_|_SERVICE|_SERVICES|_CLUSTER)"
)
_UUID_FUNC_NAMES = frozenset({
    "uuid4", "UUID",
})

_DB_EXECUTE_NAMES = frozenset({
    "execute", "executemany", "fetchone", "fetchall", "fetchmany",
    "query", "first", "all", "scalar", "scalars",
})
_DB_CLASS_NAMES = frozenset({
    "Session", "session", "cursor", "Cursor", "Connection", "connection",
    "db", "engine", "conn", "query",
})

_TYPE_CONVERSIONS = frozenset({
    "str", "int", "float", "bool", "bytes", "list", "tuple", "dict", "set",
})

_MODEL_FUNC_NAMES = frozenset({
    "generate", "decode", "predict", "__call__",
})


# ── AST traversal ─────────────────────────────────────────────────────────

def _collect_target_names(node: ast.expr) -> set[str]:
    """Extract all name identifiers from an assignment target."""
    names: set[str] = set()
    if isinstance(node, ast.Name):
        names.add(node.id)
    elif isinstance(node, (ast.Tuple, ast.List)):
        for elt in node.elts:
            names |= _collect_target_names(elt)
    elif isinstance(node, ast.Starred):
        names |= _collect_target_names(node.value)
    return names


def _walk_scope(tree: ast.AST):
    """Walk one lexical scope without descending into nested definitions."""
    yield tree
    for child in ast.iter_child_nodes(tree):
        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            continue
        yield from _walk_scope(child)


def _find_assignments(tree: ast.AST, var_name: str) -> list[tuple[int, ast.AST]]:
    """Find assignments to ``var_name`` in this lexical scope only."""
    results: list[tuple[int, ast.AST]] = []
    for node in _walk_scope(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if var_name in _collect_target_names(target):
                    results.append((node.lineno, node))
                    break
        elif isinstance(node, (ast.AnnAssign, ast.AugAssign)):
            if var_name in _collect_target_names(node.target):
                results.append((node.lineno, node))
    return results


def _nearest_assignment(
    tree: ast.AST, var_name: str, target_line: int,
) -> ast.AST | None:
    """Find the nearest assignment to var_name at or before target_line.

    Only the enclosing function's own assignments count, then module-level
    ones; an assignment to the same name in another function says nothing
    about this one (TE-14). A parameter of the enclosing function with no
    assignment inside it resolves to None, which the caller reports as
    `function_param`.
    """
    enclosing = find_enclosing_function(tree, target_line)
    if enclosing is not None:
        scope = _find_assignments(enclosing, var_name)
        own_args = (
            *enclosing.args.posonlyargs,
            *enclosing.args.args,
            *enclosing.args.kwonlyargs,
        )
        if var_name in {a.arg for a in own_args} and not scope:
            return None
        if not scope:
            scope = _find_assignments(tree, var_name)
    else:
        scope = _find_assignments(tree, var_name)
    best: tuple[int, ast.AST] | None = None
    for lineno, node in scope:
        if lineno <= target_line:
            if best is None or lineno > best[0]:
                best = (lineno, node)
    return best[1] if best else None


# ── RHS classification ────────────────────────────────────────────────────

def _unwrap_type_conversion(call_node: ast.Call) -> ast.expr | None:
    """Unwrap type conversion calls like str(expr), int(expr)."""
    if (
        isinstance(call_node.func, ast.Name)
        and call_node.func.id in _TYPE_CONVERSIONS
        and len(call_node.args) == 1
    ):
        return call_node.args[0]
    return None


def _classify_call(call_node: ast.Call) -> SourceOrigin | None:
    """Classify a function/method call's origin."""
    func = call_node.func

    if isinstance(func, ast.Attribute):
        chain = _attribute_chain(func)

        if len(chain) >= 2:
            if chain[-2] == "uuid" and chain[-1] in _UUID_FUNC_NAMES:
                return ORIGIN_UUID_GENERATED
            if chain[-2] in ("model", "tokenizer") and chain[-1] in _MODEL_FUNC_NAMES:
                return ORIGIN_MODEL_OUTPUT
            if chain[-1] in _DB_EXECUTE_NAMES:
                if any(n in _DB_CLASS_NAMES for n in chain):
                    return ORIGIN_DB_RESULT
            if chain[-1] in _HTTP_CALL_NAMES and "request" in chain:
                return ORIGIN_HTTP_INPUT
            if "environ" in chain or "getenv" in chain:
                return ORIGIN_ENV_VARIABLE

        if chain[-1] in _UUID_FUNC_NAMES:
            return ORIGIN_UUID_GENERATED
        if chain[-1] in _MODEL_FUNC_NAMES:
            return ORIGIN_MODEL_OUTPUT

    if isinstance(func, ast.Name):
        if func.id in ("input", "eval", "exec"):
            return ORIGIN_CLI_INPUT
        if func.id == "getenv":
            return ORIGIN_ENV_VARIABLE
        if func.id in _UUID_FUNC_NAMES:
            return ORIGIN_UUID_GENERATED
        if func.id == "open":
            return ORIGIN_FILE_CONTENTS

    return None


def _classify_rhs(
    rhs: ast.expr,
    tree: ast.AST | None = None,
    var_name: str | None = None,
    visited: frozenset[str] | None = None,
) -> SourceOrigin | None:
    """Classify a right-hand side expression into an origin."""
    if visited is None:
        visited = frozenset()

    if isinstance(rhs, ast.Constant):
        return ORIGIN_CONSTANT_LITERAL

    if isinstance(rhs, ast.Call):
        result = _classify_call(rhs)
        if result:
            return result
        unwrapped = _unwrap_type_conversion(rhs)
        if unwrapped is not None:
            return _classify_rhs(unwrapped, tree, var_name, visited)

        if isinstance(rhs.func, ast.Attribute):
            chain = _attribute_chain(rhs.func)
            if chain and chain[-1] in ("replace", "strip", "lower", "upper", "split", "join", "format"):
                return _classify_rhs(rhs.func.value, tree, var_name, visited)
            if len(chain) >= 2 and chain[-1] in _DB_EXECUTE_NAMES:
                if any(n in _DB_CLASS_NAMES for n in chain):
                    return ORIGIN_DB_RESULT
            if any(n in _DB_CLASS_NAMES for n in chain):
                return ORIGIN_DB_RESULT

    if isinstance(rhs, ast.Attribute):
        chain = _attribute_chain(rhs)
        chain_str = ".".join(chain)
        if "request" in chain:
            return ORIGIN_HTTP_INPUT
        if "environ" in chain or "getenv" in chain_str:
            return ORIGIN_ENV_VARIABLE
        if _CONFIG_VAR_RE.search(chain_str):
            return ORIGIN_CONFIG_CONSTANT
        if any(n in _DB_CLASS_NAMES for n in chain):
            return ORIGIN_DB_RESULT

    if isinstance(rhs, ast.Name):
        if rhs.id.isupper():
            return ORIGIN_CONFIG_CONSTANT
        if rhs.id in ("True", "False", "None"):
            return ORIGIN_CONSTANT_LITERAL
        if tree and rhs.id not in visited:
            sub = _nearest_assignment(tree, rhs.id, rhs.lineno - 1)
            if sub:
                sub_rhs = None
                if isinstance(sub, ast.Assign) or (isinstance(sub, ast.AnnAssign) and sub.value):
                    sub_rhs = sub.value
                if sub_rhs:
                    return _classify_rhs(sub_rhs, tree, rhs.id, visited | {rhs.id})
        return None

    if isinstance(rhs, ast.Subscript):
        chain = _attribute_chain(rhs.value)
        chain_str = ".".join(chain)
        if "argv" in chain_str:
            return ORIGIN_CLI_INPUT
        if "environ" in chain_str or "getenv" in chain_str:
            return ORIGIN_ENV_VARIABLE
        if "request" in chain:
            return ORIGIN_HTTP_INPUT

    if isinstance(rhs, ast.JoinedStr):
        return _classify_fstring(rhs)

    # Taint is a max over inputs: `"ls " + request.args["d"]` is HTTP input,
    # whichever side the literal is on (TE-12).
    if isinstance(rhs, ast.BinOp):
        left = _classify_rhs(rhs.left, tree, var_name, visited)
        right = _classify_rhs(rhs.right, tree, var_name, visited)
        return _most_tainted(left, right)

    if isinstance(rhs, ast.IfExp):
        body = _classify_rhs(rhs.body, tree, var_name, visited)
        orelse = _classify_rhs(rhs.orelse, tree, var_name, visited)
        return _most_tainted(body, orelse)

    return None


def _most_tainted(*origins: SourceOrigin | None) -> SourceOrigin | None:
    """The origin with the highest confidence, label and all."""
    known = [o for o in origins if o is not None]
    return max(known, key=lambda o: o.confidence) if known else None


def _classify_fstring(node: ast.JoinedStr) -> SourceOrigin | None:
    """Classify an f-string by its most tainted interpolation (TE-13)."""
    best: SourceOrigin | None = None
    for value in node.values:
        if isinstance(value, ast.FormattedValue):
            best = _most_tainted(best, _classify_rhs(value.value))
    return best


def _attribute_chain(node: ast.expr) -> list[str]:
    """Extract a dotted attribute chain like a.b.c → ['a', 'b', 'c']."""
    parts: list[str] = []
    current = node
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if isinstance(current, ast.Name):
        parts.append(current.id)
    elif isinstance(current, ast.Call):
        parts.append("...()")
        if isinstance(current.func, ast.Attribute):
            sub = _attribute_chain(current.func)
            parts.extend(sub)
        elif isinstance(current.func, ast.Name):
            parts.append(current.func.id)
    elif isinstance(current, ast.Subscript):
        sub = _attribute_chain(current.value)
        parts.extend(sub)
    parts.reverse()
    return parts


# ── public API ─────────────────────────────────────────────────────────────

@lru_cache(maxsize=512)
def _parse_file_cached(
    path: str, mtime_ns: int, ctime_ns: int, size: int, inode: int
) -> ast.AST | None:
    """Cached AST parse, keyed by file identity as well as its path."""
    try:
        return ast.parse(Path(path).read_text(encoding="utf-8", errors="ignore"))
    except (SyntaxError, OSError, UnicodeDecodeError):
        return None


def _extract_root_var(snippet: str) -> str | None:
    """Extract the root variable name from a source snippet.

    e.g. 'request.args.get("q")' → 'request'
         'dataset_id' → 'dataset_id'
         'dify_config.MARKETPLACE_API_URL' → 'dify_config'
         "f'{prefix}_{uuid}_Node'" → None (f-string, handled by classify_fstring)
    """
    snippet = snippet.strip()
    if not snippet:
        return None
    if snippet[0] in ("'", '"') or snippet.startswith(("f'", 'f"')):
        return None
    match = __import__("re").match(r"^[a-zA-Z_]\w*", snippet)
    if match:
        return match.group(0)
    return None


def _classify_snippet_expression(snippet: str, tree: ast.AST) -> SourceOrigin | None:
    """Classify the snippet's own expression, when it is itself an origin.

    Returns None for a bare name (`x`), where the expression carries no
    information and the caller must trace the variable back to its
    assignment instead. Taint snippets are frequently truncated or carry
    trailing context, so an unparseable snippet is simply not classified.
    """
    text = snippet.strip().rstrip(",;")
    if not text:
        return None
    try:
        expr = ast.parse(text, mode="eval").body
    except SyntaxError:
        return None
    if isinstance(expr, ast.Name):
        return None
    return _classify_rhs(expr, tree, None)


def trace_source(
    file_path: str,
    snippet: str,
    source_line: int,
) -> SourceOrigin:
    """Trace a taint source back to its definition and classify the origin.

    Args:
        file_path: Path to the source file.
        snippet: The source snippet from the taint flow.
        source_line: The line number where the source appears.

    Returns:
        A SourceOrigin with a label and confidence score.
    """
    root_var = _extract_root_var(snippet)
    if root_var is None:
        return ORIGIN_UNKNOWN

    try:
        stat = Path(file_path).stat()
    except OSError:
        return ORIGIN_UNKNOWN
    tree = _parse_file_cached(
        file_path, stat.st_mtime_ns, stat.st_ctime_ns, stat.st_size, stat.st_ino
    )
    if tree is None:
        return ORIGIN_UNKNOWN

    # The snippet may already BE the origin expression rather than a variable
    # that needs tracing -- `request.GET.get("q")` is HTTP input no matter
    # where `request` came from. Classify it directly first.
    #
    # Without this, Django is systematically misjudged: its views receive
    # `request` as a parameter, so the root-variable lookup below finds no
    # assignment and returns FUNCTION_PARAM (0.3), which is under every
    # category threshold in _SAFE_ORIGINS_BY_CATEGORY and floors the finding
    # to INFO. Flask escapes this only because its `request` is a module
    # global. Found while adding TNT-XSS-002 (#268), whose Django sinks were
    # unreachable in practice because of it.
    self_origin = _classify_snippet_expression(snippet, tree)
    if self_origin is not None:
        return self_origin

    assignment = _nearest_assignment(tree, root_var, source_line)
    if assignment is None:
        # A route handler's own parameters (FastAPI typed params, Flask
        # `<name>` path variables) are request input, not caller data (#59).
        func = find_enclosing_function(tree, source_line)
        if func is not None and root_var in route_input_names(func):
            return ORIGIN_HTTP_INPUT
        return ORIGIN_FUNCTION_PARAM

    rhs = None
    if isinstance(assignment, ast.Assign) or (isinstance(assignment, ast.AnnAssign) and assignment.value) or isinstance(assignment, ast.AugAssign):
        rhs = assignment.value

    if rhs is None:
        return ORIGIN_UNKNOWN

    origin = _classify_rhs(rhs, tree, root_var)
    if origin is not None:
        return origin

    return ORIGIN_UNKNOWN


def classify_origin(
    file_path: str,
    source_snippet: str,
    source_line: int,
) -> tuple[str | None, float]:
    """Entry point compatible with _classify_source_origin in enrichment.py.

    Tries AST-based tracing first. Falls back to returning None so the
    caller can use snippet-based classification.
    """
    result = trace_source(file_path, source_snippet, source_line)
    if result.label != "unknown":
        return (result.label, result.confidence)
    return (None, 0.0)
