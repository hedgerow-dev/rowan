"""Narrow safety proofs for Python sinks whose call alone is ambiguous.

Only straight-line local code is accepted. Unknown calls, control flow,
shadowed imports and response mutations make the proof fail closed.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path, PurePosixPath

from rowan.analysis.dominance import find_enclosing_function


def _imported_name(tree: ast.AST, expr: ast.expr, qualified: str) -> bool:
    """Recognize a module-level import with no rebinding anywhere in the file."""
    if not isinstance(tree, ast.Module):
        return False
    module, _, member = qualified.rpartition(".")
    for node in tree.body:
        bindings: list[tuple[str, bool]] = []
        if isinstance(node, ast.Import):
            bindings = [
                (a.asname or a.name, isinstance(expr, ast.Attribute)
                 and isinstance(expr.value, ast.Name)
                 and expr.value.id == (a.asname or a.name) and expr.attr == member)
                for a in node.names if a.name == module
            ]
        elif isinstance(node, ast.ImportFrom) and node.module == module:
            bindings = [
                (a.asname or a.name, isinstance(expr, ast.Name)
                 and expr.id == (a.asname or a.name))
                for a in node.names if a.name == member
            ]
        for name, matches in bindings:
            if not matches:
                continue
            for other in ast.walk(tree):
                if isinstance(other, ast.Name) and other.id == name and isinstance(other.ctx, (ast.Store, ast.Del)):
                    break
                if (isinstance(other, ast.Attribute) and isinstance(other.ctx, (ast.Store, ast.Del))
                        and isinstance(other.value, ast.Name) and other.value.id == name):
                    break
                if isinstance(other, ast.arg) and other.arg == name:
                    break
                if isinstance(other, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and other.name == name:
                    break
                if isinstance(other, (ast.Import, ast.ImportFrom)):
                    aliases = [a.asname or a.name.split(".")[0] for a in other.names]
                    if "*" in aliases or aliases.count(name) > (1 if other is node else 0):
                        break
            else:
                return True
    return False


def _literal(expr: ast.expr) -> bool:
    if isinstance(expr, ast.Constant):
        return True
    if isinstance(expr, (ast.Tuple, ast.List, ast.Set)):
        return all(_literal(e) for e in expr.elts)
    if isinstance(expr, ast.Dict):
        return all(k is not None and _literal(k) and _literal(v)
                   for k, v in zip(expr.keys, expr.values, strict=True))
    return False


def resolved_regex_search(tree: ast.AST, line: int) -> bool:
    """Disambiguate generic vector/LDAP search sinks from stdlib regex search.

    Keep unresolved receivers and lines containing another possible vector
    sink. Import aliases are accepted only when they have no rebinding.
    """
    candidates = [
        node for node in ast.walk(tree)
        if isinstance(node, ast.Call) and node.lineno == line
        and ((isinstance(node.func, ast.Attribute)
              and node.func.attr in {"search", "search_s", "search_ext", "query", "similarity_search"})
             or _imported_name(tree, node.func, "re.search"))
    ]
    return bool(candidates) and all(
        _imported_name(tree, call.func, "re.search") for call in candidates
    )


def safe_pickle_roundtrip(tree: ast.AST, line: int) -> bool:
    """pickle.loads of bytes made locally by pickle.dumps of literal data.

Raw bytes literals are deliberately NOT safe: they may be executable pickle
payloads. Objects passed to dumps must be literal builtin data, not arbitrary
instances with a custom __reduce__. No target program code is evaluated.
"""
    func = find_enclosing_function(tree, line)
    if func is None:
        return False
    safe_bytes: set[str] = set()

    def safe_value(expr: ast.expr) -> bool:
        if isinstance(expr, ast.Name):
            return expr.id in safe_bytes
        return (
            isinstance(expr, ast.Call)
            and _imported_name(tree, expr.func, "pickle.dumps")
            and len(expr.args) == 1 and not expr.keywords
            and _literal(expr.args[0])
        )

    for stmt in func.body:
        if stmt.lineno <= line <= (stmt.end_lineno or stmt.lineno):
            if not isinstance(stmt, (ast.Return, ast.Assign, ast.Expr)):
                return False
            calls = [n for n in ast.walk(stmt) if isinstance(n, ast.Call)]
            loads = [n for n in calls if _imported_name(tree, n.func, "pickle.loads")]
            # Do not suppress another, unsafe call sharing the finding line.
            return bool(loads) and all(
                len(n.args) == 1 and not n.keywords and safe_value(n.args[0])
                for n in loads
            ) and all(
                n in loads or (_imported_name(tree, n.func, "pickle.dumps")
                               and len(n.args) == 1 and not n.keywords and _literal(n.args[0]))
                for n in calls
            )
        if isinstance(stmt, ast.Assign) and all(isinstance(t, ast.Name) for t in stmt.targets):
            safe = safe_value(stmt.value)
            # Unknown evaluation could mutate a module binding (or call exec).
            if not safe:
                safe_bytes.clear()
            for target in stmt.targets:
                if safe:
                    safe_bytes.add(target.id)
                else:
                    safe_bytes.discard(target.id)
        else:
            safe_bytes.clear()
    return False


def safe_flask_response(tree: ast.AST, line: int) -> bool:
    """A Flask body immediately typed as non-HTML, then returned unchanged.

Requiring adjacent straight-line statements excludes conditional setters,
early returns, escapes to helpers, and subsequent content-type overrides.
"""
    func = find_enclosing_function(tree, line)
    if func is None:
        return False
    for i, stmt in enumerate(func.body):
        if not (stmt.lineno <= line <= (stmt.end_lineno or stmt.lineno)):
            continue
        if not (isinstance(stmt, ast.Assign) and len(stmt.targets) == 1
                and isinstance(stmt.targets[0], ast.Name)
                and isinstance(stmt.value, ast.Call)
                and _imported_name(tree, stmt.value.func, "flask.make_response")
                and len(stmt.value.args) == 1 and not stmt.value.keywords):
            return False
        following = func.body[i + 1:i + 3]
        if len(following) != 2:
            return False
        setter, ret = following
        name = stmt.targets[0].id
        if not (isinstance(setter, ast.Assign) and len(setter.targets) == 1
                and isinstance(setter.targets[0], ast.Attribute)
                and isinstance(setter.targets[0].value, ast.Name)
                and setter.targets[0].value.id == name
                and setter.targets[0].attr in {"mimetype", "content_type"}
                and isinstance(setter.value, ast.Constant)
                and isinstance(setter.value.value, str)
                and isinstance(ret, ast.Return) and isinstance(ret.value, ast.Name)
                and ret.value.id == name):
            return False
        return setter.value.value.lower().split(";", 1)[0].strip() in {
            "text/plain", "application/json", "application/octet-stream",
        }
    return False


def safe_flask_template_render(
    tree: ast.AST,
    line: int,
    *,
    autoescape_disabled: bool,
    source_path: str | None = None,
    target_root: Path | None = None,
) -> bool:
    """Prove that a Flask render uses a normally autoescaped template type.

    Flask autoescapes html, htm, xml, xhtml and svg templates. Dynamic names,
    other suffixes, explicit project-wide opt-outs, shadowed imports, and
    additional calls on the finding line all fail closed.
    """
    if autoescape_disabled:
        return False
    containing = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.stmt)
        and node.lineno <= line <= (node.end_lineno or node.lineno)
    ]
    statement = min(
        containing,
        key=lambda node: (node.end_lineno or node.lineno) - node.lineno,
        default=None,
    )
    if statement is None:
        return False
    calls = [node for node in ast.walk(statement) if isinstance(node, ast.Call)]
    renders = [
        call for call in calls
        if _imported_name(tree, call.func, "flask.render_template")
    ]
    if not renders or len(renders) != len(calls):
        return False
    for call in renders:
        if not call.args or not isinstance(call.args[0], ast.Constant):
            return False
        template = call.args[0].value
        if not isinstance(template, str):
            return False
        if PurePosixPath(template).suffix.lower() not in {".html", ".htm", ".xml", ".xhtml", ".svg"}:
            return False
        if source_path is not None and target_root is not None:
            source = Path(source_path).resolve()
            root = target_root.resolve()
            candidates = [root / "templates" / template]
            for parent in source.parents:
                candidates.append(parent / "templates" / template)
                if parent == root:
                    break
            for candidate in candidates:
                try:
                    contents = candidate.read_text(encoding="utf-8", errors="ignore")
                except OSError:
                    continue
                if re.search(
                    r"{%\s*autoescape\s+(?:false|off)\s*%}|\|\s*safe\b",
                    contents,
                    re.I,
                ):
                    return False
    return True
