"""Explicit model policies and conservative classification of object uses."""

from __future__ import annotations

import ast
import re
from pathlib import Path

from rowan.analysis.python_functions import FunctionIndex


def validate_model_policies(value: object) -> None:
    if not isinstance(value, dict):
        raise ValueError("authz_model_policies must be a mapping")
    for model, operations in value.items():
        if not isinstance(model, str) or not re.fullmatch(
            r"[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)+", model
        ):
            raise ValueError(
                "authz_model_policies keys must be qualified model names (e.g. app.models.Document)"
            )
        if not isinstance(operations, dict) or not operations:
            raise ValueError(f"authz_model_policies[{model}] must declare read and/or write")
        for operation, requirement in operations.items():
            if (
                operation not in {"read", "write"}
                or not isinstance(requirement, str)
                or requirement not in {"public", "principal"}
            ):
                raise ValueError(
                    f"authz_model_policies[{model}]: use read/write with public/principal"
                )
            if operation == "write" and requirement == "public":
                raise ValueError(
                    "public write policies are not supported; declare principal or leave unverified"
                )


def model_identity(
    path: Path, model: str, index: FunctionIndex, root: Path, scope: ast.AST | None = None
) -> str | None:
    if scope and any(
        (isinstance(n, ast.Name) and n.id == model and isinstance(n.ctx, ast.Store))
        or (isinstance(n, ast.arg) and n.arg == model)
        for n in ast.walk(scope)
    ):
        return None
    module_nodes = [
        n
        for stmt in index.trees[path].body
        for n in (
            [stmt]
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
            else ast.walk(stmt)
        )
    ]
    if any(
        isinstance(n, ast.Name) and n.id == model and isinstance(n.ctx, (ast.Store, ast.Del))
        for n in module_nodes
    ):
        return None
    bound = [n for n in module_nodes if isinstance(n, ast.ClassDef) and n.name == model]
    imports = [
        a
        for n in module_nodes
        if isinstance(n, (ast.Import, ast.ImportFrom))
        for a in n.names
        if (a.asname or a.name.split(".")[0]) in {model, "*"}
    ]
    if len(bound) + len(imports) != 1 or any(a.name == "*" for a in imports):
        return None

    def local(module_path, class_name):
        statements = index.trees[module_path].body
        if any(
            isinstance(n, ast.Name)
            and n.id == class_name
            and isinstance(n.ctx, (ast.Store, ast.Del))
            for stmt in statements
            if not isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
            for n in ast.walk(stmt)
        ):
            return None
        if any(
            isinstance(stmt, (ast.Import, ast.ImportFrom))
            and any((a.asname or a.name.split(".")[0]) in {class_name, "*"} for a in stmt.names)
            for stmt in statements
        ):
            return None
        if sum(isinstance(n, ast.ClassDef) and n.name == class_name for n in statements) == 1:
            try:
                parts = list(
                    module_path.resolve().relative_to(root.resolve()).with_suffix("").parts
                )
            except ValueError:
                return None
            if parts[-1] == "__init__":
                parts.pop()
            return ".".join([*parts, class_name])
        return None

    identity = local(path, model)
    if identity:
        return identity
    for stmt in index.trees[path].body:
        if isinstance(stmt, ast.ImportFrom):
            for alias in stmt.names:
                if (alias.asname or alias.name) == model:
                    module = index.module(path, stmt.module or "", stmt.level)
                    if module:
                        return local(module, alias.name)
    return None


def object_use(handler: ast.AST, call: ast.Call, object_name: str | None) -> str:
    """read, write, existence, unused, or unknown. Unknown calls may mutate.

    Public-read policy never suppresses writes or unresolved whole-object uses.
    No field-name or handler-name whitelist implies a sharing policy.
    """
    if not object_name:
        parent = next((n for n in ast.walk(handler) if call in ast.iter_child_nodes(n)), None)
        if isinstance(parent, ast.Return):
            return "read"
        if (
            isinstance(parent, ast.Compare)
            and len(parent.ops) == 1
            and isinstance(parent.ops[0], (ast.Is, ast.IsNot))
            and any(
                isinstance(n, ast.Constant) and n.value is None
                for n in [parent.left, *parent.comparators]
            )
        ):
            return "existence"
        # Other inline reads have no local alias through which to track use.
        return "unknown"
    aliases = {object_name}
    nodes = sorted(
        ast.walk(handler), key=lambda n: (getattr(n, "lineno", 0), getattr(n, "col_offset", 0))
    )
    nested = {
        id(n)
        for scope in ast.walk(handler)
        if isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda))
        and scope is not handler
        for n in ast.walk(scope)
    }
    nodes = [n for n in nodes if id(n) not in nested and getattr(n, "lineno", 0) >= call.lineno]
    for node in nodes:
        if (
            isinstance(node, ast.Assign)
            and isinstance(node.value, ast.Name)
            and node.value.id in aliases
        ):
            aliases.update(t.id for t in node.targets if isinstance(t, ast.Name))
    if any(
        id(n) in nested
        and isinstance(n, ast.Name)
        and isinstance(n.ctx, ast.Load)
        and n.id in aliases
        for n in ast.walk(handler)
    ):
        return "unknown"
    uses = [
        n
        for n in nodes
        if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load) and n.id in aliases
    ]
    for node in nodes:
        if isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign, ast.Delete)):
            targets = node.targets if isinstance(node, (ast.Assign, ast.Delete)) else [node.target]
            if any(
                isinstance(t, (ast.Attribute, ast.Subscript))
                and any(isinstance(n, ast.Name) and n.id in aliases for n in ast.walk(t))
                for t in targets
            ):
                return "write"
        if isinstance(node, ast.Call):
            receiver = node.func.value if isinstance(node.func, ast.Attribute) else None
            receiver_names = (
                {n.id for n in ast.walk(receiver) if isinstance(n, ast.Name)} if receiver else set()
            )
            # Only Names have identifiers.
            if (
                isinstance(node.func, ast.Attribute)
                and node.func.attr in {"delete", "update", "save", "add"}
                and (
                    any(isinstance(a, ast.Name) and a.id in aliases for a in node.args)
                    or bool(receiver_names & aliases)
                )
            ):
                return "write"
    for node in nodes:
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and any(isinstance(n, ast.Name) and n.id in aliases for n in ast.walk(node.func.value))
        ):
            return "unknown"
        if isinstance(node, ast.Call) and any(
            isinstance(n, ast.Name) and n.id in aliases
            for arg in [*node.args, *[kw.value for kw in node.keywords]]
            for n in ast.walk(arg)
        ):
            return "unknown"
    # Existence checks can precede a deferred operation using the selector
    # rather than the fetched instance. Track selector-derived local payloads
    # too, so a public-read policy cannot authorize that unknown operation.
    selectors = {
        n.id
        for arg in [*call.args, *[kw.value for kw in call.keywords]]
        for n in ast.walk(arg)
        if isinstance(n, ast.Name)
    }
    read_nodes = {id(n) for n in ast.walk(call)}
    for node in nodes:
        if id(node) in read_nodes or (
            getattr(node, "lineno", 0),
            getattr(node, "col_offset", 0),
        ) < (
            getattr(call, "end_lineno", call.lineno),
            getattr(call, "end_col_offset", call.col_offset),
        ):
            continue
        if (
            isinstance(node, (ast.Assign, ast.AnnAssign))
            and node.value
            and any(isinstance(n, ast.Name) and n.id in selectors for n in ast.walk(node.value))
        ):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            selectors.update(t.id for t in targets if isinstance(t, ast.Name))
        if isinstance(node, ast.Call) and any(
            isinstance(n, ast.Name) and n.id in selectors
            for arg in [*node.args, *[kw.value for kw in node.keywords]]
            for n in ast.walk(arg)
        ):
            return "unknown"
    if not uses:
        return "unused"
    if any(
        isinstance(n, ast.Attribute)
        and any(isinstance(v, ast.Name) and v.id in aliases for v in ast.walk(n.value))
        for n in nodes
    ):
        return "read"
    # Only bare truth checks / null comparisons are evidence of existence.
    existence_ids = set()
    for node in nodes:
        expr = node.test if isinstance(node, ast.If) else node
        if isinstance(node, ast.If) and isinstance(expr, ast.Name) and expr.id in aliases:
            existence_ids.add(id(expr))
        elif (
            isinstance(expr, ast.UnaryOp)
            and isinstance(expr.op, ast.Not)
            and isinstance(expr.operand, ast.Name)
            and expr.operand.id in aliases
        ):
            existence_ids.add(id(expr.operand))
        elif (
            isinstance(expr, ast.Compare)
            and len(expr.ops) == 1
            and isinstance(expr.ops[0], (ast.Is, ast.IsNot, ast.Eq, ast.NotEq))
        ):
            sides = [expr.left, *expr.comparators]
            if any(isinstance(s, ast.Constant) and s.value is None for s in sides):
                existence_ids.update(
                    id(s) for s in sides if isinstance(s, ast.Name) and s.id in aliases
                )
    for node in nodes:
        if (
            isinstance(node, ast.Assign)
            and isinstance(node.value, ast.Name)
            and node.value.id in aliases
        ):
            existence_ids.add(id(node.value))
    return "existence" if all(id(n) in existence_ids for n in uses) else "read"
