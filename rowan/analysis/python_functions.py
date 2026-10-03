"""Repository-bounded Python call resolution shared by security analyses.

No imports are executed. Dynamic dispatch and ambiguous module paths are left
unresolved; exploration is bounded by each consumer.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path

from rowan.analysis.request_sources import dotted_name


@dataclass(frozen=True)
class FunctionRef:
    path: Path
    node: ast.FunctionDef | ast.AsyncFunctionDef


class FunctionIndex:
    def __init__(self, trees: dict[Path, ast.AST]):
        self.trees = trees
        self.functions = {
            path: {
                n.name: FunctionRef(path, n)
                for n in tree.body
                if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
            }
            for path, tree in trees.items()
        }

        self.resolved: dict[tuple[Path, str], FunctionRef | None] = {}
        self.scope_bindings = {
            path: [
                (
                    node.lineno,
                    getattr(node, "end_lineno", node.lineno),
                    {
                        arg.arg
                        for arg in [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]
                    }
                    | {
                        n.id
                        for n in ast.walk(node)
                        if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store)
                    },
                )
                for node in ast.walk(tree)
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            ]
            for path, tree in trees.items()
        }

    def module(self, path: Path, name: str, level: int = 0) -> Path | None:
        parts = name.split(".") if name else []
        if level:
            base = path.parent
            for _ in range(level - 1):
                base = base.parent
            candidates = [
                base.joinpath(*parts).with_suffix(".py"),
                base.joinpath(*parts, "__init__.py"),
            ]
            return next((p for p in candidates if p in self.trees), None)
        if not parts:
            return None
        suffixes = [Path(*parts).with_suffix(".py"), Path(*parts, "__init__.py")]
        matches = [
            p for p in self.trees if any(p.parts[-len(s.parts) :] == s.parts for s in suffixes)
        ]
        return matches[0] if len(matches) == 1 else None

    def resolve(self, path: Path, call: ast.Call) -> FunctionRef | None:
        if any(isinstance(a, ast.Starred) for a in call.args) or any(
            k.arg is None for k in call.keywords
        ):
            return None
        name = dotted_name(call.func)
        head = name.split(".")[0]
        # Function-local bindings shadow module imports, even if assignment is
        # later in the function. Cache scope bindings rather than walking the
        # whole module at every call site.
        for first, last, bindings in self.scope_bindings[path]:
            if first <= call.lineno <= last and head in bindings:
                return None
        key = (path, name)
        if key not in self.resolved:
            self.resolved[key] = self._resolve_name(path, name, set())
        return self.resolved[key]

    def _resolve_name(
        self, path: Path, name: str, seen: set[tuple[Path, str]]
    ) -> FunctionRef | None:
        key = (path, name)
        if not name or key in seen or len(seen) >= 8:
            return None
        seen = seen | {key}
        if name in self.functions.get(path, {}):
            return self.functions[path][name]
        head, _, tail = name.partition(".")
        for imp in self.trees[path].body:
            if isinstance(imp, ast.Import):
                for alias in imp.names:
                    local = alias.asname or alias.name.split(".")[0]
                    if head != local:
                        continue
                    full = alias.name + ("." + tail if tail else "") if alias.asname else name
                    mod, _, fn = full.rpartition(".")
                    target = self.module(path, mod)
                    if target:
                        return self._resolve_name(target, fn, seen)
            elif isinstance(imp, ast.ImportFrom):
                for alias in imp.names:
                    if head != (alias.asname or alias.name):
                        continue
                    if tail:
                        module = ".".join(p for p in (imp.module, alias.name) if p)
                        target = self.module(path, module, imp.level)
                        if target:
                            return self._resolve_name(target, tail, seen)
                    target = self.module(path, imp.module or "", imp.level)
                    if target and not tail:
                        return self._resolve_name(target, alias.name, seen)
        return None

    def qualified_name(self, path: Path, node: ast.AST) -> str:
        name = dotted_name(node)
        head, _, tail = name.partition(".")
        for imp in self.trees[path].body:
            if isinstance(imp, ast.Import):
                for a in imp.names:
                    if head == (a.asname or a.name.split(".")[0]):
                        return a.name + ("." + tail if tail else "") if a.asname else name
            elif isinstance(imp, ast.ImportFrom) and not imp.level:
                for a in imp.names:
                    if head == (a.asname or a.name):
                        return ".".join(p for p in (imp.module, a.name, tail) if p)
        return name


def bind_arguments(
    node: ast.FunctionDef | ast.AsyncFunctionDef, call: ast.Call
) -> dict[str, ast.expr]:
    """Bind only statically known arguments; never guess *args/**kwargs."""
    params = node.args.posonlyargs + node.args.args
    result = {
        p.arg: value
        for p, value in zip(params, call.args, strict=False)
        if not isinstance(value, ast.Starred)
    }
    defaults = (
        dict(
            zip(
                [p.arg for p in params][-len(node.args.defaults) :], node.args.defaults, strict=True
            )
        )
        if node.args.defaults
        else {}
    )
    defaults.update(
        {
            p.arg: v
            for p, v in zip(node.args.kwonlyargs, node.args.kw_defaults, strict=True)
            if v is not None
        }
    )
    defaults.update(result)
    defaults.update({kw.arg: kw.value for kw in call.keywords if kw.arg is not None})
    return defaults


def specialize_returns(
    index: FunctionIndex,
    ref: FunctionRef,
    depth: int = 3,
    seen: frozenset[tuple[Path, str]] = frozenset(),
):
    """Expand expression-only repository wrappers, with parameter substitution.

    Only a single return expression is eligible. Guards, side effects, multiple
    returns, dynamic arguments, and recursive wrappers retain their call node.
    This makes generic helpers such as get_row(model, key) visible to consumers
    without losing control flow in more complicated procedures.
    """
    import copy

    key = (ref.path, ref.node.name)
    node = copy.deepcopy(ref.node)
    if depth <= 0 or key in seen:
        return node

    class Expand(ast.NodeTransformer):
        def visit_Call(self, call):
            call = self.generic_visit(call)
            target = index.resolve(ref.path, call)
            if (
                target is None
                or any(k.arg is None for k in call.keywords)
                or any(isinstance(a, ast.Starred) for a in call.args)
            ):
                return call
            body = [
                s
                for s in target.node.body
                if not (
                    isinstance(s, ast.Expr)
                    and isinstance(s.value, ast.Constant)
                    and isinstance(s.value.value, str)
                )
            ]
            if len(body) != 1 or not isinstance(body[0], ast.Return) or body[0].value is None:
                return call
            expanded = specialize_returns(index, target, depth - 1, seen | {key})
            ret = next(s for s in reversed(expanded.body) if isinstance(s, ast.Return))
            bindings = bind_arguments(target.node, call)

            class Bind(ast.NodeTransformer):
                def visit_Name(self, name):
                    if isinstance(name.ctx, ast.Load) and name.id in bindings:
                        return copy.deepcopy(bindings[name.id])
                    return name

            value = Bind().visit(copy.deepcopy(ret.value))
            # Keep the wrapper call's coordinate; findings belong to that use.
            for child in ast.walk(value):
                if hasattr(child, "lineno"):
                    child.lineno = call.lineno
                    child.end_lineno = getattr(call, "end_lineno", call.lineno)
            return ast.copy_location(value, call)

    return ast.fix_missing_locations(Expand().visit(node))
