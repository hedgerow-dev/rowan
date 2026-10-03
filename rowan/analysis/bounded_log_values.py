"""Prove bounded log rendering without trusting annotations or ORM schemas.

Unknown values, dynamic formats and unresolved helpers retain the finding.
Only log forging is affected: numeric secrets are still sensitive information.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

from rowan.analysis.python_functions import FunctionIndex, bind_arguments
from rowan.analysis.request_sources import dotted_name

_NUMBER = "number"
_TEXT = "text"
_UNKNOWN = "unknown"
_LOG_METHODS = frozenset(
    {"debug", "info", "warning", "warn", "error", "critical", "exception", "log"}
)
_PERCENT = re.compile(r"%(?:\([^)]+\))?[#0 +\-]*\d*(?:\.\d+)?[diouxXeEfFgGscra%]")


class BoundedLogValues:
    def __init__(self, trees: dict[Path, ast.AST]):
        self.trees = trees
        self.index = FunctionIndex(trees)
        self.budget = 20000
        self.builtin_names: dict[tuple[Path, int, str], str] = {}
        self.percent_receivers: dict[tuple[Path, int, str], bool] = {}

    def _builtin(self, path: Path, func: ast.AST, scope: ast.AST) -> str:
        key = (path, id(scope), dotted_name(func))
        if key not in self.builtin_names:
            self.builtin_names[key] = self._builtin_uncached(path, func, scope)
        return self.builtin_names[key]

    def _builtin_uncached(self, path: Path, func: ast.AST, scope: ast.AST) -> str:
        name = dotted_name(func)
        head = name.split(".")[0]
        bindings = set()
        wildcard = False
        for tree in (self.trees[path], scope):
            nodes = (
                [
                    n
                    for stmt in tree.body
                    for n in (
                        [stmt]
                        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
                        else ast.walk(stmt)
                    )
                ]
                if tree is self.trees[path]
                else ast.walk(tree)
            )
            for node in nodes:
                if isinstance(node, (ast.Import, ast.ImportFrom)):
                    for alias in node.names:
                        wildcard |= alias.name == "*"
                        bindings.add(alias.asname or alias.name.split(".")[0])
                elif isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
                    bindings.add(node.id)
                elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    bindings.add(node.name)
                elif isinstance(node, ast.arg):
                    bindings.add(node.arg)
                elif isinstance(node, ast.Attribute) and isinstance(node.ctx, (ast.Store, ast.Del)):
                    bindings.add(node.attr)
        if wildcard or head in bindings:
            return ""
        return name if name in {"int", "float", "bool", "len", "str"} else ""

    def _value(
        self, expr: ast.AST, state: dict[str, str], path: Path, scope: ast.AST, depth: int = 0
    ) -> str:
        self.budget -= 1
        if self.budget < 0 or depth > 4:
            return _UNKNOWN
        if isinstance(expr, ast.Constant):
            return (
                _NUMBER
                if type(expr.value) in {int, float, bool}
                else (_TEXT if isinstance(expr.value, str) or expr.value is None else _UNKNOWN)
            )
        if isinstance(expr, ast.Name):
            return state.get(expr.id, _UNKNOWN)
        if isinstance(expr, ast.UnaryOp) and isinstance(expr.op, (ast.UAdd, ast.USub, ast.Invert)):
            return (
                _NUMBER
                if self._value(expr.operand, state, path, scope, depth) == _NUMBER
                else _UNKNOWN
            )
        if isinstance(expr, ast.BinOp):
            left = self._value(expr.left, state, path, scope, depth)
            right = self._value(expr.right, state, path, scope, depth)
            if left == right == _NUMBER:
                return _NUMBER
            if isinstance(expr.op, ast.Add) and left == right == _TEXT:
                return _TEXT
        if isinstance(expr, ast.JoinedStr):
            for part in expr.values:
                if isinstance(part, ast.FormattedValue):
                    if self._value(part.value, state, path, scope, depth) == _UNKNOWN:
                        return _UNKNOWN
                    if part.format_spec and any(
                        isinstance(n, ast.FormattedValue) for n in ast.walk(part.format_spec)
                    ):
                        return _UNKNOWN
                    if part.format_spec and any(
                        isinstance(n, ast.Constant)
                        and isinstance(n.value, str)
                        and n.value.endswith("c")
                        for n in ast.walk(part.format_spec)
                    ):
                        # Character formatting can turn numeric input into a
                        # newline (format(10, 'c')); numeric provenance alone
                        # does not bound its rendered alphabet.
                        return _UNKNOWN
            return _TEXT
        if isinstance(expr, ast.Call):
            builtin = self._builtin(path, expr.func, scope)
            if builtin in {"int", "float", "bool", "len"}:
                return _NUMBER
            if builtin == "str" and len(expr.args) == 1:
                return (
                    _TEXT
                    if self._value(expr.args[0], state, path, scope, depth) != _UNKNOWN
                    else _UNKNOWN
                )
            ref = self.index.resolve(path, expr)
            if ref and depth < 4 and not isinstance(ref.node, ast.AsyncFunctionDef):
                head = dotted_name(expr.func).split(".")[0]
                for candidate_path, candidate_name in ((path, head), (ref.path, ref.node.name)):
                    if any(
                        isinstance(n, ast.Name)
                        and n.id == candidate_name
                        and isinstance(n.ctx, (ast.Store, ast.Del))
                        for stmt in self.trees[candidate_path].body
                        if not isinstance(
                            stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
                        )
                        for n in ast.walk(stmt)
                    ):
                        return _UNKNOWN
                    declarations = 0
                    for stmt in self.trees[candidate_path].body:
                        if (
                            isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
                            and stmt.name == candidate_name
                        ):
                            declarations += 1
                        if isinstance(stmt, (ast.Import, ast.ImportFrom)):
                            for alias in stmt.names:
                                if alias.name == "*":
                                    return _UNKNOWN
                                declarations += (
                                    alias.asname or alias.name.split(".")[0]
                                ) == candidate_name
                    if declarations != 1:
                        return _UNKNOWN
                if any(
                    isinstance(n, ast.Attribute)
                    and isinstance(n.ctx, (ast.Store, ast.Del))
                    and dotted_name(n) == dotted_name(expr.func)
                    for n in ast.walk(scope)
                ):
                    return _UNKNOWN
                if any(
                    isinstance(n, (ast.Import, ast.ImportFrom))
                    and any((a.asname or a.name.split(".")[0]) in {head, "*"} for a in n.names)
                    for n in ast.walk(scope)
                ):
                    return _UNKNOWN
                if any(
                    not isinstance(default, ast.Constant)
                    for default in [
                        *ref.node.args.defaults,
                        *[d for d in ref.node.args.kw_defaults if d],
                    ]
                ):
                    return _UNKNOWN
                bound = bind_arguments(ref.node, expr)
                if bound is not None:
                    # Resolve only straight-line return helpers, not annotations,
                    # generators, decorators, closures or conditional protocols.
                    if ref.node.decorator_list or any(
                        isinstance(n, (ast.Yield, ast.YieldFrom, ast.Global, ast.Nonlocal))
                        for n in ast.walk(ref.node)
                    ):
                        return _UNKNOWN
                    local = {
                        name: self._value(value, state, path, scope, depth + 1)
                        for name, value in bound.items()
                    }
                    for stmt in ref.node.body:
                        if isinstance(stmt, (ast.Assign, ast.AnnAssign)):
                            self._assign(stmt, local, ref.path, ref.node, depth + 1)
                        elif isinstance(stmt, ast.Return):
                            return (
                                self._value(stmt.value, local, ref.path, ref.node, depth + 1)
                                if stmt.value
                                else _TEXT
                            )
                        elif not (
                            isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant)
                        ):
                            return _UNKNOWN
        return _UNKNOWN

    def _assign(
        self,
        stmt: ast.Assign | ast.AnnAssign,
        state: dict[str, str],
        path: Path,
        scope: ast.AST,
        depth: int = 0,
    ) -> None:
        value = self._value(stmt.value, state, path, scope, depth) if stmt.value else _UNKNOWN
        targets = stmt.targets if isinstance(stmt, ast.Assign) else [stmt.target]
        for target in targets:
            if isinstance(target, ast.Name):
                state[target.id] = value
            else:
                for node in ast.walk(target):
                    if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
                        state[node.id] = _UNKNOWN

    def _safe_log(self, call: ast.Call, state: dict[str, str], path: Path, scope: ast.AST) -> bool:
        if not isinstance(call.func, ast.Attribute) or call.func.attr not in _LOG_METHODS:
            return False
        standard_percent = self._standard_percent_receiver(call.func.value, path, scope)
        if call.func.attr == "log" and not standard_percent:
            return False
        args = call.args[1:] if call.func.attr == "log" else call.args
        if not args or any(isinstance(a, ast.Starred) for a in args) or call.keywords:
            return False
        if len(args) == 1:
            return self._value(args[0], state, path, scope) != _UNKNOWN
        if not (isinstance(args[0], ast.Constant) and isinstance(args[0].value, str)):
            return False
        fmt = args[0].value
        directives = []
        pos = 0
        while pos < len(fmt):
            if fmt[pos] != "%":
                pos += 1
                continue
            match = _PERCENT.match(fmt, pos)
            if not match or "(" in match.group():
                return False
            if match.group() != "%%":
                directives.append(match.group()[-1])
            pos = match.end()
        if len(directives) != len(args) - 1:
            return False
        return all(
            code != "c"
            and (
                (standard_percent and code in "diouxXeEfFgG")
                or self._value(arg, state, path, scope) != _UNKNOWN
            )
            for code, arg in zip(directives, args[1:], strict=True)
        )

    def _standard_percent_receiver(self, receiver: ast.AST, path: Path, scope: ast.AST) -> bool:
        key = (path, id(scope), dotted_name(receiver))
        if key not in self.percent_receivers:
            self.percent_receivers[key] = self._standard_percent_receiver_uncached(
                receiver, path, scope
            )
        return self.percent_receivers[key]

    def _standard_percent_receiver_uncached(
        self, receiver: ast.AST, path: Path, scope: ast.AST
    ) -> bool:
        """Formatting unknown values requires the stdlib logging contract."""
        if not isinstance(receiver, ast.Name):
            return False
        module_nodes = [
            n
            for stmt in self.trees[path].body
            for n in (
                [stmt]
                if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
                else ast.walk(stmt)
            )
        ]
        nodes = [*module_nodes, *ast.walk(scope)]

        def logging_module(name):
            imports = [
                a
                for n in nodes
                if isinstance(n, (ast.Import, ast.ImportFrom))
                for a in n.names
                if (a.asname or a.name.split(".")[0]) in {name, "*"}
            ]
            valid = [
                a
                for n in nodes
                if isinstance(n, ast.Import)
                for a in n.names
                if a.name == "logging" and (a.asname or a.name) == name
            ]
            shadowed = any(
                (
                    isinstance(n, ast.Name)
                    and n.id == name
                    and isinstance(n.ctx, (ast.Store, ast.Del))
                )
                or (isinstance(n, ast.arg) and n.arg == name)
                or (
                    isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
                    and n.name == name
                )
                or (
                    isinstance(n, ast.Attribute)
                    and isinstance(n.ctx, (ast.Store, ast.Del))
                    and dotted_name(n).startswith(name + ".")
                )
                for n in nodes
            )
            return len(imports) == len(valid) == 1 and not shadowed

        if logging_module(receiver.id):
            return True
        if any(
            isinstance(n, ast.Call)
            and isinstance(n.func, ast.Attribute)
            and n.func.attr == "setLoggerClass"
            for n in nodes
        ):
            return False
        if any(
            (
                isinstance(n, ast.Attribute)
                and isinstance(n.ctx, (ast.Store, ast.Del))
                and dotted_name(n).startswith(receiver.id + ".")
            )
            or (
                isinstance(n, (ast.Import, ast.ImportFrom))
                and any((a.asname or a.name.split(".")[0]) in {receiver.id, "*"} for a in n.names)
            )
            or (
                isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
                and n.name == receiver.id
            )
            for n in nodes
        ):
            return False
        writes = [
            n
            for n in nodes
            if isinstance(n, ast.Name)
            and n.id == receiver.id
            and isinstance(n.ctx, (ast.Store, ast.Del))
        ]
        if len(writes) != 1 or any(isinstance(n, ast.arg) and n.arg == receiver.id for n in nodes):
            return False
        for node in nodes:
            if (
                isinstance(node, ast.Assign)
                and len(node.targets) == 1
                and node.targets[0] is writes[0]
                and isinstance(node.value, ast.Call)
            ):
                func = node.value.func
                if (
                    isinstance(func, ast.Attribute)
                    and func.attr == "getLogger"
                    and isinstance(func.value, ast.Name)
                ):
                    return logging_module(func.value.id)
        return False

    def safe_lines(self, path: Path) -> set[int]:
        outcomes: dict[int, list[bool]] = {}

        def block(stmts, state, scope):
            for stmt in stmts:
                if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    continue
                for node in ast.walk(stmt):
                    if isinstance(node, ast.NamedExpr) and isinstance(node.target, ast.Name):
                        state[node.target.id] = _UNKNOWN
                    if isinstance(node, ast.Call) and dotted_name(node.func) in {"exec", "eval"}:
                        state.update({k: _UNKNOWN for k in state})
                if isinstance(stmt, ast.If):
                    left, right = dict(state), dict(state)
                    block(stmt.body, left, scope)
                    block(stmt.orelse, right, scope)
                    state.update(
                        {
                            k: left.get(k, _UNKNOWN) if left.get(k) == right.get(k) else _UNKNOWN
                            for k in left.keys() | right.keys()
                        }
                    )
                    continue
                if isinstance(
                    stmt,
                    (ast.For, ast.AsyncFor, ast.While, ast.Try, ast.With, ast.AsyncWith, ast.Match),
                ):
                    # Mutation/control flow we do not model invalidates written
                    # variables; do not infer safe sinks inside it.
                    for node in ast.walk(stmt):
                        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
                            state[node.id] = _UNKNOWN
                    continue
                for call in ast.walk(stmt):
                    if (
                        isinstance(call, ast.Call)
                        and isinstance(call.func, ast.Attribute)
                        and call.func.attr in _LOG_METHODS
                    ):
                        outcomes.setdefault(call.lineno, []).append(
                            self._safe_log(call, state, path, scope)
                        )
                if isinstance(stmt, (ast.Assign, ast.AnnAssign)):
                    self._assign(stmt, state, path, scope)
                elif isinstance(stmt, (ast.AugAssign, ast.Delete)):
                    for node in ast.walk(stmt):
                        if isinstance(node, ast.Name) and isinstance(
                            node.ctx, (ast.Store, ast.Del)
                        ):
                            state[node.id] = _UNKNOWN

        for func in ast.walk(self.trees[path]):
            if isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if any(isinstance(n, (ast.Global, ast.Nonlocal)) for n in ast.walk(func)):
                    continue
                block(func.body, {}, func)
        return {line for line, safe in outcomes.items() if safe and all(safe)}
