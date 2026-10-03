"""Bounded parameter/return trust analysis for Python serialization and JWTs.

Values carry request origins and transformation stages, rather than relying on
helper names. Unknown calls are not assumed to propagate or sanitize trust.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path

from rowan.analysis.python_functions import FunctionIndex, FunctionRef, bind_arguments
from rowan.analysis.request_sources import (
    KNOWN_SOURCE_PREFIXES,
    expr_reads_source,
    is_http_route,
    route_input_names,
)
from rowan.core.findings import Category, Finding, Severity, TaintFlow, TaintNode


@dataclass(frozen=True)
class Value:
    sources: frozenset[tuple[Path, int]] = frozenset()
    split: bool = False
    decoded: bool = False
    claims: frozenset[tuple[Path, int, int]] = frozenset()
    sensitive: bool = False
    unpicklers: frozenset[tuple[Path, int, int]] = frozenset()


def union(values):
    values = list(values)
    return Value(
        frozenset().union(*(v.sources for v in values)),
        any(v.split for v in values),
        any(v.decoded for v in values),
        frozenset().union(*(v.claims for v in values)),
        any(v.sensitive for v in values),
        frozenset().union(*(v.unpicklers for v in values)),
    )


class TrustFlow:
    def __init__(self, index: FunctionIndex, privilege_fields=frozenset(), max_depth: int = 4):
        self.index = index
        self.max_depth = max_depth
        self.identity_fields = {
            "sub",
            "user_id",
            "account_id",
            "role",
            "tier",
            "is_admin",
            "permissions",
        } | set(privilege_fields)
        self.findings: dict[tuple, Finding] = {}
        self.cache: dict[tuple, Value] = {}
        self.active: set[tuple] = set()

    def run(self) -> list[Finding]:
        for path, tree in self.index.trees.items():
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    inputs = {
                        name: Value(frozenset({(path, node.lineno)}))
                        for name in route_input_names(node)
                    }
                    self.function(FunctionRef(path, node), inputs, 0)
        return list(self.findings.values())

    def emit(self, kind: str, value: Value, sink: tuple[Path, int, int]):
        if not value.sources:
            return
        path, line, column = sink
        source = min(value.sources, key=lambda x: (str(x[0]), x[1]))
        rule = "PY-DESER-FLOW-001" if kind == "pickle" else "PY-JWT-TRUST-001"
        key = (rule, path, line, column)
        previous = self.findings.get(key)
        origins = set(value.sources)
        if previous:
            origins.update((Path(p), n) for p, n in previous.metadata.get("source_origins", []))
        source = min(origins, key=lambda x: (str(x[0]), x[1]))
        self.findings[key] = Finding(
            rule_id=rule,
            message=(
                "Request-derived data reaches unrestricted Unpickler.load(); arbitrary object reconstruction can execute code."
                if kind == "pickle"
                else "Request-derived JWT payload is decoded without signature verification and used as identity or privilege claims."
            ),
            severity=Severity.HIGH,
            category=Category.DESERIALIZATION if kind == "pickle" else Category.AUTH,
            file_path=str(path),
            start_line=line,
            start_column=column,
            confidence=0.85,
            cwe_ids=[502 if kind == "pickle" else 347],
            engine="python-trust",
            taint_flow=TaintFlow(
                source=TaintNode(str(source[0]), source[1]),
                sink=TaintNode(str(path), line, column),
            ),
            metadata={
                "analysis": "bounded-parameter-return",
                "max_call_depth": self.max_depth,
                "source_origins": sorted((str(p), n) for p, n in origins),
                "operation_id": f"{path}:{line}:{column}",
            },
        )

    def trust(self, value: Value):
        if value.sensitive:
            for sink in value.claims:
                self.emit("jwt", value, sink)

    def function(self, ref: FunctionRef, args: dict[str, Value], depth: int) -> Value:
        key = (ref.path, ref.node.lineno, self.max_depth - depth, tuple(sorted(args.items())))
        if depth > self.max_depth or key in self.active:
            return Value()
        if key in self.cache:
            return self.cache[key]
        self.active.add(key)
        env = dict(args)
        returned = self.block(ref.path, ref.node.body, env, depth, is_http_route(ref.node))
        self.active.remove(key)
        result = union(returned)
        self.cache[key] = result
        return result

    def assign(self, path, target, value, env):
        if isinstance(target, ast.Name):
            env[target.id] = value
        elif isinstance(target, (ast.Tuple, ast.List)):
            for child in target.elts:
                self.assign(path, child, value, env)
        elif isinstance(target, ast.Starred):
            self.assign(path, target.value, value, env)
        elif isinstance(target, (ast.Attribute, ast.Subscript)):
            # Writing decoded claims to a principal/session establishes trust.
            text = ast.unparse(target)
            if text.startswith(("g.", "session[", "request.session[")):
                self.trust(value)

    def block(self, path, body, env, depth, route=False):
        returned = []
        for stmt in body:
            if isinstance(stmt, (ast.Assign, ast.AnnAssign)):
                if stmt.value is None:
                    continue
                value = self.expr(path, stmt.value, env, depth)
                for target in stmt.targets if isinstance(stmt, ast.Assign) else [stmt.target]:
                    self.assign(path, target, value, env)
            elif isinstance(stmt, ast.Return):
                value = self.expr(path, stmt.value, env, depth)
                if route:
                    self.trust(value)
                returned.append(value)
                break
            elif isinstance(stmt, ast.Expr):
                self.expr(path, stmt.value, env, depth)
                if isinstance(stmt.value, ast.Call) and self.verified_decode(path, stmt.value, env):
                    token = (
                        stmt.value.args[0]
                        if stmt.value.args
                        else next((k.value for k in stmt.value.keywords if k.arg == "jwt"), None)
                    )
                    if isinstance(token, ast.Name):
                        env[token.id] = Value()
            elif isinstance(stmt, ast.Raise):
                break
            elif isinstance(stmt, ast.If):
                self.expr(path, stmt.test, env, depth)
                branches = []
                for branch in (stmt.body, stmt.orelse):
                    child = dict(env)
                    returned.extend(self.block(path, branch, child, depth, route))
                    if not branch or not isinstance(branch[-1], (ast.Return, ast.Raise)):
                        branches.append(child)
                for name in set().union(*(set(b) for b in branches)):
                    env[name] = union(b.get(name, Value()) for b in branches)
            elif isinstance(stmt, ast.Try):
                # Except paths cannot establish successful verification.
                branches = []
                for branch in [stmt.body, *(h.body for h in stmt.handlers)]:
                    child = dict(env)
                    returned.extend(self.block(path, branch, child, depth, route))
                    if not branch or not isinstance(branch[-1], (ast.Return, ast.Raise)):
                        branches.append(child)
                for name in set().union(*(set(b) for b in branches)):
                    env[name] = union(b.get(name, Value()) for b in branches)
                returned.extend(self.block(path, stmt.orelse + stmt.finalbody, env, depth, route))
            elif isinstance(stmt, (ast.With, ast.AsyncWith, ast.For, ast.AsyncFor, ast.While)):
                child = dict(env)
                returned.extend(self.block(path, stmt.body, child, depth, route))
                for name in child:
                    env[name] = union([env.get(name, Value()), child[name]])
        return returned

    def expr(self, path, node, env, depth) -> Value:
        if node is None:
            return Value()
        if isinstance(node, ast.Name):
            return env.get(node.id, Value())
        if isinstance(node, ast.Call):
            return self.call(path, node, env, depth)
        if isinstance(node, ast.Subscript):
            value = self.expr(path, node.value, env, depth)
            field = node.slice.value if isinstance(node.slice, ast.Constant) else None
            if value.claims and field in self.identity_fields:
                value = Value(
                    value.sources, value.split, value.decoded, value.claims, True, value.unpicklers
                )
            if expr_reads_source(node):
                value = union([value, Value(frozenset({(path, node.lineno)}))])
            return value
        value = union(
            self.expr(path, c, env, depth)
            for c in ast.iter_child_nodes(node)
            if isinstance(c, ast.expr)
        )
        if expr_reads_source(node):
            value = union([value, Value(frozenset({(path, node.lineno)}))])
        return value

    def verified_decode(self, path, node, env=None):
        if self.index.qualified_name(path, node.func) not in {"jwt.decode", "jose.jwt.decode"}:
            return False
        key = (
            node.args[1]
            if len(node.args) > 1
            else next((k.value for k in node.keywords if k.arg == "key"), None)
        )
        algorithms = next((k.value for k in node.keywords if k.arg == "algorithms"), None)
        if key is None or (isinstance(key, ast.Constant) and not key.value) or algorithms is None:
            return False
        if isinstance(algorithms, (ast.List, ast.Tuple)) and not algorithms.elts:
            return False
        if expr_reads_source(key) or expr_reads_source(algorithms):
            return False
        if env and any(
            isinstance(n, ast.Name) and env.get(n.id, Value()).sources
            for expr in (key, algorithms)
            for n in ast.walk(expr)
        ):
            return False
        options = next((k.value for k in node.keywords if k.arg == "options"), None)
        if options is not None:
            if not isinstance(options, ast.Dict):
                return False
            for option, value in zip(options.keys, options.values, strict=True):
                if option is None or not isinstance(option, ast.Constant):
                    return False
                if option.value == "verify_signature" and not (
                    isinstance(value, ast.Constant) and value.value is True
                ):
                    return False
        return True

    def call(self, path, node, env, depth):
        name = self.index.qualified_name(path, node.func)
        args = [self.expr(path, a, env, depth) for a in node.args]
        kwargs = [self.expr(path, k.value, env, depth) for k in node.keywords]
        receiver = (
            self.expr(path, node.func.value, env, depth)
            if isinstance(node.func, ast.Attribute)
            else Value()
        )
        value = union([*args, *kwargs])
        if any(name == prefix or name.startswith(prefix + ".") for prefix in KNOWN_SOURCE_PREFIXES):
            return union([value, Value(frozenset({(path, node.lineno)}))])
        if name in {"jwt.decode", "jose.jwt.decode"}:
            # Library verified decoding is a new trusted value; unsigned modes aren't.
            return Value() if self.verified_decode(path, node, env) else value
        if name in {"pickle.Unpickler", "cPickle.Unpickler", "dill.Unpickler", "_pickle.Unpickler"}:
            return Value(
                value.sources, unpicklers=frozenset({(path, node.lineno, node.col_offset)})
            )
        if (
            isinstance(node.func, ast.Attribute)
            and node.func.attr == "load"
            and receiver.unpicklers
        ):
            for sink in receiver.unpicklers:
                self.emit("pickle", receiver, sink)
            return receiver
        ref = self.index.resolve(path, node)
        if ref:
            bindings = bind_arguments(ref.node, node)
            bound = {p: self.expr(path, expr, env, depth) for p, expr in bindings.items()}
            return self.function(ref, bound, depth + 1)
        if name in {"base64.b64decode", "base64.urlsafe_b64decode", "base64.standard_b64decode"}:
            return Value(
                value.sources, value.split, True, value.claims, value.sensitive, value.unpicklers
            )
        if name == "json.loads":
            claims = value.claims
            if value.sources and value.split and value.decoded:
                claims = claims | {(path, node.lineno, node.col_offset)}
            return Value(
                value.sources, value.split, value.decoded, claims, value.sensitive, value.unpicklers
            )
        if isinstance(node.func, ast.Attribute) and node.func.attr == "split":
            dot = bool(
                node.args and isinstance(node.args[0], ast.Constant) and node.args[0].value == "."
            )
            return Value(
                receiver.sources,
                receiver.split or dot,
                receiver.decoded,
                receiver.claims,
                receiver.sensitive,
            )
        if isinstance(node.func, ast.Attribute) and node.func.attr in {
            "get",
            "read",
            "decode",
            "encode",
            "strip",
        }:
            result = union([receiver, value])
            field = (
                node.args[0].value if node.args and isinstance(node.args[0], ast.Constant) else None
            )
            if result.claims and field in self.identity_fields:
                result = Value(
                    result.sources,
                    result.split,
                    result.decoded,
                    result.claims,
                    True,
                    result.unpicklers,
                )
            if node.func.attr == "get" and name.endswith("session.get"):
                self.trust(value)
            return result
        if name in {
            "io.BytesIO",
            "io.BufferedReader",
            "str",
            "bytes",
            "int",
            "dict",
            "json.dumps",
            "jsonify",
            "flask.jsonify",
        }:
            return value
        if name in {"jwt.encode", "jose.jwt.encode"}:
            self.trust(value)
        return Value()
