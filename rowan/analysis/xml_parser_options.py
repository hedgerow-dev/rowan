"""Resolve static lxml parser options at the parser call, never at unused dicts."""

from __future__ import annotations

import ast

from rowan.analysis.python_functions import FunctionIndex
from rowan.core.findings import Category, Finding, Severity

_UNKNOWN = object()


def parser_option_findings(index: FunctionIndex) -> list[Finding]:
    return [
        finding
        for path, tree in index.trees.items()
        for finding in _file_findings(index, path, tree)
    ]


def _file_findings(index, path, tree):
    findings = []

    def value(expr, env):
        if isinstance(expr, ast.Constant):
            return expr.value
        if isinstance(expr, ast.Name):
            return env.get(expr.id, _UNKNOWN)
        if isinstance(expr, ast.Dict):
            result = {}
            for key, item in zip(expr.keys, expr.values, strict=True):
                if key is None:
                    expanded = value(item, env)
                    if not isinstance(expanded, dict):
                        return _UNKNOWN
                    result.update(expanded)
                else:
                    key_value = value(key, env)
                    if not isinstance(key_value, str):
                        return _UNKNOWN
                    result[key_value] = value(item, env)
            return result
        if (
            isinstance(expr, ast.Call)
            and isinstance(expr.func, ast.Name)
            and expr.func.id == "dict"
            and not expr.args
        ):
            return {kw.arg: value(kw.value, env) for kw in expr.keywords if kw.arg is not None}
        return _UNKNOWN

    def calls(stmt, env):
        for call in ast.walk(stmt):
            if not isinstance(call, ast.Call) or index.qualified_name(path, call.func) not in {
                "lxml.etree.XMLParser",
                "etree.XMLParser",
            }:
                continue
            opts = {}
            for kw in call.keywords:
                if kw.arg:
                    opts[kw.arg] = value(kw.value, env)
                else:
                    expanded = value(kw.value, env)
                    if not isinstance(expanded, dict):
                        opts = {}
                        break
                    opts.update(expanded)
            if opts.get("resolve_entities") is True or opts.get("no_network") is False:
                findings.append(
                    Finding(
                        rule_id="ns-websec-611-001",
                        message="lxml XMLParser is constructed with unsafe entity/network options resolved from its keyword arguments; use resolve_entities=False, no_network=True, load_dtd=False for untrusted XML.",
                        severity=Severity.MEDIUM,
                        category=Category.DESERIALIZATION,
                        file_path=str(path),
                        start_line=call.lineno,
                        start_column=call.col_offset,
                        confidence=0.85,
                        cwe_ids=[611],
                        engine="python-options",
                        metadata={
                            "analysis": "resolved-parser-options",
                            "operation_id": f"{path}:{call.lineno}:{call.col_offset}",
                        },
                    )
                )

    def block(body, env, inspect=True):
        for stmt in body:
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if not inspect:
                    continue
                local = dict(module_env)
                local.update({name: val for name, val in env.items() if name not in module_env})
                for arg in stmt.args.posonlyargs + stmt.args.args + stmt.args.kwonlyargs:
                    local[arg.arg] = _UNKNOWN
                block(stmt.body, local)
            elif isinstance(stmt, ast.ClassDef):
                if inspect:
                    block(stmt.body, dict(env))
            elif isinstance(stmt, (ast.Assign, ast.AnnAssign)):
                if inspect:
                    calls(stmt, env)
                evaluated = value(stmt.value, env) if stmt.value else _UNKNOWN
                for target in stmt.targets if isinstance(stmt, ast.Assign) else [stmt.target]:
                    if isinstance(target, ast.Name):
                        env[target.id] = evaluated
                    elif isinstance(target, ast.Subscript) and isinstance(target.value, ast.Name):
                        mapping = env.get(target.value.id)
                        key = value(target.slice, env)
                        if isinstance(mapping, dict) and isinstance(key, str):
                            env[target.value.id] = {**mapping, key: evaluated}
            elif isinstance(stmt, (ast.If, ast.Try, ast.For, ast.While, ast.With)):
                # Branch assignments cannot establish a single configuration.
                branches = [getattr(stmt, "body", []), getattr(stmt, "orelse", [])]
                branches += [h.body for h in getattr(stmt, "handlers", [])]
                for branch in branches:
                    block(branch, dict(env), inspect)
                for child in ast.walk(stmt):
                    if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Store):
                        env[child.id] = _UNKNOWN
            else:
                if inspect:
                    calls(stmt, env)
                if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
                    call = stmt.value
                    if (
                        isinstance(call.func, ast.Attribute)
                        and isinstance(call.func.value, ast.Name)
                        and call.func.value.id in env
                    ):
                        # Mutating methods invalidate a static dictionary.
                        env[call.func.value.id] = _UNKNOWN

    # Evaluate final module bindings without inspecting function bodies;
    # functions read globals at call time, not at definition time.
    module_env = {}
    block(tree.body, module_env, inspect=False)
    block(tree.body, {})
    return findings
