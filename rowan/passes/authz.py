"""Object-level authorization (BOLA/IDOR) detection pass.

Detects a request handler that reads an object of a recognized ORM model keyed
by an attacker-controlled id, with **no ownership predicate** constraining that
read to the current principal. It is the inversion of the taint model: instead
of "does a sanitizer dominate this sink?", it asks "does an authorization guard
constrain this object fetch?" -- and reports the gap. See ADR-0003.

Scope: the four BOLARAY models -- **ownership** (issue #171, query-fused),
**fetch-then-guard** dominance for ownership (issue #172), and **membership** /
**hierarchical** / **status** plus decorator/middleware gates (issue #173) --
for Django/DRF/SQLAlchemy ORM idioms. A user-keyed read is a gap only if *none*
of the four models is satisfied on its path; satisfying any one suppresses the
finding. It does NOT cover function-level authz, custom raw-SQL data-access
layers or runtime dispatch it cannot resolve. Repository aliases and bounded
expression-only retrieval wrappers are resolved without importing the target.
Returned object/permission pairs are checked against the caller's guard;
unresolved imported object reads produce informational coverage signals.
The detector is off by default (ScanConfig.enable_authz). Phase 6 adds escape-based
use tracking (late-built local payloads are not themselves escapes) and
same-module helper guard delegation (`require_owner(obj)`). Phase 7 adds
FastAPI dependency-injected parameters (`Depends`/`Security` are not path
ids) and SQLAlchemy session-query reads (`db.query(Model).filter(...)`).

Issue #185 adds `AUTHZ-LLM-001`, which inverts the question again: instead of
"is a guard present?" (BOLA/IDOR above) it asks "is the PRESENT guard's
decision actually the server's to make?" A permission-shaped `if` test built
from an LLM completion or a tool-call argument provides no real protection --
anything that can steer the model can force the allow path. Same dominance
machinery, applied to a guard whose condition, not whose absence, is the
problem.
"""

from __future__ import annotations

import ast
import copy
import logging
import re
import time
from pathlib import Path

from rowan.analysis.dominance import collect_dominating_candidates
from rowan.analysis.python_functions import (
    FunctionIndex,
    bind_arguments,
    specialize_returns,
)
from rowan.analysis.request_sources import dotted_name
from rowan.core.authz_predicates import (
    authorizing_decorators,
    class_authz_gate,
    is_existence_check,
    is_hierarchical_parent_read,
    is_llm_derived_expr,
    is_membership_check,
    is_ownership_fused_read,
    is_ownership_guard,
    is_ownership_key,
    is_principal_expr,
    is_status_fused_read,
    is_status_gate,
    is_user_keyed_read,
    model_derived_permission_guard_kind,
    ownership_fused_guard_ids,
    principal_expressions,
    read_model_class,
)
from rowan.core.confidence import AUTHZ_BOLA_HIGH, AUTHZ_BOLA_MEDIUM, AUTHZ_LLM_HIGH
from rowan.core.findings import Category, Finding, ScanResult, Severity
from rowan.core.paths import iter_within_root
from rowan.passes.base import ScanContext, scan_span
from rowan.passes.sources import filter_python_paths, iter_python_sources

logger = logging.getLogger(__name__)

_RULE_ID = "AUTHZ-BOLA-001"
_PRINCIPAL_OVERRIDE_RULE_ID = "AUTHZ-PRINCIPAL-OVERRIDE-001"
_TENANT_SCOPE_RULE_ID = "AUTHZ-TENANT-SCOPE-001"
_RAG_TENANT_SCOPE_RULE_ID = "AUTHZ-RAG-TENANT-SCOPE-001"
_REMEDIATION = (
    "Scope the object read to the current principal (e.g. filter "
    "owner_id=current_user.id) or add a dominating ownership/membership/status "
    "guard before the object escapes."
)
_PUBLIC_IDENTITY_MODEL_RE = re.compile(r"^(?:User|Account|Member)s?$", re.IGNORECASE)
_IDENTITY_HANDLER_RE = re.compile(
    r"(?:login|sign_?in|sign_?up|register|reset|verify|logout)", re.IGNORECASE
)

# Parameter names that are never the attacker-controlled object id.
_NON_KEY_PARAMS: frozenset[str] = frozenset({"self", "cls", "request", "req"})

# Last decorator segments that mark an HTTP route handler.
_ROUTE_DECORATOR_TAILS: frozenset[str] = frozenset({
    "route", "get", "post", "put", "patch", "delete", "websocket",
    "api_view", "require_http_methods", "api_route",
})

# HTTP-verb method names on a class-based view.
_CBV_METHOD_NAMES: frozenset[str] = frozenset(
    {
        "get", "post", "put", "patch", "delete", "list", "retrieve",
        "create", "update", "partial_update", "destroy",
    }
)

def _contains_principal(expr: ast.AST, principal_names: set[str]) -> bool:
    return any(
        isinstance(node, (ast.Name, ast.Attribute))
        and is_principal_expr(node, principal_names)
        for node in ast.walk(expr)
    )


def _principal_override_source(call: ast.Call, principal_names: set[str]) -> bool:
    """`request.args.get('owner', current_user.id)` style override source."""
    if not (
        isinstance(call.func, ast.Attribute)
        and call.func.attr == "get"
        and len(call.args) >= 2
        and isinstance(call.args[0], ast.Constant)
        and isinstance(call.args[0].value, str)
        and is_ownership_key(call.args[0].value)
    ):
        return False
    receiver = dotted_name(call.func.value)
    if not receiver or not any(
        receiver == prefix or receiver.startswith(prefix + ".")
        for prefix in (
            "request.args", "request.GET", "request.query_params",
            "request.form", "request.json", "flask.request.args",
        )
    ):
        return False
    return _contains_principal(call.args[1], principal_names)


def _guard_body_denies(body: list[ast.stmt]) -> bool:
    if not body:
        return False
    last = body[-1]
    if isinstance(last, (ast.Return, ast.Raise)):
        return True
    if isinstance(last, ast.Expr) and isinstance(last.value, ast.Call):
        name = dotted_name(last.value.func).rsplit(".", 1)[-1]
        return name in {"abort", "deny", "forbid", "forbidden", "raise_forbidden"}
    return False


def _is_principal_mismatch_guard(
    stmt: ast.stmt, value_name: str, principal_names: set[str]
) -> bool:
    if not isinstance(stmt, ast.If) or not _guard_body_denies(stmt.body):
        return False
    if isinstance(stmt.test, ast.BoolOp) and isinstance(stmt.test.op, ast.And):
        has_mismatch = any(
            _is_principal_mismatch_test(test, value_name, principal_names)
            for test in stmt.test.values
        )
        has_privilege = any(
            any(
                isinstance(node, ast.Attribute)
                and node.attr in {"is_admin", "is_superuser"}
                and is_principal_expr(node.value, principal_names)
                for node in ast.walk(test)
            )
            for test in stmt.test.values
        )
        return has_mismatch and has_privilege
    return _is_principal_mismatch_test(stmt.test, value_name, principal_names)


def _is_principal_mismatch_test(
    test: ast.expr, value_name: str, principal_names: set[str]
) -> bool:
    if not (
        isinstance(test, ast.Compare)
        and len(test.ops) == 1
        and isinstance(test.ops[0], (ast.NotEq, ast.IsNot))
        and len(test.comparators) == 1
    ):
        return False
    sides = (test.left, test.comparators[0])
    return any(
        any(isinstance(node, ast.Name) and node.id == value_name for node in ast.walk(side))
        for side in sides
    ) and any(_contains_principal(side, principal_names) for side in sides)


def _string_fragments(node: ast.AST) -> list[str]:
    return [
        part.value
        for part in ast.walk(node)
        if isinstance(part, ast.Constant) and isinstance(part.value, str)
    ]


def _unscoped_collection_query(
    func: ast.FunctionDef | ast.AsyncFunctionDef,
    owner_models: set[str] | None = None,
) -> tuple[int, str] | None:
    """Return the sink line and model/table for an owner-bearing collection
    query that never constrains an ownership column."""
    text = " ".join(_string_fragments(func))
    select = re.search(r"(?is)\bselect\b.+?\bfrom\s+([a-zA-Z_]\w*)", text)
    owner_column = re.search(r"\b(?:owner|user|tenant|account)_id\b", text, re.I)
    owner_predicate = re.search(
        r"\b(?:owner|user|tenant|account)_id\b\s*(?:=|\bin\b)", text, re.I
    )
    if select and owner_column and not owner_predicate:
        for call in ast.walk(func):
            if isinstance(call, ast.Call) and dotted_name(call.func).endswith(
                (".execute", ".exec_driver_sql")
            ):
                return call.lineno, select.group(1)

    for call in ast.walk(func):
        if not isinstance(call, ast.Call) or not isinstance(call.func, ast.Attribute):
            continue
        if call.func.attr not in {"all", "count", "aggregate", "values", "values_list"}:
            continue
        rendered = ast.unparse(call)
        if ".query" not in rendered and ".objects" not in rendered:
            continue
        model = rendered.split(".", 1)[0]
        if owner_models is not None and model not in owner_models:
            continue
        if is_ownership_fused_read(call):
            continue
        return call.lineno, model
    return None


def _owner_scoped_written_models(trees: list[ast.AST]) -> set[str]:
    """Models constructed with an ownership field bound to the principal."""
    models: set[str] = set()
    for tree in trees:
        for call in (node for node in ast.walk(tree) if isinstance(node, ast.Call)):
            name = dotted_name(call.func).rsplit(".", 1)[-1]
            if not name or not name[:1].isupper():
                continue
            if any(
                kw.arg is not None
                and is_ownership_key(kw.arg)
                and _contains_principal(kw.value, set())
                for kw in call.keywords
            ):
                models.add(name)
    return models


def _unscoped_rag_retrieval(
    func: ast.FunctionDef | ast.AsyncFunctionDef,
    owner_written_models: set[str],
) -> tuple[int, str, int] | None:
    """Unscoped owner-model rows later supplied as LLM/RAG context."""
    gap = _unscoped_collection_query(func)
    if gap is None:
        return None
    query_line, model = gap
    if model not in owner_written_models:
        return None

    derived: set[str] = set()
    for node in ast.walk(func):
        if (
            isinstance(node, ast.Assign)
            and getattr(node.value, "lineno", -1) == query_line
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
        ):
            derived.add(node.targets[0].id)
    while derived:
        changed = False
        for node in ast.walk(func):
            if not isinstance(node, (ast.Assign, ast.AnnAssign)):
                continue
            value = node.value
            target = node.targets[0] if isinstance(node, ast.Assign) and len(node.targets) == 1 else (
                node.target if isinstance(node, ast.AnnAssign) else None
            )
            if (
                value is not None
                and isinstance(target, ast.Name)
                and target.id not in derived
                and _load_names(value) & derived
            ):
                derived.add(target.id)
                changed = True
        if not changed:
            break

    for call in (node for node in ast.walk(func) if isinstance(node, ast.Call)):
        name = dotted_name(call.func).lower()
        if not re.search(r"(?:agent|chat|complet|generate|invoke|predict)", name):
            continue
        supplied = [*call.args, *(kw.value for kw in call.keywords)]
        if any(_load_names(value) & derived for value in supplied):
            return call.lineno, model, query_line
    return None


def _resolve_imported_function(
    caller_file: Path,
    local_name: str,
    tree: ast.AST,
    files: set[Path],
) -> tuple[Path, str] | None:
    for stmt in getattr(tree, "body", []):
        if not isinstance(stmt, ast.ImportFrom):
            continue
        for alias in stmt.names:
            if (alias.asname or alias.name) != local_name:
                continue
            module_parts = (stmt.module or "").split(".")
            suffix = Path(*module_parts).with_suffix(".py") if module_parts else None
            candidates = [
                path for path in files
                if suffix is not None and path.as_posix().endswith(suffix.as_posix())
            ]
            if len(candidates) == 1:
                return candidates[0], alias.name
    return None


def _handler_has_auth_gate(func: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    if authorizing_decorators(func):
        return True
    return any(
        re.search(r"auth|login|permission", name, re.IGNORECASE)
        for name in _decorator_tail_names(func)
    )


# Calls that build a local response value without making it externally visible;
# assigning one to a local before an authz guard is safe if the guarded return
# is the only escape (ModelForge D50's `payload = jsonify(...)` idiom).
_LOCAL_RESPONSE_BUILDER_TAILS: frozenset[str] = frozenset({
    "jsonify", "JsonResponse", "Response", "make_response",
})


def _decorator_tail_names(func: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    tails: set[str] = set()
    for dec in func.decorator_list:
        target = dec.func if isinstance(dec, ast.Call) else dec
        dotted = dotted_name(target)
        if dotted:
            tails.add(dotted.rsplit(".", 1)[-1])
    return tails


def _class_is_view(cls: ast.ClassDef) -> bool:
    """A Django/DRF class-based view: a base whose name ends in View/ViewSet."""
    for base in cls.bases:
        name = dotted_name(base).rsplit(".", 1)[-1]
        if name.endswith(("View", "ViewSet")):
            return True
    return False


def _param_names(func: ast.FunctionDef | ast.AsyncFunctionDef) -> list[str]:
    a = func.args
    return [p.arg for p in (*a.posonlyargs, *a.args, *a.kwonlyargs)]


def _is_dependency_default(default: ast.expr | None) -> bool:
    if default is None:
        return False
    target = default.func if isinstance(default, ast.Call) else default
    dotted = dotted_name(target)
    return bool(dotted) and dotted.rsplit(".", 1)[-1] in {"Depends", "Security"}


def _dependency_param_names(func: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    """FastAPI/Starlette injected parameters (`x = Depends(...)`,
    `x = Security(...)`). These are framework-supplied values, not path
    parameters, so they must not mark an object read as attacker-keyed."""
    names: set[str] = set()
    positional = [*func.args.posonlyargs, *func.args.args]
    defaults: list[ast.expr | None] = (
        [None] * (len(positional) - len(func.args.defaults)) + func.args.defaults
    )
    for arg, default in zip(positional, defaults, strict=False):
        if _is_dependency_default(default):
            names.add(arg.arg)
    for arg, default in zip(func.args.kwonlyargs, func.args.kw_defaults, strict=False):
        if _is_dependency_default(default):
            names.add(arg.arg)
    return names


def _user_controlled_names(func: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    """Handler parameters that are attacker-controlled object ids: every
    parameter except framework-supplied ones (self/cls/request) and
    dependency-injected values (FastAPI `Depends`/`Security`). Route and path
    parameters (`pk`, `doc_id`, ...) are bound here by the framework from the
    URL, so they are user input."""
    supplied = _NON_KEY_PARAMS | _dependency_param_names(func)
    names = {p for p in _param_names(func) if p not in supplied}
    if func.args.kwarg is not None:
        names.add(func.args.kwarg.arg)
    return names


def _is_handler(
    func: ast.FunctionDef | ast.AsyncFunctionDef,
    in_view_class: bool,
    *,
    has_django_import: bool = False,
    registered_names: set[str] | None = None,
) -> bool:
    if func.name.startswith("test_") or "fixture" in _decorator_tail_names(func):
        return False
    if _decorator_tail_names(func) & _ROUTE_DECORATOR_TAILS:
        return True
    if in_view_class and (
        func.name in _CBV_METHOD_NAMES or "action" in _decorator_tail_names(func)
    ):
        return True
    # Django function-based view: first positional parameter named `request`.
    params = _param_names(func)
    return bool(params) and params[0] == "request" and (
        bool(func.decorator_list)
        or has_django_import
        or func.name in (registered_names or set())
    )


def _iter_handlers(tree: ast.AST):
    """Yield (handler, enclosing_class) for every handler function in the
    module -- `enclosing_class` is None for a function-based view, and is used
    to resolve class-level authorization gates (#173) -- without descending
    into nested function bodies."""
    has_django_import = any(
        isinstance(node, ast.ImportFrom)
        and (node.module or "").startswith(("django", "rest_framework"))
        for node in getattr(tree, "body", [])
    )
    registered_names: set[str] = set()
    for call in (node for node in ast.walk(tree) if isinstance(node, ast.Call)):
        if (dotted_name(call.func) or "").rsplit(".", 1)[-1] not in {"path", "url", "re_path"}:
            continue
        registered_names.update(arg.id for arg in call.args if isinstance(arg, ast.Name))

    def walk(body: list[ast.stmt], in_view_class: ast.ClassDef | None):
        for node in body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if _is_handler(
                    node,
                    in_view_class is not None,
                    has_django_import=has_django_import,
                    registered_names=registered_names,
                ):
                    yield node, in_view_class
            elif isinstance(node, ast.ClassDef):
                is_view = node if _class_is_view(node) else None
                for sub in node.body:
                    if isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        if _is_handler(
                            sub,
                            is_view is not None,
                            has_django_import=has_django_import,
                            registered_names=registered_names,
                        ):
                            yield sub, is_view
                    elif isinstance(sub, ast.ClassDef):
                        yield from walk([sub], is_view)

    module_body = getattr(tree, "body", [])
    yield from walk(module_body, in_view_class=None)


def _module_functions(tree: ast.AST) -> dict[str, ast.FunctionDef | ast.AsyncFunctionDef]:
    return {
        node.name: node
        for node in getattr(tree, "body", [])
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }


# ---------------------------------------------------------------------------
# Principal aliases (#172): names that hold the principal without being one of
# the framework-canonical `_PRINCIPAL_BASES`.
#
# Real applications rarely write `current_user.id` at the authorization site.
# They bind the principal once -- in an auth decorator, in a FastAPI dependency,
# or in a local at the top of the handler -- and then authorize against that
# name. Without resolving the binding, a genuine query-fused ownership check
# like `Service.query(id=ds_id, tenant_id=tenant_id)` reads as unguarded and the
# handler is reported as a BOLA. On ragflow's document_api.py that accounted for
# every false positive the pass produced.
#
# Each source below establishes the alias by construction, not by guessing at
# names, except `Depends(...)`, which is deliberately restricted to
# current-user-shaped dependency callables -- treating a wrong name as the
# principal would suppress a real finding, so this errs toward reporting.
# ---------------------------------------------------------------------------

#: Dependency callables whose return value is the authenticated principal.
#: Matched on the callable's last dotted segment.
_CURRENT_USER_DEPENDENCY_RE = re.compile(
    r"^(?:get_|require_|verify_|fetch_)?current_(?:active_|authenticated_)?"
    r"(?:user|actor|principal|identity)$"
    r"|^(?:get_|require_)(?:authenticated|logged_in)_(?:user|actor)$",
    re.IGNORECASE,
)


def _decorator_names(func: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    """Every decorator on `func`, by last dotted segment."""
    names: set[str] = set()
    for dec in func.decorator_list:
        target = dec.func if isinstance(dec, ast.Call) else dec
        dotted = dotted_name(target)
        if dotted:
            names.add(dotted.rsplit(".", 1)[-1])
    return names


def principal_injecting_decorators(trees: list[ast.AST]) -> dict[str, set[str]]:
    """Map decorator name -> the kwarg names it populates with the principal.

    Recognizes the wrapper idiom, wherever in the corpus it is defined::

        def add_tenant_id_to_kwargs(func):
            @wraps(func)
            async def wrapper(**kwargs):
                kwargs["tenant_id"] = current_user.id
                return await func(**kwargs)
            return wrapper

    A handler decorated with `@add_tenant_id_to_kwargs` therefore receives
    `tenant_id` already bound to the principal, even though nothing in the
    handler's own body says so.
    """
    injectors: dict[str, set[str]] = {}
    for tree in trees:
        for outer in ast.walk(tree):
            if not isinstance(outer, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            injected: set[str] = set()
            for node in ast.walk(outer):
                if not isinstance(node, ast.Assign) or not is_principal_expr(node.value):
                    continue
                for target in node.targets:
                    # kwargs["tenant_id"] = current_user.id
                    if (
                        isinstance(target, ast.Subscript)
                        and isinstance(target.slice, ast.Constant)
                        and isinstance(target.slice.value, str)
                    ):
                        injected.add(target.slice.value)
            if injected:
                injectors.setdefault(outer.name, set()).update(injected)
    return injectors


def handler_principal_aliases(
    handler: ast.FunctionDef | ast.AsyncFunctionDef,
    injectors: dict[str, set[str]],
) -> set[str]:
    """Names that hold the authenticated principal inside `handler`.

    Three sources, in increasing order of inference:

    1. A parameter injected by a principal-injecting decorator applied to this
       handler (see `principal_injecting_decorators`).
    2. A FastAPI/Starlette parameter defaulted to `Depends(...)`/`Security(...)`
       over a current-user-shaped dependency callable.
    3. A local assigned directly from a principal expression
       (``tenant_id = current_user.id``).
    """
    aliases: set[str] = set()
    params = set(_param_names(handler))

    # 1. decorator-injected kwargs
    for dec_name in _decorator_names(handler):
        for injected in injectors.get(dec_name, ()):
            if injected in params:
                aliases.add(injected)

    # 2. FastAPI dependency injection
    args = handler.args
    positional = [*args.posonlyargs, *args.args]
    paired: list[tuple[ast.arg, ast.expr | None]] = [
        *zip(positional[len(positional) - len(args.defaults):], args.defaults, strict=True),
        *zip(args.kwonlyargs, args.kw_defaults, strict=True),
    ]
    for arg, default in paired:
        if not isinstance(default, ast.Call):
            continue
        outer_name = dotted_name(default.func) or ""
        if outer_name.rsplit(".", 1)[-1] not in {"Depends", "Security"}:
            continue
        for dep in default.args:
            dep_name = dotted_name(dep) or ""
            if dep_name and _CURRENT_USER_DEPENDENCY_RE.match(dep_name.rsplit(".", 1)[-1]):
                aliases.add(arg.arg)

    # 3. local assignment from a principal expression
    for node in ast.walk(handler):
        if not isinstance(node, ast.Assign) or not is_principal_expr(node.value):
            continue
        for target in node.targets:
            if isinstance(target, ast.Name):
                aliases.add(target.id)

    return aliases


def _resolve_helper_callee(
    py_file: Path,
    tree: ast.AST,
    call: ast.Call,
    corpus: dict[Path, dict[str, ast.FunctionDef | ast.AsyncFunctionDef]],
) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
    """The same-repository function a handler calls as `fn(...)` (imported by
    name or defined in this module) or `module.fn(...)`. Ambiguous or
    unresolvable calls return None."""
    files = set(corpus)
    if isinstance(call.func, ast.Name):
        if call.func.id in corpus.get(py_file, {}):
            return corpus[py_file][call.func.id]
        resolved = _resolve_imported_function(py_file, call.func.id, tree, files)
        return corpus.get(resolved[0], {}).get(resolved[1]) if resolved else None
    if isinstance(call.func, ast.Attribute) and isinstance(call.func.value, ast.Name):
        matches = [f for f in files if f.stem == call.func.value.id]
        if len(matches) == 1:
            return corpus[matches[0]].get(call.func.attr)
    return None


def _helper_read(
    callee: ast.FunctionDef | ast.AsyncFunctionDef,
    call: ast.Call,
    handler_user_names: set[str],
    principal_names: set[str],
) -> ast.Call | None:
    """An object read keyed by a request-fed parameter. Guard correctness is
    checked separately in the specialized callee and its calling handler."""
    params = _param_names(callee)
    fed: set[str] = set()
    for index, arg in enumerate(call.args):
        if index < len(params) and any(
            isinstance(n, ast.Name) and n.id in handler_user_names for n in ast.walk(arg)
        ):
            fed.add(params[index])
    for kw in call.keywords:
        if kw.arg in params and any(
            isinstance(n, ast.Name) and n.id in handler_user_names for n in ast.walk(kw.value)
        ):
            fed.add(kw.arg)
    if not fed:
        return None
    # Parameters the handler fed from the principal (`fetch(id, g.user_id)`):
    # a read scoped by one of them is ownership-fused.
    reassigned = {n.id for n in ast.walk(callee) if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store)}
    principal_params = {
        params[i] for i, arg in enumerate(call.args)
        if i < len(params) and is_principal_expr(arg, principal_names)
    } | {
        kw.arg for kw in call.keywords
        if kw.arg in params and is_principal_expr(kw.value, principal_names)
    }
    principal_params -= reassigned
    for read in _outermost_read_calls(callee):
        if (
            not is_ownership_fused_read(read, principal_params)
            and not is_status_fused_read(read)
            and is_user_keyed_read(read, fed)
        ):
            return read
    return None


def _outermost_read_calls(func: ast.FunctionDef | ast.AsyncFunctionDef) -> list[ast.Call]:
    """Recognized object-read calls in the handler body, de-duplicated so that a
    chained read (`Model.objects.filter(...).first()`) is reported once, at its
    outermost call, not once per link in the chain. Nested function bodies are
    not descended into."""
    # Nodes belonging to a nested function/lambda are attributed to that scope,
    # not to this handler (ast.walk flattens them, so they must be excluded by id).
    nested: set[int] = set()
    for child in ast.walk(func):
        if child is not func and isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            nested.update(id(n) for n in ast.walk(child))

    reads: list[ast.Call] = []
    for stmt in func.body:
        for node in ast.walk(stmt):
            if (
                isinstance(node, ast.Call)
                and id(node) not in nested
                and read_model_class(node) is not None
            ):
                reads.append(node)

    # Drop calls that are an inner link of another recognized read's chain.
    inner: set[int] = set()
    for r in reads:
        cur = r.func
        while isinstance(cur, ast.Attribute):
            if isinstance(cur.value, ast.Call):
                inner.add(id(cur.value))
                cur = cur.value.func
            else:
                cur = cur.value
    return [r for r in reads if id(r) not in inner]


def _assigned_var_for_call(
    func: ast.FunctionDef | ast.AsyncFunctionDef, call: ast.Call
) -> tuple[str, int] | None:
    """The (name, lineno) of a simple `obj_var = <call>` assignment whose value
    is exactly `call`, or None if the read isn't assigned to a plain variable
    (e.g. returned or used inline) -- there is nothing for a later guard to
    dominate in that case, so it falls back to Phase 1's direct behavior."""
    for node in ast.walk(func):
        if (
            isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
            and node.value is call
        ):
            return node.targets[0].id, node.lineno
    return None


def _guard_test_node_ids(
    func: ast.FunctionDef | ast.AsyncFunctionDef, obj_var: str, principal_names: set[str]
) -> set[int]:
    """Node ids inside the `test` of every recognized guard on `obj_var`
    (ownership, membership, status, or a bare existence/null check) --
    excluded when searching for the variable's first real *use*, since
    checking a guard condition is not itself a use."""
    ids: set[int] = set()
    for node in ast.walk(func):
        if not isinstance(node, ast.If):
            continue
        if (
            is_ownership_guard(node, obj_var, principal_names)
            or is_membership_check(node, obj_var, principal_names)
            or is_status_gate(node, obj_var)
            or is_existence_check(node.test, obj_var)
        ):
            ids.update(id(n) for n in ast.walk(node.test))
    return ids


def _nested_scope_ids(func: ast.FunctionDef | ast.AsyncFunctionDef) -> set[int]:
    nested: set[int] = set()
    for child in ast.walk(func):
        if child is not func and isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            nested.update(id(n) for n in ast.walk(child))
    return nested


def _load_names(expr: ast.AST) -> set[str]:
    return {n.id for n in ast.walk(expr) if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load)}


def _plain_target_names(targets: list[ast.expr]) -> set[str]:
    names: set[str] = set()
    for target in targets:
        if isinstance(target, ast.Name):
            names.add(target.id)
            continue
        if isinstance(target, (ast.Tuple, ast.List)) and all(isinstance(elt, ast.Name) for elt in target.elts):
            names.update(elt.id for elt in target.elts)
            continue
        return set()
    return names


def _expr_has_external_call(expr: ast.AST) -> bool:
    for node in ast.walk(expr):
        if not isinstance(node, ast.Call):
            continue
        dotted = dotted_name(node.func)
        tail = dotted.rsplit(".", 1)[-1] if dotted else None
        if tail not in _LOCAL_RESPONSE_BUILDER_TAILS:
            return True
    return False


def _pure_derivation_value(stmt: ast.stmt, derived: set[str]) -> ast.expr | None:
    """The RHS of a local assignment that only repackages `derived` into
    another local name (`payload = {'id': note.id}`), or None if the statement
    may make the value externally visible (a non-response-builder call, an
    attribute/subscript target, or no derived input). Building a local payload
    before an authorization guard is not itself an escape; using it is."""
    if isinstance(stmt, ast.Assign):
        targets = _plain_target_names(stmt.targets)
        value = stmt.value
    elif isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
        targets = {stmt.target.id}
        value = stmt.value
    else:
        return None
    if not targets or value is None or _expr_has_external_call(value):
        return None
    if not (_load_names(value) & derived):
        return None
    return value


def _derived_local_names(
    func: ast.FunctionDef | ast.AsyncFunctionDef, obj_var: str, nested: set[int]
) -> set[str]:
    derived = {obj_var}
    while True:
        changed = False
        for node in ast.walk(func):
            if id(node) in nested:
                continue
            value = _pure_derivation_value(node, derived)
            if value is None:
                continue
            targets = (
                _plain_target_names(node.targets)
                if isinstance(node, ast.Assign)
                else {node.target.id}
            )
            new = targets - derived
            if new:
                derived |= new
                changed = True
        if not changed:
            return derived


def _module_helper_guards(
    functions: dict[str, ast.FunctionDef | ast.AsyncFunctionDef],
    principal_names: set[str],
) -> dict[str, tuple[list[str], dict[str, set[str]]]]:
    """Precompute, once per module function, which parameters are guarded and
    by which BOLARAY model(s). Cross-function call sites then do a dict lookup
    instead of re-walking the callee body for every guard candidate."""
    helpers: dict[str, tuple[list[str], dict[str, set[str]]]] = {}
    for name, func in functions.items():
        params = _param_names(func)
        if not params:
            continue
        by_param: dict[str, set[str]] = {}
        for node in ast.walk(func):
            if not isinstance(node, ast.If):
                continue
            for param in params:
                if is_ownership_guard(node, param, principal_names):
                    by_param.setdefault(param, set()).add("ownership")
                if is_membership_check(node, param, principal_names):
                    by_param.setdefault(param, set()).add("membership")
                if is_status_gate(node, param):
                    by_param.setdefault(param, set()).add("status")
        if by_param:
            helpers[name] = (params, by_param)
    return helpers


_PRIVILEGED_PRINCIPAL_ATTRS: frozenset[str] = frozenset({"is_superuser", "is_admin"})


def _privileged_gate_param(
    func: ast.FunctionDef | ast.AsyncFunctionDef,
) -> str | None:
    """Return the principal parameter protected by a fail-closed role gate.

    This is intentionally narrower than a generic helper-name heuristic: the
    helper must inspect a privilege attribute on one of its own parameters and
    terminate the deny branch. Boolean-return helpers and log-only checks do
    not qualify.
    """
    params = set(_param_names(func))
    # Only a top-level deny guard is unconditionally reached when the helper
    # is called.  A matching check nested in a feature branch or a caught
    # ``try`` is fail-open and must not summarize the whole helper.
    for node in func.body:
        if not isinstance(node, ast.If) or not _guard_body_denies(node.body):
            continue
        test = node.test
        if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
            test = test.operand
        else:
            # The deny branch must represent the absence of privilege. Avoid
            # treating `if user.is_admin: raise` as an authorization gate.
            continue
        if (
            isinstance(test, ast.Attribute)
            and test.attr in _PRIVILEGED_PRINCIPAL_ATTRS
            and isinstance(test.value, ast.Name)
            and test.value.id in params
        ):
            return test.value.id
        if (
            isinstance(test, ast.Call)
            and isinstance(test.func, ast.Name)
            and test.func.id == "getattr"
            and len(test.args) >= 2
            and isinstance(test.args[0], ast.Name)
            and test.args[0].id in params
            and isinstance(test.args[1], ast.Constant)
            and test.args[1].value in _PRIVILEGED_PRINCIPAL_ATTRS
            and (
                len(test.args) == 2
                or (
                    len(test.args) == 3
                    and isinstance(test.args[2], ast.Constant)
                    and test.args[2].value is False
                )
            )
        ):
            return test.args[0].id
    return None


def _module_principal_gate_helpers(
    functions: dict[str, ast.FunctionDef | ast.AsyncFunctionDef],
) -> dict[str, tuple[list[str], str]]:
    helpers: dict[str, tuple[list[str], str]] = {}
    for name, func in functions.items():
        protected_param = _privileged_gate_param(func)
        if protected_param is not None:
            helpers[name] = (_param_names(func), protected_param)
    return helpers


def _is_principal_gate_call(
    call: ast.Call,
    helpers: dict[str, tuple[list[str], str]],
    principal_names: set[str],
) -> bool:
    if not isinstance(call.func, ast.Name):
        return False
    helper = helpers.get(call.func.id)
    if helper is None:
        return False
    params, protected_param = helper
    for idx, arg in enumerate(call.args):
        if idx < len(params) and params[idx] == protected_param:
            return is_principal_expr(arg, principal_names)
    return any(
        kw.arg == protected_param and is_principal_expr(kw.value, principal_names)
        for kw in call.keywords
        if kw.arg is not None
    )


def _has_dominating_principal_gate(
    handler: ast.FunctionDef | ast.AsyncFunctionDef,
    sink_line: int,
    helpers: dict[str, tuple[list[str], str]],
    principal_names: set[str],
) -> bool:
    _, dominators = collect_dominating_candidates(handler.body, sink_line)

    def direct_call(stmt: ast.stmt) -> ast.Call | None:
        if not isinstance(stmt, ast.Expr):
            return None
        value = stmt.value
        if isinstance(value, ast.Await):
            value = value.value
        return value if isinstance(value, ast.Call) else None

    return any(
        call is not None and _is_principal_gate_call(call, helpers, principal_names)
        for stmt in dominators
        if (call := direct_call(stmt)) is not None
    )


def _helper_guard_models(
    call: ast.Call,
    helpers: dict[str, tuple[list[str], dict[str, set[str]]]],
    obj_var: str,
) -> set[str]:
    """The BOLARAY model(s) enforced by a same-module helper call for
    `obj_var` -- `require_owner(note)` where `require_owner` guards its
    corresponding parameter. Deliberately narrow: bare-name callees only, no
    imported helpers, methods, or transitive guard calls."""
    if not isinstance(call.func, ast.Name):
        return set()
    helper = helpers.get(call.func.id)
    if helper is None:
        return set()
    params, by_param = helper
    models: set[str] = set()
    for idx, arg in enumerate(call.args):
        if idx >= len(params):
            break
        if isinstance(arg, ast.Name) and arg.id == obj_var:
            models |= by_param.get(params[idx], set())
    for kw in call.keywords:
        if kw.arg is None:
            continue
        if isinstance(kw.value, ast.Name) and kw.value.id == obj_var:
            models |= by_param.get(kw.arg, set())
    return models


def _helper_guard_call_ids(
    func: ast.FunctionDef | ast.AsyncFunctionDef,
    helpers: dict[str, tuple[list[str], dict[str, set[str]]]],
    obj_var: str,
) -> set[int]:
    ids: set[int] = set()
    for node in ast.walk(func):
        if isinstance(node, ast.Call) and _helper_guard_models(node, helpers, obj_var):
            ids.update(id(n) for n in ast.walk(node))
    return ids


def _first_escape_line(
    func: ast.FunctionDef | ast.AsyncFunctionDef,
    obj_var: str,
    after_line: int,
    principal_names: set[str],
    helpers: dict[str, tuple[list[str], dict[str, set[str]]]],
) -> int | None:
    """The line of the earliest post-fetch reference to `obj_var` (or a local
    derived from it) that can escape the handler -- a return, call argument,
    attribute/subscript write, or other non-local use. Local-only derivation
    (`payload = {'id': obj.id}`) is deliberately not an escape by itself: the
    ModelForge D50 idiom builds the response payload before the ownership
    guard but discards it on the deny path."""
    excluded = _guard_test_node_ids(func, obj_var, principal_names)
    excluded |= _helper_guard_call_ids(func, helpers, obj_var)
    nested = _nested_scope_ids(func)
    derived = _derived_local_names(func, obj_var, nested)

    derivation_value_ids: set[int] = set()
    for node in ast.walk(func):
        if id(node) in nested:
            continue
        value = _pure_derivation_value(node, derived)
        if value is not None:
            derivation_value_ids.update(id(n) for n in ast.walk(value))

    loads = [
        n for n in ast.walk(func)
        if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load)
    ]
    loads.sort(key=lambda n: (getattr(n, "lineno", 0), getattr(n, "col_offset", 0)))
    for node in loads:
        if id(node) in excluded or id(node) in nested or id(node) in derivation_value_ids:
            continue
        if node.id not in derived:
            continue
        line = getattr(node, "lineno", None)
        if line is None or line <= after_line:
            continue
        return line

    # No escape: preserve the old first-reference behavior for handlers that
    # fetch and only repackage the object locally (or never use it at all).
    for node in loads:
        if id(node) in excluded or id(node) in nested:
            continue
        if node.id != obj_var:
            continue
        line = getattr(node, "lineno", None)
        if line is None or line <= after_line:
            continue
        return line
    return None


def _authorized_parent_vars(
    func: ast.FunctionDef | ast.AsyncFunctionDef,
    extra_principals: set[str] | None = None,
) -> set[str]:
    """Names already known to be authorized for this principal -- the
    precondition for the hierarchical model, where a child read scoped to one
    of them is covered by the parent's own authorization.

    Two shapes qualify:

    1. A local *bound* from an ownership-fused parent read
       (``kb = Kb.objects.get(id=pk, owner=request.user)``).
    2. An id *proven* by an ownership-fused guard that denies on failure
       (``if not Kb.query(id=ds_id, tenant_id=tenant_id): return deny``) --
       nothing is assigned, but passing the guard is the authorization.
    """
    aliases = extra_principals or set()
    found: set[str] = set()
    for node in ast.walk(func):
        if (
            isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
            and isinstance(node.value, ast.Call)
            and read_model_class(node.value) is not None
            and is_ownership_fused_read(node.value, aliases)
        ):
            found.add(node.targets[0].id)
        elif isinstance(node, ast.If):
            found |= ownership_fused_guard_ids(node, aliases)
    return found


def _guard_state(
    func: ast.FunctionDef | ast.AsyncFunctionDef,
    dominators: list[ast.stmt],
    obj_var: str | None,
    use_line: int | None,
    predicate,
) -> str:
    """"ok" if a guard matching `predicate` dominates `use_line`, "partial" if
    one exists anywhere in `func` but doesn't dominate, "absent" if none
    exists at all (or there is no assigned variable/use to check against)."""
    if obj_var is None or use_line is None:
        return "absent"
    if any(isinstance(d, ast.If) and predicate(d) for d in dominators):
        return "ok"
    if any(isinstance(n, ast.If) and predicate(n) for n in ast.walk(func)):
        return "partial"
    return "absent"


def _delegated_guard_state(
    func: ast.FunctionDef | ast.AsyncFunctionDef,
    dominators: list[ast.stmt],
    obj_var: str | None,
    use_line: int | None,
    helpers: dict[str, tuple[list[str], dict[str, set[str]]]],
) -> str:
    """"ok"/"partial"/"absent" for a same-module helper call that delegates
    the object-level guard (`require_owner(obj)`), using the same dominance
    rule as an inline `if` guard."""
    if obj_var is None or use_line is None:
        return "absent"

    def is_guard_call(stmt: ast.stmt) -> bool:
        return any(
            isinstance(node, ast.Call)
            and _helper_guard_models(node, helpers, obj_var)
            for node in ast.walk(stmt)
        )

    if any(is_guard_call(d) for d in dominators):
        return "ok"
    if any(isinstance(n, ast.stmt) and is_guard_call(n) for n in ast.walk(func)):
        return "partial"
    return "absent"


def _has_drf_object_permission_gate(
    handler: ast.FunctionDef | ast.AsyncFunctionDef,
    read_line: int,
    use_line: int | None,
    obj_var: str | None,
) -> bool:
    if obj_var is None or use_line is None:
        return False
    for stmt in handler.body:
        if not read_line < stmt.lineno <= use_line:
            continue
        if not isinstance(stmt, ast.Expr):
            continue
        value = stmt.value.value if isinstance(stmt.value, ast.Await) else stmt.value
        if not isinstance(value, ast.Call):
            continue
        if not (dotted_name(value.func) or "").endswith("check_object_permissions"):
            continue
        if len(value.args) >= 2 and isinstance(value.args[1], ast.Name):
            if value.args[1].id == obj_var:
                return True
    return False


class AuthzPass:
    name = "authz"

    def _python_files(
        self,
        root: Path,
        ignore_patterns: list[str],
        candidates: tuple[Path, ...] | None = None,
    ) -> list[Path]:
        """Compatibility wrapper retaining the standalone discovery API."""
        paths = iter_within_root(root, "*.py") if candidates is None else candidates
        return list(
            filter_python_paths(
                root, paths, ignore_patterns, skip_tests=False
            )
        )

    def run(self, context: ScanContext) -> ScanResult:
        start = time.perf_counter()
        result = ScanResult()

        if not getattr(context.config, "enable_authz", False):
            return result

        trees: list[tuple[Path, ast.AST]] = []
        principal_names: set[str] = set()

        for py_file, tree in iter_python_sources(context, owner=self.name, skip_tests=False):
            trees.append((py_file, tree))
            principal_names |= principal_expressions(tree)

        # Auth decorators that bind the principal into a handler kwarg are
        # frequently defined in a shared utils module, not next to the handler,
        # so this index is built over the whole corpus before any tree is
        # scanned (#172).
        injectors = principal_injecting_decorators([t for _, t in trees])

        # A missing ownership check is only a BOLA if the app has a principal
        # concept at all; otherwise it is a (different) missing-auth finding.
        if principal_names:
            corpus = {py_file: _module_functions(tree) for py_file, tree in trees}
            index = FunctionIndex(dict(trees))
            for py_file, tree in trees:
                result.findings.extend(
                    self._scan_tree(py_file, tree, principal_names, injectors, corpus, index)
                )

        # AUTHZ-LLM-001 (#185) is not gated on `principal_names`: the flaw is
        # that the model made the decision at all, which holds regardless of
        # whether the app tracks a "current user" concept anywhere else.
        for py_file, tree in trees:
            result.findings.extend(self._scan_llm_authz(py_file, tree))
            result.findings.extend(
                self._scan_principal_overrides(py_file, tree, principal_names)
            )
        result.findings.extend(self._scan_unscoped_collections(trees))
        result.findings.extend(self._scan_unscoped_rag(trees))

        result.files_scanned = len(trees)
        duration = time.perf_counter() - start
        scan_span(self.name, duration)
        logger.info("AuthzPass: %d finding(s) in %.2fs", len(result.findings), duration)
        return result

    def _scan_tree(
        self,
        py_file: Path,
        tree: ast.AST,
        principal_names: set[str],
        injectors: dict[str, set[str]] | None = None,
        corpus: dict[Path, dict[str, ast.FunctionDef | ast.AsyncFunctionDef]] | None = None,
        index: FunctionIndex | None = None,
    ) -> list[Finding]:
        findings: list[Finding] = []
        functions = _module_functions(tree)
        helper_guards = _module_helper_guards(functions, principal_names)
        principal_gate_helpers = _module_principal_gate_helpers(functions)
        for handler, view_cls in _iter_handlers(tree):
            # Names that hold the principal in *this* handler (#172). Folded
            # into principal_names so every downstream guard predicate --
            # ownership, membership, escape analysis -- sees them too, and
            # subtracted from the user-controlled set: a server-injected
            # principal is the opposite of attacker-controlled, so leaving it
            # in would let `query(id=pk, tenant_id=tenant_id)` read as
            # "keyed by user input" on the tenant_id argument.
            aliases = handler_principal_aliases(handler, injectors or {})
            user_names = _user_controlled_names(handler) - aliases
            handler_principals = principal_names | aliases
            # (call node reported, model of the read, True if the read is in a helper)
            reads = [
                (call, read_model_class(call) or "object", False)
                for call in _outermost_read_calls(handler)
            ]
            for helper_call, inner in self._helper_reads(
                py_file, tree, handler, user_names, handler_principals, corpus or {}, index
            ):
                reads.append((helper_call, read_model_class(inner) or "object", True))
            for call, model, via_helper in reads:
                if not via_helper:
                    if (
                        _PUBLIC_IDENTITY_MODEL_RE.match(model)
                        and _IDENTITY_HANDLER_RE.search(handler.name)
                        and not any(is_principal_expr(node, aliases) for node in ast.walk(handler))
                    ):
                        continue
                    if is_ownership_fused_read(call, aliases) or is_status_fused_read(call):
                        continue
                    if not is_user_keyed_read(call, user_names):
                        continue
                analysis_handler, analysis_call = self._returned_guard_handler(
                    handler, call, py_file, index
                ) if via_helper and index else (handler, call)
                verdict = self._gap_verdict(
                    analysis_handler,
                    view_cls,
                    analysis_call,
                    helper_guards,
                    principal_gate_helpers,
                    handler_principals,
                )
                severity, confidence, reason, missing, partial = verdict
                if severity is None:
                    continue
                missing_desc = "/".join(missing) if missing else "authorization"
                findings.append(Finding(
                    rule_id=_RULE_ID,
                    message=(
                        f"Handler '{handler.name}' reads {model} keyed by "
                        f"user-controlled input with no {missing_desc} check -- "
                        f"possible broken object-level authorization (BOLA/IDOR)."
                    ),
                    severity=severity,
                    category=Category.AUTH,
                    file_path=str(py_file),
                    start_line=call.lineno,
                    end_line=getattr(call, "end_lineno", call.lineno),
                    start_column=call.col_offset,
                    confidence=confidence,
                    cwe_ids=[639],
                    owasp_ids=["API1:2023", "A01:2021"],
                    engine="authz",
                    metadata={
                        "model": model, "reason": reason,
                        "missing_models": missing, "partial_models": partial,
                        "remediation": _REMEDIATION,
                        # Different handlers are different entry points; the
                        # adjacent-line dedup keys on this (AZ-01).
                        "caller": handler.name,
                    },
                ))
        if index:
            findings.extend(self._unverified_helpers(py_file, tree, principal_names, index))
        return findings

    def _unverified_helpers(self, py_file, tree, principal_names, index):
        """Coverage signals for imported, unresolved object-returning calls.

        Require a request-keyed call and an object attribute that later escapes.
        An unresolved call is not itself evidence of a vulnerability.
        """
        findings = []
        imports = {
            alias.asname or alias.name.split(".")[0]
            for stmt in tree.body if isinstance(stmt, (ast.Import, ast.ImportFrom))
            for alias in stmt.names
        }
        for handler, view_cls in _iter_handlers(tree):
            user_names = _user_controlled_names(handler)
            for stmt in handler.body:
                if not isinstance(stmt, ast.Assign) or len(stmt.targets) != 1 or not isinstance(stmt.targets[0], ast.Name):
                    continue
                call = stmt.value
                if not isinstance(call, ast.Call) or index.resolve(py_file, call) is not None:
                    continue
                tail = dotted_name(call.func).rsplit(".", 1)[-1]
                if read_model_class(call) is not None or tail[:1].isupper():
                    continue
                if dotted_name(call.func).split(".")[0] not in imports:
                    continue
                if not any(_load_names(arg) & user_names for arg in [*call.args, *(k.value for k in call.keywords)]):
                    continue
                obj = stmt.targets[0].id
                if not any(isinstance(n, ast.Attribute) and isinstance(n.value, ast.Name) and n.value.id == obj
                           and n.lineno > stmt.lineno for n in ast.walk(handler)):
                    continue
                if _first_escape_line(handler, obj, stmt.lineno, principal_names, {}) is None:
                    continue
                if self._gap_verdict(handler, view_cls, call, {}, {}, principal_names)[0] is None:
                    continue
                findings.append(Finding(
                    rule_id="AUTHZ-UNVERIFIED-001", message=(
                        f"Authorization coverage incomplete: cannot resolve '{dotted_name(call.func)}' "
                        "for a request-keyed object used by this handler. Verify scoping in the external or dynamic callee."
                    ), severity=Severity.INFO, category=Category.AUTH, file_path=str(py_file),
                    start_line=call.lineno, confidence=0.3, engine="authz",
                    metadata={"coverage_signal": True, "caller": handler.name,
                              "callee": dotted_name(call.func), "reason": "unresolved-callee"},
                ))
        return findings

    def _helper_reads(
        self,
        py_file: Path,
        tree: ast.AST,
        handler: ast.FunctionDef | ast.AsyncFunctionDef,
        user_names: set[str],
        principal_names: set[str],
        corpus: dict[Path, dict[str, ast.FunctionDef | ast.AsyncFunctionDef]],
        index: FunctionIndex | None = None,
    ) -> list[tuple[ast.Call, ast.Call]]:
        """Repository reads, including bounded expression-only wrappers,
        whose object id originates in the handler. Keep guard-bearing helper
        bodies intact and check their authorization before reporting."""
        found: list[tuple[ast.Call, ast.Call]] = []
        for stmt in handler.body:
            for node in ast.walk(stmt):
                if not isinstance(node, ast.Call) or read_model_class(node) is not None:
                    continue
                ref = index.resolve(py_file, node) if index else None
                callee = specialize_returns(index, ref) if ref else (
                    _resolve_helper_callee(py_file, tree, node, corpus) if index is None else None
                )
                if callee is None or (callee.name == handler.name and (ref is None or ref.path == py_file)):
                    continue
                inner = _helper_read(callee, node, user_names, principal_names)
                if inner is not None:
                    bindings = bind_arguments(callee, node)
                    callee_principals = principal_names | {
                        name for name, value in bindings.items()
                        if is_principal_expr(value, principal_names)
                    }
                    reassigned = {n.id for n in ast.walk(callee) if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store)}
                    callee_principals -= reassigned & set(_param_names(callee))
                    # A returned predicate does not expose the fetched object.
                    returns = [n.value for n in ast.walk(callee) if isinstance(n, ast.Return) and n.value is not None]
                    if returns and all(isinstance(v, (ast.Compare, ast.BoolOp)) or
                                       (isinstance(v, ast.Call) and dotted_name(v.func) == "bool")
                                       for v in returns):
                        assigned = _assigned_var_for_call(callee, inner)
                        first_escape = _first_escape_line(callee, assigned[0], assigned[1], callee_principals, {}) if assigned else None
                        return_lines = [n.lineno for n in ast.walk(callee) if isinstance(n, ast.Return)]
                        if first_escape is None or first_escape >= min(return_lines):
                            continue
                    verdict = self._gap_verdict(callee, None, inner, {}, {}, callee_principals)
                    if verdict[0] is None:
                        continue
                    found.append((node, inner))
        return found

    def _returned_guard_handler(self, handler, call, py_file, index):
        """Bind a returned (object, predicate) pair at the caller's guard.

        Only a single non-null result tuple is summarized. Reassignments of the
        predicate or object in the caller invalidate the summary. Existing
        dominance predicates then decide whether the caller actually denies.
        """
        ref = index.resolve(py_file, call)
        if ref is None:
            return handler, call
        callee = specialize_returns(index, ref)
        returns = [n.value for n in ast.walk(callee) if isinstance(n, ast.Return)
                   and isinstance(n.value, ast.Tuple) and len(n.value.elts) == 2
                   and isinstance(n.value.elts[0], ast.Name)]
        if len(returns) != 1:
            return handler, call
        assignment = next((n for n in ast.walk(handler) if isinstance(n, ast.Assign)
                           and n.value is call and len(n.targets) == 1
                           and isinstance(n.targets[0], (ast.Tuple, ast.List))
                           and len(n.targets[0].elts) == 2
                           and all(isinstance(x, ast.Name) for x in n.targets[0].elts)), None)
        if assignment is None:
            return handler, call
        obj, flag = assignment.targets[0].elts
        for n in ast.walk(handler):
            if n is assignment or getattr(n, "lineno", 0) <= assignment.lineno:
                continue
            if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store) and n.id in {obj.id, flag.id}:
                return handler, call
        bindings = bind_arguments(callee, call)
        bindings[returns[0].elts[0].id] = ast.Name(id=obj.id, ctx=ast.Load())
        expression = returns[0].elts[1]
        protected = returns[0].elts[0].id
        parameters = set(_param_names(callee))
        if any(isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store) and n.id in parameters
               for n in ast.walk(callee)):
            return handler, call
        if any(isinstance(n, (ast.Attribute, ast.Subscript)) and isinstance(n.ctx, ast.Store)
               and isinstance(n.value, ast.Name) and n.value.id == protected for n in ast.walk(callee)):
            return handler, call
        if not isinstance(expression, ast.Compare):
            return handler, call

        class Bind(ast.NodeTransformer):
            def visit_Name(self, node):
                return copy.deepcopy(bindings[node.id]) if isinstance(node.ctx, ast.Load) and node.id in bindings else node

        predicate = Bind().visit(copy.deepcopy(expression))
        clone = copy.deepcopy(handler)
        cloned_call = next(n for n in ast.walk(clone) if isinstance(n, ast.Call)
                           and n.lineno == call.lineno and n.col_offset == call.col_offset)
        cloned_assign = next(n for n in ast.walk(clone) if isinstance(n, ast.Assign) and n.value is cloned_call)
        cloned_assign.targets = [ast.copy_location(ast.Name(id=obj.id, ctx=ast.Store()), obj)]

        class Predicate(ast.NodeTransformer):
            def visit_Name(self, node):
                if node.id == flag.id and isinstance(node.ctx, ast.Load):
                    value = copy.deepcopy(predicate)
                    for child in ast.walk(value):
                        if isinstance(child, ast.expr):
                            ast.copy_location(child, node)
                    return value
                return node

        return ast.fix_missing_locations(Predicate().visit(clone)), cloned_call

    def _scan_principal_overrides(
        self, py_file: Path, tree: ast.AST, principal_names: set[str]
    ) -> list[Finding]:
        """Find tenant/owner selectors whose fallback is the current user but
        whose supplied value remains caller-controlled."""
        findings: list[Finding] = []
        for handler, _view_cls in _iter_handlers(tree):
            nested = _nested_scope_ids(handler)
            parents = {
                id(child): parent
                for parent in ast.walk(handler)
                for child in ast.iter_child_nodes(parent)
            }
            for call in ast.walk(handler):
                if (
                    id(call) in nested
                    or not isinstance(call, ast.Call)
                    or not _principal_override_source(call, principal_names)
                ):
                    continue
                value_name: str | None = None
                for node in ast.walk(handler):
                    if (
                        isinstance(node, ast.Assign)
                        and node.value is call
                        and len(node.targets) == 1
                        and isinstance(node.targets[0], ast.Name)
                    ):
                        value_name = node.targets[0].id
                        break

                use_line = call.lineno
                if value_name is not None:
                    guard_test_ids = {
                        id(part)
                        for stmt in ast.walk(handler)
                        if isinstance(stmt, ast.If)
                        and _is_principal_mismatch_guard(stmt, value_name, principal_names)
                        for part in ast.walk(stmt.test)
                    }
                    uses = [
                        node.lineno
                        for node in ast.walk(handler)
                        if isinstance(node, (ast.Call, ast.Return))
                        and id(node) not in guard_test_ids
                        and getattr(node, "lineno", 0) > call.lineno
                        and any(
                            isinstance(part, ast.Name)
                            and isinstance(part.ctx, ast.Load)
                            and part.id == value_name
                            for part in ast.walk(node)
                        )
                    ]
                    if not uses:
                        continue
                    use_line = min(uses)
                    _, dominators = collect_dominating_candidates(handler.body, use_line)
                    if any(
                        _is_principal_mismatch_guard(stmt, value_name, principal_names)
                        for stmt in dominators
                    ):
                        continue
                else:
                    # Inline use must be nested in another expression/call;
                    # a discarded `request.args.get(...)` has no auth impact.
                    if not isinstance(parents.get(id(call)), (ast.Call, ast.Return)):
                        continue

                key = call.args[0].value
                findings.append(Finding(
                    rule_id=_PRINCIPAL_OVERRIDE_RULE_ID,
                    message=(
                        f"Handler '{handler.name}' lets the caller override the '{key}' "
                        "principal selector even though it defaults to the authenticated "
                        "user. Bind ownership to server-side identity or reject mismatches."
                    ),
                    severity=Severity.HIGH,
                    category=Category.AUTH,
                    file_path=str(py_file),
                    start_line=call.lineno,
                    end_line=getattr(call, "end_lineno", call.lineno),
                    start_column=call.col_offset,
                    confidence=AUTHZ_BOLA_HIGH,
                    cwe_ids=[639],
                    owasp_ids=["API1:2023", "A01:2021"],
                    engine="authz",
                    metadata={
                        "caller": handler.name,
                        "principal_parameter": key,
                        "use_line": use_line,
                        "remediation": (
                            "Use the authenticated principal directly; if an administrative "
                            "override is required, enforce an explicit role/policy check."
                        ),
                    },
                ))
        return findings

    def _scan_unscoped_collections(
        self, trees: list[tuple[Path, ast.AST]]
    ) -> list[Finding]:
        """Connect authenticated list/search handlers to local or imported
        collection queries that return owner-bearing rows without tenant scope."""
        risky: dict[tuple[Path, str], tuple[int, str]] = {}
        tree_by_file = {path.resolve(): tree for path, tree in trees}
        files = set(tree_by_file)
        owner_models = _owner_scoped_written_models(list(tree_by_file.values()))
        for path, tree in tree_by_file.items():
            for func in _iter_functions(tree):
                gap = _unscoped_collection_query(func, owner_models)
                if gap is not None:
                    risky[(path, func.name)] = gap

        findings: list[Finding] = []
        seen: set[tuple[Path, int, str]] = set()
        for path, tree in tree_by_file.items():
            for handler, _view_cls in _iter_handlers(tree):
                if not _handler_has_auth_gate(handler):
                    continue
                direct_gap = risky.get((path, handler.name))
                if direct_gap is not None:
                    sink_line, model = direct_gap
                    self._append_tenant_scope_finding(
                        findings, seen, path, handler, handler.name,
                        sink_line, model, sink_line,
                    )
                for call in (n for n in ast.walk(handler) if isinstance(n, ast.Call)):
                    if not isinstance(call.func, ast.Name):
                        continue
                    target_file = path
                    target_name = call.func.id
                    imported = _resolve_imported_function(
                        path, target_name, tree, files
                    )
                    if imported is not None:
                        target_file, target_name = imported
                    gap = risky.get((target_file, target_name))
                    if gap is None:
                        continue
                    sink_line, model = gap
                    self._append_tenant_scope_finding(
                        findings, seen, path, handler, target_name,
                        call.lineno, model, sink_line,
                    )
        return findings

    def _scan_unscoped_rag(
        self, trees: list[tuple[Path, ast.AST]]
    ) -> list[Finding]:
        """Report owner-scoped persisted records retrieved without ownership
        scope and then inserted into an LLM/RAG request in the same handler."""
        written = _owner_scoped_written_models([tree for _, tree in trees])
        findings: list[Finding] = []
        for path, tree in trees:
            for handler, _view_cls in _iter_handlers(tree):
                if not _handler_has_auth_gate(handler):
                    continue
                gap = _unscoped_rag_retrieval(handler, written)
                if gap is None:
                    continue
                llm_line, model, query_line = gap
                findings.append(Finding(
                    rule_id=_RAG_TENANT_SCOPE_RULE_ID,
                    message=(
                        f"Authenticated handler '{handler.name}' retrieves owner-scoped "
                        f"{model} records without an owner predicate and inserts them into "
                        "LLM/RAG context, allowing cross-tenant disclosure."
                    ),
                    severity=Severity.HIGH,
                    category=Category.AUTH,
                    file_path=str(path),
                    start_line=llm_line,
                    confidence=AUTHZ_BOLA_HIGH,
                    cwe_ids=[639],
                    owasp_ids=["API1:2023", "A01:2021"],
                    engine="authz",
                    metadata={
                        "caller": handler.name,
                        "model": model,
                        "query_line": query_line,
                        "llm_line": llm_line,
                        "missing_models": ["ownership"],
                        "remediation": (
                            "Bind the authenticated owner/tenant id in the retrieval query "
                            "before constructing LLM context."
                        ),
                    },
                ))
        return findings

    @staticmethod
    def _append_tenant_scope_finding(
        findings: list[Finding],
        seen: set[tuple[Path, int, str]],
        path: Path,
        handler: ast.FunctionDef | ast.AsyncFunctionDef,
        helper_name: str,
        line: int,
        model: str,
        sink_line: int,
    ) -> None:
        key = (path, line, helper_name)
        if key in seen:
            return
        seen.add(key)
        findings.append(Finding(
            rule_id=_TENANT_SCOPE_RULE_ID,
            message=(
                f"Authenticated handler '{handler.name}' reaches collection query "
                f"'{helper_name}' for {model} without an owner/tenant predicate. "
                "Bound SQL parameters prevent injection but do not isolate tenants."
            ),
            severity=Severity.HIGH,
            category=Category.AUTH,
            file_path=str(path),
            start_line=line,
            confidence=AUTHZ_BOLA_HIGH,
            cwe_ids=[639],
            owasp_ids=["API1:2023", "A01:2021"],
            engine="authz",
            metadata={
                "caller": handler.name,
                "model": model,
                "helper": helper_name,
                "sink_line": sink_line,
                "missing_models": ["ownership"],
                "remediation": (
                    "Fuse the authenticated owner/tenant id into the collection query "
                    "and pass it through every service helper."
                ),
            },
        ))

    def _gap_verdict(
        self,
        handler: ast.FunctionDef | ast.AsyncFunctionDef,
        view_cls: ast.ClassDef | None,
        call: ast.Call,
        helpers: dict[str, tuple[list[str], dict[str, set[str]]]],
        principal_gate_helpers: dict[str, tuple[list[str], str]],
        principal_names: set[str],
    ) -> tuple[Severity | None, float, str, list[str], list[str]]:
        """Decide whether a user-keyed read is a gap, and at what tier
        (#172, #173). Checks all four BOLARAY models; satisfying any one
        suppresses the finding entirely (`(None, 0.0, ..., [], [])`).
        Otherwise the tier depends on the strongest partial signal found: a
        dominating guard beats none of the models being satisfied at all
        (High); a route-level-only auth gate or a guard present-but-not-
        dominating downgrades to Medium. `partial` names the model(s) whose
        guard is present-but-not-dominating -- distinct from `missing`
        (models with no guard at all), since a Medium "guard exists but
        doesn't dominate" finding is still evidence that model's guard was
        found, just not proven sound.
        """
        if view_cls is not None and class_authz_gate(view_cls) == "object":
            return None, 0.0, "object_decorator", [], []
        if _has_dominating_principal_gate(
            handler, call.lineno, principal_gate_helpers, principal_names
        ):
            return None, 0.0, "privileged_principal_gate", [], []

        has_route_gate = bool(authorizing_decorators(handler)) or (
            view_cls is not None and class_authz_gate(view_cls) == "route"
        )

        obj_var: str | None = None
        use_line: int | None = None
        assign_line = 0
        assigned = _assigned_var_for_call(handler, call)
        if assigned is not None:
            obj_var, assign_line = assigned
            use_line = _first_escape_line(handler, obj_var, assign_line, principal_names, helpers)

        dominators: list[ast.stmt] = []
        if obj_var is not None and use_line is not None:
            _, dominators = collect_dominating_candidates(handler.body, use_line)
            # A guard written before this read checked an earlier binding of
            # obj_var, not this read's value (AZ-14).
            dominators = [d for d in dominators if d.lineno > assign_line]
        if view_cls is not None and _has_drf_object_permission_gate(
            handler, call.lineno, use_line, obj_var
        ):
            return None, 0.0, "object_permission_call", [], []

        ownership = _guard_state(
            handler, dominators, obj_var, use_line,
            lambda s: is_ownership_guard(s, obj_var, principal_names),
        )
        membership = _guard_state(
            handler, dominators, obj_var, use_line,
            lambda s: is_membership_check(s, obj_var, principal_names),
        )
        status = _guard_state(
            handler, dominators, obj_var, use_line, lambda s: is_status_gate(s, obj_var)
        )
        hierarchical = "ok" if is_hierarchical_parent_read(
            call, _authorized_parent_vars(handler, principal_names)
        ) else "absent"

        states = {
            "ownership": ownership,
            "membership": membership,
            "hierarchical": hierarchical,
            "status": status,
        }
        delegated = _delegated_guard_state(handler, dominators, obj_var, use_line, helpers)
        if any(v == "ok" for v in states.values()) or delegated == "ok":
            return None, 0.0, "authorized", [], []

        missing = sorted(m for m, v in states.items() if v == "absent")
        partial = sorted(
            [m for m, v in states.items() if v == "partial"]
            + (["delegated"] if delegated == "partial" else [])
        )
        if has_route_gate:
            return Severity.MEDIUM, AUTHZ_BOLA_MEDIUM, "route_decorator_only", missing, partial
        if partial:
            return Severity.MEDIUM, AUTHZ_BOLA_MEDIUM, "guard_not_dominating", missing, partial
        return Severity.HIGH, AUTHZ_BOLA_HIGH, "no_guard", missing, partial

    # -----------------------------------------------------------------------
    # AUTHZ-LLM-001 (#185): the guard is present, but the model decides it.
    # -----------------------------------------------------------------------

    def _scan_llm_authz(self, py_file: Path, tree: ast.AST) -> list[Finding]:
        """Every recognized ORM read in every function (not scoped to
        `_iter_handlers`'s route-decorator heuristic -- the flawed guard can
        just as well sit in a helper a handler calls, and unlike BOLA this
        rule isn't asking "does an entry point exist", it's asking "did the
        model make this decision"), gated by a permission-shaped `if` whose
        condition is built from an LLM completion or tool-call argument."""
        findings: list[Finding] = []
        for func in _iter_functions(tree):
            reads = _outermost_read_calls(func)
            if not reads:
                continue
            # Not gated on `derived` being non-empty: the guard test can be
            # LLM-derived directly (`tool_call.function.arguments.get(...)`
            # used inline, with no intermediate assignment) with no traced
            # local names at all. `_model_derived_names` only extends
            # coverage to variables assigned FROM such an expression.
            derived = _model_derived_names(func)
            nested = _nested_scope_ids(func)

            guard_kinds: dict[int, str] = {}
            allow_bodies: list[list[ast.stmt]] = []
            for node in ast.walk(func):
                if id(node) in nested or not isinstance(node, ast.If):
                    continue
                kind = model_derived_permission_guard_kind(node, derived)
                if kind is None:
                    continue
                guard_kinds[id(node)] = kind
                if kind == "allow":
                    allow_bodies.append(node.body)
            if not guard_kinds:
                continue

            for call in reads:
                if id(call) in nested:
                    continue
                _, dominators = collect_dominating_candidates(func.body, call.lineno)
                deny_hit = any(
                    isinstance(d, ast.If) and guard_kinds.get(id(d)) == "deny"
                    for d in dominators
                )
                allow_hit = not deny_hit and any(
                    _stmt_block_contains(body, call, nested) for body in allow_bodies
                )
                if deny_hit or allow_hit:
                    findings.append(
                        self._llm_authz_finding(py_file, func, call, "deny" if deny_hit else "allow")
                    )
        return findings

    def _llm_authz_finding(
        self, py_file: Path, func: ast.FunctionDef | ast.AsyncFunctionDef, call: ast.Call, kind: str
    ) -> Finding:
        model = read_model_class(call) or "object"
        shape = (
            "an early-return check that denies when the model's verdict is negative"
            if kind == "deny"
            else "a positive-branch check that proceeds only when the model's verdict is affirmative"
        )
        return Finding(
            rule_id=_LLM_AUTHZ_RULE_ID,
            message=(
                f"'{func.name}' reads {model} behind {shape}, but the check's own "
                "condition is derived from an LLM completion or tool-call argument -- "
                "the model decides whether access is allowed, not the server. Anything "
                "that can steer the model (a prompt injection in retrieved content, a "
                "poisoned tool description, a crafted user message) can force the "
                "allow path."
            ),
            severity=Severity.HIGH,
            category=Category.AUTH,
            file_path=str(py_file),
            start_line=call.lineno,
            end_line=getattr(call, "end_lineno", call.lineno),
            start_column=call.col_offset,
            confidence=AUTHZ_LLM_HIGH,
            cwe_ids=[863],
            owasp_ids=["API1:2023", "A01:2021"],
            engine="authz",
            metadata={
                "caller": func.name,
                "model": model,
                "guard_kind": kind,
                "remediation": _LLM_AUTHZ_REMEDIATION,
            },
        )


# ---------------------------------------------------------------------------
# AUTHZ-LLM-001 module-level helpers (#185).
# ---------------------------------------------------------------------------

_LLM_AUTHZ_RULE_ID = "AUTHZ-LLM-001"
_LLM_AUTHZ_REMEDIATION = (
    "Never let the model make the authorization decision. Verify the claimed "
    "identity or permission server-side against data the model cannot "
    "influence -- a database membership check, a policy-engine call "
    "(Casbin/OPA), or a comparison against the session principal -- and "
    "treat any model-supplied verdict as an untrusted claim, not a fact."
)


def _iter_functions(tree: ast.AST):
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            yield node


def _is_passthrough_value(value: ast.expr, derived: set[str]) -> bool:
    """True if `value` merely re-exposes an already-derived name: a bare
    alias, an attribute/subscript access on one (`decision['allowed']`,
    `data.owner`), or a call whose receiver or an argument is derived
    (`json.loads(completion_text)`, `response.json()`). Provenance-preserving
    on purpose -- parsing or indexing into a model-derived payload doesn't
    make the result any more trustworthy than the payload itself."""
    if isinstance(value, ast.Name):
        return value.id in derived
    if isinstance(value, (ast.Attribute, ast.Subscript)):
        return _is_passthrough_value(value.value, derived)
    if isinstance(value, ast.Call):
        if any(_is_passthrough_value(a, derived) for a in value.args):
            return True
        if isinstance(value.func, ast.Attribute):
            return _is_passthrough_value(value.func.value, derived)
    return False


def _model_derived_names(func: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    """Local variable names in `func` traced back to an LLM completion or
    tool-call argument, directly or through one or more hops of parsing/
    repackaging. Mirrors `_derived_local_names`'s one-hop-at-a-time fixed
    point, seeded by LLM-shaped expressions instead of a fixed `obj_var`.
    Function *parameters* that are themselves LLM-derived (`def
    handler(tool_call):`, used inline as `tool_call.function.arguments`
    without an intermediate assignment) don't need to appear here --
    `references_model_derived_name` checks the guard test itself for that
    shape directly."""
    nested = _nested_scope_ids(func)
    derived: set[str] = set()
    while True:
        changed = False
        for node in ast.walk(func):
            if id(node) in nested:
                continue
            if isinstance(node, ast.Assign):
                targets = _plain_target_names(node.targets)
                value = node.value
            elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
                targets = {node.target.id}
                value = node.value
            else:
                continue
            if not targets or value is None:
                continue
            if not (is_llm_derived_expr(value) or _is_passthrough_value(value, derived)):
                continue
            new = targets - derived
            if new:
                derived |= new
                changed = True
        if not changed:
            return derived


def _stmt_block_contains(stmts: list[ast.stmt], target: ast.AST, nested: set[int]) -> bool:
    """True if `target` is a descendant of any statement in `stmts`, ignoring
    nodes that belong to a nested function/lambda scope."""
    target_id = id(target)
    for stmt in stmts:
        for node in ast.walk(stmt):
            if id(node) in nested:
                continue
            if id(node) == target_id:
                return True
    return False
