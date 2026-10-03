"""Object-level authorization predicate recognition (BOLA/IDOR detection).

This module recognizes the authorization *predicates* whose absence constitutes a
Broken Object Level Authorization (BOLA) / Insecure Direct Object Reference
(IDOR) vulnerability. It is the recognizer half of `AuthzPass`; the pass drives
extraction and the gap decision (see `rowan/passes/authz.py` and ADR-0003).

Phase 1 (issue #171) implements the **ownership** model in its highest-precision
form only -- *query-fused* ownership, where the object read binds an owner column
to the current principal in the read call itself:

    Document.objects.get(id=pk, owner=request.user)          # fused -> safe
    Document.objects.filter(owner=request.user).first()      # fused -> safe
    get_object_or_404(Document, id=pk, owner=request.user)   # fused -> safe

Phase 2 (issue #172) adds the **fetch-then-guard** shape, where the object is
read first and an ownership check gates its later use:

    obj = Document.objects.get(id=pk)           # user-keyed read
    if obj.owner_id != request.user.id:          # ownership guard...
        raise PermissionDenied                   # ...that must dominate the use
    return obj.render()

`is_ownership_guard` recognizes the guard statement itself (the `if`); whether
it actually *dominates* the use is a control-flow question answered by
`AuthzPass` via `collect_dominating_candidates`, not by this module.

Phase 3 (issue #173) completes BOLARAY's four-model taxonomy:
`is_membership_check` (the principal belongs to the object's group/tenant/org),
`is_status_gate` (a state gate constrains which object states are reachable),
and `is_hierarchical_parent_read` (the child is fetched through an already-
authorized parent, so no guard statement is involved at all). It also adds
`authorizing_decorators`/`class_authz_gate` for function- and class-level
authorization: an object-level gate (DRF `has_object_permission` /
`permission_classes=[IsOwner]`) suppresses; a route-level-only gate
(`@login_required`, `PermissionRequiredMixin`) authenticates but doesn't scope
to an object, so it downgrades rather than suppresses.

Scope: object-level authz in recognized Django/DRF/SQLAlchemy ORM idioms only.
It does not model function-level authz, custom raw-SQL data-access layers, or
authorization enforced in a service this pass cannot see.
"""

from __future__ import annotations

import ast
import re
from collections.abc import Collection

from rowan.analysis.orm_reads import is_pascal_case, orm_read_class
from rowan.analysis.request_sources import dotted_name, expr_reads_source
from rowan.core.llm_sources import is_llm_derived_text

# ---------------------------------------------------------------------------
# Principal ("current user") recognition.
# ---------------------------------------------------------------------------

#: Dotted expression bases that denote the authenticated principal. A node is a
#: principal expression if its dotted name equals one of these or is an attribute
#: access on one (`request.user`, `request.user.id`, `current_user.id`).
_PRINCIPAL_BASES: tuple[str, ...] = (
    "request.user",
    "self.request.user",
    "current_user",
    "self.current_user",
    "g.user",
    # A minimal Flask idiom distinct from `g.user`: the authenticated user's
    # bare integer id stashed directly on `g` by request-scoped auth (no
    # `g.user` object at all) -- e.g. `g.user_id = int(claims["sub"])` in an
    # auth decorator, then compared straight against an owner_id column.
    "g.user_id",
    "g.account_id",
    "g.tenant_id",
    "flask_login.current_user",
)

_SESSION_PRINCIPAL_KEYS: frozenset[str] = frozenset(
    {"user_id", "uid", "user", "account_id"}
)


def is_principal_expr(node: ast.AST, extra: Collection[str] = ()) -> bool:
    """True if `node` reads the authenticated principal (or an attribute of it).

    `extra` carries locally-resolved principal aliases -- names that provably
    hold the principal in the enclosing handler even though they are not one of
    the framework-canonical `_PRINCIPAL_BASES`. See
    `rowan.passes.authz.handler_principal_aliases` for how they are
    derived (decorator kwargs injection, FastAPI `Depends`, local assignment).
    """
    if isinstance(node, ast.Subscript):
        base = dotted_name(node.value)
        key = node.slice.value if isinstance(node.slice, ast.Constant) else None
        if base in {"session", "flask.session", "request.session"} and key in _SESSION_PRINCIPAL_KEYS:
            return True
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        if node.func.attr in {"get_id", "get_user_id"} and is_principal_expr(
            node.func.value, extra
        ):
            return True
        if node.func.attr == "get" and node.args:
            base = dotted_name(node.func.value)
            key = node.args[0].value if isinstance(node.args[0], ast.Constant) else None
            if base in {"session", "flask.session", "request.session"} and key in _SESSION_PRINCIPAL_KEYS:
                return True
    dotted = dotted_name(node)
    if not dotted:
        return False
    for base in _PRINCIPAL_BASES:
        if dotted == base or dotted.startswith(base + "."):
            return True
    return any(dotted == name or dotted.startswith(name + ".") for name in extra)


def principal_expressions(tree: ast.AST) -> set[str]:
    """Every distinct principal expression (dotted form) read anywhere in `tree`.

    A non-empty result is the signal that the codebase *has* a notion of the
    current user -- the precondition for calling a missing ownership check a
    BOLA rather than a (different) missing-authentication issue.
    """
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Attribute, ast.Name, ast.Subscript, ast.Call)) and is_principal_expr(node):
            found.add(dotted_name(node) or ast.unparse(node))
    return found


# ---------------------------------------------------------------------------
# Ownership predicate recognition.
# ---------------------------------------------------------------------------

#: Keyword-argument names that bind a row to its owning principal. A read that
#: constrains one of these to a principal expression is ownership-authorized.
OWNER_KEYWORDS: frozenset[str] = frozenset({
    "owner", "owner_id", "user", "user_id", "author", "author_id",
    "created_by", "account", "account_id", "member", "member_id",
    "customer", "customer_id", "tenant", "tenant_id",
})

# Backward-compatible private alias for the predicate implementations below.
_OWNER_KEYWORDS = OWNER_KEYWORDS


def is_ownership_key(name: str) -> bool:
    """Whether a parameter/column name identifies an owning principal."""
    return name.lower() in OWNER_KEYWORDS

#: Django/DRF object-fetch shortcuts that read a single row (or 404).
_GET_OR_404_NAMES: frozenset[str] = frozenset({"get_object_or_404", "get_list_or_404"})


def _call_chain(call: ast.Call):
    """Yield each ast.Call in a `a.b(...).c(...)` chain, outermost first."""
    node: ast.AST = call
    while isinstance(node, ast.Call):
        yield node
        node = node.func
        if isinstance(node, ast.Attribute):
            node = node.value


def _names_in(expr: ast.AST) -> set[str]:
    return {n.id for n in ast.walk(expr) if isinstance(n, ast.Name)}


def read_model_class(call: ast.Call) -> str | None:
    """The ORM model class this call reads a row from, or None if it is not a
    recognized object read. Extends the shared `orm_read_class` DAL inference
    with Django's `get_object_or_404(Model, ...)` / `get_list_or_404` shortcuts.
    """
    cls = orm_read_class(call)
    if cls is not None:
        return cls

    func = call.func
    name = func.id if isinstance(func, ast.Name) else (
        func.attr if isinstance(func, ast.Attribute) else None
    )
    if name in _GET_OR_404_NAMES and call.args:
        first = call.args[0]
        if isinstance(first, ast.Name) and is_pascal_case(first.id):
            return first.id
        # get_object_or_404(Model.objects, id=pk) / (Model.objects.filter(...), ...)
        node: ast.AST = first
        while isinstance(node, ast.Attribute):
            if (
                node.attr == "objects"
                and isinstance(node.value, ast.Name)
                and is_pascal_case(node.value.id)
            ):
                return node.value.id
            node = node.value
    return None


def _is_model_column_attr(expr: ast.expr, keywords: frozenset[str]) -> bool:
    """True if `expr` is a model-class column reference in a SQLAlchemy
    `.filter(...)` compare -- `Item.owner_id`, `Item.owner.id`."""
    dotted = dotted_name(expr)
    if not dotted:
        return False
    parts = dotted.split(".")
    if len(parts) < 2 or not is_pascal_case(parts[0]):
        return False
    if parts[-1] in keywords:
        return True
    return len(parts) >= 3 and parts[-2] in keywords and parts[-1] in {"id", "pk"}


def _filter_binds_column(
    call: ast.Call, keywords: frozenset[str], value_pred
) -> bool:
    """SQLAlchemy positional-filter form of a fused predicate:
    `.filter(Item.owner_id == current_user.id)`. Keyword queries are handled
    separately; this covers the session-query idiom FastAPI code commonly
    uses, where the predicate is a positional `Compare`."""
    if not (isinstance(call.func, ast.Attribute) and call.func.attr == "filter"):
        return False
    for arg in call.args:
        if not (
            isinstance(arg, ast.Compare)
            and len(arg.ops) == 1
            and isinstance(arg.ops[0], ast.Eq)
            and len(arg.comparators) == 1
        ):
            continue
        left, right = arg.left, arg.comparators[0]
        if (_is_model_column_attr(left, keywords) and value_pred(right)) or (
            _is_model_column_attr(right, keywords) and value_pred(left)
        ):
            return True
    return False


def is_ownership_fused_read(call: ast.Call, extra_principals: Collection[str] = ()) -> bool:
    """True if any call in `call`'s chain binds an owner column to the current
    principal -- e.g. `.get(id=pk, owner=request.user)` or
    `.filter(owner_id=current_user.id)`. This is the query-fused ownership model.

    `extra_principals` lets a handler-local alias count as the principal, so
    `Service.query(id=ds_id, tenant_id=tenant_id)` is recognized when
    `tenant_id` was injected by an auth decorator rather than read from
    `current_user` inline.
    """
    def _is_principal(node: ast.AST) -> bool:
        return is_principal_expr(node, extra_principals)

    for c in _call_chain(call):
        for kw in c.keywords:
            if kw.arg in _OWNER_KEYWORDS and _is_principal(kw.value):
                return True
        if _filter_binds_column(c, _OWNER_KEYWORDS, _is_principal):
            return True
    return False


def is_user_keyed_read(call: ast.Call, user_controlled_names: set[str]) -> bool:
    """True if the object read is keyed by an attacker-controlled value: any
    argument in the call chain that reads a request source directly
    (`request.GET["id"]`) or references a user-controlled name (a route/path
    parameter of the enclosing handler, passed in via `user_controlled_names`).
    """
    for c in _call_chain(call):
        for arg in [*c.args, *(kw.value for kw in c.keywords)]:
            if expr_reads_source(arg):
                return True
            if _names_in(arg) & user_controlled_names:
                return True
    return False


# ---------------------------------------------------------------------------
# Fetch-then-guard ownership recognition (#172).
# ---------------------------------------------------------------------------

#: Exception class names whose raise is unambiguously an authorization deny,
#: regardless of framework.
_DENY_EXCEPTION_NAMES: frozenset[str] = frozenset({
    "PermissionDenied", "HTTPException", "Forbidden", "PermissionError",
})


def _call_name(call: ast.Call) -> str | None:
    func = call.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return None


def _has_403_signal(call: ast.Call) -> bool:
    """True if `call` carries an explicit 403/401 status somewhere in its
    arguments -- `abort(403)`, `Response(status=403)`,
    `JsonResponse(..., status=403)`, `status_code=status.HTTP_403_FORBIDDEN`."""
    for kw in call.keywords:
        if kw.arg not in {"status", "status_code"}:
            continue
        v = kw.value
        if isinstance(v, ast.Constant) and v.value in (401, 403):
            return True
        dotted = dotted_name(v)
        if dotted and dotted.rsplit(".", 1)[-1] in {
            "HTTP_403_FORBIDDEN", "HTTP_401_UNAUTHORIZED",
        }:
            return True
    if call.args:
        a0 = call.args[0]
        if isinstance(a0, ast.Constant) and a0.value in (401, 403):
            return True
    return False


def _is_deny_call(call: ast.Call) -> bool:
    name = _call_name(call)
    if name in _DENY_EXCEPTION_NAMES:
        return True
    if name in {"HttpResponseForbidden", "Http404"}:
        return True
    return _has_403_signal(call)


def _is_deny_stmt(stmt: ast.stmt) -> bool:
    """True if `stmt` halts the current branch in a way consistent with an
    authorization denial: raising, returning (bare, a call, or Flask's
    `return response_call, status_code` tuple idiom), or a bare `abort(...)`
    expression statement. The comparison that gates this statement (an
    ownership mismatch) already does the narrowing; this only needs to
    confirm the branch doesn't fall through to normal use.
    """
    if isinstance(stmt, ast.Raise):
        return True
    if isinstance(stmt, ast.Return):
        if stmt.value is None or isinstance(stmt.value, ast.Call) or (
            isinstance(stmt.value, ast.Constant) and (stmt.value.value is None or stmt.value.value is False)
        ):
            return True
        return isinstance(stmt.value, ast.Tuple) and any(
            isinstance(elt, ast.Call) or (isinstance(elt, ast.Constant) and elt.value in {401, 403, 404})
            for elt in stmt.value.elts
        )
    if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
        return _call_name(stmt.value) == "abort"
    return False


def _is_owner_attr_of(expr: ast.expr, obj_var: str) -> bool:
    """True if `expr` is an owner-ish attribute access on `obj_var`:
    `obj.owner`, `obj.owner_id`, or a two-level chain like `obj.owner.id`."""
    if (
        isinstance(expr, ast.Call)
        and isinstance(expr.func, ast.Name)
        and expr.func.id in {"str", "int", "UUID"}
        and len(expr.args) == 1
    ):
        expr = expr.args[0]
    dotted = dotted_name(expr)
    if not dotted or not dotted.startswith(obj_var + "."):
        return False
    rest = dotted[len(obj_var) + 1:]
    if rest in _OWNER_KEYWORDS:
        return True
    base, _, tail = rest.rpartition(".")
    return bool(base) and base in _OWNER_KEYWORDS and tail in {"id", "pk"}


def _principal_matches(expr: ast.expr, principal_names: set[str]) -> bool:
    if (
        isinstance(expr, ast.Call)
        and isinstance(expr.func, ast.Name)
        and expr.func.id in {"str", "int", "UUID"}
        and len(expr.args) == 1
    ):
        expr = expr.args[0]
    if is_principal_expr(expr, principal_names):
        return True
    dotted = dotted_name(expr)
    return bool(dotted) and dotted in principal_names


def _ownership_compare(
    cmp: ast.Compare, obj_var: str, principal_names: set[str]
) -> str | None:
    """Classify `cmp` as an ownership comparison between `obj_var`'s owner
    attribute and the current principal. Returns "ne" for `obj.owner !=
    principal` (the guard's body must deny), "eq" for `obj.owner == principal`
    (the guard's else must deny), or None if `cmp` isn't an ownership compare.
    """
    if len(cmp.ops) != 1 or len(cmp.comparators) != 1:
        return None
    op = cmp.ops[0]
    if not isinstance(op, (ast.NotEq, ast.Eq)):
        return None
    for a, b in ((cmp.left, cmp.comparators[0]), (cmp.comparators[0], cmp.left)):
        if _is_owner_attr_of(a, obj_var) and _principal_matches(b, principal_names):
            return "ne" if isinstance(op, ast.NotEq) else "eq"
    return None


_ID_ATTRS = frozenset({"id", "pk", "uuid", "slug"})


def _returns_var(stmt: ast.stmt, obj_var: str) -> bool:
    """True if `stmt` is a `return` whose value uses `obj_var`: a deny branch
    that hands back the protected object guards nothing (AZ-15). Its id
    alone (`redirect(..., pk=obj.pk)`) is not the object."""
    if not isinstance(stmt, ast.Return) or stmt.value is None:
        return False
    id_reads = {
        id(n.value) for n in ast.walk(stmt.value)
        if isinstance(n, ast.Attribute) and n.attr in _ID_ATTRS
    }
    return any(
        isinstance(n, ast.Name) and n.id == obj_var and id(n) not in id_reads
        for n in ast.walk(stmt.value)
    )


def _guard_denies_unless(stmt: ast.If, kind: str | None, obj_var: str) -> bool:
    """Shared guard-shape check for all four models: `kind` is "ne" (the test
    asserts the *negation* of the authorizing fact, so the `if` body must
    deny -- `if obj.owner_id != request.user.id: raise ...`) or "eq" (the
    test asserts the fact itself, so the `else` must deny -- `if
    obj.owner_id == request.user.id: ... else: abort(403)`). None means the
    test didn't match the predicate's shape at all.
    """
    if kind is None:
        return False
    branch = stmt.body if kind == "ne" else stmt.orelse
    if any(_returns_var(s, obj_var) for s in branch):
        return False
    return any(_is_deny_stmt(s) for s in branch)


def _unwrap_not(test: ast.expr) -> tuple[ast.expr, bool]:
    if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
        return test.operand, True
    return test, False


def is_existence_check(test: ast.expr, obj_var: str) -> bool:
    """True if `test` is a bare existence/null check on `obj_var` alone --
    `not obj`, `obj`, `obj is None` -- as opposed to an attribute access.
    Shared by two consumers: `passes/authz.py` excludes this shape when
    searching for `obj_var`'s first real *use* (the near-universal `obj =
    fetch(); if not obj: return 404` idiom must never count as a use), and
    `_effective_guard_test` below strips it as the short-circuit half of a
    combined `if not obj or obj.owner != principal: deny()` guard.
    """
    if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
        return isinstance(test.operand, ast.Name) and test.operand.id == obj_var
    if isinstance(test, ast.Name):
        return test.id == obj_var
    if isinstance(test, ast.Compare) and len(test.ops) == 1 and len(test.comparators) == 1:
        if isinstance(test.ops[0], (ast.Is, ast.IsNot)):
            for a, b in ((test.left, test.comparators[0]), (test.comparators[0], test.left)):
                if (
                    isinstance(a, ast.Name) and a.id == obj_var
                    and isinstance(b, ast.Constant) and b.value is None
                ):
                    return True
    return False


def _effective_guard_test(test: ast.expr, obj_var: str) -> ast.expr:
    """Strip a leading existence-check disjunct from a combined `if not obj
    or <real check>:` test, returning `<real check>` alone. The
    near-universal `if not obj or obj.owner_id != principal: deny()` idiom
    fuses the null guard and the authz guard into one `BoolOp(Or, ...)`,
    which would otherwise hide the authz compare (a plain `ast.Compare`, not
    a `BoolOp`) from every guard recognizer below -- falsely treating a
    correctly-guarded handler as unguarded."""
    if isinstance(test, ast.BoolOp) and isinstance(test.op, ast.Or) and len(test.values) >= 2:
        non_existence = [v for v in test.values if not is_existence_check(v, obj_var)]
        if len(non_existence) == 1:
            return non_existence[0]
    return test


def is_ownership_guard(stmt: ast.stmt, obj_var: str, principal_names: set[str]) -> bool:
    """True if `stmt` is an `if` that denies access unless `obj_var`'s owner
    attribute matches the current principal -- `if obj.owner_id !=
    request.user.id: raise PermissionDenied` and its `==`/early-return-in-else
    inversion (`if obj.owner_id == request.user.id: ... else: abort(403)`),
    either shape with the condition wrapped in `not (...)`, or combined with
    a leading existence check (`if not obj or obj.owner_id != principal:`).
    """
    if not isinstance(stmt, ast.If):
        return False
    test, inverted = _unwrap_not(_effective_guard_test(stmt.test, obj_var))
    if not isinstance(test, ast.Compare):
        return False
    kind = _ownership_compare(test, obj_var, principal_names)
    if kind is not None and inverted:
        kind = "eq" if kind == "ne" else "ne"
    return _guard_denies_unless(stmt, kind, obj_var)


# ---------------------------------------------------------------------------
# Membership predicate recognition (#173): the current user belongs to the
# object's group / tenant / organization.
# ---------------------------------------------------------------------------


def _references_obj_var(expr: ast.expr, obj_var: str) -> bool:
    dotted = dotted_name(expr)
    return bool(dotted) and (dotted == obj_var or dotted.startswith(obj_var + "."))


def _is_model_attr(expr: ast.expr) -> bool:
    dotted = dotted_name(expr)
    if not dotted:
        return False
    parts = dotted.split(".")
    return len(parts) >= 2 and is_pascal_case(parts[0])


def _positional_filter_has(call: ast.Call, value_pred) -> bool:
    """True if a SQLAlchemy `.filter(...)` call in `call`'s chain has a
    positional `Model.col == <value>` compare whose non-model side satisfies
    `value_pred` -- used for membership queries, where the column names vary
    by schema (`org_id`, `team_id`, `account_id`, ...)."""
    for c in _call_chain(call):
        if not (isinstance(c.func, ast.Attribute) and c.func.attr == "filter"):
            continue
        for arg in c.args:
            if not (
                isinstance(arg, ast.Compare)
                and len(arg.ops) == 1
                and isinstance(arg.ops[0], ast.Eq)
                and len(arg.comparators) == 1
            ):
                continue
            left, right = arg.left, arg.comparators[0]
            if (_is_model_attr(left) and value_pred(right)) or (
                _is_model_attr(right) and value_pred(left)
            ):
                return True
    return False


def _is_sqlalchemy_membership_query(
    call: ast.Call, obj_var: str, principal_names: set[str]
) -> bool:
    """`db.query(Membership).filter(Membership.org_id == obj.org_id,
    Membership.user_id == current_user.id).first()` -- a positional SQLAlchemy
    membership query tying both the object and the principal into one lookup."""
    return _positional_filter_has(call, lambda e: _principal_matches(e, principal_names)) and (
        _positional_filter_has(call, lambda e: _references_obj_var(e, obj_var))
    )


def _is_membership_query_call(
    call: ast.Call, obj_var: str, principal_names: set[str]
) -> bool:
    """`Membership.objects.filter(org=obj.org, user=request.user).exists()` --
    a `.filter(...).exists()` call whose kwargs include both a principal
    expression and an attribute chain rooted at `obj_var`."""
    if not (isinstance(call.func, ast.Attribute) and call.func.attr == "exists"):
        return False
    inner = call.func.value
    if not (
        isinstance(inner, ast.Call)
        and isinstance(inner.func, ast.Attribute)
        and inner.func.attr == "filter"
    ):
        return False
    has_principal = any(_principal_matches(kw.value, principal_names) for kw in inner.keywords)
    has_obj_ref = any(_references_obj_var(kw.value, obj_var) for kw in inner.keywords)
    return has_principal and has_obj_ref


def _membership_assertion(
    expr: ast.expr, obj_var: str, principal_names: set[str]
) -> str | None:
    """Classify `expr` as an assertion that the principal is a member with
    respect to `obj_var`. Returns "eq" (asserted -- true means a member),
    "ne" (negated -- true means NOT a member, so the body must deny), or None.
    """
    node, negated = _unwrap_not(expr)
    kind: str | None = None
    if isinstance(node, ast.Compare) and len(node.ops) == 1 and len(node.comparators) == 1:
        op = node.ops[0]
        if isinstance(op, (ast.In, ast.NotIn)):
            left, right = node.left, node.comparators[0]
            if _principal_matches(left, principal_names) and _references_obj_var(right, obj_var):
                kind = "ne" if isinstance(op, ast.NotIn) else "eq"
    elif isinstance(node, ast.Call) and (
        _is_membership_query_call(node, obj_var, principal_names)
        or _is_sqlalchemy_membership_query(node, obj_var, principal_names)
    ):
        kind = "eq"
    if kind is None:
        return None
    if negated:
        kind = "eq" if kind == "ne" else "ne"
    return kind


def is_membership_check(stmt: ast.stmt, obj_var: str, principal_names: set[str]) -> bool:
    """True if `stmt` is an `if` that denies access unless the principal is a
    member of `obj_var`'s group/tenant/org -- `if request.user not in
    obj.team.members: abort(403)`, or a `Membership.objects.filter(org=obj.org,
    user=request.user).exists()` check with the standard `not .../else-deny`
    guard shapes."""
    if not isinstance(stmt, ast.If):
        return False
    kind = _membership_assertion(_effective_guard_test(stmt.test, obj_var), obj_var, principal_names)
    return _guard_denies_unless(stmt, kind, obj_var)


# ---------------------------------------------------------------------------
# Status predicate recognition (#173): a state gate constrains which object
# states are reachable.
# ---------------------------------------------------------------------------

#: Attribute names that denote a state/visibility gate on an object.
_STATUS_KEYWORDS: frozenset[str] = frozenset({
    "status", "state", "is_active", "active", "is_published", "published",
    "is_deleted", "deleted", "is_public", "visibility",
})


def _is_state_literal(expr: ast.expr) -> bool:
    """A literal state value: a constant, or an enum/constants-class member
    (`Status.PUBLISHED`). `request.args` or `self.x` is an attribute too, but
    not a fixed state (AZ-17)."""
    if isinstance(expr, ast.Constant):
        return True
    if not isinstance(expr, ast.Attribute) or expr_reads_source(expr):
        return False
    # An enum member (`Status.PUBLISHED`, `models.Status.X`) or a named
    # constant (`self.PUBLISHED`, `settings.DEFAULT_STATE`).
    parts = (dotted_name(expr) or "").split(".")
    return any(is_pascal_case(part) for part in parts[:-1]) or (
        len(parts) > 1 and parts[-1].isupper()
    )


def is_status_fused_read(call: ast.Call) -> bool:
    """True if any call in `call`'s chain constrains a status/state column to
    a literal value -- e.g. `.get(id=pk, status="published")` or
    `.filter(is_active=True)`. This is the query-fused status model."""
    for c in _call_chain(call):
        for kw in c.keywords:
            if kw.arg in _STATUS_KEYWORDS and _is_state_literal(kw.value):
                return True
        if _filter_binds_column(c, _STATUS_KEYWORDS, _is_state_literal):
            return True
    return False


def _is_status_attr_of(expr: ast.expr, obj_var: str) -> bool:
    dotted = dotted_name(expr)
    if not dotted or not dotted.startswith(obj_var + "."):
        return False
    return dotted[len(obj_var) + 1:] in _STATUS_KEYWORDS


def _status_assertion(expr: ast.expr, obj_var: str) -> str | None:
    """Classify `expr` as a status-gate assertion on `obj_var` -- `obj.status
    == "published"` (asserted) or `obj.status != "published"` (negated),
    matched in either operand order."""
    node, negated = _unwrap_not(expr)
    if not (isinstance(node, ast.Compare) and len(node.ops) == 1 and len(node.comparators) == 1):
        return None
    op = node.ops[0]
    if not isinstance(op, (ast.Eq, ast.NotEq)):
        return None
    kind: str | None = None
    for a, b in ((node.left, node.comparators[0]), (node.comparators[0], node.left)):
        if _is_status_attr_of(a, obj_var) and isinstance(b, ast.Constant):
            kind = "ne" if isinstance(op, ast.NotEq) else "eq"
            break
    if kind is None:
        return None
    if negated:
        kind = "eq" if kind == "ne" else "ne"
    return kind


def is_status_gate(stmt: ast.stmt, obj_var: str) -> bool:
    """True if `stmt` is an `if` that denies access unless `obj_var`'s state
    matches the reachable value -- `if obj.status != "published": abort(404)`,
    or its `==`/else-deny inversion."""
    if not isinstance(stmt, ast.If):
        return False
    kind = _status_assertion(_effective_guard_test(stmt.test, obj_var), obj_var)
    return _guard_denies_unless(stmt, kind, obj_var)


# ---------------------------------------------------------------------------
# Hierarchical predicate recognition (#173): a parent-object ownership check
# covers the child fetched through it.
# ---------------------------------------------------------------------------


def _kwarg_binds_to_parent(value: ast.expr, authorized_parent_vars: set[str]) -> bool:
    """True if an FK-fusing kwarg value is the authorized parent object
    itself (`project=project`) or its id/pk attribute (`project_id=project.id`,
    the more common Django/SQLAlchemy idiom -- the parent's own primary key,
    not the parent variable, is what actually gets bound to the FK column)."""
    if isinstance(value, ast.Name):
        return value.id in authorized_parent_vars
    if isinstance(value, ast.Attribute) and value.attr in {"id", "pk"}:
        return isinstance(value.value, ast.Name) and value.value.id in authorized_parent_vars
    return False


def ownership_fused_guard_ids(
    stmt: ast.If, extra_principals: Collection[str] = ()
) -> set[str]:
    """Object ids that `stmt` proves belong to the principal.

    Covers the guard-by-fused-query idiom, which is how service-layer codebases
    authorize a *parent* before touching its children::

        if not KnowledgebaseService.query(id=dataset_id, tenant_id=tenant_id):
            return error("You don't own the dataset.")
        docs = DocumentService.query(kb_id=dataset_id, id=doc_id)

    The fused read is never assigned, so `_authorized_parent_vars`' assignment
    shape does not see it -- but passing the guard establishes that
    `dataset_id` is the caller's, and every later read scoped to it inherits
    that. Returns the plain-`Name` id arguments of the fused read (the owner
    keyword itself is excluded -- that binds the principal, not the object).
    """
    test, negated = _unwrap_not(stmt.test)
    branch = stmt.body if negated else stmt.orelse
    if not branch or not any(_is_deny_stmt(s) for s in branch):
        return set()

    ids: set[str] = set()
    for node in ast.walk(test):
        if not isinstance(node, ast.Call) or not is_ownership_fused_read(node, extra_principals):
            continue
        for c in _call_chain(node):
            for kw in c.keywords:
                if kw.arg and kw.arg not in _OWNER_KEYWORDS and isinstance(kw.value, ast.Name):
                    ids.add(kw.value.id)
    return ids


def is_hierarchical_parent_read(call: ast.Call, authorized_parent_vars: set[str]) -> bool:
    """True if `call` reads the object through (or scoped to) a variable
    already known to hold an authorized parent object: either the call chain
    is rooted at such a variable (`project.tasks.get(id=task_id)`, a
    related-manager read) or a keyword argument in the chain binds to it or
    its id/pk (`Task.objects.get(id=task_id, project=project)` /
    `Task.query.filter_by(id=task_id, project_id=project.id)`, an FK-fused
    read). `authorized_parent_vars` is the caller's set of local variable
    names bound from an authorized parent read (e.g. ownership-fused).

    Note: the related-manager shape only matches here if the read was
    already recognized as an object read by `read_model_class` in the first
    place -- `orm_read_class` currently only infers a model class from a
    `.objects`/`.query` marker in the chain, so a read rooted at an arbitrary
    local variable (not a Model class) is invisible to extraction and never
    reaches this predicate at all. FK-fused reads (rooted at a Model class)
    are the shape this currently covers end-to-end.
    """
    for c in _call_chain(call):
        for kw in c.keywords:
            if _kwarg_binds_to_parent(kw.value, authorized_parent_vars):
                return True
        if isinstance(c.func, ast.Attribute) and c.func.attr == "filter":
            for arg in c.args:
                if isinstance(arg, ast.Compare) and len(arg.ops) == 1 and isinstance(arg.ops[0], ast.Eq):
                    left, right = arg.left, arg.comparators[0]
                    if (_is_model_attr(left) and _kwarg_binds_to_parent(right, authorized_parent_vars)) or (
                        _is_model_attr(right) and _kwarg_binds_to_parent(left, authorized_parent_vars)
                    ):
                        return True
    node: ast.AST = call
    while isinstance(node, ast.Call):
        node = node.func
        if isinstance(node, ast.Attribute):
            node = node.value
    return isinstance(node, ast.Name) and node.id in authorized_parent_vars


# ---------------------------------------------------------------------------
# Decorator / middleware gate recognition (#173).
# ---------------------------------------------------------------------------

#: Route-level auth decorators: they prove the request is authenticated (or
#: passes some function-level test), but say nothing about *which* object the
#: authenticated user may access -- an object-level check is still required.
_ROUTE_LEVEL_DECORATOR_TAILS: frozenset[str] = frozenset({
    "login_required", "permission_required", "user_passes_test",
    "requires_permission",
})

#: Class mixins with the same route-level-only meaning as the decorators above.
_ROUTE_LEVEL_MIXIN_TAILS: frozenset[str] = frozenset({
    "LoginRequiredMixin", "PermissionRequiredMixin",
})

#: Substrings that mark a DRF `permission_classes` entry as object-level
#: (checked against the class name, case-insensitively).
_OBJECT_PERMISSION_NAME_HINTS: tuple[str, ...] = ("owner", "object")


def authorizing_decorators(func: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    """The route-level auth decorator tails found on `func`
    (`login_required`, `permission_required`, `user_passes_test`,
    `requires_permission`) -- present but insufficient on their own for
    object-level authorization."""
    found: set[str] = set()
    for dec in func.decorator_list:
        target = dec.func if isinstance(dec, ast.Call) else dec
        dotted = dotted_name(target)
        if not dotted:
            continue
        tail = dotted.rsplit(".", 1)[-1]
        if tail in _ROUTE_LEVEL_DECORATOR_TAILS:
            found.add(tail)
    return found


def _permission_classes_grant_object_level(cls: ast.ClassDef) -> bool:
    for item in cls.body:
        if not (
            isinstance(item, ast.Assign)
            and any(isinstance(t, ast.Name) and t.id == "permission_classes" for t in item.targets)
            and isinstance(item.value, ast.List)
        ):
            continue
        for elt in item.value.elts:
            name = dotted_name(elt).rsplit(".", 1)[-1] if dotted_name(elt) else None
            if name and any(hint in name.lower() for hint in _OBJECT_PERMISSION_NAME_HINTS):
                return True
    return False


def class_authz_gate(cls: ast.ClassDef) -> str | None:
    """The authorization gate an enclosing class-based view provides:
    "object" (a DRF `permission_classes` entry naming an object-level
    permission, or a `has_object_permission` method defined on the class --
    suppresses an otherwise-unguarded object-level read), "route" (a
    `LoginRequiredMixin`/`PermissionRequiredMixin` base -- authenticates but
    doesn't scope to an object, downgrades rather than suppresses), or None.
    """
    if _permission_classes_grant_object_level(cls) or any(
        isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
        and item.name == "has_object_permission"
        for item in cls.body
    ):
        return "object"
    for base in cls.bases:
        tail = dotted_name(base).rsplit(".", 1)[-1]
        if tail in _ROUTE_LEVEL_MIXIN_TAILS:
            return "route"
    return None


# ---------------------------------------------------------------------------
# Model-derived authorization predicate recognition (issue #185).
#
# Inverts the question the rest of this module asks. Everywhere above:
# "is a required authorization check ABSENT?" Here: a check is PRESENT, but
# its decision was made by the model, not by the server -- so the check
# provides no real protection at all. A prompt injection in retrieved
# content, a poisoned tool description, or a crafted user message can steer
# the model to whatever verdict it wants.
#
#     verdict = client.chat.completions.create(...)
#     decision = json.loads(verdict.choices[0].message.content)
#     if decision["allowed"]:                    # <-- the gate is a model
#         return Document.objects.get(id=doc_id)  #     opinion, not a fact
# ---------------------------------------------------------------------------

#: Dotted-name tail / string-subscript-key tokens that read like an
#: authorization decision. Matched against the LAST component only (not an
#: arbitrary substring of the whole expression), so `user_role_display_name`
#: does not qualify merely for containing "role".
_PERMISSION_TOKEN_RE = re.compile(
    r"(?i)^(allowed|authorized|is_admin|has_access|access_granted"
    r"|can_[a-z_]+|permit(?:ted)?|granted|grant|role|access)$"
)


def _dotted_tail(expr: ast.expr) -> str | None:
    dotted = dotted_name(expr)
    return dotted.rsplit(".", 1)[-1] if dotted else None


def is_permission_shaped(expr: ast.expr) -> bool:
    """True if `expr` reads like an authorization decision: a dotted
    attribute/name whose last component matches `_PERMISSION_TOKEN_RE`
    (`decision.allowed`, `result.is_admin`), or a subscript with a string key
    of the same shape (`decision["allowed"]`, `data['role']`)."""
    if isinstance(expr, (ast.Attribute, ast.Name)):
        tail = _dotted_tail(expr)
        return bool(tail and _PERMISSION_TOKEN_RE.match(tail))
    if isinstance(expr, ast.Subscript):
        key = expr.slice
        if isinstance(key, ast.Constant) and isinstance(key.value, str):
            return bool(_PERMISSION_TOKEN_RE.match(key.value))
        # `decision[some_var]` -- the key isn't a literal, fall through to
        # checking the subscripted object itself (`decision["allowed"]` chains
        # through `.get("allowed")` too, handled by the Call branch below).
        return is_permission_shaped(expr.value)
    if isinstance(expr, ast.Call) and isinstance(expr.func, ast.Attribute) and expr.func.attr == "get":
        if expr.args and isinstance(expr.args[0], ast.Constant) and isinstance(expr.args[0].value, str):
            return bool(_PERMISSION_TOKEN_RE.match(expr.args[0].value))
    return False


def is_llm_derived_expr(expr: ast.expr) -> bool:
    """True if `expr` is itself an unambiguous LLM completion / tool-call
    shape (`resp.choices[0].message.content`, `tool_call.function.arguments`,
    `llm.invoke(...)`). Rendered via `ast.unparse` and matched against the
    same regex `enrichment.py`'s taint-origin classifier uses, so an
    AST expression and a taint-flow snippet cannot disagree about what counts
    as "from the model" -- see `core/llm_sources.py`."""
    try:
        text = ast.unparse(expr)
    except (ValueError, RecursionError):
        return False
    return is_llm_derived_text(text)


def references_model_derived_name(expr: ast.expr, model_derived_names: set[str]) -> bool:
    """True if `expr` reads (loads) any name in `model_derived_names` --
    variables the caller has already traced back to an LLM completion or
    tool-call argument (one or more hops of pure repackaging), or is itself
    an LLM-derived expression."""
    if is_llm_derived_expr(expr):
        return True
    return any(
        isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load) and n.id in model_derived_names
        for n in ast.walk(expr)
    )


def model_derived_permission_guard_kind(
    stmt: ast.If, model_derived_names: set[str]
) -> str | None:
    """Classify `stmt` as an authorization guard whose decision is
    model-derived: "deny" for the early-return/deny shape (`if not
    <model-derived permission test>: raise/return/abort`, where the
    inversion means the deny happens when the model said no), "allow" for
    the positive-branch shape (`if <model-derived permission test>:
    <proceeds>`, no inversion -- the guarded body is reached only when the
    model said yes), or None if `stmt` doesn't match either shape.

    Deliberately does NOT require `stmt.body` to deny in the "allow" case --
    unlike `is_ownership_guard`'s "eq" kind, a bare `if decision["allowed"]:`
    with no `else` is still a real (if weak) gate, and it is exactly the
    shape the motivating example uses. What DOES matter, and is the caller's
    job (`AuthzPass`), is confirming the object access is actually reached
    only through the guarded path -- contained in `stmt.body` for "allow",
    or dominated by `stmt` for "deny".
    """
    if not isinstance(stmt, ast.If):
        return None
    test, inverted = _unwrap_not(stmt.test)
    if not is_permission_shaped(test):
        return None
    if not references_model_derived_name(test, model_derived_names):
        return None
    if inverted:
        return "deny" if any(_is_deny_stmt(s) for s in stmt.body) else None
    return "allow"
