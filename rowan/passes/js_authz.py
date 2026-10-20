"""JavaScript/TypeScript object-level authorization (BOLA/IDOR) detection.

Optional, precision-first MVP for Express/Koa/Next.js handlers: a
Mongoose/Sequelize/Prisma model read (`Doc.findById(req.params.id)`,
`Doc.findByPk(...)`, `prisma.doc.findUnique({ where: { id: req.params.id } })`)
in an `app`/`router` route handler, a default-export Pages API handler, or a
named App Router export (`GET`/`POST`), with no structured owner guard before
the object escapes in a response (`res.json(...)`, `ctx.body = ...`,
`NextResponse.json(...)`). Mirrors `AuthzPass`'s stance: route auth middleware
downgrades, an object-level owner check suppresses, anything else is High.
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from rowan.core.confidence import AUTHZ_BOLA_HIGH, AUTHZ_BOLA_MEDIUM
from rowan.core.findings import Category, Finding, ScanResult, Severity
from rowan.passes.base import ScanContext, scan_span
from rowan.passes.file_scan import load_ignore_patterns
from rowan.passes.js_cross_file import (
    TREE_SITTER_AVAILABLE,
    _collect_js_files,
    _collect_pattern_identifiers,
    _get_parsers,
    _node_text,
    _params_of,
    _walk_all,
)

_RULE_ID = "AUTHZ-BOLA-001"
_REMEDIATION = (
    "Scope the read to the current principal (e.g. add ownerId: req.user.id to "
    "the query) or add a dominating owner check before the object is returned."
)
_EXPRESS_METHODS = {"get", "post", "put", "patch", "delete", "all"}
_EXPRESS_OBJECTS = {"app", "router", "api", "server"}
_READ_METHODS = {
    "findbyid", "findone", "findoneandupdate", "findoneanddelete",
    "findbyidandupdate", "findbyidanddelete", "findbyidandremove",
    "findbypk", "findunique", "findfirst",
}
_PRISMA_WRITE_METHODS = {"update", "delete"}
_NEXT_RESPONSE_OBJECTS = {"NextResponse", "Response"}
_HTTP_METHOD_EXPORTS = {"GET", "POST", "PUT", "PATCH", "DELETE"}
_RESPONSE_METHODS = {"json", "send", "render"}
_OWNER_HINTS = ("owner", "user", "tenant", "account", "org")


def _member_parts(node: Any, source: bytes) -> tuple[str, str] | None:
    if node.type != "member_expression":
        return None
    obj = node.child_by_field_name("object")
    prop = node.child_by_field_name("property")
    if obj is None or prop is None:
        return None
    return _node_text(obj, source), _node_text(prop, source)


def _unwrap_expr(node: Any | None) -> Any | None:
    while node is not None and node.type in {
        "parenthesized_expression", "as_expression", "satisfies_expression", "non_null_expression",
    }:
        node = next((c for c in node.children if c.is_named), None)
    return node


def _dotted(node: Any | None, source: bytes) -> str | None:
    node = _unwrap_expr(node)
    if node is not None and node.type == "call_expression":
        func = node.child_by_field_name("function")
        if func is not None and func.type == "member_expression":
            prop = func.child_by_field_name("property")
            args = node.child_by_field_name("arguments")
            named_args = [c for c in args.children if c.is_named] if args is not None else []
            if (
                prop is not None
                and _node_text(prop, source) in {"toString", "valueOf"}
                and not named_args
            ):
                node = _unwrap_expr(func.child_by_field_name("object"))
        if (
            func is not None
            and func.type == "identifier"
            and _node_text(func, source) in {"String", "Number", "Boolean"}
        ):
            args = node.child_by_field_name("arguments")
            named = [c for c in args.children if c.is_named] if args is not None else []
            if len(named) == 1:
                node = _unwrap_expr(named[0])
    parts: list[str] = []
    while node is not None and node.type == "member_expression":
        prop = node.child_by_field_name("property")
        if prop is None:
            return None
        parts.append(_node_text(prop, source))
        node = _unwrap_expr(node.child_by_field_name("object"))
    if node is not None and node.type == "identifier":
        parts.append(_node_text(node, source))
        return ".".join(reversed(parts))
    return None


def _base_ident(node: Any | None, source: bytes) -> str | None:
    node = _unwrap_expr(node)
    while node is not None:
        if node.type == "identifier":
            return _node_text(node, source)
        if node.type == "member_expression":
            node = _unwrap_expr(node.child_by_field_name("object"))
            continue
        if node.type == "call_expression":
            node = _unwrap_expr(node.child_by_field_name("function"))
            continue
        node = next((c for c in node.children if c.is_named), None)
    return None


def _handler_function(
    call: Any, source: bytes, named_handlers: dict[str, Any] | None = None
) -> tuple[Any, bool] | None:
    func = call.child_by_field_name("function")
    parts = _member_parts(func, source) if func is not None else None
    if parts is None or parts[1] not in _EXPRESS_METHODS:
        return None
    if parts[0] not in _EXPRESS_OBJECTS:
        receiver = func.child_by_field_name("object") if func is not None else None
        if receiver is None or receiver.type != "call_expression":
            return None
        route_func = receiver.child_by_field_name("function")
        route_parts = _member_parts(route_func, source) if route_func is not None else None
        if not (
            route_parts
            and route_parts[0] in _EXPRESS_OBJECTS
            and route_parts[1] == "route"
        ):
            return None
    args = call.child_by_field_name("arguments")
    if args is None:
        return None
    handler = None
    middleware = 0
    for child in args.children:
        if child.type in ("arrow_function", "function_expression"):
            handler = child
        elif child.type == "identifier" and _node_text(child, source) in (named_handlers or {}):
            handler = (named_handlers or {})[_node_text(child, source)]
        elif child.is_named and child.type != "string":
            middleware += 1
    if handler is None:
        return None
    return handler, middleware > 0


def _default_export_handlers(root: Any, source: bytes):
    """Next.js Pages API route handlers: `export default function handler(...)`
    or `export default (req, res) => ...`."""
    del source
    for node in _walk_all(root):
        if node.type != "export_statement":
            continue
        if not any(c.type == "default" for c in node.children):
            continue
        for child in node.children:
            if child.type in ("function_declaration", "function_expression", "arrow_function"):
                yield child


def _named_export_handlers(root: Any, source: bytes):
    """Next.js App Router handlers: `export async function GET/POST/...`."""
    for node in _walk_all(root):
        if node.type != "export_statement":
            continue
        declaration = node.child_by_field_name("declaration")
        if declaration is None or declaration.type != "function_declaration":
            continue
        name = declaration.child_by_field_name("name")
        if name is not None and _node_text(name, source) in _HTTP_METHOD_EXPORTS:
            yield declaration


def _handler_names(params: list[str]) -> tuple[str, str, str, str | None]:
    req_name = params[0] if params else "req"
    if req_name in {"ctx", "context"}:
        return req_name, req_name, f"{req_name}.state.user", req_name
    res_name = params[1] if len(params) > 1 else "res"
    return req_name, res_name, f"{req_name}.user", None


def _assigned_var(call: Any, source: bytes) -> str | None:
    node = call.parent
    if node is not None and node.type == "await_expression":
        node = node.parent
    if node is None or node.type != "variable_declarator":
        return None
    name = node.child_by_field_name("name")
    if name is None or name.type != "identifier":
        return None
    return _node_text(name, source)


def _read_model(call: Any, source: bytes) -> str | None:
    func = call.child_by_field_name("function")
    parts = _member_parts(func, source) if func is not None else None
    if parts is None:
        return None
    method = parts[1].lower()
    model = parts[0]
    if model[:1].isupper() and method in _READ_METHODS:
        return model
    if (model.startswith("prisma.") or model.startswith("this.prisma.")) and (
        method in _READ_METHODS or method in _PRISMA_WRITE_METHODS
    ):
        return model.rsplit(".", 1)[-1]
    return None


def _request_value_names(
    body: Any, source: bytes, req_name: str, route_params_name: str | None
) -> set[str]:
    """Local names bound from request-controlled values (`const { id } = params`,
    `const id = req.params.id`). Keeps App Router destructured params and
    Express aliases from disappearing before `_uses_request_input`."""
    tainted: set[str] = set()
    if route_params_name is not None:
        tainted.add(route_params_name)
    prefixes = (
        f"{req_name}.params", f"{req_name}.query", f"{req_name}.body",
        f"{req_name}.request.body", f"{req_name}.nextUrl",
    )
    while True:
        changed = False
        for node in _walk_all(body):
            if node.type != "variable_declarator":
                continue
            name = node.child_by_field_name("name")
            value = node.child_by_field_name("value")
            if name is None or value is None:
                continue
            dotted = _dotted(value, source)
            if not dotted or not (
                dotted in tainted
                or any(dotted == p or dotted.startswith(p + ".") for p in prefixes)
            ):
                continue
            names = (
                [_node_text(name, source)]
                if name.type == "identifier"
                else _collect_pattern_identifiers(name, source)
            )
            for bound in names:
                if bound not in tainted:
                    tainted.add(bound)
                    changed = True
        if not changed:
            return tainted


def _uses_request_input(
    call: Any, source: bytes, req_name: str, tainted_names: set[str]
) -> bool:
    args = call.child_by_field_name("arguments")
    if args is None:
        return False
    text = _node_text(args, source)
    markers = (
        f"{req_name}.params", f"{req_name}.query", f"{req_name}.body",
        f"{req_name}.request.body", f"{req_name}.nextUrl",
    )
    if any(marker in text for marker in markers):
        return True
    return any(
        node.type == "identifier" and _node_text(node, source) in tainted_names
        for node in _walk_all(args)
    )


def _is_fused_owner_read(call: Any, source: bytes, principal_prefix: str) -> bool:
    """Query-fused ownership for object-literal filters:
    `Doc.findOne({ _id: req.params.id, ownerId: req.user.id })`."""
    for node in _walk_all(call):
        if node.type != "pair":
            continue
        key = node.child_by_field_name("key")
        value = node.child_by_field_name("value")
        if key is None or value is None:
            continue
        if not any(hint in _node_text(key, source).lower() for hint in _OWNER_HINTS):
            continue
        dotted = _dotted(value, source)
        if dotted is not None and dotted.startswith(principal_prefix):
            return True
    return False


def _references(node: Any, source: bytes, name: str) -> bool:
    """True when ``node`` uses the variable ``name``: an identifier, not a
    substring of a string literal such as 'doc not found' (AZ-13)."""
    return any(
        n.type in ("identifier", "shorthand_property_identifier")
        and _node_text(n, source) == name
        for n in _walk_all(node)
    )


def _first_escape_line(
    body: Any,
    source: bytes,
    obj_var: str | None,
    res_name: str,
    ctx_name: str | None = None,
    app_router: bool = False,
) -> int | None:
    if obj_var is None:
        return None
    best: int | None = None
    for node in _walk_all(body):
        line = node.start_point[0] + 1
        if node.type == "return_statement" and _references(node, source, obj_var):
            best = line if best is None else min(best, line)
            continue
        if node.type == "assignment_expression" and ctx_name is not None:
            left = _dotted(node.child_by_field_name("left"), source)
            right = node.child_by_field_name("right")
            if left in {f"{ctx_name}.body", f"{ctx_name}.response.body"} and (
                right is not None and _references(right, source, obj_var)
            ):
                best = line if best is None else min(best, line)
            continue
        if node.type != "call_expression":
            continue
        func = node.child_by_field_name("function")
        parts = _member_parts(func, source) if func is not None else None
        if parts is None:
            continue
        base = _base_ident(func, source)
        if app_router and base in _NEXT_RESPONSE_OBJECTS and parts[1] == "json":
            args = node.child_by_field_name("arguments")
            if args is not None and _references(args, source, obj_var):
                best = line if best is None else min(best, line)
            continue
        if base != res_name or parts[1] not in _RESPONSE_METHODS:
            continue
        args = node.child_by_field_name("arguments")
        if args is not None and _references(args, source, obj_var):
            best = line if best is None else min(best, line)
    return best


def _owner_compare_kind(
    if_node: Any, source: bytes, obj_var: str, principal_prefix: str
) -> str | None:
    condition = if_node.child_by_field_name("condition")
    if condition is None:
        return None
    for node in _walk_all(condition):
        if node.type != "call_expression":
            continue
        func = node.child_by_field_name("function")
        parts = _member_parts(func, source) if func is not None else None
        if parts is None or parts[1] != "equals":
            continue
        owner = parts[0]
        if not owner.startswith(obj_var + ".") or not any(
            hint in owner.lower() for hint in _OWNER_HINTS
        ):
            continue
        args = node.child_by_field_name("arguments")
        named = [child for child in args.children if child.is_named] if args is not None else []
        if len(named) != 1:
            continue
        principal = _dotted(named[0], source)
        if principal is None or not principal.startswith(principal_prefix):
            continue
        parent = node.parent
        negated = (
            parent is not None
            and parent.type == "unary_expression"
            and _node_text(parent, source).lstrip().startswith("!")
        )
        return "ne" if negated else "eq"
    for node in _walk_all(condition):
        if node.type != "binary_expression":
            continue
        op = node.child_by_field_name("operator")
        op_text = _node_text(op, source) if op is not None else ""
        if op_text not in {"!==", "!=", "===", "=="}:
            continue
        left = _dotted(node.child_by_field_name("left"), source)
        right = _dotted(node.child_by_field_name("right"), source)
        for obj_side, principal_side in ((left, right), (right, left)):
            if not obj_side or not principal_side:
                continue
            if not obj_side.startswith(obj_var + "."):
                continue
            if not any(hint in obj_side.lower() for hint in _OWNER_HINTS):
                continue
            if principal_side.startswith(principal_prefix):
                return "ne" if op_text in {"!==", "!="} else "eq"
    return None


def _response_deny_call(call: Any, source: bytes, res_name: str) -> bool:
    func = call.child_by_field_name("function")
    parts = _member_parts(func, source) if func is not None else None
    if parts is None:
        return False
    base = _base_ident(func, source)
    text = _node_text(call, source).lower()
    if base in _NEXT_RESPONSE_OBJECTS and parts[1] == "json":
        return any(code in text for code in ("401", "403"))
    if base != res_name:
        return False
    if parts[1] == "throw":
        return any(code in text for code in ("401", "403"))
    return any(code in text for code in ("sendstatus(403", "sendstatus(401", "status(403", "status(401"))


def _branch_denies(branch: Any | None, source: bytes, res_name: str) -> bool:
    if branch is None:
        return False
    for node in _walk_all(branch):
        if node.type == "throw_statement":
            return True
        if node.type == "call_expression" and _response_deny_call(node, source, res_name):
            return True
    return False


def _guard_denies(if_node: Any, kind: str, source: bytes, res_name: str) -> bool:
    if kind == "ne":
        return _branch_denies(if_node.child_by_field_name("consequence"), source, res_name)
    return _branch_denies(if_node.child_by_field_name("alternative"), source, res_name)


def _has_dominating_owner_guard(
    body: Any,
    source: bytes,
    obj_var: str | None,
    principal_prefix: str,
    res_name: str,
    read_line: int,
    escape_line: int | None,
) -> tuple[bool, bool]:
    """(dominates, exists_anywhere) for an inline owner guard: a structured
    owner/principal compare whose deny branch halts with a 401/403 or throw."""
    if obj_var is None:
        return False, False
    exists = False
    for node in _walk_all(body):
        if node.type != "if_statement":
            continue
        kind = _owner_compare_kind(node, source, obj_var, principal_prefix)
        if kind is None or not _guard_denies(node, kind, source, res_name):
            continue
        exists = True
        line = node.start_point[0] + 1
        if line > read_line and (escape_line is None or line < escape_line):
            return True, True
    return False, exists


class JSAuthzPass:
    name = "js_authz"

    def run(self, context: ScanContext) -> ScanResult:
        start = time.perf_counter()
        result = ScanResult()
        # None means the policy chose; the scan plan only runs this pass when enabled.
        if context.config.enable_authz is False or not TREE_SITTER_AVAILABLE:
            return result

        target = context.target_path
        ignore_patterns = load_ignore_patterns(target, context.config)
        parsers = _get_parsers()
        parsed: list[tuple[Path, bytes, Any]] = []
        principal_found = False

        for path in _collect_js_files(target, ignore_patterns):
            try:
                source = path.read_bytes()
                tree = parsers[path.suffix].parse(source)
            except (OSError, UnicodeError, ValueError):
                continue
            parsed.append((path, source, tree.root_node))
            lowered = source.lower()
            principal_found = principal_found or any(
                marker in lowered for marker in (b"req.user", b"request.user", b"ctx.state.user")
            )

        if principal_found:
            for path, source, root in parsed:
                result.findings.extend(self._scan_root(path, source, root))

        result.files_scanned = len(parsed)
        scan_span(self.name, time.perf_counter() - start)
        return result

    def _scan_root(self, path: Path, source: bytes, root: Any) -> list[Finding]:
        findings: list[Finding] = []
        named_handlers: dict[str, Any] = {}
        for candidate in _walk_all(root):
            if candidate.type == "function_declaration":
                name = candidate.child_by_field_name("name")
                if name is not None:
                    named_handlers[_node_text(name, source)] = candidate
            elif candidate.type == "variable_declarator":
                name = candidate.child_by_field_name("name")
                value = candidate.child_by_field_name("value")
                if (
                    name is not None
                    and name.type == "identifier"
                    and value is not None
                    and value.type in {"arrow_function", "function_expression"}
                ):
                    named_handlers[_node_text(name, source)] = value
        for node in _walk_all(root):
            if node.type != "call_expression":
                continue
            extracted = _handler_function(node, source, named_handlers)
            if extracted is None:
                continue
            handler, has_middleware = extracted
            body = handler.child_by_field_name("body")
            if body is None or body.type != "statement_block":
                continue
            params = _params_of(handler.child_by_field_name("parameters"), source)
            req_name, res_name, principal_prefix, ctx_name = _handler_names(params)
            findings.extend(
                self._scan_handler(
                    path, source, body, req_name, res_name, principal_prefix, ctx_name, has_middleware
                )
            )
        for handler in _default_export_handlers(root, source):
            body = handler.child_by_field_name("body")
            if body is None or body.type != "statement_block":
                continue
            params = _params_of(handler.child_by_field_name("parameters"), source)
            req_name, res_name, principal_prefix, ctx_name = _handler_names(params)
            findings.extend(
                self._scan_handler(
                    path, source, body, req_name, res_name, principal_prefix, ctx_name, False
                )
            )
        for handler in _named_export_handlers(root, source):
            body = handler.child_by_field_name("body")
            if body is None or body.type != "statement_block":
                continue
            params = _params_of(handler.child_by_field_name("parameters"), source)
            req_name = params[0] if params else "req"
            route_params_name = params[1] if len(params) > 1 else None
            findings.extend(
                self._scan_handler(
                    path, source, body, req_name, "", f"{req_name}.user", None, False,
                    route_params_name=route_params_name, app_router=True,
                )
            )
        return findings

    def _scan_handler(
        self,
        path: Path,
        source: bytes,
        body: Any,
        req_name: str,
        res_name: str,
        principal_prefix: str,
        ctx_name: str | None,
        has_middleware: bool,
        route_params_name: str | None = None,
        app_router: bool = False,
    ) -> list[Finding]:
        findings: list[Finding] = []
        tainted_names = _request_value_names(body, source, req_name, route_params_name)
        for call in _walk_all(body):
            if call.type != "call_expression":
                continue
            model = _read_model(call, source)
            if model is None or not _uses_request_input(call, source, req_name, tainted_names):
                continue
            if _is_fused_owner_read(call, source, principal_prefix):
                continue
            read_line = call.start_point[0] + 1
            obj_var = _assigned_var(call, source)
            escape_line = _first_escape_line(
                body, source, obj_var, res_name, ctx_name, app_router=app_router
            )
            dominates, exists = _has_dominating_owner_guard(
                body, source, obj_var, principal_prefix, res_name, read_line, escape_line
            )
            if dominates:
                continue
            if exists or has_middleware:
                severity, confidence, reason = (
                    Severity.MEDIUM,
                    AUTHZ_BOLA_MEDIUM,
                    "guard_not_dominating" if exists else "route_middleware_only",
                )
            else:
                severity, confidence, reason = Severity.HIGH, AUTHZ_BOLA_HIGH, "no_guard"
            findings.append(Finding(
                rule_id=_RULE_ID,
                message=(
                    f"Handler reads {model} keyed by user-controlled input with no "
                    "object-level authorization check -- possible BOLA/IDOR."
                ),
                severity=severity,
                category=Category.AUTH,
                file_path=str(path),
                start_line=read_line,
                end_line=read_line,
                start_column=call.start_point[1],
                confidence=confidence,
                cwe_ids=[639],
                owasp_ids=["API1:2023", "A01:2021"],
                engine="js_authz",
                metadata={
                    "model": model,
                    "reason": reason,
                    "remediation": _REMEDIATION,
                    # Inline handlers have no name; the body's first line is
                    # unique per handler and keeps dedup from merging them.
                    "caller": f"handler@{body.start_point[0] + 1}",
                },
            ))
        return findings
