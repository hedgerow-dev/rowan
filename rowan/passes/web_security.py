"""Project-aware Python web security checks with structural evidence."""

from __future__ import annotations

import ast
import logging
import time
from dataclasses import dataclass
from pathlib import Path

from rowan.analysis.python_functions import FunctionIndex
from rowan.analysis.trust_flow import TrustFlow
from rowan.analysis.xml_parser_options import parser_option_findings
from rowan.config import ScanConfig
from rowan.core.findings import (
    Category,
    Finding,
    ScanResult,
    Severity,
    TaintFlow,
    TaintNode,
)
from rowan.passes.base import ScanContext, scan_span
from rowan.passes.sources import iter_python_sources

logger = logging.getLogger(__name__)

_PRIVILEGED = frozenset({"role", "is_admin", "is_staff", "is_superuser", "permissions"})
_ADMIN_VALUES = frozenset({"admin", "administrator", "superuser", "staff", "owner", "root"})
_PRINCIPAL_BASES = frozenset({"g", "current_user", "request.user", "session", "self.user"})
_SECRET_WORDS = ("token", "secret", "password", "api_key", "apikey", "signature", "digest")
_SAFE_ROLE_VALUES = frozenset({"user", "member", "viewer", "customer", "guest"})


def _call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _call_name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    return ""


def _text(node: ast.AST) -> str:
    try:
        return ast.unparse(node)
    except Exception:
        return ""


def _request_expr(node: ast.AST, tainted: set[str]) -> bool:
    rendered = _text(node)
    if "request." in rendered and any(
        part in rendered for part in (
            ".json", ".form", ".args", ".values", ".headers", ".cookies",
            ".authorization", "get_json",
        )
    ):
        return True
    return any(isinstance(n, ast.Name) and n.id in tainted for n in ast.walk(node))


def _tainted_names(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    tainted: set[str] = set()
    changed = True
    while changed:
        changed = False
        for node in ast.walk(fn):
            if not isinstance(node, (ast.Assign, ast.AnnAssign, ast.NamedExpr)):
                continue
            value = node.value
            if value is None or not _request_expr(value, tainted):
                continue
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                for name in (n.id for n in ast.walk(target) if isinstance(n, ast.Name)):
                    if name not in tainted:
                        tainted.add(name)
                        changed = True
    return tainted


def _rejecting_guard(fn: ast.AST, name: str, allowed: frozenset[str] | None = None) -> bool:
    """Recognize a membership guard whose failing branch exits."""
    for node in ast.walk(fn):
        if not isinstance(node, ast.If) or not any(
            isinstance(x, (ast.Return, ast.Raise, ast.Continue, ast.Break))
            for stmt in node.body for x in ast.walk(stmt)
        ):
            continue
        test = node.test
        if not isinstance(test, ast.Compare) or not isinstance(test.left, ast.Name):
            continue
        if test.left.id != name or not any(isinstance(op, ast.NotIn) for op in test.ops):
            continue
        if allowed is None:
            return True
        values = {
            x.value for comp in test.comparators for x in ast.walk(comp)
            if isinstance(x, ast.Constant) and isinstance(x.value, str)
        }
        if values and values <= allowed:
            return True
    return False


@dataclass
class _Parsed:
    path: Path
    text: str
    tree: ast.Module


class WebSecurityPass:
    name = "web-security"

    def run(self, context: ScanContext) -> ScanResult:
        started = time.perf_counter()
        parsed = self._parse(context)
        findings: list[Finding] = []
        mass_sinks = self._mass_assignment_sinks(parsed)
        privilege_gate = self._privilege_gate(parsed)
        privileged = _PRIVILEGED | self._guarded_fields(parsed)
        has_cookie_auth = any("request.cookies" in item.text for item in parsed)
        has_svg_store = any(self._has_svg_store(item.tree) for item in parsed)
        framing_configured = any(
            "x-frame-options" in item.text.lower() or "frame-ancestors" in item.text.lower()
            for item in parsed
        )
        csrf_configured = any(
            marker in item.text.lower()
            for item in parsed
            for marker in ("csrfprotect(", "csrfmiddleware")
        )

        for item in parsed:
            jsonpickle_decoders = self._jsonpickle_decoders(item.tree)
            for fn in (n for n in ast.walk(item.tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))):
                tainted = _tainted_names(fn)
                findings.extend(
                    self._scan_function(
                        item.path, fn, tainted, mass_sinks, privilege_gate,
                        jsonpickle_decoders, privileged,
                    )
                )
                findings.extend(self._scan_predictable_recovery_code(item.path, fn))
                if has_svg_store:
                    findings.extend(self._scan_inline_svg(item.path, fn))
                if has_cookie_auth and not csrf_configured:
                    findings.extend(self._scan_csrf(item.path, fn))
                if not framing_configured:
                    findings.extend(self._scan_framing(item.path, fn))

        index = FunctionIndex({item.path: item.tree for item in parsed})
        findings.extend(TrustFlow(index, privileged).run())
        findings.extend(parser_option_findings(index))
        result = ScanResult(findings=findings, files_scanned=len(parsed))
        duration = time.perf_counter() - started
        scan_span(self.name, duration)
        logger.info("WebSecurityPass: %d finding(s) in %.2fs", len(findings), duration)
        return result

    def _parse(self, context: ScanContext | Path) -> list[_Parsed]:
        # Preserve the standalone path-based helper used by integrations while
        # the pipeline passes its shared context/snapshot.
        excluded_parts = None
        if isinstance(context, Path):
            root = context
            context = ScanContext(
                target_path=root,
                config=ScanConfig(target=root),
                result=ScanResult(),
            )
            # Historical standalone behavior excluded site-packages but not
            # node_modules. Pipeline calls retain the stricter shared default.
            excluded_parts = frozenset({"site-packages"})
        result: list[_Parsed] = []
        kwargs = {"excluded_parts": excluded_parts} if excluded_parts is not None else {}
        for path, tree in iter_python_sources(
            context,
            owner=self.name,
            skip_tests=True,
            **kwargs,
        ):
            text = context.source_snapshot.read_text(path)
            if text is None:
                continue
            result.append(_Parsed(path, text, tree))
        return result

    def _finding(self, rule: str, path: Path, node: ast.AST, message: str,
                 category: Category, cwe: int, severity: Severity = Severity.HIGH,
                 sink: tuple[Path, int] | None = None) -> Finding:
        return Finding(
            rule_id=rule, message=message, severity=severity, category=category,
            file_path=str(path), start_line=node.lineno,
            end_line=getattr(node, "end_lineno", node.lineno),
            start_column=getattr(node, "col_offset", 0), confidence=0.85,
            cwe_ids=[cwe], engine=self.name,
            taint_flow=(
                TaintFlow(
                    source=TaintNode(str(path), node.lineno),
                    sink=TaintNode(str(sink[0]), sink[1]),
                ) if sink else None
            ),
            metadata={"evidence_tier": "engine", "structural_evidence": True},
        )

    def _privilege_gate(self, parsed: list[_Parsed]) -> tuple[Path, int] | None:
        functions = [
            (item, fn)
            for item in parsed
            for fn in ast.walk(item.tree)
            if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef))
        ]
        functions.sort(key=lambda pair: pair[1].name != "require_admin")
        for item, fn in functions:
            text = _text(fn).lower()
            if ("admin" in fn.name.lower() or "require_admin" in text) and any(
                word in text for word in ("role", "is_admin", "is_staff", "is_superuser")
            ):
                gate = next(
                    (n for n in ast.walk(fn) if isinstance(n, (ast.Compare, ast.If))), fn
                )
                return item.path, gate.lineno
        return None

    def _guarded_fields(self, parsed: list[_Parsed]) -> frozenset[str]:
        """Attribute names an authorization check compares to an admin-like
        value on the current principal (``g.tier == "admin"``): privilege fields found by use, not name."""
        fields: set[str] = set()
        for item in parsed:
            for compare in (n for n in ast.walk(item.tree) if isinstance(n, ast.Compare)):
                operands = [compare.left, *compare.comparators]
                if not any(
                    isinstance(x, ast.Constant) and x.value in _ADMIN_VALUES
                    for op in operands for x in ast.walk(op)
                ):
                    continue
                fields.update(
                    op.args[1].value for op in operands
                    if isinstance(op, ast.Call) and _call_name(op.func) == "getattr"
                    and len(op.args) >= 2 and _text(op.args[0]) in _PRINCIPAL_BASES
                    and isinstance(op.args[1], ast.Constant) and isinstance(op.args[1].value, str)
                )
                fields.update(
                    op.attr for op in operands
                    if isinstance(op, ast.Attribute) and _text(op.value) in _PRINCIPAL_BASES
                )
        return frozenset(fields)

    def _jsonpickle_decoders(self, tree: ast.AST) -> set[str]:
        names = {"jsonpickle.decode", "jsonpickle.loads"}
        module_aliases = {
            alias.asname or alias.name
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
            if alias.name == "jsonpickle"
        }
        for alias in module_aliases:
            names.update({f"{alias}.decode", f"{alias}.loads"})
        for node in ast.walk(tree):
            if not isinstance(node, ast.ImportFrom) or node.module != "jsonpickle":
                continue
            for alias in node.names:
                if alias.name in {"decode", "loads"}:
                    names.add(alias.asname or alias.name)
        return names

    def _mass_assignment_sinks(self, parsed: list[_Parsed]) -> set[str]:
        sinks: set[str] = set()
        for item in parsed:
            for fn in (n for n in ast.walk(item.tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))):
                params = {a.arg for a in fn.args.args + fn.args.posonlyargs + fn.args.kwonlyargs}
                for loop in (n for n in ast.walk(fn) if isinstance(n, (ast.For, ast.AsyncFor))):
                    if not isinstance(loop.target, (ast.Tuple, ast.List)) or len(loop.target.elts) < 2:
                        continue
                    key, value = loop.target.elts[:2]
                    if not isinstance(key, ast.Name) or not isinstance(value, ast.Name):
                        continue
                    if not isinstance(loop.iter, ast.Call) or not isinstance(loop.iter.func, ast.Attribute):
                        continue
                    base = loop.iter.func.value
                    if loop.iter.func.attr != "items" or not isinstance(base, ast.Name) or base.id not in params:
                        continue
                    unsafe = any(
                        isinstance(call, ast.Call) and _call_name(call.func).endswith("setattr")
                        and len(call.args) >= 3 and isinstance(call.args[1], ast.Name)
                        and call.args[1].id == key.id and isinstance(call.args[2], ast.Name)
                        and call.args[2].id == value.id
                        for call in ast.walk(loop)
                    )
                    if unsafe and not _rejecting_guard(loop, key.id):
                        sinks.add(fn.name)
        return sinks

    def _scan_function(self, path: Path, fn: ast.FunctionDef | ast.AsyncFunctionDef,
                       tainted: set[str], mass_sinks: set[str],
                       privilege_gate: tuple[Path, int] | None,
                       jsonpickle_decoders: set[str],
                       privileged: frozenset[str] = _PRIVILEGED) -> list[Finding]:
        out: list[Finding] = []
        for call in (n for n in ast.walk(fn) if isinstance(n, ast.Call)):
            name = _call_name(call.func)
            if name in jsonpickle_decoders and call.args and _request_expr(call.args[0], tainted):
                out.append(self._finding(
                    "WEB-DESER-JSONPICKLE-001", path, call,
                    "Request-derived typed JSON reaches jsonpickle.decode(), which may execute py/reduce object constructors before post-decode validation.",
                    Category.DESERIALIZATION, 502,
                ))
            if name.split(".")[-1] in mass_sinks and call.args and any(
                _request_expr(arg, tainted) for arg in call.args
            ):
                out.append(self._finding(
                    "WEB-MASS-ASSIGN-001", path, call,
                    f"Request-controlled mapping reaches unrestricted setattr loop '{name.split('.')[-1]}'. Allow-list writable fields before applying updates.",
                    Category.INJECTION, 915,
                ))
            terminal = name.split(".")[-1]
            stores_object = bool(terminal[:1].isupper() or terminal in {
                "create", "update", "insert", "save", "add", "add_user", "create_user"
            })
            for keyword in call.keywords:
                if not stores_object:
                    continue
                if keyword.arg not in privileged or not _request_expr(keyword.value, tainted):
                    continue
                source_name = next((n.id for n in ast.walk(keyword.value) if isinstance(n, ast.Name) and n.id in tainted), "")
                if source_name and _rejecting_guard(fn, source_name, _SAFE_ROLE_VALUES):
                    continue
                out.append(self._finding(
                    "WEB-PRIVILEGE-ASSIGN-001", path, keyword.value,
                    f"Improper privilege assignment: client-controlled '{keyword.arg}' is stored during account/object creation without a fixed public-role allow-list.",
                    Category.AUTH, 266, sink=privilege_gate,
                ))

        auth_context = any(word in fn.name.lower() for word in ("auth", "login", "token", "signature"))
        for assign in (n for n in ast.walk(fn) if isinstance(n, (ast.Assign, ast.AnnAssign))):
            value = assign.value
            if value is None:
                continue
            targets = assign.targets if isinstance(assign, ast.Assign) else [assign.target]
            for target in targets:
                source_name = next(
                    (n.id for n in ast.walk(value) if isinstance(n, ast.Name) and n.id in tainted),
                    "",
                )
                if (
                    isinstance(target, ast.Attribute)
                    and target.attr in privileged
                    and _request_expr(value, set() if _text(target.value) in _PRINCIPAL_BASES else tainted)
                    and not (source_name and _rejecting_guard(fn, source_name, _SAFE_ROLE_VALUES))
                ):
                    out.append(self._finding(
                        "WEB-PRIVILEGE-ASSIGN-001", path, assign,
                        f"Improper privilege assignment: client-controlled '{target.attr}' is stored without a fixed public-role allow-list.",
                        Category.AUTH, 266, sink=privilege_gate,
                    ))
        for compare in (n for n in ast.walk(fn) if isinstance(n, ast.Compare)):
            if not any(isinstance(op, (ast.Eq, ast.NotEq)) for op in compare.ops):
                continue
            operands = [compare.left, *compare.comparators]
            rendered = [x.lower() for x in map(_text, operands)]
            has_secret = any(any(word in value for word in _SECRET_WORDS) for value in rendered)
            has_presented = any(_request_expr(node, tainted) for node in operands) or any(
                any(word in value for word in ("presented", "provided", "candidate"))
                for value in rendered
            )
            if auth_context and has_secret and has_presented and not any(value in {"none", "''", '""'} for value in rendered):
                out.append(self._finding(
                    "WEB-AUTH-TIMING-001", path, compare,
                    "Authentication secret is compared with short-circuiting equality. Use hmac.compare_digest() or the platform constant-time primitive.",
                    Category.CRYPTO, 208, Severity.MEDIUM,
                ))
        return out

    def _has_svg_store(self, tree: ast.AST) -> bool:
        for fn in (
            n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
        ):
            tainted = _tainted_names(fn)
            for call in (n for n in ast.walk(fn) if isinstance(n, ast.Call)):
                if (
                    _call_name(call.func).endswith("write_text")
                    and call.args
                    and _request_expr(call.args[0], tainted)
                ):
                    return True
        return False

    def _scan_inline_svg(self, path: Path, fn: ast.AST) -> list[Finding]:
        for call in (n for n in ast.walk(fn) if isinstance(n, ast.Call)):
            text = _text(call).lower()
            if "response(" not in text or not any(x in text for x in ("image/svg+xml", "application/xml", "text/xml")):
                continue
            if "attachment" in text:
                continue
            return [self._finding(
                "WEB-INLINE-ACTIVE-CONTENT-001", path, call,
                "Attacker-stored SVG/XML is served inline from the application origin, allowing active content to execute in an authenticated viewer's origin.",
                Category.XSS, 79,
            )]
        return []

    def _scan_csrf(self, path: Path, fn: ast.FunctionDef | ast.AsyncFunctionDef) -> list[Finding]:
        text = _text(fn).lower()
        decorators = " ".join(_text(d).lower() for d in fn.decorator_list)
        state_changing = "post" in decorators or 'request.method == "post"' in text or "request.method == 'post'" in text
        mutates_state = any(
            _call_name(call.func).split(".")[-1] in {
                "add", "commit", "delete", "execute", "merge", "merge_namespace",
                "update",
            }
            for call in ast.walk(fn) if isinstance(call, ast.Call)
        )
        if state_changing and mutates_state and "request.form" in text and "csrf" not in text and "authorization" not in text:
            return [self._finding(
                "WEB-CSRF-COOKIE-001", path, fn,
                "Cookie-authenticated state-changing form handler has no visible CSRF token, validation, decorator, or middleware.",
                Category.AUTH, 352,
            )]
        return []

    def _scan_framing(self, path: Path, fn: ast.FunctionDef | ast.AsyncFunctionDef) -> list[Finding]:
        decorators = " ".join(_text(d).lower() for d in fn.decorator_list)
        text = _text(fn).lower()
        if "after_request" in decorators and "headers" in text and "x-content-type-options" in text:
            return [self._finding(
                "WEB-CLICKJACKING-001", path, fn,
                "Application response-hardening hook omits both CSP frame-ancestors and X-Frame-Options, leaving authenticated pages frameable.",
                Category.CONFIG, 1021, Severity.MEDIUM,
            )]
        return []

    def _scan_predictable_recovery_code(
        self, path: Path, fn: ast.FunctionDef | ast.AsyncFunctionDef
    ) -> list[Finding]:
        """Detect recovery credentials deterministically derived from identity data."""
        context = f"{fn.name} {ast.get_docstring(fn) or ''}".lower()
        if not any(word in context for word in ("reset", "recovery", "recover", "forgot")):
            return []
        params = {
            arg.arg
            for arg in (*fn.args.posonlyargs, *fn.args.args, *fn.args.kwonlyargs)
            if arg.arg not in {"self", "cls"}
        }
        identity_params = {
            name for name in params
            if any(word in name.lower() for word in ("user", "email", "account", "phone", "login", "name", "id"))
        }
        if not identity_params:
            return []
        fn_text = _text(fn).lower()
        if any(marker in fn_text for marker in (
            "secrets.", "os.urandom", "systemrandom", "hmac.", "fernet", "signer.sign",
        )):
            return []
        for call in (node for node in ast.walk(fn) if isinstance(node, ast.Call)):
            name = _call_name(call.func).lower()
            if not (
                name.startswith("hashlib.")
                or name in {"uuid.uuid3", "uuid.uuid5"}
                or name.endswith((".hexdigest", ".digest"))
            ):
                continue
            if not any(
                isinstance(child, ast.Name) and child.id in identity_params
                for child in ast.walk(call)
            ):
                # The identity can sit in the receiver of `.hexdigest()`.
                if not any(
                    isinstance(child, ast.Name) and child.id in identity_params
                    for parent in ast.walk(fn)
                    if isinstance(parent, (ast.Return, ast.Assign, ast.AnnAssign))
                    and call in ast.walk(parent)
                    for child in ast.walk(parent)
                ):
                    continue
            return [self._finding(
                "WEB-PREDICTABLE-RECOVERY-001",
                path,
                call,
                "Predictable password-reset token or recovery code is deterministically derived from public account identity. A short expiry does not provide sufficient randomness; generate a single-use value with secrets.token_urlsafe().",
                Category.AUTH,
                640,
            )]
        return []
