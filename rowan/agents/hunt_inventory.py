"""Source-grounded Hunt scheduling and bounded Python verification context.

This is a coverage inventory, not a vulnerability detector or proof of reachability.
Unknown dispatch and unsupported languages remain explicitly unresolved.
"""

from __future__ import annotations

import ast
import hashlib
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from rowan.config import ScanConfig
from rowan.passes.file_scan import FileScanPass, is_ai_instruction_file

ENTRY_DECORATORS = frozenset(
    {
        "route",
        "get",
        "post",
        "put",
        "delete",
        "patch",
        "api_route",
        "websocket",
        "tool",
        "task",
        "shared_task",
        "job",
        "message_handler",
        "subscribe",
    }
)
SENSITIVE_CALLS = frozenset(
    {
        "eval",
        "exec",
        "execute",
        "executemany",
        "system",
        "popen",
        "run",
        "loads",
        "load",
        "decode",
        "from_string",
        "render_template_string",
        "open",
        "send_file",
        "fetch",
        "urlopen",
        "request",
        "add_task",
        "delay",
        "apply_async",
        "invoke",
        "ainvoke",
        "from_pretrained",
    }
)
REACHABILITY_STATES = frozenset(
    {"reachable", "conditional", "no_demonstrated_caller", "unresolved"}
)
EVIDENCE_FIELDS = (
    "attacker_control",
    "path",
    "sink",
    "protection",
    "protection_failure",
    "impact",
)


@dataclass(frozen=True)
class HuntBudgets:
    discovery_files: int = 25
    source_lines: int = 400
    context_lines: int = 240
    context_files: int = 4

    def __post_init__(self) -> None:
        for name, ceiling in (
            ("discovery_files", 500),
            ("source_lines", 10000),
            ("context_lines", 5000),
            ("context_files", 25),
        ):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= ceiling:
                raise ValueError(f"{name} must be between 1 and {ceiling}")


def source_paths(target: Path, config: ScanConfig) -> list[Path]:
    """Use the scanner's ignore, language, size and symlink scope rules."""
    return sorted(
        p.resolve()
        for p in FileScanPass([])._collect_files(target, config)
        if not is_ai_instruction_file(p)
    )


def _name(node: ast.AST) -> str:
    if isinstance(node, ast.Call):
        return _name(node.func)
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return f"{_name(node.value)}.{node.attr}"
    return ""


def build_inventory(target: Path, config: ScanConfig) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    file_hashes = {}
    for path in source_paths(target, config):
        rel = path.relative_to(target.resolve()).as_posix()
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            records.append(_record(rel, 1, "unresolved", "", "read_failed"))
            continue
        file_hashes[rel] = hashlib.sha256(text.encode()).hexdigest()
        if len(text.splitlines()) > config.max_file_lines:
            records.append(_record(rel, 1, "unresolved", "", "inventory_line_limit"))
            continue
        if path.suffix != ".py":
            records.append(_record(rel, 1, "unresolved", "", "unsupported_language"))
            continue
        try:
            tree = ast.parse(text)
        except (SyntaxError, ValueError, RecursionError, MemoryError):
            records.append(_record(rel, 1, "unresolved", "", "parse_failed"))
            continue
        functions = [
            n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
        ]
        for node in tree.body:
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                record = _record(rel, node.lineno, "import", "", "navigation_only")
                record.update(end_line=node.end_lineno or node.lineno, calls=[])
                records.append(record)
        for fn in functions:
            decorators = [_name(d) for d in fn.decorator_list]
            entries = [d for d in decorators if d.rsplit(".", 1)[-1] in ENTRY_DECORATORS]
            calls = sorted({_name(n.func) for n in ast.walk(fn) if isinstance(n, ast.Call)})
            sinks = [c for c in calls if c.rsplit(".", 1)[-1] in SENSITIVE_CALLS]
            kind = "entrypoint" if entries else "sensitive_operation" if sinks else "helper"
            record = _record(
                rel,
                min([fn.lineno, *(d.lineno for d in fn.decorator_list)]),
                kind,
                fn.name,
                "not_scheduled",
            )
            record.update(
                end_line=fn.end_lineno or fn.lineno,
                decorators=decorators,
                calls=calls,
                sensitive_operations=sinks,
                references=sorted({n.id for n in ast.walk(fn) if isinstance(n, ast.Name)}),
                inputs=[a.arg for a in fn.args.args],
                trust_boundary="candidate_external_to_application" if entries else "unresolved",
                reachable="unresolved",
            )
            records.append(record)
        if not functions:
            records.append(_record(rel, 1, "module", "", "no_recognized_surface"))
        function_lines = {
            line for fn in functions for line in range(fn.lineno, (fn.end_lineno or fn.lineno) + 1)
        }
        module_calls = [
            n for n in ast.walk(tree) if isinstance(n, ast.Call) and n.lineno not in function_lines
        ]
        for call in module_calls:
            name = _name(call.func)
            if name.rsplit(".", 1)[-1] in SENSITIVE_CALLS:
                record = _record(
                    rel, call.lineno, "sensitive_operation", f"<module>:{name}", "not_scheduled"
                )
                record.update(
                    end_line=call.end_lineno or call.lineno,
                    calls=[name],
                    inputs=[],
                    trust_boundary="unresolved",
                    reachable="unresolved",
                )
                records.append(record)
    for record in records:
        record["source_text_hash"] = file_hashes.get(record["file"])
    return list({r["id"]: r for r in records}.values())


def _record(file: str, line: int, kind: str, symbol: str, reason: str) -> dict[str, Any]:
    identity = hashlib.sha256(f"{file}:{line}:{kind}:{symbol}".encode()).hexdigest()[:20]
    return {
        "id": identity,
        "file": file,
        "line": line,
        "kind": kind,
        "symbol": symbol,
        "status": "unresolved" if kind == "unresolved" else "skipped",
        "reason": reason,
    }


def inventory_paths(target: Path, records: list[dict[str, Any]]) -> list[Path]:
    return sorted(
        {
            target.resolve() / r["file"]
            for r in records
            if r["kind"] in {"entrypoint", "sensitive_operation"}
        }
    )


def reachability_assessment(value: Any = None, *, fallback: str = "") -> dict[str, Any]:
    """Never infer proof of reachability from an unstructured narrative."""
    record = value if isinstance(value, dict) else {}
    status = record.get("status", "unresolved")
    if not isinstance(status, str) or status not in REACHABILITY_STATES:
        status = "unresolved"
    return {
        "status": status,
        "entrypoint": str(record.get("entrypoint") or "")[:500],
        "prerequisites": [str(x)[:500] for x in record.get("prerequisites", [])]
        if isinstance(record.get("prerequisites"), list)
        else [],
        "reason": str(record.get("reason") or fallback)[:1000],
    }


def verification_evidence(verdict: dict[str, Any]) -> tuple[dict[str, Any], bool]:
    raw = verdict.get("evidence")
    evidence = raw if isinstance(raw, dict) else {}
    result = {name: str(evidence.get(name) or "")[:2000] for name in EVIDENCE_FIELDS}
    assumptions = evidence.get("assumptions", [])
    result["assumptions"] = (
        [str(x)[:500] for x in assumptions] if isinstance(assumptions, list) else []
    )
    result["validation_method"] = "static_review"
    assessment = reachability_assessment(verdict.get("reachability_assessment"))
    complete = all(
        isinstance(evidence.get(name), str) and evidence[name].strip() for name in EVIDENCE_FIELDS
    )
    return result, complete and assessment["status"] == "reachable" and bool(
        assessment["entrypoint"]
    ) and not assessment["prerequisites"] and not result["assumptions"]


def evidence_locations_supported(
    evidence: dict[str, Any], assessment: dict[str, Any], context: dict[str, Any]
) -> bool:
    """Gate citations against inspected snippets, without claiming path semantics.

    A model's complete-looking record cannot borrow evidence from an unseen file.
    Source-to-sink correctness remains an adversarial judgment, not a regex proof.
    """
    snippets = context.get("snippets", [])
    for key in ("attacker_control", "path", "sink", "protection_failure", "entrypoint"):
        text = assessment["entrypoint"] if key == "entrypoint" else evidence.get(key, "")
        refs = re.findall(r"([\w./-]+\.\w+):(\d+)", text)
        if not refs:
            return False
        for file, line in refs:
            if not any(
                s["file"] == file and s["start_line"] <= int(line) <= s["end_line"]
                for s in snippets
            ):
                return False
    return True


def verification_context(
    target: Path, file: str, line: int, records: list[dict[str, Any]], budgets: HuntBudgets
) -> dict[str, Any]:
    """Retrieve enclosing functions, local callees and callers, with hard budgets.

    Symbol matches are navigation leads, not resolved call-graph edges. Ambiguous
    names, dynamic dispatch and dependencies must still be assessed by the verifier.
    """
    root = target.resolve()
    path = Path(file)
    path = (root / path).resolve() if not path.is_absolute() else path.resolve()
    if not path.is_relative_to(root):
        return {"snippets": [], "omitted": ["outside_target"], "resolution": "unresolved"}
    rel = path.relative_to(root).as_posix()
    if not any(r["file"] == rel for r in records):
        return {"snippets": [], "omitted": ["outside_resolved_scope"], "resolution": "unresolved"}
    enclosing = [
        r for r in records if r["file"] == rel and r.get("end_line", r["line"]) >= line >= r["line"]
    ]
    enclosing.sort(key=lambda r: r.get("end_line", r["line"]) - r["line"])
    selected = enclosing[:1]
    if selected:
        names = {c.rsplit(".", 1)[-1] for c in selected[0].get("calls", [])}
        names.update(selected[0].get("references", []))
        symbol = selected[0]["symbol"]
        selected += [
            r
            for r in records
            if r not in selected
            and (
                r["symbol"] in names
                or (symbol and any(c.rsplit(".", 1)[-1] == symbol for c in r.get("calls", [])))
            )
        ]
        files = {r["file"] for r in selected}
        selected += [r for r in records if r["file"] in files and r["kind"] == "import"]
    if not selected:
        selected = [{"file": rel, "line": max(1, line - 25), "end_line": line + 25}]
    snippets: list[dict[str, Any]] = []
    omitted: list[str] = []
    seen: set[tuple[str, int]] = set()
    files: set[str] = set()
    remaining = budgets.context_lines
    for record in selected:
        key = (record["file"], record["line"])
        if key in seen:
            continue
        seen.add(key)
        candidate = (root / record["file"]).resolve()
        if not candidate.is_relative_to(root) or is_ai_instruction_file(candidate):
            omitted.append(f"{record['file']}:scope")
            continue
        if remaining <= 0 or (record["file"] not in files and len(files) >= budgets.context_files):
            omitted.append(f"{record['file']}:{record['line']}:budget")
            continue
        try:
            lines = candidate.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            omitted.append(f"{record['file']}:read_failed")
            continue
        if record["line"] > len(lines):
            omitted.append(f"{record['file']}:{record['line']}:source_changed")
            continue
        lo = max(0, record["line"] - 1)
        end = min(len(lines), record.get("end_line", record["line"]) + 1)
        # Keep the cited sink visible even if a large enclosing function is truncated.
        if record["file"] == rel and end - lo > remaining:
            lo = max(lo, line - 1 - remaining // 2)
        hi = min(end, lo + remaining)
        if hi < end or lo > record["line"] - 1:
            omitted.append(f"{record['file']}:{record['line']}:partial_function")
        code = "\n".join(f"{i + 1}: {lines[i]}" for i in range(lo, hi))
        snippets.append(
            {"file": record["file"], "start_line": lo + 1, "end_line": hi, "code": code}
        )
        files.add(record["file"])
        remaining -= hi - lo
    return {
        "snippets": snippets,
        "omitted": omitted,
        "resolution": "symbol_candidates_not_proven_edges",
    }
