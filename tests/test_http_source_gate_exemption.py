"""A taint flow from a declared HTTP-request source proves its web context.

The web gate floors web-category findings in files with no web-framework
import, and the library profile floors web categories in repos that do not
look like servers. Both are file/repo-level guesses. A rule whose sources are
request reads (`source_kind: http_input`) that produced a taint flow already
shows the input comes from a request, as tool and model-output sources do.
Seen on NodeGoat (route file without an express import), WebGoat.NET
(Web Forms code-behind) and govwa (httprouter, detected as a library).
"""

from __future__ import annotations

import tempfile

from rowan.config import ScanConfig
from rowan.core.findings import Category, Finding, ScanResult, Severity, TaintFlow, TaintNode
from rowan.passes.enrichment import EnrichmentPass


def _finding(path: str, *, source_kind: str | None, flow: bool = True) -> Finding:
    metadata = {"source_kind": source_kind} if source_kind else {}
    return Finding(
        rule_id="tnt-js-redirect-001",
        message="open redirect",
        severity=Severity.MEDIUM,
        category=Category.SSRF,
        file_path=path,
        start_line=3,
        engine="opengrep",
        taint_flow=TaintFlow(source=TaintNode(path, 2), sink=TaintNode(path, 3)) if flow else None,
        metadata=metadata,
    )


def _route_file() -> str:
    # No framework import: `app` is handed in from another module.
    with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False, encoding="utf-8") as fh:
        fh.write("module.exports = (app) => {\n  app.get('/learn', (req, res) => {\n    res.redirect(req.query.url);\n  });\n};\n")
        return fh.name


def test_web_gate_keeps_http_sourced_taint_flow():
    path = _route_file()
    [kept] = EnrichmentPass()._suppress_web_rules_on_non_web_files([_finding(path, source_kind="http_input")])
    assert kept.severity == Severity.MEDIUM
    assert "web_context_gate" not in kept.metadata


def test_web_gate_still_floors_findings_without_that_evidence():
    path = _route_file()
    no_kind = _finding(path, source_kind=None)
    no_flow = _finding(path, source_kind="http_input", flow=False)
    result = EnrichmentPass()._suppress_web_rules_on_non_web_files([no_kind, no_flow])
    assert all(f.severity == Severity.INFO for f in result)


def test_library_profile_keeps_http_sourced_taint_flow(tmp_path):
    (tmp_path / "lib.py").write_text("def helper():\n    return 1\n", encoding="utf-8")
    context = type("Ctx", (), {
        "config": ScanConfig(target=tmp_path, profile="library"),
        "target_path": tmp_path,
        "metadata": {},
        "result": ScanResult(),
    })()
    finding = _finding(str(tmp_path / "lib.py"), source_kind="http_input")
    [kept] = EnrichmentPass()._apply_profile_filter([finding], context)
    assert kept.severity == Severity.MEDIUM
