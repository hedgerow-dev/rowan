"""Regression tests for enrichment pipeline ordering and boundary detection.

_score_confidence used to run AFTER the false-positive suppression heuristics
in EnrichmentPass.run(), so its unconditional per-engine confidence
assignment (0.65-0.90 for opengrep taint findings) clobbered the min()-based
demotions those heuristics had just applied -- a finding correctly downgraded
to severity=INFO retained a misleadingly high confidence score. Fixed by
scoring confidence first, so every suppressor's min(f.confidence, X) call
lowers a real baseline instead of getting overwritten afterward.

Also covers the FastAPI external-boundary detection gap in _cap_exploitability:
@app.route (Flask) was recognized but @app.get/post/put/delete (FastAPI's
primary routing style) was not, causing real internet-facing findings in
FastAPI apps to be force-capped to MEDIUM severity.

DEF-6 (historical): a finding's category used to be corrected mid-run(), from
opengrep's SARIF-inferred fallback (GENERAL by default, since SARIF 1.22.0
doesn't propagate metadata: into properties) to the rule's real declared
category -- but that correction ran AFTER every category-gated suppressor
(_apply_profile_filter, _suppress_ai_on_non_ai,
_suppress_web_rules_on_non_web_files), so they all silently checked the wrong
(GENERAL) category on the default engine path. Issue #118 removed the whole
SARIF-based parse path (and the manifest-based category correction it
required): OpengrepAdapter now parses Opengrep's native --json output
directly, which carries the rule's declared category inline per-result, so
every Finding gets the right category at creation time and this class of
ordering bug can't recur -- there's no more correction step to order.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from rowan.config import ScanConfig
from rowan.core.findings import Category, Finding, ScanResult, Severity, TaintFlow, TaintNode
from rowan.passes.base import ScanContext
from rowan.passes.enrichment import EnrichmentPass


def _run_enrichment(findings: list[Finding]) -> list[Finding]:
    ctx = type(
        "Ctx",
        (),
        {
            "target_path": Path("."),
            "config": ScanConfig(target=Path(".")),
            "result": ScanResult(findings=findings),
            "metadata": {},
        },
    )()
    EnrichmentPass().run(ctx)
    return ctx.result.findings


class TestConfidenceNotClobberedBySuppression:
    def test_test_findings_are_audit_only(self):
        finding = Finding(
            rule_id="TNT-TEST-001",
            message="fixture sink",
            severity=Severity.MEDIUM,
            category=Category.INJECTION,
            file_path="tests/test_handler.py",
            start_line=10,
            engine="opengrep",
        )

        result = EnrichmentPass()._suppress_test_findings([finding])

        assert result[0].severity == Severity.LOW
        assert result[0].confidence <= 0.4
        assert result[0].metadata["test_context"] is True

    def test_test_graph_topology_lead_is_not_actionable(self):
        finding = Finding(
            rule_id="ns-aiml-138",
            message="unbounded topology",
            severity=Severity.MEDIUM,
            category=Category.AI_ML,
            file_path="tests/test_graph.py",
            start_line=10,
            engine="opengrep",
        )

        result = EnrichmentPass()._suppress_test_findings([finding])

        assert result[0].severity == Severity.LOW
        assert result[0].confidence <= 0.3
        assert result[0].metadata["test_topology_lead"] is True

    def test_parent_temp_directory_named_after_test_does_not_demote_target_file(self, tmp_path):
        target = tmp_path / "test_named_parent" / "target"
        target.mkdir(parents=True)
        source = target / "broker.py"
        source.write_text("value = 1\n", encoding="utf-8")
        finding = Finding(
            rule_id="TNT-DESER-001",
            message="production sink",
            severity=Severity.HIGH,
            category=Category.DESERIALIZATION,
            file_path=str(source),
            start_line=1,
            engine="opengrep",
        )
        context = ScanContext(
            target_path=target,
            config=ScanConfig(target=target),
            result=ScanResult(findings=[finding]),
        )

        result = EnrichmentPass()._suppress_test_findings([finding], context)

        assert result[0].severity == Severity.HIGH
        assert "test_context" not in result[0].metadata

    def test_full_pipeline_keeps_suppressed_confidence_low(self):
        """An opengrep taint finding suppressed as a non-web-file false
        positive must not have its confidence raised back to 0.65-0.90 by
        the engine-based scoring step later in the pipeline."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".py", delete=False, encoding="utf-8"
        ) as fh:
            fh.write("import math\nresult = math.sqrt(4)\n")
            tmp_path = fh.name

        try:
            findings = [
                Finding(
                    rule_id="TNT-SSRF-001",
                    message="ssrf",
                    severity=Severity.HIGH,
                    category=Category.SSRF,
                    file_path=tmp_path,
                    start_line=2,
                    engine="opengrep",
                    confidence=0.9,
                    taint_flow=TaintFlow(
                        source=TaintNode(file_path=tmp_path, line=1),
                        sink=TaintNode(file_path=tmp_path, line=2),
                        intermediate=[],
                    ),
                ),
            ]
            result = _run_enrichment(findings)
        finally:
            Path(tmp_path).unlink(missing_ok=True)

        assert len(result) == 1
        f = result[0]
        assert f.severity == Severity.INFO
        assert f.metadata.get("web_context_gate") is True
        assert f.confidence <= 0.3, (
            f"suppressed finding's confidence was raised back up to {f.confidence} "
            "by engine-based scoring running after suppression"
        )

    def test_unsuppressed_taint_finding_still_gets_baseline_confidence(self):
        """A finding with no matching suppression heuristic must still get
        the normal engine-based confidence baseline (regression guard for
        the reorder itself)."""
        findings = [
            Finding(
                rule_id="TEST-002",
                message="Test",
                severity=Severity.HIGH,
                category=Category.GENERAL,
                file_path="b.py",
                start_line=20,
                engine="opengrep",
                confidence=1.0,
                taint_flow=TaintFlow(
                    source=TaintNode(file_path="b.py", line=5),
                    sink=TaintNode(file_path="b.py", line=20),
                    intermediate=[],
                ),
            ),
        ]
        result = _run_enrichment(findings)
        assert result[0].confidence >= 0.80


class TestFastAPIExternalBoundary:
    def test_fastapi_get_decorator_recognized_as_external_boundary(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".py", delete=False, encoding="utf-8"
        ) as fh:
            fh.write(
                "from fastapi import FastAPI\n"
                "app = FastAPI()\n\n"
                "@app.get('/items/{item_id}')\n"
                "def read_item(item_id: str):\n"
                "    return eval(item_id)\n"
            )
            tmp_path = fh.name

        try:
            findings = [
                Finding(
                    rule_id="NS-EVAL-001",
                    message="eval",
                    severity=Severity.HIGH,
                    category=Category.INJECTION,
                    file_path=tmp_path,
                    start_line=5,
                    engine="neuroscan",
                    confidence=0.9,
                ),
            ]
            ep = EnrichmentPass()
            result = ep._cap_exploitability(findings)
        finally:
            Path(tmp_path).unlink(missing_ok=True)

        # An @app.get-decorated endpoint is internet-facing -- _cap_exploitability
        # must leave severity uncapped (HIGH), not force it down to MEDIUM.
        assert result[0].severity == Severity.HIGH


class TestMcpConfigExemptFromExploitabilityCap:
    def test_mcp_config_finding_severity_not_capped(self, tmp_path):
        """_cap_exploitability reads a finding's file "head" for
        route-decorator/import evidence of an external boundary -- a
        meaningless signal for a JSON deployment artifact (no Python source
        to read). Before the engine=="mcpconfig" exemption, every one of
        these findings fell through to the function's default "no signal
        found" MEDIUM cap, silently downgrading a HIGH over-privileged-server
        finding regardless of mcp_config.py's own severity assignment."""
        fp = tmp_path / "mcp.json"
        fp.write_text('{"mcpServers": {}}', encoding="utf-8")
        findings = [
            Finding(
                rule_id="MCP-CONFIG-002",
                message="over-privileged",
                severity=Severity.HIGH,
                category=Category.AI_ML,
                file_path=str(fp),
                start_line=1,
                engine="mcpconfig",
                confidence=0.65,
            ),
        ]
        ep = EnrichmentPass()
        result = ep._cap_exploitability(findings)
        assert result[0].severity == Severity.HIGH


class TestWebGateSeesCorrectCategoryFromCreation:
    def test_web_gate_applies_to_opengrep_finding_with_auth_category(self):
        """An opengrep-engine finding declared as AUTH (read directly from
        Opengrep's --json metadata at parse time, per issue #118 -- no more
        mid-pipeline manifest correction) must go through
        _suppress_web_rules_on_non_web_files like any other category."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".py", delete=False, encoding="utf-8"
        ) as fh:
            fh.write("import requests\nrequests.get('https://example.com')\n")
            tmp_path = fh.name

        try:
            findings = [
                Finding(
                    rule_id="ns-fw-js-003",
                    message="csrf",
                    severity=Severity.MEDIUM,
                    category=Category.AUTH,
                    file_path=tmp_path,
                    start_line=2,
                    engine="opengrep",
                    confidence=0.7,
                ),
            ]
            result = _run_enrichment(findings)
        finally:
            Path(tmp_path).unlink(missing_ok=True)

        assert len(result) == 1
        f = result[0]
        assert f.category == Category.AUTH
        assert f.metadata.get("web_context_gate") is True, (
            "web-framework-context gate did not apply to an auth-category finding "
            "on a file with no web-framework imports"
        )
        assert f.severity == Severity.INFO
        assert f.confidence <= 0.3


class TestTimingAttackAuthContextEscalation:
    """DEF-43: ns-infra-001 ("timing attack in string comparison", CWE-208)
    ships with severity: info in misc_rules.yaml, so it was permanently
    invisible to the README-recommended `rowan scan . --severity high`
    CI gate regardless of context -- the same failure mode BACKLOG.md DEF-2
    fixed for deserialization/command-injection sinks.
    _suppress_non_auth_timing now matches _AUTH_CONTEXT_RE within a +/-20 line
    window of the finding (was: anywhere in the whole file, confirmed too
    coarse -- see below) and records `auth_context_confirmed` on the hits.

    It deliberately does NOT escalate severity. The narrowing is measured; the
    escalation was not. On chainlit + flashrag, all 8 real ns-infra-001
    findings stayed INFO and none reached the confirmed branch, so raising
    severity there would ship on a plausibility argument with no real-world
    case behind it. These tests lock in that decision: a confirmed hit keeps
    the rule's own severity and carries the marker, so a future escalation can
    be gated on the marker once a corpus actually exercises the path.
    """

    def test_confirmed_auth_context_is_marked_but_not_escalated(self, tmp_path):
        """A password comparison inside a Flask login route is genuine auth
        context and network-reachable, so it gets the marker -- but severity
        stays at the rule's own INFO until the escalation is validated."""
        fp = tmp_path / "login.py"
        fp.write_text(
            "from flask import Flask, request\n"
            "app = Flask(__name__)\n\n\n"
            "@app.route('/login', methods=['POST'])\n"
            "def login():\n"
            "    supplied = request.form['password']\n"
            "    if supplied == STORED_PASSWORD:\n"
            "        return 'ok'\n"
            "    return 'denied', 403\n",
            encoding="utf-8",
        )
        findings = [
            Finding(
                rule_id="ns-infra-001",
                message="timing attack",
                severity=Severity.INFO,
                category=Category.CRYPTO,
                file_path=str(fp),
                start_line=7,
                engine="neuroscan",
                confidence=0.6,
            ),
        ]
        result = _run_enrichment(findings)
        assert len(result) == 1
        f = result[0]
        assert f.metadata.get("auth_context_confirmed") is True
        assert f.severity == Severity.INFO, (
            f"escalation is deliberately not enabled -- a confirmed auth "
            f"context should keep the rule's own severity, got {f.severity}"
        )
        assert f.metadata.get("no_auth_context") is None

    def test_confirmed_auth_context_outside_web_boundary_also_not_escalated(self, tmp_path):
        """A bcrypt-adjacent secret comparison with no web-framework boundary
        is also marked and also not escalated -- the marker records auth
        proximity, it does not assert reachability."""
        fp = tmp_path / "auth_utils.py"
        fp.write_text(
            "import bcrypt\n\n\n"
            "def check_password(candidate, expected_hash):\n"
            "    if candidate == expected_hash:\n"
            "        return True\n"
            "    return False\n",
            encoding="utf-8",
        )
        findings = [
            Finding(
                rule_id="ns-infra-001",
                message="timing attack",
                severity=Severity.INFO,
                category=Category.CRYPTO,
                file_path=str(fp),
                start_line=5,
                engine="neuroscan",
                confidence=0.6,
            ),
        ]
        result = _run_enrichment(findings)
        assert len(result) == 1
        f = result[0]
        assert f.metadata.get("auth_context_confirmed") is True
        assert f.severity == Severity.INFO, (
            f"escalation is deliberately not enabled, got {f.severity}"
        )

    def test_no_auth_context_anywhere_stays_info(self, tmp_path):
        """A plain equality check with no auth-related identifier anywhere
        near it must stay suppressed to INFO/low confidence -- unchanged
        baseline behavior for the non-auth case."""
        fp = tmp_path / "compare.py"
        fp.write_text(
            "def check_signature(sig, expected):\n"
            "    if sig == expected:\n"
            "        return True\n"
            "    return False\n",
            encoding="utf-8",
        )
        findings = [
            Finding(
                rule_id="ns-infra-001",
                message="timing attack",
                severity=Severity.INFO,
                category=Category.CRYPTO,
                file_path=str(fp),
                start_line=2,
                engine="neuroscan",
                confidence=0.6,
            ),
        ]
        result = _run_enrichment(findings)
        assert len(result) == 1
        f = result[0]
        assert f.severity == Severity.INFO
        assert f.confidence <= 0.1
        assert f.metadata.get("no_auth_context") is True

    def test_auth_context_word_far_outside_window_does_not_confirm(self, tmp_path):
        """Regression guard for the original whole-file bug: an incidental
        `hashlib` import at the top of a large file (used for something
        unrelated, e.g. a cache key) must not confirm auth context for an
        unrelated comparison dozens of lines away. Confirmed empirically
        against the pre-fix whole-file version of this suppressor that this
        exact shape (hashlib import + a same-named-as-a-secret-category
        comparison far below it) sailed through untouched."""
        filler = "\n".join(f"# filler line {i}" for i in range(40))
        fp = tmp_path / "big_module.py"
        fp.write_text(
            "import hashlib\n\n"
            "def cache_key(text):\n"
            "    return hashlib.sha256(text.encode()).hexdigest()\n\n"
            f"{filler}\n\n"
            "def tokenize(text, stop_token):\n"
            "    out = []\n"
            "    for token in text.split():\n"
            "        if token == stop_token:\n"
            "            break\n"
            "        out.append(token)\n"
            "    return out\n",
            encoding="utf-8",
        )
        content = fp.read_text(encoding="utf-8")
        match_line = next(
            i
            for i, line in enumerate(content.splitlines(), start=1)
            if "if token == stop_token" in line
        )
        findings = [
            Finding(
                rule_id="ns-infra-001",
                message="timing attack",
                severity=Severity.INFO,
                category=Category.CRYPTO,
                file_path=str(fp),
                start_line=match_line,
                engine="neuroscan",
                confidence=0.6,
            ),
        ]
        result = _run_enrichment(findings)
        assert len(result) == 1
        f = result[0]
        assert f.severity == Severity.INFO, (
            "an unrelated `hashlib` import far outside the proximity window "
            f"must not confirm auth context, got severity={f.severity}"
        )
        assert f.metadata.get("no_auth_context") is True


class TestEngineFindingsKeepTheirSeverity:
    """#60: the exploitability cap re-judged evidence-bearing engine findings
    from a 50-line file-head regex, so one route's shell injection was HIGH,
    MEDIUM or LOW depending on the router's variable name and whether the head
    happened to contain open(...)."""

    _HANDLER = (
        "@{router}.post('/run')\n"
        "def run(host: str):\n"
        "    subprocess.run('ping ' + host, shell=True)\n"
    )

    def _cap(self, tmp_path, head: str, router: str, engine: str) -> Severity:
        fp = tmp_path / f"{router}_{engine}.py"
        fp.write_text(head + self._HANDLER.format(router=router), encoding="utf-8")
        f = Finding(
            rule_id="HTTP-ROUTE-001", message="m", severity=Severity.HIGH,
            category=Category.COMMAND_INJECTION, file_path=str(fp), start_line=3,
            engine=engine, confidence=0.9,
        )
        return EnrichmentPass()._cap_exploitability([f])[0].severity

    def test_engine_finding_is_not_capped_by_file_head(self, tmp_path):
        local_read = "import json, subprocess\ncfg = json.load(open('c.json'))\n"
        assert self._cap(tmp_path, local_read, "api", "crossfile") == Severity.HIGH
        assert self._cap(tmp_path, "import subprocess\n", "items_router", "crossfile") == Severity.HIGH

    def test_pattern_finding_is_still_capped(self, tmp_path):
        local_read = "import json, subprocess\ncfg = json.load(open('c.json'))\n"
        assert self._cap(tmp_path, local_read, "api", "neuroscan") == Severity.LOW


def test_http_boundary_findings_count_as_proven_external_input():
    from rowan.passes.enrichment import _has_proven_external_source

    route = Finding(rule_id="HTTP-ROUTE-001", message="m", severity=Severity.HIGH,
                    category=Category.COMMAND_INJECTION, file_path="a.py", start_line=1,
                    engine="crossfile", metadata={"boundary_source": True, "source_kind": "http_input"})
    assert _has_proven_external_source(route)
    pattern = Finding(rule_id="NS-CMDI-002", message="m", severity=Severity.HIGH,
                      category=Category.COMMAND_INJECTION, file_path="a.py", start_line=1,
                      engine="neuroscan", metadata={"source_kind": "http_input"})
    assert not _has_proven_external_source(pattern)
