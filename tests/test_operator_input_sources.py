"""Operator input is not attacker input (#73).

CLI arguments, environment variables and `input()` are set by whoever runs
the program. Most taint rules dropped them as sources; SQL and command
injection keep them, and enrichment reports those findings at MEDIUM with
`operator_controlled_source` instead of at the HTTP severity.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from rowan.config import ScanConfig
from rowan.core.findings import Category, Finding, ScanResult, Severity, TaintFlow, TaintNode
from rowan.passes.enrichment import EnrichmentPass
from rowan.taint.opengrep_adapter import OpengrepAdapter

RULES_DIR = Path(__file__).parent.parent / "rules"
RULE_FILES = sorted(RULES_DIR.glob("*taint*.yaml"))

needs_opengrep = pytest.mark.skipif(
    not OpengrepAdapter().is_installed(),
    reason="Opengrep binary not installed; these tests need a live scan.",
)


def _rule_ids(tmp_path, src):
    (tmp_path / "app.py").write_text(src, encoding="utf-8")
    findings = OpengrepAdapter().scan_with_rules(tmp_path, RULE_FILES, languages=["python"])
    return {f.rule_id for f in findings}


@needs_opengrep
@pytest.mark.parametrize(
    "src,rule_id",
    [
        ("import sys, joblib\njoblib.load(sys.argv[1])\n", "TNT-DESER-005"),
        ("import sys, joblib\njoblib.load(sys.argv[1])\n", "TNT-AIML-003"),
        ("import os, requests\nrequests.get(os.getenv('API_URL'))\n", "TNT-SSRF-001"),
        ("import os\nfrom a2a.client import A2ACardResolver\n"
         "A2ACardResolver(httpx_client=c, base_url=os.getenv('REMOTE_AGENT_URL'))\n", "TNT-A2A-001"),
        ("import logging\nlogging.info(input('name: '))\n", "TNT-LOG-001"),
    ],
)
def test_operator_input_is_not_a_source(tmp_path, src, rule_id):
    assert rule_id not in _rule_ids(tmp_path, src)


@needs_opengrep
@pytest.mark.parametrize(
    "src,rule_id",
    [
        ("import joblib\nfrom flask import request\n"
         "def h():\n    joblib.load(request.args.get('p'))\n", "TNT-DESER-005"),
        ("import requests\nfrom flask import request\n"
         "def h():\n    requests.get(request.args.get('u'))\n", "TNT-SSRF-001"),
    ],
)
def test_http_input_still_fires(tmp_path, src, rule_id):
    assert rule_id in _rule_ids(tmp_path, src)


@needs_opengrep
@pytest.mark.parametrize(
    "src,rule_id",
    [
        ("import os, sys\nos.system(sys.argv[1])\n", "TNT-CMDI-001"),
        ("import os\nos.system('ls ' + os.environ['DIR'])\n", "TNT-CMDI-001"),
        ("def main(args, cursor):\n    cursor.execute('SELECT * FROM t WHERE n = ' + args.name)\n",
         "TNT-SQLI-002"),
    ],
)
def test_sql_and_command_rules_keep_operator_input(tmp_path, src, rule_id):
    assert rule_id in _rule_ids(tmp_path, src)


def _enrich(tmp_path, rule_id, category, source_line):
    fp = tmp_path / "app.py"
    fp.write_text(f"import os, sys\nfrom flask import request\n{source_line}\nos.system(x)\n", encoding="utf-8")
    finding = Finding(
        rule_id=rule_id,
        message="m",
        severity=Severity.HIGH,
        category=category,
        file_path=str(fp),
        start_line=4,
        engine="opengrep",
        taint_flow=TaintFlow(
            source=TaintNode(file_path=str(fp), line=3, snippet=source_line),
            sink=TaintNode(file_path=str(fp), line=4),
        ),
    )
    ctx = type(
        "Ctx",
        (),
        {
            "target_path": tmp_path,
            "config": ScanConfig(target=tmp_path),
            "result": ScanResult(findings=[finding]),
            "metadata": {},
        },
    )()
    EnrichmentPass().run(ctx)
    return ctx.result.findings[0]


@pytest.mark.parametrize("source_line", ["x = sys.argv[1]", "x = os.environ['DIR']", "x = input()"])
def test_operator_sourced_finding_is_medium(tmp_path, source_line):
    f = _enrich(tmp_path, "TNT-CMDI-001", Category.COMMAND_INJECTION, source_line)
    assert f.severity == Severity.MEDIUM
    assert f.metadata["operator_controlled_source"] is True


def test_http_sourced_finding_keeps_severity(tmp_path):
    f = _enrich(tmp_path, "TNT-CMDI-001", Category.COMMAND_INJECTION, "x = request.args.get('c')")
    assert f.severity == Severity.HIGH
    assert "operator_controlled_source" not in f.metadata
