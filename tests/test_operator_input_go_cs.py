"""Operator input is not attacker input: Go and C# (#73).

Env vars and argv are set by whoever runs the program. Go log/header rules
and the C# path/SSRF/XSS/deser/LDAP/log rules no longer take them. C# SQL and
command injection keep them in WARNING `-002` siblings with
`source_kind: operator_input`, as Java (EXT-19) and Go already do.
Requires the Opengrep binary.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from rowan.taint.opengrep_adapter import OpengrepAdapter

RULES_DIR = Path(__file__).parent.parent / "rules"

pytestmark = pytest.mark.skipif(
    not OpengrepAdapter().is_installed(),
    reason="Opengrep binary not installed; these tests need a live scan.",
)


def _findings(tmp_path, filename, rule_file, language, src):
    (tmp_path / filename).write_text(src, encoding="utf-8")
    return OpengrepAdapter().scan_with_rules(tmp_path, [RULES_DIR / rule_file], languages=[language])


def _go(body):
    return (
        "package main\n\n"
        'import (\n\t"log"\n\t"net/http"\n\t"os"\n)\n\n'
        "func h(w http.ResponseWriter, r *http.Request) {\n" + body + "}\n"
    )


def _cs(body):
    return (
        "using System;\nusing System.Data.SqlClient;\nusing System.Diagnostics;\nusing System.IO;\n"
        "using Microsoft.AspNetCore.Mvc;\n\n"
        "public class C : Controller {\n"
        "    public void Run([FromQuery] string q, string[] args) {\n" + body + "    }\n}\n"
    )


GO_ENV = '\tv := os.Getenv("X")\n'
GO_HTTP = '\tv := r.FormValue("x")\n'


@pytest.mark.parametrize(
    "rule_id,sink",
    [("tnt-go-log-001", '\tlog.Printf("%s", v)\n'), ("tnt-go-header-001", '\tw.Header().Set("X", v)\n')],
)
def test_go_log_and_header_ignore_operator_input(tmp_path, rule_id, sink):
    env = _findings(tmp_path, "main.go", "go_taint.yaml", "go", _go(GO_ENV + sink))
    assert rule_id not in {f.rule_id for f in env}
    http = _findings(tmp_path, "main.go", "go_taint.yaml", "go", _go(GO_HTTP + sink))
    assert rule_id in {f.rule_id for f in http}


CS_ENV = '        var v = Environment.GetEnvironmentVariable("X");\n'
CS_ARGV = "        var v = args[0];\n"
CS_HTTP = "        var v = q;\n"

CS_NOT_OPERATOR = [
    ("tnt-cs-path-001", "        File.ReadAllText(v);\n"),
    ("tnt-cs-xss-001", "        Response.Write(v);\n"),
    ("tnt-cs-log-001", "        _logger.LogInformation(v);\n"),
]


@pytest.mark.parametrize("source", [CS_ENV, CS_ARGV])
@pytest.mark.parametrize("rule_id,sink", CS_NOT_OPERATOR)
def test_cs_rules_ignore_operator_input(tmp_path, source, rule_id, sink):
    ids = {f.rule_id for f in _findings(tmp_path, "C.cs", "csharp_taint.yaml", "csharp", _cs(source + sink))}
    assert rule_id not in ids


@pytest.mark.parametrize("rule_id,sink", CS_NOT_OPERATOR)
def test_cs_rules_still_take_http_input(tmp_path, rule_id, sink):
    ids = {f.rule_id for f in _findings(tmp_path, "C.cs", "csharp_taint.yaml", "csharp", _cs(CS_HTTP + sink))}
    assert rule_id in ids


CS_OPERATOR_SIBLINGS = [
    ("tnt-cs-sqli", '        new SqlCommand("SELECT * FROM t WHERE n = " + v);\n'),
    ("tnt-cs-cmdi", "        Process.Start(v);\n"),
]


@pytest.mark.parametrize("source", [CS_ENV, CS_ARGV])
@pytest.mark.parametrize("family,sink", CS_OPERATOR_SIBLINGS)
def test_cs_sql_and_command_report_operator_input_as_warning(tmp_path, source, family, sink):
    found = _findings(tmp_path, "C.cs", "csharp_taint.yaml", "csharp", _cs(source + sink))
    ids = {f.rule_id for f in found}
    assert f"{family}-001" not in ids
    assert f"{family}-002" in ids
    sibling = next(f for f in found if f.rule_id == f"{family}-002")
    assert sibling.metadata.get("source_kind") == "operator_input"


@pytest.mark.parametrize("family,sink", CS_OPERATOR_SIBLINGS)
def test_cs_sql_and_command_http_input_stays_in_001(tmp_path, family, sink):
    ids = {f.rule_id for f in _findings(tmp_path, "C.cs", "csharp_taint.yaml", "csharp", _cs(CS_HTTP + sink))}
    assert f"{family}-001" in ids
    assert f"{family}-002" not in ids
