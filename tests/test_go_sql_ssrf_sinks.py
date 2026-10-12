"""Go SQL and SSRF sinks focus the argument that carries the risk (#56).

Shared registry sink fragments `sql_go` and `http_url_go` feed the SQL and
SSRF rules in go_taint.yaml and go_ai_taint.yaml. Requires the Opengrep binary.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from rowan.taint.opengrep_adapter import OpengrepAdapter

RULES = Path(__file__).parent.parent / "rules" / "go_taint.yaml"

pytestmark = pytest.mark.skipif(
    not OpengrepAdapter().is_installed(),
    reason="Opengrep binary not installed; these tests need a live scan.",
)

HEADER = (
    "package main\n\n"
    'import (\n\t"context"\n\t"database/sql"\n\t"fmt"\n\t"net/http"\n)\n\n'
    "func h(ctx context.Context, w http.ResponseWriter, r *http.Request, db *sql.DB, conn *pgx.Conn, client *http.Client) {\n"
    '\tid := r.FormValue("id")\n'
)


def _lines(tmp_path, rule_id, body):
    src = HEADER + body + "}\n"
    (tmp_path / "main.go").write_text(src, encoding="utf-8")
    findings = OpengrepAdapter().scan_with_rules(tmp_path, [RULES], languages=["go"])
    return {f.start_line for f in findings if f.rule_id == rule_id}


SQL_FIRES = [
    '\tdb.Query("SELECT * FROM t WHERE id = " + id)\n',
    '\tdb.QueryRow(fmt.Sprintf("SELECT * FROM t WHERE id = %s", id))\n',
    '\tconn.Query(ctx, "SELECT * FROM t WHERE id = " + id)\n',
    '\tgdb.Raw("SELECT * FROM t WHERE id = " + id)\n',
    "\tgdb.Where(\"name = '\" + id + \"'\")\n",
    '\tdb.Prepare("SELECT * FROM t WHERE id = " + id)\n',
]
SQL_QUIET = [
    '\tdb.Query("SELECT * FROM t WHERE id = $1", id)\n',
    '\tconn.Query(ctx, "SELECT * FROM t WHERE id = $1", id)\n',
    '\tstmt, _ := db.Prepare("SELECT * FROM t WHERE id = $1")\n\tstmt.QueryRow(id)\n',
    '\tgdb.Where("name = ?", id)\n',
]
SSRF_FIRES = [
    "\thttp.Get(id)\n",
    '\treq, _ := http.NewRequest("GET", id, nil)\n\tclient.Do(req)\n',
    "\tclient.Get(id)\n",
]
SSRF_QUIET = [
    '\thttp.Post("https://api.example.com/x", "application/json", r.Body)\n',
    '\treq, _ := http.NewRequest("POST", "https://api.example.com/x", r.Body)\n\thttp.DefaultClient.Do(req)\n',
]


@pytest.mark.parametrize("body", SQL_FIRES)
def test_sql_text_from_request_fires(tmp_path, body):
    assert _lines(tmp_path, "tnt-go-sqli-001", body), body


@pytest.mark.parametrize("body", SQL_QUIET)
def test_bound_parameter_is_quiet(tmp_path, body):
    assert not _lines(tmp_path, "tnt-go-sqli-001", body), body


@pytest.mark.parametrize("body", SSRF_FIRES)
def test_request_url_from_input_fires(tmp_path, body):
    assert _lines(tmp_path, "tnt-go-ssrf-001", body), body


@pytest.mark.parametrize("body", SSRF_QUIET)
def test_tainted_body_to_fixed_url_is_quiet(tmp_path, body):
    assert not _lines(tmp_path, "tnt-go-ssrf-001", body), body


def test_go_sql_and_ssrf_rules_share_the_registry_sinks():
    text = "".join(
        (Path(__file__).parent.parent / "rules" / f).read_text(encoding="utf-8")
        for f in ("go_taint.yaml", "go_ai_taint.yaml")
    )
    assert text.count("rowan-registry:begin sink=sql_go") == 4
    assert text.count("rowan-registry:begin sink=http_url_go") == 4
