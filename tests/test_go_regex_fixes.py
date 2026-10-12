"""Go regex rules that fired on safe code or missed common forms (#56).

Runs the converted rules, the default engine. Requires the Opengrep binary.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from rowan.taint.opengrep_adapter import OpengrepAdapter

CONVERTED = Path(__file__).parent.parent / "rules" / "converted" / "go.yaml"

pytestmark = pytest.mark.skipif(
    not OpengrepAdapter().is_installed(),
    reason="Opengrep binary not installed; these tests need a live scan.",
)


def _ids(tmp_path, body, filename="main.go"):
    (tmp_path / filename).write_text("package main\n\nfunc h() {\n" + body + "}\n", encoding="utf-8")
    return {f.rule_id for f in OpengrepAdapter().scan_with_rules(tmp_path, [CONVERTED], languages=["go"])}


FIRES = [
    ("GO-INJECT-001", '\texec.Command("sh", "-c", "ping -c 1 "+host).Run()\n'),
    ("GO-INJECT-001", '\texec.CommandContext(ctx, "bash", "-c", cmd).Run()\n'),
    ("GO-INJECT-002", '\tq := fmt.Sprintf("SELECT * FROM users WHERE name = \'%s\'", name)\n'),
    ("GO-INJECT-002", '\tdb.QueryRow("select * from t where id=" + id)\n'),
    ("GO-INJECT-002", '\tdb.QueryContext(ctx, fmt.Sprintf("DELETE FROM t WHERE id = %s", id))\n'),
    ("GO-XSS-001", "\tv := template.HTML(comment)\n"),
    ("GO-XSS-001", '\tv := template.HTML("<b>" + name + "</b>")\n'),
    ("GO-CRYPTO-001", '\timport "crypto/rc4"\n'),
    ("GO-CRYPTO-002", "\ttoken := rand.Int63()\n"),
    ("GO-CRYPTO-002", "\tsessionID := fmt.Sprint(rand.Intn(1000000))\n"),
    ("GO-CONFIG-001", "\tcfg.InsecureSkipVerify = true\n"),
    ("GO-CONFIG-001", "\tc := &tls.Config{InsecureSkipVerify: true}\n"),
]

QUIET = [
    ("GO-INJECT-001", '\texec.Command("git", "status").Run()\n'),
    ("GO-INJECT-001", '\texec.Command("sh", "-c", "ls -la").Run()\n'),
    ("GO-XSS-001", '\tv := template.HTML("<b>static</b>")\n'),
    ("GO-CRYPTO-002", "\tjitter := time.Duration(rand.Intn(100)) * time.Millisecond\n"),
    ("GO-CRYPTO-002", '\timport "math/rand"\n'),
]


@pytest.mark.parametrize("rule_id,body", FIRES)
def test_fires(tmp_path, rule_id, body):
    assert rule_id in _ids(tmp_path, body), body


@pytest.mark.parametrize("rule_id,body", QUIET)
def test_quiet(tmp_path, rule_id, body):
    assert rule_id not in _ids(tmp_path, body), body


def test_tls_skip_in_test_file_is_quiet(tmp_path):
    assert "GO-CONFIG-001" not in _ids(tmp_path, "\tcfg.InsecureSkipVerify = true\n", "client_test.go")
