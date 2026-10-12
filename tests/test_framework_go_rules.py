"""Gin/Echo framework regex rules (#53, #56). Runs the converted rules.
Requires the Opengrep binary.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from rowan.taint.opengrep_adapter import OpengrepAdapter

RULES = Path(__file__).parent.parent / "rules"

pytestmark = pytest.mark.skipif(
    not OpengrepAdapter().is_installed(),
    reason="Opengrep binary not installed; these tests need a live scan.",
)


def _ids(tmp_path, rule_file, body):
    src = "package main\n\nfunc h(c *gin.Context) {\n\t" + body + "\n}\n"
    (tmp_path / "main.go").write_text(src, encoding="utf-8")
    return {f.rule_id for f in OpengrepAdapter().scan_with_rules(tmp_path, [RULES / rule_file], languages=["go"])}


@pytest.mark.parametrize(
    "rule_id,body",
    [
        ("ns-fw-go-002", "r.Use(cors.Default())"),
        ("ns-fw-go-002", "handler := cors.AllowAll().Handler(mux)"),
        ("ns-fw-go-002", "r.Use(cors.New(cors.Config{AllowAllOrigins: true}))"),
        ("ns-fw-go-005", 'c.Redirect(302, c.QueryParam("next"))'),
        ("ns-fw-go-005", 'c.Redirect(302, c.Query("next"))'),
    ],
)
def test_fires(tmp_path, rule_id, body):
    assert rule_id in _ids(tmp_path, "converted/framework_rules.yaml", body), body


def test_gin_html_render_is_not_flagged_as_xss(tmp_path):
    # Gin's c.HTML renders through html/template, which escapes by context.
    body = 'c.HTML(200, "t.html", gin.H{"q": c.Query("q")})'
    assert "ns-fw-go-003" not in _ids(tmp_path, "converted/framework_rules.yaml", body)


def test_template_html_from_request_is_the_taint_rule(tmp_path):
    body = 'q := c.Query("q")\n\tc.HTML(200, "t.html", gin.H{"q": template.HTML(q)})'
    assert "tnt-go-xss-001" in _ids(tmp_path, "go_taint.yaml", body)
