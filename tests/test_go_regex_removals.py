"""Go regex rules that fired on every call are removed (#56).

GO-SSRF-001 fired on every http.Get (literal URLs too), GO-PATH-001 on every
os.Open("config.json"), GO-SUPPLY-001 on any `.Do(`, GO-AUTH-001 on every
ListenAndServe (plain HTTP behind a TLS proxy is normal) and GO-SSTI-001 on
any text/template import. go_taint covers SSRF and path traversal; template
injection becomes tnt-go-ssti-001: request input reaching Parse().
"""

from __future__ import annotations

from pathlib import Path

import pytest

from rowan.taint.opengrep_adapter import OpengrepAdapter

RULES = Path(__file__).parent.parent / "rules"


def test_removed_rules_are_gone():
    text = (RULES / "go.yaml").read_text(encoding="utf-8")
    for rid in ("GO-SSRF-001", "GO-PATH-001", "GO-SUPPLY-001", "GO-AUTH-001", "GO-SSTI-001"):
        assert f"id: {rid}\n" not in text, rid


needs_opengrep = pytest.mark.skipif(
    not OpengrepAdapter().is_installed(),
    reason="Opengrep binary not installed; these tests need a live scan.",
)

HEADER = 'package main\n\nimport (\n\t"net/http"\n\t"text/template"\n)\n\nfunc h(w http.ResponseWriter, r *http.Request) {\n'


def _ssti(tmp_path, body):
    (tmp_path / "main.go").write_text(HEADER + body + "}\n", encoding="utf-8")
    findings = OpengrepAdapter().scan_with_rules(tmp_path, [RULES / "go_taint.yaml"], languages=["go"])
    return [f for f in findings if f.rule_id == "tnt-go-ssti-001"]


@needs_opengrep
@pytest.mark.parametrize(
    "body",
    [
        '\tt, _ := template.New("x").Parse(r.FormValue("tpl"))\n\tt.Execute(w, nil)\n',
        '\ttpl := r.URL.Query().Get("tpl")\n\tt := template.New("x")\n\tt, _ = t.Parse(tpl)\n\tt.Execute(w, nil)\n',
    ],
)
def test_request_input_as_template_source_fires(tmp_path, body):
    assert _ssti(tmp_path, body), body


@needs_opengrep
def test_constant_template_with_request_data_is_quiet(tmp_path):
    body = '\tt, _ := template.New("x").Parse("Hello {{.}}")\n\tt.Execute(w, r.FormValue("name"))\n'
    assert _ssti(tmp_path, body) == []
