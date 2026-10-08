"""tnt-go-xss-001: request input written raw into an HTTP response.

Go had no XSS rule. The sinks are an http.ResponseWriter written without
escaping (fmt.Fprint/Fprintf, io.WriteString, Write) and html/template's
escape-bypassing types (template.HTML, template.JS, template.HTMLAttr).
Writing to anything that is not the response, or JSON-encoding, is not XSS.
Requires the Opengrep binary.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from rowan.taint.opengrep_adapter import OpengrepAdapter

RULES_DIR = Path(__file__).parent.parent / "rules"
RULE = "tnt-go-xss-001"

pytestmark = pytest.mark.skipif(
    not OpengrepAdapter().is_installed(),
    reason="Opengrep binary not installed; these tests need a live scan.",
)


def _hits(tmp_path, imports: str, body: str):
    src = (
        "package main\n\nimport (\n"
        + "".join(f'\t"{i}"\n' for i in imports.split())
        + ")\n\n"
        + "func handle(w http.ResponseWriter, r *http.Request) {\n"
        + body
        + "}\n"
    )
    (tmp_path / "main.go").write_text(src, encoding="utf-8")
    findings = OpengrepAdapter().scan_with_rules(
        tmp_path, [RULES_DIR / "go_taint.yaml"], languages=["go"]
    )
    return [f for f in findings if f.rule_id == RULE]


class TestFlagged:
    def test_fprintf_query_param_into_response(self, tmp_path):
        body = '\tname := r.URL.Query().Get("name")\n\tfmt.Fprintf(w, "<h1>Hello %s</h1>", name)\n'
        assert _hits(tmp_path, "fmt net/http", body)

    def test_write_form_value_bytes(self, tmp_path):
        assert _hits(tmp_path, "net/http", '\tw.Write([]byte(r.FormValue("q")))\n')

    def test_io_write_string(self, tmp_path):
        assert _hits(tmp_path, "io net/http", '\tio.WriteString(w, r.FormValue("q"))\n')

    def test_explicit_html_content_type_still_flagged(self, tmp_path):
        body = (
            '\tw.Header().Set("Content-Type", "text/html; charset=utf-8")\n'
            '\tw.Write([]byte(r.FormValue("q")))\n'
        )
        assert _hits(tmp_path, "net/http", body)

    def test_template_html_bypasses_escaping(self, tmp_path):
        body = (
            '\tbio := template.HTML(r.FormValue("bio"))\n'
            '\ttmpl.Execute(w, map[string]any{"Bio": bio})\n'
        )
        assert _hits(tmp_path, "html/template net/http", body)


class TestNotFlagged:
    def test_html_escaped_value(self, tmp_path):
        body = '\tname := html.EscapeString(r.URL.Query().Get("name"))\n\tfmt.Fprintf(w, "<h1>%s</h1>", name)\n'
        assert not _hits(tmp_path, "fmt html net/http", body)

    def test_constant_output(self, tmp_path):
        assert not _hits(tmp_path, "fmt net/http", '\tfmt.Fprintf(w, "<h1>Hello</h1>")\n')

    def test_writing_to_stdout_is_not_xss(self, tmp_path):
        body = '\tfmt.Fprintf(os.Stdout, "%s\\n", r.FormValue("q"))\n'
        assert not _hits(tmp_path, "fmt os net/http", body)

    def test_non_html_content_type_is_not_xss(self, tmp_path):
        # Seen on a real gateway: JSON and attachment bodies a browser will not render.
        body = (
            '\tw.Header().Set("Content-Type", "application/json")\n'
            '\tw.Write([]byte(r.FormValue("q")))\n'
        )
        assert not _hits(tmp_path, "net/http", body)

    def test_json_encoding_is_not_xss(self, tmp_path):
        body = '\tjson.NewEncoder(w).Encode(map[string]string{"q": r.FormValue("q")})\n'
        assert not _hits(tmp_path, "encoding/json net/http", body)
