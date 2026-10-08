"""Server-side template injection (CWE-1336) taint rules for JS and Java.

The template source itself must be attacker-controlled. User input passed as
template *data* (a render context) is the normal, escaped case and must not
be flagged. Requires the Opengrep binary.
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


def _hits(tmp_path, filename, rule_file, source, rule_id, language):
    (tmp_path / filename).write_text(source, encoding="utf-8")
    findings = OpengrepAdapter().scan_with_rules(
        tmp_path, [RULES_DIR / rule_file], languages=[language]
    )
    return [f for f in findings if f.rule_id == rule_id]


class TestJavaScript:
    RULE = "tnt-js-ssti-001"

    def _scan(self, tmp_path, body):
        src = "const express = require('express');\nconst app = express();\n" + body + "\n"
        return _hits(tmp_path, "app.js", "javascript_taint.yaml", src, self.RULE, "javascript")

    @pytest.mark.parametrize(
        "call",
        [
            "ejs.render(req.body.tpl, {})",
            "pug.compile(req.query.t)()",
            "Handlebars.compile(req.body.tpl)({})",
            "nunjucks.renderString(req.query.t, {})",
            "_.template(req.body.t)({})",
        ],
    )
    def test_user_controlled_template_source(self, tmp_path, call):
        assert self._scan(tmp_path, f"app.post('/p', (req, res) => {{ res.send({call}); }});")

    def test_user_input_as_template_data_is_safe(self, tmp_path):
        body = "app.get('/p', (req, res) => { res.send(ejs.render('<p><%= name %></p>', { name: req.query.name })); });"
        assert not self._scan(tmp_path, body)

    def test_render_named_view_is_safe(self, tmp_path):
        assert not self._scan(tmp_path, "app.get('/p', (req, res) => { res.render('page', { q: req.query.q }); });")


class TestJava:
    RULE = "tnt-ja-ssti-001"

    def _scan(self, tmp_path, src):
        return _hits(tmp_path, "Render.java", "java_taint.yaml", src, self.RULE, "java")

    def test_velocity_evaluate_request_template(self, tmp_path):
        src = (
            "import javax.servlet.http.*;\nimport java.io.StringWriter;\n"
            "import org.apache.velocity.app.Velocity;\nimport org.apache.velocity.VelocityContext;\n"
            "public class Render extends HttpServlet {\n"
            "  protected void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {\n"
            "    StringWriter out = new StringWriter();\n"
            '    Velocity.evaluate(new VelocityContext(), out, "t", request.getParameter("tpl"));\n'
            "  }\n}\n"
        )
        assert self._scan(tmp_path, src)

    def test_freemarker_template_from_request_param(self, tmp_path):
        src = (
            "import java.io.StringReader;\nimport freemarker.template.*;\n"
            "import org.springframework.web.bind.annotation.*;\n"
            "@RestController\npublic class Render {\n"
            "  private Configuration cfg;\n"
            '  @PostMapping("/render")\n'
            "  public String render(@RequestParam String tpl) throws Exception {\n"
            '    Template t = new Template("user", new StringReader(tpl), cfg);\n'
            "    return t.toString();\n"
            "  }\n}\n"
        )
        assert self._scan(tmp_path, src)

    def test_user_input_in_velocity_context_is_safe(self, tmp_path):
        src = (
            "import javax.servlet.http.*;\nimport java.io.StringWriter;\n"
            "import org.apache.velocity.app.Velocity;\nimport org.apache.velocity.VelocityContext;\n"
            "public class Render extends HttpServlet {\n"
            "  protected void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {\n"
            "    VelocityContext ctx = new VelocityContext();\n"
            '    ctx.put("name", request.getParameter("name"));\n'
            "    StringWriter out = new StringWriter();\n"
            '    Velocity.evaluate(ctx, out, "t", "Hello $name");\n'
            "  }\n}\n"
        )
        assert not self._scan(tmp_path, src)
