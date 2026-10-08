"""Open redirect (CWE-601) taint rules outside Python.

Python had TNT-REDIR-001; JavaScript only caught `res.redirect(userInput)` as
header injection (CWE-113), the wrong class: Node rejects CR/LF in header
values, while sending the victim to an attacker's site is the real risk.

Each rule gets a true positive per framework and a true negative with a
constant target. Requires the Opengrep binary.
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
    RULE = "tnt-js-redirect-001"

    def _scan(self, tmp_path, body, rule_id=RULE):
        src = f"const express = require('express');\nconst app = express();\n{body}\n"
        return _hits(tmp_path, "app.js", "javascript_taint.yaml", src, rule_id, "javascript")

    def test_express_redirect_to_query_param(self, tmp_path):
        assert self._scan(tmp_path, "app.get('/login', (req, res) => { res.redirect(req.query.next); });")

    def test_koa_redirect_to_query_param(self, tmp_path):
        assert self._scan(tmp_path, "router.get('/login', (ctx) => { ctx.redirect(ctx.query.next); });")

    def test_constant_target_is_not_flagged(self, tmp_path):
        assert not self._scan(tmp_path, "app.get('/login', (req, res) => { res.redirect('/home'); });")

    def test_header_rule_no_longer_claims_redirects(self, tmp_path):
        body = "app.get('/login', (req, res) => { res.redirect(req.query.next); });"
        assert not self._scan(tmp_path, body, rule_id="tnt-js-header-001")


class TestGo:
    RULE = "tnt-go-redirect-001"

    def _scan(self, tmp_path, imports, body, rule_id=RULE):
        src = f"package main\n\nimport (\n{imports})\n\n{body}\n"
        return _hits(tmp_path, "main.go", "go_taint.yaml", src, rule_id, "go")

    NET = '\t"net/http"\n'
    GIN = '\t"github.com/gin-gonic/gin"\n'

    def test_net_http_redirect_to_query_param(self, tmp_path):
        body = (
            "func login(w http.ResponseWriter, r *http.Request) {\n"
            '\tnext := r.URL.Query().Get("next")\n'
            "\thttp.Redirect(w, r, next, http.StatusFound)\n}"
        )
        assert self._scan(tmp_path, self.NET, body)

    def test_gin_redirect_to_query_param(self, tmp_path):
        body = 'func login(c *gin.Context) {\n\tc.Redirect(302, c.Query("next"))\n}'
        assert self._scan(tmp_path, self.GIN, body)

    def test_constant_target_is_not_flagged(self, tmp_path):
        body = (
            "func login(w http.ResponseWriter, r *http.Request) {\n"
            '\thttp.Redirect(w, r, "/home", http.StatusFound)\n}'
        )
        assert not self._scan(tmp_path, self.NET, body)

    def test_header_rule_no_longer_claims_redirects(self, tmp_path):
        body = (
            "func login(w http.ResponseWriter, r *http.Request) {\n"
            '\tnext := r.URL.Query().Get("next")\n'
            "\thttp.Redirect(w, r, next, http.StatusFound)\n}"
        )
        assert not self._scan(tmp_path, self.NET, body, rule_id="tnt-go-header-001")


class TestJava:
    RULE = "tnt-ja-redirect-001"

    def _scan(self, tmp_path, body):
        return _hits(tmp_path, "Login.java", "java_taint.yaml", body, self.RULE, "java")

    def test_servlet_send_redirect_to_parameter(self, tmp_path):
        src = (
            "import javax.servlet.http.*;\n"
            "public class Login extends HttpServlet {\n"
            "  protected void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {\n"
            '    response.sendRedirect(request.getParameter("next"));\n'
            "  }\n}\n"
        )
        assert self._scan(tmp_path, src)

    def test_spring_redirect_view_name_from_request_param(self, tmp_path):
        src = (
            "import org.springframework.web.bind.annotation.*;\n"
            "@Controller\npublic class Login {\n"
            '  @GetMapping("/login")\n'
            "  public String login(@RequestParam String next) {\n"
            '    return "redirect:" + next;\n'
            "  }\n}\n"
        )
        assert self._scan(tmp_path, src)

    def test_numeric_id_selecting_a_fixed_path_is_not_flagged(self, tmp_path):
        # WebGoat OpenRedirectSecureController: an Integer cannot carry a URL.
        src = (
            "import java.util.Map;\nimport org.springframework.web.bind.annotation.*;\n"
            "@Controller\npublic class Safe {\n"
            '  private static final Map<Integer, String> DEST = Map.of(1, "/welcome", 2, "/login");\n'
            '  @GetMapping("/safe")\n'
            '  public String safe(@RequestParam(name = "destId") Integer destId) {\n'
            '    return "redirect:" + DEST.getOrDefault(destId, "/welcome");\n'
            "  }\n}\n"
        )
        assert not self._scan(tmp_path, src)

    def test_constant_target_is_not_flagged(self, tmp_path):
        src = (
            "import javax.servlet.http.*;\n"
            "public class Login extends HttpServlet {\n"
            "  protected void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {\n"
            '    response.sendRedirect("/home");\n'
            "  }\n}\n"
        )
        assert not self._scan(tmp_path, src)


class TestCSharp:
    RULE = "tnt-cs-redirect-001"

    def _scan(self, tmp_path, action):
        src = (
            "using Microsoft.AspNetCore.Mvc;\n"
            "public class AccountController : Controller {\n"
            f"{action}\n"
            "}\n"
        )
        return _hits(tmp_path, "AccountController.cs", "csharp_taint.yaml", src, self.RULE, "csharp")

    def test_mvc_redirect_to_query_param(self, tmp_path):
        assert self._scan(
            tmp_path,
            "  public IActionResult Login([FromQuery] string returnUrl) { return Redirect(returnUrl); }",
        )

    def test_response_redirect_to_query_value(self, tmp_path):
        assert self._scan(
            tmp_path, '  public void Login() { Response.Redirect(Request.Query["next"]); }'
        )

    def test_web_forms_query_string(self, tmp_path):
        # WebGoat.NET CustomerLogin.aspx.cs: classic ASP.NET request access.
        assert self._scan(
            tmp_path,
            '  public void Login() { string u = Request.QueryString["ReturnUrl"]; Response.Redirect(u); }',
        )

    def test_local_redirect_is_not_flagged(self, tmp_path):
        # LocalRedirect throws for any non-local URL, so it is not a sink.
        assert not self._scan(
            tmp_path,
            "  public IActionResult Login([FromQuery] string returnUrl) { return LocalRedirect(returnUrl); }",
        )

    def test_constant_target_is_not_flagged(self, tmp_path):
        assert not self._scan(tmp_path, '  public IActionResult Login() { return Redirect("/home"); }')
