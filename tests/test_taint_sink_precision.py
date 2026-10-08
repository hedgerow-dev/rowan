"""Regression tests for taint-rule sink precision (DEF-11, BACKLOG.md).

`tnt-go-deser-001` (rules/go_taint.yaml) listed `json.Unmarshal(...)` as a
"deserialization... enabling code execution" sink. Go's encoding/json is
memory-safe: decoding attacker-controlled bytes into a typed struct cannot
execute code or instantiate arbitrary types, unlike true polymorphic
deserialization (Python pickle, Java ObjectInputStream, PHP unserialize).
Found via a 5+ repo corpus scan: 100% of this rule's 579 fires in ragflow
were `json.Unmarshal(bodyBytes, &req)` decoding an HTTP body into a
concrete request struct -- completely standard, safe JSON API parsing.

`tnt-js-proto-001` (rules/javascript_taint.yaml) had the same mistake:
`JSON.parse(...)` listed as a prototype-pollution sink. Parsing untrusted
JSON produces a plain object; it cannot pollute `Object.prototype` by
itself -- pollution requires a subsequent unsafe merge (Object.assign,
lodash.merge, etc.), which are separately and correctly listed as sinks.

Requires the Opengrep binary (skipped entirely if not installed, matching
the project's convention -- CI does not install it, see .github/workflows/ci.yml).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from rowan.taint.opengrep_adapter import OpengrepAdapter

RULES_DIR = Path(__file__).parent.parent / "rules"

_adapter = OpengrepAdapter()
pytestmark = pytest.mark.skipif(
    not _adapter.is_installed(),
    reason="Opengrep binary not installed; these tests need a live scan.",
)


def _scan(tmp_path, filename, rule_file, source, rule_id, language):
    fp = tmp_path / filename
    fp.write_text(source, encoding="utf-8")
    adapter = OpengrepAdapter()
    findings = adapter.scan_with_rules(tmp_path, [RULES_DIR / rule_file], languages=[language])
    return [f for f in findings if f.rule_id == rule_id]


class TestGoDeserializationSinkPrecision:
    """tnt-go-deser-001 (rules/go_taint.yaml)."""

    def test_json_unmarshal_into_typed_struct_no_longer_flagged(self, tmp_path):
        """Decoding an HTTP body into a concrete struct is safe, memory-checked
        JSON parsing -- it must not be flagged as deserialization RCE."""
        src = (
            "package handler\n\n"
            "import (\n"
            '\t"encoding/json"\n'
            '\t"io/ioutil"\n'
            '\t"net/http"\n'
            ")\n\n"
            "type ChatRequest struct {\n"
            '\tModel string `json:"model"`\n'
            "}\n\n"
            "func Handle(r *http.Request) {\n"
            "\tbodyBytes, _ := ioutil.ReadAll(r.Body)\n"
            "\tvar req ChatRequest\n"
            "\tjson.Unmarshal(bodyBytes, &req)\n"
            "}\n"
        )
        findings = _scan(tmp_path, "handler.go", "go_taint.yaml", src, "tnt-go-deser-001", "go")
        assert not findings, (
            "json.Unmarshal into a typed struct is memory-safe and must not "
            f"be flagged as deserialization RCE, got: {findings}"
        )

    def test_gob_decoder_still_flagged(self, tmp_path):
        """encoding/gob decoding untrusted input is a genuinely risky sink
        (attacker-influenced type registration) and must still be reported."""
        src = (
            "package handler\n\n"
            "import (\n"
            '\t"encoding/gob"\n'
            '\t"net/http"\n'
            ")\n\n"
            "func Handle(r *http.Request) {\n"
            "\tvar v interface{}\n"
            "\tdec := gob.NewDecoder(r.Body)\n"
            "\tdec.Decode(&v)\n"
            "}\n"
        )
        findings = _scan(tmp_path, "handler.go", "go_taint.yaml", src, "tnt-go-deser-001", "go")
        assert findings, "gob.NewDecoder on the request body must still be flagged"


class TestGoSqliSinkReceiverPrecision:
    """tnt-go-sqli-001 (rules/go_taint.yaml), EXT-01.

    The sink `$DB.Query(...)` bound `$DB` to `req.URL` and to gin's `c`, so
    the HTTP query-string getters `r.URL.Query()` and `c.Query("k")` were
    simultaneously source and sink and fired with no database in sight.
    Seen on gin-gonic/gin at binding/query.go:16 and context.go:581.
    """

    def test_query_string_getters_without_db_not_flagged(self, tmp_path):
        src = (
            "package handler\n\n"
            "import (\n"
            '\t"net/http"\n\n'
            '\t"github.com/gin-gonic/gin"\n'
            ")\n\n"
            "func Handle(r *http.Request) string {\n"
            '\treturn r.URL.Query().Get("id")\n'
            "}\n\n"
            "func GinHandle(c *gin.Context) {\n"
            '\tid := c.Query("id")\n'
            "\tc.String(200, id)\n"
            "}\n"
        )
        findings = _scan(tmp_path, "handler.go", "go_taint.yaml", src, "tnt-go-sqli-001", "go")
        assert not findings, (
            f"reading a query string with no database call is not SQL injection, got: {findings}"
        )

    def test_url_query_into_db_query_still_flagged(self, tmp_path):
        src = (
            "package handler\n\n"
            "import (\n"
            '\t"database/sql"\n'
            '\t"net/http"\n'
            ")\n\n"
            "func Handle(db *sql.DB, r *http.Request) {\n"
            '\tq := r.URL.Query().Get("id")\n'
            '\tdb.Query("SELECT * FROM t WHERE id = " + q)\n'
            "}\n"
        )
        findings = _scan(tmp_path, "handler.go", "go_taint.yaml", src, "tnt-go-sqli-001", "go")
        assert len(findings) == 1, f"expected exactly one db.Query finding, got: {findings}"

    def test_url_query_into_db_exec_still_flagged(self, tmp_path):
        src = (
            "package handler\n\n"
            "import (\n"
            '\t"database/sql"\n'
            '\t"net/http"\n'
            ")\n\n"
            "func Handle(db *sql.DB, r *http.Request) {\n"
            '\tname := r.URL.Query().Get("name")\n'
            '\tdb.Exec("DELETE FROM users WHERE name = \'" + name + "\'")\n'
            "}\n"
        )
        findings = _scan(tmp_path, "handler.go", "go_taint.yaml", src, "tnt-go-sqli-001", "go")
        assert len(findings) == 1, f"expected exactly one db.Exec finding, got: {findings}"

    def test_constant_db_query_is_not_its_own_source(self, tmp_path):
        """The gin source `$C.Query(...)` also matched `db.Query(...)`, so a
        constant SQL string with no user input fired as source and sink."""
        src = (
            "package handler\n\n"
            'import "database/sql"\n\n'
            "func List(db *sql.DB) {\n"
            '\trows, _ := db.Query("SELECT name FROM users")\n'
            "\tdefer rows.Close()\n"
            "}\n"
        )
        findings = _scan(tmp_path, "handler.go", "go_taint.yaml", src, "tnt-go-sqli-001", "go")
        assert not findings, f"a constant db.Query has no user input, got: {findings}"

    def test_gin_context_with_unconventional_name_not_flagged(self, tmp_path):
        """The exclusion must come from the *gin.Context type, not from the
        receiver being named c/ctx."""
        src = (
            "package handler\n\n"
            'import "github.com/gin-gonic/gin"\n\n'
            "func H(g *gin.Context) {\n"
            '\tid := g.Query("id")\n'
            "\tg.String(200, id)\n"
            "}\n"
        )
        findings = _scan(tmp_path, "handler.go", "go_taint.yaml", src, "tnt-go-sqli-001", "go")
        assert not findings, f"gin context named g must not self-match, got: {findings}"

    def test_db_handle_with_unconventional_name_is_not_a_source(self, tmp_path):
        """A DB handle not named db/conn/sql must not become its own source."""
        src = (
            "package handler\n\n"
            'import "context"\n\n'
            "type PG struct{}\n\n"
            "func (p *PG) Query(ctx context.Context, q string) {}\n\n"
            "func List(pg *PG) {\n"
            '\tpg.Query(context.Background(), "SELECT name FROM users")\n'
            "}\n"
        )
        findings = _scan(tmp_path, "handler.go", "go_taint.yaml", src, "tnt-go-sqli-001", "go")
        assert not findings, f"constant pg.Query has no user input, got: {findings}"

    def test_http_client_get_is_not_a_sql_sink(self, tmp_path):
        """`$DB.Get(...)` matched `httplib.Get(url)` (gogs hook.go:240)."""
        src = (
            "package handler\n\n"
            "import (\n"
            '\t"net/http"\n\n'
            '\t"github.com/gogs/go-gogs-client/httplib"\n'
            ")\n\n"
            "func Handle(r *http.Request) {\n"
            '\tu := r.URL.Query().Get("u")\n'
            "\thttplib.Get(u)\n"
            "}\n"
        )
        findings = _scan(tmp_path, "handler.go", "go_taint.yaml", src, "tnt-go-sqli-001", "go")
        assert not findings, f"an HTTP client Get is not a SQL sink, got: {findings}"

    def test_sqlx_get_with_tainted_query_still_flagged(self, tmp_path):
        src = (
            "package handler\n\n"
            "import (\n"
            '\t"net/http"\n\n'
            '\t"github.com/jmoiron/sqlx"\n'
            ")\n\n"
            "type User struct{ Name string }\n\n"
            "func Handle(db *sqlx.DB, r *http.Request) {\n"
            '\tid := r.URL.Query().Get("id")\n'
            "\tvar u User\n"
            '\tdb.Get(&u, "SELECT * FROM users WHERE id = " + id)\n'
            "}\n"
        )
        findings = _scan(tmp_path, "handler.go", "go_taint.yaml", src, "tnt-go-sqli-001", "go")
        assert len(findings) == 1, f"expected exactly one sqlx Get finding, got: {findings}"

    def test_gin_query_into_db_query_still_flagged(self, tmp_path):
        src = (
            "package handler\n\n"
            "import (\n"
            '\t"database/sql"\n\n'
            '\t"github.com/gin-gonic/gin"\n'
            ")\n\n"
            "func H(g *gin.Context, db *sql.DB) {\n"
            '\tid := g.Query("id")\n'
            '\tdb.Query("SELECT * FROM t WHERE id = " + id)\n'
            "}\n"
        )
        findings = _scan(tmp_path, "handler.go", "go_taint.yaml", src, "tnt-go-sqli-001", "go")
        assert len(findings) == 1, f"expected exactly one db.Query finding, got: {findings}"


class TestGoSqliSourceTrustSplit:
    """tnt-go-sqli-001 vs tnt-go-sqli-002 (rules/go_taint.yaml), EXT-08.

    Env vars, flags and argv are operator-controlled. gogs
    internal/dbtest/dbtest.go built `DROP DATABASE` from os.Getenv and was
    reported as HIGH SQL injection by 001. Those sources now live in 002 at
    WARNING/MEDIUM; request-shaped sources stay in 001.
    """

    def test_env_var_into_db_exec_is_config_sourced_not_injection(self, tmp_path):
        src = (
            "package dbtest\n\n"
            "import (\n"
            '\t"database/sql"\n'
            '\t"os"\n'
            ")\n\n"
            "func Drop(db *sql.DB) {\n"
            '\tname := os.Getenv("MYSQL_DB")\n'
            '\tdb.Exec("DROP DATABASE " + name)\n'
            "}\n"
        )
        high = _scan(tmp_path, "dbtest.go", "go_taint.yaml", src, "tnt-go-sqli-001", "go")
        assert not high, f"os.Getenv is operator input and must not fire 001, got: {high}"
        medium = _scan(tmp_path, "dbtest.go", "go_taint.yaml", src, "tnt-go-sqli-002", "go")
        assert len(medium) == 1, f"expected exactly one 002 finding, got: {medium}"

    def test_request_input_into_db_query_stays_in_001(self, tmp_path):
        src = (
            "package handler\n\n"
            "import (\n"
            '\t"database/sql"\n'
            '\t"net/http"\n'
            ")\n\n"
            "func Handle(db *sql.DB, r *http.Request) {\n"
            '\tid := r.URL.Query().Get("id")\n'
            '\tdb.Query("SELECT * FROM t WHERE id = " + id)\n'
            "}\n"
        )
        high = _scan(tmp_path, "handler.go", "go_taint.yaml", src, "tnt-go-sqli-001", "go")
        assert len(high) == 1, f"expected exactly one 001 finding, got: {high}"
        medium = _scan(tmp_path, "handler.go", "go_taint.yaml", src, "tnt-go-sqli-002", "go")
        assert not medium, f"request input must not fire the config-sourced rule, got: {medium}"


class TestDeser006SourceAndSinkPrecision:
    """TNT-DESER-006 / TNT-INJECT-004 (rules/supply_chain_taint.yaml).

    Two defects, found by scanning langflow 1.2.0 while checking whether Rowan
    retroactively detects CVE-2025-3248:

    1. The source list contained `$HTTP.body`. `$HTTP` is a metavariable, so it
       matched ANY attribute access ending in `.body` -- including `tree.body`
       on an `ast.Module`. That produced HIGH findings carrying a `taint-flow`
       evidence tier on code with no user input anywhere. The scan-targets
       corpus holds 900+ non-request `.body` accesses (`response.body`,
       `node.body`, `module.body`, ...). Python request bodies have a fixed
       `request` receiver, unlike Go's `$R.Body`, which stays legitimate.
    2. The sink list included `exec(...)`/`eval(...)` while the rule's message,
       CWE-502 and fix text were all pickle-specific, so an `exec()` hit
       reported "crafted base64 pickle payload for RCE". Those sinks moved to
       TNT-INJECT-004 (CWE-94) with an accurate message.
    """

    def test_ast_node_body_is_not_an_http_source(self, tmp_path):
        """`tree.body` on a parsed AST is not an HTTP request body."""
        src = (
            "import ast\n\n"
            "def validate_code(code):\n"
            "    tree = ast.parse(code)\n"
            "    for node in tree.body:\n"
            "        code_obj = compile("
            "ast.Module(body=[node], type_ignores=[]), '<string>', 'exec')\n"
            "        exec(code_obj)\n"
        )
        for rule_id in ("TNT-DESER-006", "TNT-INJECT-004"):
            findings = _scan(
                tmp_path, "validate.py", "supply_chain_taint.yaml", src, rule_id, "python"
            )
            assert not findings, (
                f"{rule_id} treated `tree.body` as an HTTP request body, "
                f"asserting a dataflow that does not exist: {findings}"
            )

    def test_real_request_body_to_exec_still_flagged(self, tmp_path):
        """The genuine flow must survive the narrowing, under the correct rule."""
        src = (
            "import base64\n"
            "from fastapi import Request\n\n"
            "async def handler(request: Request):\n"
            "    raw = await request.body()\n"
            "    decoded = base64.b64decode(raw)\n"
            "    exec(decoded)\n"
        )
        findings = _scan(
            tmp_path, "handler.py", "supply_chain_taint.yaml", src, "TNT-INJECT-004", "python"
        )
        assert findings, "request body -> base64 -> exec must still be reported"

    def test_deser_006_no_longer_claims_exec_is_pickle(self):
        """The pickle rule must not carry code-execution sinks.

        A finding whose message names a payload format the code never uses is
        worse than no finding: it is confidently wrong.
        """
        import yaml

        rules = yaml.safe_load((RULES_DIR / "supply_chain_taint.yaml").read_text(encoding="utf-8"))[
            "rules"
        ]
        rule = next(r for r in rules if r["id"] == "TNT-DESER-006")

        def patterns(node):
            if isinstance(node, dict):
                for k, v in node.items():
                    if k == "pattern" and isinstance(v, str):
                        yield v.strip()
                    else:
                        yield from patterns(v)
            elif isinstance(node, list):
                for item in node:
                    yield from patterns(item)

        sinks = list(patterns(rule["pattern-sinks"]))
        assert sinks, "TNT-DESER-006 lost its sinks"
        assert all(s.startswith("pickle.") for s in sinks), (
            f"TNT-DESER-006 declares CWE-502 deserialization but has non-pickle sinks: {sinks}"
        )


class TestJSPrototypePollutionSinkPrecision:
    """tnt-js-proto-001 (rules/javascript_taint.yaml)."""

    def test_json_parse_alone_no_longer_flagged(self, tmp_path):
        """Parsing untrusted JSON into a plain object cannot pollute
        Object.prototype by itself -- only a subsequent unsafe merge can."""
        src = (
            "const express = require('express');\n"
            "function handler(req) {\n"
            "  const parsed = JSON.parse(req.body);\n"
            "  return parsed;\n"
            "}\n"
        )
        findings = _scan(
            tmp_path, "handler.js", "javascript_taint.yaml", src, "tnt-js-proto-001", "javascript"
        )
        assert not findings, (
            "JSON.parse alone cannot pollute Object.prototype and must not "
            f"be flagged, got: {findings}"
        )

    def test_object_assign_merge_still_flagged(self, tmp_path):
        """Merging attacker-controlled data into an existing object with
        Object.assign is a genuine prototype-pollution sink."""
        src = (
            "function handler(req) {\n"
            "  const target = {};\n"
            "  Object.assign(target, req.body);\n"
            "  return target;\n"
            "}\n"
        )
        findings = _scan(
            tmp_path, "handler.js", "javascript_taint.yaml", src, "tnt-js-proto-001", "javascript"
        )
        assert findings, "Object.assign(target, req.body) must still be flagged"


_JAVA_SERVLET_PREAMBLE = (
    "package demo;\n\n"
    "import java.io.File;\n"
    "import java.sql.Connection;\n"
    "import java.sql.Statement;\n"
    "import javax.servlet.http.HttpServletRequest;\n\n"
    "public class Handler {\n"
)


class TestJavaTaintRulesFire:
    """rules/java_taint.yaml positive guard (EXT-02, BACKLOG.md).

    A javalin scan produced zero `taint-flow` findings while reporting Java as
    a dataflow language. These tests pin the servlet-style source-to-sink
    flows the rules are written for, so a rule-loading or language-routing
    regression cannot silently turn the Java taint path into a no-op again.
    """

    def test_sqli_getparameter_into_execute_query(self, tmp_path):
        src = _JAVA_SERVLET_PREAMBLE + (
            "    void run(HttpServletRequest request, Connection conn) throws Exception {\n"
            '        String id = request.getParameter("id");\n'
            "        Statement stmt = conn.createStatement();\n"
            '        stmt.executeQuery("SELECT * FROM t WHERE id=" + id);\n'
            "    }\n"
            "}\n"
        )
        findings = _scan(
            tmp_path, "Handler.java", "java_taint.yaml", src, "tnt-ja-sqli-001", "java"
        )
        assert findings, "request.getParameter into Statement.executeQuery must be flagged"

    def test_path_getparameter_into_new_file(self, tmp_path):
        src = _JAVA_SERVLET_PREAMBLE + (
            "    void run(HttpServletRequest request) throws Exception {\n"
            '        String name = request.getParameter("name");\n'
            '        File f = new File("/data/" + name);\n'
            "    }\n"
            "}\n"
        )
        findings = _scan(
            tmp_path, "Handler.java", "java_taint.yaml", src, "tnt-ja-path-001", "java"
        )
        assert findings, "request.getParameter into new File(...) must be flagged"

    def test_cmdi_getparameter_into_runtime_exec(self, tmp_path):
        src = _JAVA_SERVLET_PREAMBLE + (
            "    void run(HttpServletRequest request) throws Exception {\n"
            '        String host = request.getParameter("host");\n'
            '        Runtime.getRuntime().exec("ping " + host);\n'
            "    }\n"
            "}\n"
        )
        findings = _scan(
            tmp_path, "Handler.java", "java_taint.yaml", src, "tnt-ja-cmdi-001", "java"
        )
        assert findings, "request.getParameter into Runtime.exec must be flagged"


_KOTLIN_PREAMBLE = (
    "package demo\n\n"
    "import io.javalin.http.Context\n"
    "import java.io.File\n"
    "import java.net.URL\n"
    "import java.sql.Connection\n"
    "import java.sql.Statement\n\n"
    "class Handler {\n"
)


class TestKotlinTaintRulesFire:
    """rules/kotlin_taint.yaml source-to-sink guard (EXT-03, BACKLOG.md).

    One Javalin-style true positive and one constant-input true negative per
    rule, plus a Ktor and a servlet source for sqli. Kotlin has no `new`, so
    the sinks are bare constructor calls and the SQL text is a string template.
    """

    @pytest.mark.parametrize(
        "rule_id, body",
        [
            (
                "tnt-kt-sqli-001",
                "    fun run(ctx: Context, st: Statement) {\n"
                '        val id = ctx.queryParam("id")\n'
                '        st.executeQuery("SELECT * FROM t WHERE id=$id")\n'
                "    }\n",
            ),
            (
                "tnt-kt-cmdi-001",
                "    fun run(ctx: Context) {\n"
                '        val host = ctx.queryParam("host")\n'
                '        Runtime.getRuntime().exec("ping $host")\n'
                "    }\n",
            ),
            (
                "tnt-kt-path-001",
                "    fun run(ctx: Context) {\n"
                '        val name = ctx.queryParam("name")\n'
                '        val f = File("/data/$name")\n'
                "    }\n",
            ),
            (
                "tnt-kt-ssrf-001",
                "    fun run(ctx: Context) {\n"
                '        val target = ctx.queryParam("url")\n'
                "        val u = URL(target)\n"
                "    }\n",
            ),
        ],
    )
    def test_javalin_query_param_reaches_sink(self, tmp_path, rule_id, body):
        src = _KOTLIN_PREAMBLE + body + "}\n"
        findings = _scan(tmp_path, "Handler.kt", "kotlin_taint.yaml", src, rule_id, "kotlin")
        assert findings, f"{rule_id}: ctx.queryParam into the sink must be flagged"

    @pytest.mark.parametrize(
        "rule_id, body",
        [
            (
                "tnt-kt-sqli-001",
                "    fun run(st: Statement) {\n"
                '        st.executeQuery("SELECT * FROM t WHERE id=1")\n'
                "    }\n",
            ),
            (
                "tnt-kt-cmdi-001",
                '    fun run() {\n        Runtime.getRuntime().exec("ping localhost")\n    }\n',
            ),
            (
                "tnt-kt-path-001",
                '    fun run() {\n        val f = File("/data/fixed.txt")\n    }\n',
            ),
            (
                "tnt-kt-ssrf-001",
                '    fun run() {\n        val u = URL("https://example.invalid/health")\n    }\n',
            ),
        ],
    )
    def test_constant_input_is_not_flagged(self, tmp_path, rule_id, body):
        src = _KOTLIN_PREAMBLE + body + "}\n"
        findings = _scan(tmp_path, "Handler.kt", "kotlin_taint.yaml", src, rule_id, "kotlin")
        assert not findings, f"{rule_id}: constant input must not be flagged, got: {findings}"

    def test_sqli_ktor_parameters_into_execute_query(self, tmp_path):
        src = _KOTLIN_PREAMBLE + (
            "    fun run(call: ApplicationCall, st: Statement) {\n"
            '        val id = call.parameters["id"]\n'
            '        st.executeQuery("SELECT * FROM t WHERE id=$id")\n'
            "    }\n"
            "}\n"
        )
        findings = _scan(
            tmp_path, "Handler.kt", "kotlin_taint.yaml", src, "tnt-kt-sqli-001", "kotlin"
        )
        assert findings, "call.parameters[...] into Statement.executeQuery must be flagged"

    def test_sqli_servlet_get_parameter_into_execute_query(self, tmp_path):
        src = _KOTLIN_PREAMBLE + (
            "    fun run(request: HttpServletRequest, st: Statement) {\n"
            '        val id = request.getParameter("id")\n'
            '        st.executeQuery("SELECT * FROM t WHERE id=" + id)\n'
            "    }\n"
            "}\n"
        )
        findings = _scan(
            tmp_path, "Handler.kt", "kotlin_taint.yaml", src, "tnt-kt-sqli-001", "kotlin"
        )
        assert findings, "request.getParameter into Statement.executeQuery must be flagged"


_CS_CONTROLLER_PREAMBLE = (
    "using System.Net.Http;\n"
    "using System.Threading.Tasks;\n"
    "using Microsoft.AspNetCore.Mvc;\n\n"
    "public interface IGetOrgQuery { Task<string> GetAsync(string id); }\n\n"
    "public class C : Controller {\n"
    "    private readonly HttpClient _http;\n"
    "    private readonly IGetOrgQuery _query;\n"
    "    public C(HttpClient http, IGetOrgQuery query) { _http = http; _query = query; }\n"
)


class TestCSharpSsrfSinkReceiverPrecision:
    """tnt-cs-ssrf-001 (rules/csharp_taint.yaml).

    A bare `$X.GetAsync(...)` sink matched CQRS query objects on
    bitwarden/server (`_orgQuery.GetAsync(orgId)`); the sink is now typed to
    HttpClient.
    """

    def test_cqrs_query_get_async_not_flagged(self, tmp_path):
        src = _CS_CONTROLLER_PREAMBLE + (
            "    public async Task<string> Get([FromQuery] string id) {\n"
            "        return await _query.GetAsync(id);\n"
            "    }\n"
            "}\n"
        )
        findings = _scan(tmp_path, "C.cs", "csharp_taint.yaml", src, "tnt-cs-ssrf-001", "csharp")
        assert not findings, f"a query object's GetAsync is not an HTTP request, got: {findings}"

    def test_http_client_field_and_local_still_flagged(self, tmp_path):
        src = _CS_CONTROLLER_PREAMBLE + (
            "    public async Task<string> Fetch([FromQuery] string url) {\n"
            "        await _http.GetAsync(url);\n"
            "        var local = new HttpClient();\n"
            "        await local.PostAsync(url, null);\n"
            '        return "";\n'
            "    }\n"
            "}\n"
        )
        findings = _scan(tmp_path, "C.cs", "csharp_taint.yaml", src, "tnt-cs-ssrf-001", "csharp")
        assert len(findings) == 2, f"expected the field and local HttpClient calls, got: {findings}"


_JAVA_SPRING_PREAMBLE = (
    "package demo;\n\n"
    "import java.io.File;\n"
    "import java.nio.file.Path;\n"
    "import java.nio.file.Paths;\n"
    "import java.sql.Connection;\n"
    "import java.sql.PreparedStatement;\n"
    "import java.sql.Statement;\n"
    "import org.springframework.web.bind.annotation.*;\n"
    "import org.springframework.web.multipart.MultipartFile;\n\n"
    "public class Handler {\n"
    "    private javax.sql.DataSource dataSource;\n"
)

_JAVA_SQLI_TAIL = (
    "        Connection connection = dataSource.getConnection();\n"
    "        Statement statement = connection.createStatement();\n"
    '        statement.executeQuery("SELECT * FROM t WHERE a=\'" + q + "\'");\n'
    '        return "";\n'
    "    }\n"
    "}\n"
)


class TestJavaRecallGapsFromWebGoat:
    """rules/java_taint.yaml recall gaps found by scanning OWASP WebGoat.

    Each test is the minimal shape of a WebGoat handler that Rowan originally
    missed; the source or sink that closed the gap is named in the assertion.
    """

    def test_sqli_requestparam_with_name_argument(self, tmp_path):
        src = (
            _JAVA_SPRING_PREAMBLE
            + (
                '    @PostMapping("/x")\n'
                '    public String run(@RequestParam("q") String q) throws Exception {\n'
            )
            + _JAVA_SQLI_TAIL
        )
        findings = _scan(
            tmp_path, "Handler.java", "java_taint.yaml", src, "tnt-ja-sqli-001", "java"
        )
        assert findings, "WebGoat SqlInjectionChallenge.java:62"

    def test_sqli_requestparam_with_value_argument(self, tmp_path):
        src = (
            _JAVA_SPRING_PREAMBLE
            + (
                '    @PostMapping("/x")\n'
                '    public String run(@RequestParam(value = "q") String q) throws Exception {\n'
            )
            + _JAVA_SQLI_TAIL
        )
        findings = _scan(
            tmp_path, "Handler.java", "java_taint.yaml", src, "tnt-ja-sqli-001", "java"
        )
        assert findings, "WebGoat SqlInjectionLesson6a.java:72"

    def test_sqli_unannotated_spring_handler_param(self, tmp_path):
        src = (
            _JAVA_SPRING_PREAMBLE
            + ('    @PostMapping("/x")\n    public String run(String q) throws Exception {\n')
            + _JAVA_SQLI_TAIL
        )
        findings = _scan(
            tmp_path, "Handler.java", "java_taint.yaml", src, "tnt-ja-sqli-001", "java"
        )
        assert findings, "WebGoat SqlInjectionLesson5.java:65"

    def test_sqli_statement_execute(self, tmp_path):
        src = _JAVA_SPRING_PREAMBLE + (
            '    @PostMapping("/x")\n'
            "    public String run(@RequestParam String q) throws Exception {\n"
            "        Connection connection = dataSource.getConnection();\n"
            "        Statement statement = connection.createStatement();\n"
            '        statement.execute("SELECT * FROM t WHERE a=\'" + q + "\'");\n'
            '        return "";\n'
            "    }\n"
            "}\n"
        )
        findings = _scan(
            tmp_path, "Handler.java", "java_taint.yaml", src, "tnt-ja-sqli-001", "java"
        )
        assert findings, "WebGoat SqlInjectionLesson9.java:65"

    def test_sqli_var_connection_preparestatement(self, tmp_path):
        src = _JAVA_SPRING_PREAMBLE + (
            '    @PostMapping("/x")\n'
            "    public String run(@RequestParam String q) throws Exception {\n"
            "        try (var connection = dataSource.getConnection()) {\n"
            '            PreparedStatement s = connection.prepareStatement("SELECT * FROM t WHERE a=\'" + q + "\'");\n'
            "            s.executeQuery();\n"
            "        }\n"
            '        return "";\n'
            "    }\n"
            "}\n"
        )
        findings = _scan(
            tmp_path, "Handler.java", "java_taint.yaml", src, "tnt-ja-sqli-001", "java"
        )
        assert findings, "WebGoat challenges/challenge5/Assignment5.java:44"

    def test_sqli_chained_createstatement_executequery(self, tmp_path):
        src = _JAVA_SPRING_PREAMBLE + (
            '    @PostMapping("/x")\n'
            "    public String run(@RequestParam String q) throws Exception {\n"
            "        Connection connection = dataSource.getConnection();\n"
            '        connection.createStatement().executeQuery("SELECT * FROM t WHERE a=\'" + q + "\'");\n'
            '        return "";\n'
            "    }\n"
            "}\n"
        )
        findings = _scan(
            tmp_path, "Handler.java", "java_taint.yaml", src, "tnt-ja-sqli-001", "java"
        )
        assert findings, "WebGoat jwt/claimmisuse/JWTHeaderKIDEndpoint.java:75"

    def test_path_multipart_named_requestparam_getoriginalfilename(self, tmp_path):
        src = _JAVA_SPRING_PREAMBLE + (
            '    @PostMapping("/x")\n'
            '    public String run(@RequestParam("up") MultipartFile file) throws Exception {\n'
            '        File f = new File("/data", file.getOriginalFilename());\n'
            '        return "";\n'
            "    }\n"
            "}\n"
        )
        findings = _scan(
            tmp_path, "Handler.java", "java_taint.yaml", src, "tnt-ja-path-001", "java"
        )
        assert findings, "WebGoat pathtraversal/ProfileUploadRemoveUserInput.java:41"

    def test_path_resolve(self, tmp_path):
        src = _JAVA_SPRING_PREAMBLE + (
            '    @PostMapping("/x")\n'
            "    public String run(@RequestParam String name) throws Exception {\n"
            '        Path p = Paths.get("/data").resolve(name);\n'
            '        return "";\n'
            "    }\n"
            "}\n"
        )
        findings = _scan(
            tmp_path, "Handler.java", "java_taint.yaml", src, "tnt-ja-path-001", "java"
        )
        assert findings, "WebGoat pathtraversal/ProfileZipSlip.java:72"


class TestGoSqliContextSinks:
    """tnt-go-sqli-001: QueryRow and the *Context variants are the most common
    database/sql entry points and were not sinks (seen on 0c34/govwa)."""

    def test_query_row_and_context_variants_are_sinks(self, tmp_path):
        src = (
            "package handler\n\n"
            "import (\n"
            '\t"context"\n'
            '\t"database/sql"\n'
            '\t"net/http"\n'
            ")\n\n"
            "func Handle(db *sql.DB, r *http.Request) {\n"
            '\tid := r.FormValue("id")\n'
            '\tdb.QueryRow("SELECT * FROM t WHERE id = " + id)\n'
            '\tdb.QueryContext(context.Background(), "SELECT * FROM t WHERE id = " + id)\n'
            '\tdb.ExecContext(context.Background(), "DELETE FROM t WHERE id = " + id)\n'
            "}\n"
        )
        findings = _scan(tmp_path, "handler.go", "go_taint.yaml", src, "tnt-go-sqli-001", "go")
        assert len(findings) == 3, (
            f"expected QueryRow, QueryContext and ExecContext, got: {findings}"
        )


class TestChatTemplateSstiSinkIsTemplateString:
    """TNT-ML-001 / TNT-ML-008 (rules/ml_taint.yaml).

    SSTI is a tainted template STRING. The old `$T.render(...)` sink flagged
    tainted render arguments, and because Opengrep resolves
    `from django.shortcuts import render`, it also matched every Django
    `render(request, ...)` call (20 hits on pygoat).
    """

    def test_django_render_with_tainted_context_not_flagged(self, tmp_path):
        src = (
            "from django.shortcuts import render\n\n"
            "def view(request):\n"
            "    q = request.GET.get('q', '')\n"
            "    return render(request, 'lab.html', {'company': q})\n"
        )
        findings = _scan(tmp_path, "views.py", "ml_taint.yaml", src, "TNT-ML-001", "python")
        assert not findings, f"Django render of a context dict is not SSTI, got: {findings}"

    def test_tainted_render_arguments_not_flagged(self, tmp_path):
        src = (
            "import jinja2\n\n"
            "def view(request):\n"
            "    name = request.GET.get('name')\n"
            "    return jinja2.Template('Hello {{ name }}').render(name=name)\n"
        )
        findings = _scan(tmp_path, "views.py", "ml_taint.yaml", src, "TNT-ML-001", "python")
        assert not findings, (
            f"tainted render kwargs on a constant template are not SSTI, got: {findings}"
        )

    def test_tainted_template_string_still_flagged(self, tmp_path):
        src = (
            "import jinja2\n\n"
            "def view(request):\n"
            "    tpl = request.GET.get('tpl')\n"
            "    return jinja2.Template(tpl).render()\n"
        )
        findings = _scan(tmp_path, "views.py", "ml_taint.yaml", src, "TNT-ML-001", "python")
        assert len(findings) == 1, f"a request-controlled template string is SSTI, got: {findings}"

    def test_chat_template_from_tokenizer_config_still_flagged(self, tmp_path):
        src = (
            "from jinja2 import Template\n\n"
            "def render_chat(tokenizer_config, messages):\n"
            "    chat_template = tokenizer_config.get('chat_template')\n"
            "    return Template(chat_template).render(messages=messages)\n"
        )
        findings = _scan(tmp_path, "chat.py", "ml_taint.yaml", src, "TNT-ML-008", "python")
        assert len(findings) == 1, f"the CVE-2026-5760 shape must still fire, got: {findings}"


class TestNoSqlSinkPrecision:
    """TNT-NOSQL-001 (rules/python_taint_extended.yaml), seen on pygoat."""

    def test_django_keyword_filter_not_flagged(self, tmp_path):
        src = (
            "from .models import Login\n\n"
            "def view(request):\n"
            "    name = request.POST.get('name')\n"
            "    return Login.objects.filter(user=name)\n"
        )
        findings = _scan(
            tmp_path, "views.py", "python_taint_extended.yaml", src, "TNT-NOSQL-001", "python"
        )
        assert not findings, f"keyword lookups are parameterised, got: {findings}"

    def test_str_find_with_start_index_not_flagged(self, tmp_path):
        src = (
            "def view(request):\n"
            "    text = request.POST.get('text')\n"
            "    return text.find('<', 3)\n"
        )
        findings = _scan(
            tmp_path, "views.py", "python_taint_extended.yaml", src, "TNT-NOSQL-001", "python"
        )
        assert not findings, f"str.find is not a Mongo query, got: {findings}"

    def test_unpacked_request_dict_into_filter_still_flagged(self, tmp_path):
        src = (
            "from .models import Login\n\n"
            "def view(request):\n"
            "    params = request.GET.get('q')\n"
            "    return Login.objects.filter(**params)\n"
        )
        findings = _scan(
            tmp_path, "views.py", "python_taint_extended.yaml", src, "TNT-NOSQL-001", "python"
        )
        assert len(findings) == 1, (
            f"request dict unpacked into a lookup is injectable, got: {findings}"
        )

    def test_mongo_find_with_document_still_flagged(self, tmp_path):
        src = (
            "def view(request, db):\n"
            "    user = request.json.get('user')\n"
            "    return db.users.find({'user': user})\n"
        )
        findings = _scan(
            tmp_path, "views.py", "python_taint_extended.yaml", src, "TNT-NOSQL-001", "python"
        )
        assert len(findings) == 1, (
            f"a tainted value inside a Mongo filter document is a sink, got: {findings}"
        )


_JAVA_XML_PREAMBLE = (
    "package demo;\n\n"
    "import java.io.StringReader;\n"
    "import javax.xml.XMLConstants;\n"
    "import javax.xml.parsers.DocumentBuilder;\n"
    "import javax.xml.parsers.DocumentBuilderFactory;\n"
    "import javax.xml.parsers.SAXParser;\n"
    "import javax.xml.parsers.SAXParserFactory;\n"
    "import javax.xml.stream.XMLInputFactory;\n"
    "import jakarta.xml.bind.JAXBContext;\n"
    "import jakarta.xml.bind.Unmarshaller;\n"
    "import org.xml.sax.InputSource;\n"
    "import org.springframework.web.bind.annotation.*;\n\n"
    "public class Handler {\n"
)


def _xxe(tmp_path, body):
    src = (
        _JAVA_XML_PREAMBLE
        + (
            '    @PostMapping("/x")\n'
            "    public String run(@RequestBody String xml) throws Exception {\n"
        )
        + body
        + ('        return "";\n    }\n}\n')
    )
    return _scan(tmp_path, "Handler.java", "java_taint.yaml", src, "tnt-ja-xxe-001", "java")


class TestJavaXxeRule:
    """tnt-ja-xxe-001 (rules/java_taint.yaml), found via WebGoat's xxe lesson.

    Hardening is a factory property, so it is a sink-side `pattern-not-inside`
    guard rather than a sanitizer; each negative puts the hardening call in
    the same method body as the parse.
    """

    def test_document_builder_parse_fires(self, tmp_path):
        findings = _xxe(
            tmp_path,
            (
                "        DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();\n"
                "        DocumentBuilder b = f.newDocumentBuilder();\n"
                "        b.parse(new InputSource(new StringReader(xml)));\n"
            ),
        )
        assert len(findings) == 1, (
            f"DocumentBuilder.parse on request XML must fire, got: {findings}"
        )

    def test_document_builder_disallow_doctype_is_quiet(self, tmp_path):
        findings = _xxe(
            tmp_path,
            (
                "        DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();\n"
                '        f.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);\n'
                "        DocumentBuilder b = f.newDocumentBuilder();\n"
                "        b.parse(new InputSource(new StringReader(xml)));\n"
            ),
        )
        assert not findings, (
            f"disallow-doctype-decl in the same method must suppress, got: {findings}"
        )

    def test_sax_parser_parse_fires(self, tmp_path):
        findings = _xxe(
            tmp_path,
            (
                "        SAXParserFactory f = SAXParserFactory.newInstance();\n"
                "        SAXParser p = f.newSAXParser();\n"
                "        p.parse(new InputSource(new StringReader(xml)), null);\n"
            ),
        )
        assert len(findings) == 1, f"SAXParser.parse on request XML must fire, got: {findings}"

    def test_sax_parser_external_entities_off_is_quiet(self, tmp_path):
        findings = _xxe(
            tmp_path,
            (
                "        SAXParserFactory f = SAXParserFactory.newInstance();\n"
                '        f.setFeature("http://xml.org/sax/features/external-general-entities", false);\n'
                "        SAXParser p = f.newSAXParser();\n"
                "        p.parse(new InputSource(new StringReader(xml)), null);\n"
            ),
        )
        assert not findings, f"external-general-entities=false must suppress, got: {findings}"

    def test_stax_stream_reader_fires(self, tmp_path):
        findings = _xxe(
            tmp_path,
            (
                "        var xif = XMLInputFactory.newInstance();\n"
                "        var xsr = xif.createXMLStreamReader(new StringReader(xml));\n"
            ),
        )
        assert len(findings) == 1, "WebGoat xxe/CommentsCache.java:79 shape must fire"

    def test_stax_support_dtd_off_is_quiet(self, tmp_path):
        findings = _xxe(
            tmp_path,
            (
                "        var xif = XMLInputFactory.newInstance();\n"
                "        xif.setProperty(XMLInputFactory.SUPPORT_DTD, false);\n"
                "        var xsr = xif.createXMLStreamReader(new StringReader(xml));\n"
            ),
        )
        assert not findings, f"SUPPORT_DTD=false must suppress, got: {findings}"

    def test_jaxb_unmarshal_fires(self, tmp_path):
        findings = _xxe(
            tmp_path,
            (
                "        Unmarshaller u = JAXBContext.newInstance(Object.class).createUnmarshaller();\n"
                "        Object o = u.unmarshal(new StringReader(xml));\n"
            ),
        )
        assert len(findings) == 1, (
            f"Unmarshaller.unmarshal on request XML must fire, got: {findings}"
        )

    def test_jaxb_over_hardened_stax_is_quiet(self, tmp_path):
        findings = _xxe(
            tmp_path,
            (
                "        var xif = XMLInputFactory.newInstance();\n"
                '        xif.setProperty(XMLConstants.ACCESS_EXTERNAL_DTD, "");\n'
                "        var xsr = xif.createXMLStreamReader(new StringReader(xml));\n"
                "        Unmarshaller u = JAXBContext.newInstance(Object.class).createUnmarshaller();\n"
                "        Object o = u.unmarshal(xsr);\n"
            ),
        )
        assert not findings, (
            f'ACCESS_EXTERNAL_DTD="" must suppress both parse calls, got: {findings}'
        )

    def test_constant_xml_is_quiet(self, tmp_path):
        findings = _xxe(
            tmp_path,
            (
                "        DocumentBuilder b = DocumentBuilderFactory.newInstance().newDocumentBuilder();\n"
                '        b.parse(new InputSource(new StringReader("<a/>")));\n'
            ),
        )
        assert not findings, f"parsing a constant string is not XXE, got: {findings}"


_JAVA_JACKSON_PREAMBLE = (
    "package demo;\n\n"
    "import java.io.ObjectInputStream;\n"
    "import javax.servlet.http.HttpServletRequest;\n"
    "import com.fasterxml.jackson.annotation.JsonTypeInfo;\n"
    "import com.fasterxml.jackson.databind.ObjectMapper;\n"
    "import org.springframework.web.bind.annotation.*;\n\n"
    "public class Handler {\n"
)


def _deser(tmp_path, body, preamble=_JAVA_JACKSON_PREAMBLE):
    src = (
        preamble
        + (
            '    @PostMapping("/x")\n'
            "    public String run(@RequestBody String body) throws Exception {\n"
            "        ObjectMapper mapper = new ObjectMapper();\n"
        )
        + body
        + ('        return "";\n    }\n}\n')
    )
    return _scan(tmp_path, "Handler.java", "java_taint.yaml", src, "tnt-ja-deser-001", "java")


class TestJavaJacksonDeserPrecision:
    """tnt-ja-deser-001 (rules/java_taint.yaml): Jackson readValue is only a
    gadget-chain sink with polymorphic typing on. Found via three WebGoat
    `readValue(json, Concrete.class)` false positives.
    """

    def test_read_value_into_concrete_class_is_quiet(self, tmp_path):
        findings = _deser(tmp_path, "        Comment c = mapper.readValue(body, Comment.class);\n")
        assert not findings, (
            f"WebGoat xss/stored/StoredXssComments.java:96 is typed binding, got: {findings}"
        )

    def test_activate_default_typing_then_read_value_fires(self, tmp_path):
        findings = _deser(
            tmp_path,
            (
                "        mapper.activateDefaultTyping(null, ObjectMapper.DefaultTyping.NON_FINAL);\n"
                "        Object o = mapper.readValue(body, Object.class);\n"
            ),
        )
        assert len(findings) == 1, (
            f"activateDefaultTyping + readValue must fire once, got: {findings}"
        )

    def test_enable_default_typing_then_read_value_fires(self, tmp_path):
        findings = _deser(
            tmp_path,
            (
                "        mapper.enableDefaultTyping();\n"
                "        Object o = mapper.readValue(body, Object.class);\n"
            ),
        )
        assert len(findings) == 1, (
            f"enableDefaultTyping + readValue must fire once, got: {findings}"
        )

    def test_default_typing_on_another_mapper_is_quiet(self, tmp_path):
        findings = _deser(
            tmp_path,
            (
                "        ObjectMapper unsafe = new ObjectMapper();\n"
                "        unsafe.enableDefaultTyping();\n"
                "        Object o = mapper.readValue(body, Object.class);\n"
            ),
        )
        assert not findings, (
            f"default typing on a different mapper must not taint this one, got: {findings}"
        )

    def test_json_type_info_class_target_fires(self, tmp_path):
        preamble = _JAVA_JACKSON_PREAMBLE.replace(
            "public class Handler {\n",
            "@JsonTypeInfo(use = JsonTypeInfo.Id.CLASS)\nclass Payload {\n    public String name;\n}\n\n"
            "public class Handler {\n",
        )
        findings = _deser(
            tmp_path, "        Payload p = mapper.readValue(body, Payload.class);\n", preamble
        )
        assert len(findings) == 1, (
            f"readValue into a @JsonTypeInfo(Id.CLASS) class must fire, got: {findings}"
        )

    def test_object_input_stream_still_fires(self, tmp_path):
        src = _JAVA_JACKSON_PREAMBLE + (
            "    public String run(HttpServletRequest request) throws Exception {\n"
            "        ObjectInputStream ois = new ObjectInputStream(request.getInputStream());\n"
            "        Object o = ois.readObject();\n"
            '        return "";\n'
            "    }\n"
            "}\n"
        )
        findings = _scan(
            tmp_path, "Handler.java", "java_taint.yaml", src, "tnt-ja-deser-001", "java"
        )
        assert len(findings) == 1, f"ObjectInputStream.readObject must still fire, got: {findings}"


class TestJavaOperatorInputSplit:
    """tnt-ja-{sqli,cmdi}-001 vs -002 (rules/java_taint.yaml), EXT-19.

    `System.getenv`, `System.getProperty`, main-method argv and Spring
    `Environment.getProperty` are operator-controlled (ADR-0005 "Option B at
    scale": dubbo's env-sourced path and log hits were the whole Java FP set).
    Same split as EXT-08 for Go: request sources stay in 001 at ERROR,
    operator sources move to 002 at WARNING with `source_kind: operator_input`.
    """

    def test_getenv_into_execute_query_is_002_not_001(self, tmp_path):
        src = _JAVA_SERVLET_PREAMBLE + (
            "    void run(Connection conn) throws Exception {\n"
            '        String db = System.getenv("DB_NAME");\n'
            "        Statement stmt = conn.createStatement();\n"
            '        stmt.executeUpdate("DROP DATABASE " + db);\n'
            "    }\n"
            "}\n"
        )
        high = _scan(tmp_path, "Handler.java", "java_taint.yaml", src, "tnt-ja-sqli-001", "java")
        assert not high, f"System.getenv is operator input and must not fire 001, got: {high}"
        medium = _scan(tmp_path, "Handler.java", "java_taint.yaml", src, "tnt-ja-sqli-002", "java")
        assert len(medium) == 1, f"expected exactly one 002 finding, got: {medium}"

    def test_getparameter_into_execute_query_stays_001(self, tmp_path):
        src = _JAVA_SERVLET_PREAMBLE + (
            "    void run(HttpServletRequest request, Connection conn) throws Exception {\n"
            '        String id = request.getParameter("id");\n'
            "        Statement stmt = conn.createStatement();\n"
            '        stmt.executeQuery("SELECT * FROM t WHERE id=" + id);\n'
            "    }\n"
            "}\n"
        )
        high = _scan(tmp_path, "Handler.java", "java_taint.yaml", src, "tnt-ja-sqli-001", "java")
        assert len(high) == 1, f"expected exactly one 001 finding, got: {high}"
        medium = _scan(tmp_path, "Handler.java", "java_taint.yaml", src, "tnt-ja-sqli-002", "java")
        assert not medium, f"request input must not fire the operator rule, got: {medium}"

    def test_getenv_into_runtime_exec_is_002_not_001(self, tmp_path):
        src = _JAVA_SERVLET_PREAMBLE + (
            "    void run() throws Exception {\n"
            '        String tool = System.getenv("TOOL");\n'
            '        Runtime.getRuntime().exec(tool + " --version");\n'
            "    }\n"
            "}\n"
        )
        high = _scan(tmp_path, "Handler.java", "java_taint.yaml", src, "tnt-ja-cmdi-001", "java")
        assert not high, f"System.getenv is operator input and must not fire 001, got: {high}"
        medium = _scan(tmp_path, "Handler.java", "java_taint.yaml", src, "tnt-ja-cmdi-002", "java")
        assert len(medium) == 1, f"expected exactly one 002 finding, got: {medium}"

    def test_getparameter_into_runtime_exec_stays_001(self, tmp_path):
        src = _JAVA_SERVLET_PREAMBLE + (
            "    void run(HttpServletRequest request) throws Exception {\n"
            '        String host = request.getParameter("host");\n'
            '        Runtime.getRuntime().exec("ping " + host);\n'
            "    }\n"
            "}\n"
        )
        high = _scan(tmp_path, "Handler.java", "java_taint.yaml", src, "tnt-ja-cmdi-001", "java")
        assert len(high) == 1, f"expected exactly one 001 finding, got: {high}"
        medium = _scan(tmp_path, "Handler.java", "java_taint.yaml", src, "tnt-ja-cmdi-002", "java")
        assert not medium, f"request input must not fire the operator rule, got: {medium}"

    def test_spring_environment_get_property_fires_002(self, tmp_path):
        src = (
            "package demo;\n\n"
            "import org.springframework.core.env.Environment;\n\n"
            "public class Boot {\n"
            "    Environment env;\n\n"
            "    void run() throws Exception {\n"
            '        String tool = env.getProperty("app.tool");\n'
            '        new ProcessBuilder(tool, "--check").start();\n'
            "    }\n"
            "}\n"
        )
        medium = _scan(tmp_path, "Boot.java", "java_taint.yaml", src, "tnt-ja-cmdi-002", "java")
        assert len(medium) == 1, f"Environment.getProperty must fire 002, got: {medium}"
        high = _scan(tmp_path, "Boot.java", "java_taint.yaml", src, "tnt-ja-cmdi-001", "java")
        assert not high, f"Environment.getProperty must not fire 001, got: {high}"


class TestGoOperatorInputSplit:
    """tnt-go-{cmdi,path}-001 vs -002 (rules/go_taint.yaml), EXT-19.

    Extends the EXT-08 sqli split to cmdi, path and ssrf: `os.Getenv`,
    `flag.*`, `os.Args` and viper lookups are operator-controlled (gogs
    `GOGS_CUSTOM`, kubernetes-mcp-server startup flags in ADR-0005) and now
    fire the WARNING 002 sibling, never the ERROR 001.
    """

    def test_getenv_into_exec_command_is_002_not_001(self, tmp_path):
        src = (
            "package main\n\n"
            "import (\n"
            '\t"os"\n'
            '\t"os/exec"\n'
            ")\n\n"
            "func run() {\n"
            '\tgit := os.Getenv("GIT_BIN")\n'
            '\texec.Command(git, "status").Run()\n'
            "}\n"
        )
        high = _scan(tmp_path, "main.go", "go_taint.yaml", src, "tnt-go-cmdi-001", "go")
        assert not high, f"os.Getenv is operator input and must not fire 001, got: {high}"
        medium = _scan(tmp_path, "main.go", "go_taint.yaml", src, "tnt-go-cmdi-002", "go")
        assert len(medium) == 1, f"expected exactly one 002 finding, got: {medium}"

    def test_form_value_into_exec_command_stays_001(self, tmp_path):
        src = (
            "package handler\n\n"
            "import (\n"
            '\t"net/http"\n'
            '\t"os/exec"\n'
            ")\n\n"
            "func Handle(r *http.Request) {\n"
            '\tcmd := r.FormValue("cmd")\n'
            "\texec.Command(cmd).Run()\n"
            "}\n"
        )
        high = _scan(tmp_path, "handler.go", "go_taint.yaml", src, "tnt-go-cmdi-001", "go")
        assert len(high) == 1, f"expected exactly one 001 finding, got: {high}"
        medium = _scan(tmp_path, "handler.go", "go_taint.yaml", src, "tnt-go-cmdi-002", "go")
        assert not medium, f"request input must not fire the operator rule, got: {medium}"

    def test_getenv_into_os_open_is_002_not_001(self, tmp_path):
        src = (
            "package main\n\n"
            'import "os"\n\n'
            "func load() {\n"
            '\tcustom := os.Getenv("GOGS_CUSTOM")\n'
            '\tos.Open(custom + "/conf/app.ini")\n'
            "}\n"
        )
        high = _scan(tmp_path, "main.go", "go_taint.yaml", src, "tnt-go-path-001", "go")
        assert not high, f"os.Getenv is operator input and must not fire 001, got: {high}"
        medium = _scan(tmp_path, "main.go", "go_taint.yaml", src, "tnt-go-path-002", "go")
        assert len(medium) == 1, f"expected exactly one 002 finding, got: {medium}"

    def test_form_value_into_os_open_stays_001(self, tmp_path):
        src = (
            "package handler\n\n"
            "import (\n"
            '\t"net/http"\n'
            '\t"os"\n'
            ")\n\n"
            "func Handle(r *http.Request) {\n"
            '\tname := r.FormValue("name")\n'
            '\tos.Open("/data/" + name)\n'
            "}\n"
        )
        high = _scan(tmp_path, "handler.go", "go_taint.yaml", src, "tnt-go-path-001", "go")
        assert len(high) == 1, f"expected exactly one 001 finding, got: {high}"
        medium = _scan(tmp_path, "handler.go", "go_taint.yaml", src, "tnt-go-path-002", "go")
        assert not medium, f"request input must not fire the operator rule, got: {medium}"

    def test_viper_get_string_fires_002(self, tmp_path):
        src = (
            "package main\n\n"
            "import (\n"
            '\t"os"\n\n'
            '\t"github.com/spf13/viper"\n'
            ")\n\n"
            "func load() {\n"
            '\tdir := viper.GetString("data.dir")\n'
            '\tos.ReadFile(dir + "/state.json")\n'
            "}\n"
        )
        medium = _scan(tmp_path, "main.go", "go_taint.yaml", src, "tnt-go-path-002", "go")
        assert len(medium) == 1, f"viper.GetString must fire 002, got: {medium}"
        high = _scan(tmp_path, "main.go", "go_taint.yaml", src, "tnt-go-path-001", "go")
        assert not high, f"viper.GetString must not fire 001, got: {high}"


class TestGoSqliParameterizedArgs:
    """tnt-go-sqli-001 (BACKLOG RT-01): the sink matched the whole call, so a
    tainted value in a placeholder ARGUMENT position (`db.Query("... $1", id)`)
    was reported as SQL injection. Only the SQL text argument is a sink."""

    _PREAMBLE = 'package handler\n\nimport (\n\t"context"\n\t"database/sql"\n\t"net/http"\n)\n\n'

    def test_placeholder_arguments_not_flagged(self, tmp_path):
        src = self._PREAMBLE + (
            "func Handle(db *sql.DB, r *http.Request) {\n"
            '\tid := r.FormValue("id")\n'
            '\trows, _ := db.Query("SELECT name FROM users WHERE id = $1", id)\n'
            '\tdb.Exec("UPDATE users SET name = ? WHERE id = 1", id)\n'
            '\tdb.QueryContext(context.Background(), "SELECT 1 WHERE id = $1", id)\n'
            "\t_ = rows\n"
            "}\n"
        )
        assert _scan(tmp_path, "handler.go", "go_taint.yaml", src, "tnt-go-sqli-001", "go") == []

    def test_sql_text_position_still_flagged(self, tmp_path):
        src = self._PREAMBLE + (
            "func Handle(db *sql.DB, r *http.Request) {\n"
            '\tid := r.FormValue("id")\n'
            '\trows, _ := db.Query("SELECT name FROM users WHERE id = " + id)\n'
            '\tdb.QueryContext(context.Background(), "SELECT 1 WHERE id = " + id)\n'
            "\t_ = rows\n"
            "}\n"
        )
        findings = _scan(tmp_path, "handler.go", "go_taint.yaml", src, "tnt-go-sqli-001", "go")
        assert sorted(f.start_line for f in findings) == [11, 12]


class TestJsSqliParameterizedArgs:
    """tnt-js-sqli-001 (BACKLOG RT-01): same whole-call sink shape in JS."""

    def test_placeholder_arguments_not_flagged(self, tmp_path):
        src = (
            "app.get('/u', async (req, res) => {\n"
            "  const rows = await pool.query('SELECT name FROM users WHERE id = $1', [req.query.id]);\n"
            "  const more = await db.query('SELECT 1 WHERE id = ?', [req.params.id]);\n"
            "  res.json(rows);\n"
            "});\n"
        )
        assert (
            _scan(tmp_path, "app.js", "javascript_taint.yaml", src, "tnt-js-sqli-001", "javascript")
            == []
        )

    def test_sql_text_position_still_flagged(self, tmp_path):
        src = (
            "app.get('/u', async (req, res) => {\n"
            "  const rows = await pool.query('SELECT name FROM users WHERE id = ' + req.query.id);\n"
            "  res.json(rows);\n"
            "});\n"
        )
        findings = _scan(
            tmp_path, "app.js", "javascript_taint.yaml", src, "tnt-js-sqli-001", "javascript"
        )
        assert [f.start_line for f in findings] == [2]


class TestCmdiListForm:
    """TNT-CMDI-001 (BACKLOG RT-02): the sink was the whole `subprocess.run(...)`
    call and the `shell=False` "sanitizer" was a keyword fragment that never
    matched a value, so list-form calls fired at ERROR. The command argument
    is the sink; a list is not a shell string."""

    _SRC = (
        "import subprocess\n"
        "from flask import request\n\n"
        "def list_form():\n"
        '    name = request.args.get("name")\n'
        '    subprocess.run(["ls", "-l", name])\n\n'
        "def list_form_no_shell():\n"
        '    name = request.args.get("name")\n'
        '    subprocess.run(["ls", "-l", name], shell=False)\n\n'
        "def string_shell():\n"
        '    name = request.args.get("name")\n'
        '    subprocess.run("ls -l " + name, shell=True)\n\n'
        "def string_no_shell_kw():\n"
        '    name = request.args.get("name")\n'
        '    subprocess.run("ls -l " + name)\n'
    )

    def test_list_form_not_flagged_string_form_flagged(self, tmp_path):
        findings = _scan(
            tmp_path, "app.py", "python_taint_extended.yaml", self._SRC, "TNT-CMDI-001", "python"
        )
        assert sorted(f.start_line for f in findings) == [14, 18]


class TestAiml004SinkReceiver:
    """TNT-AIML-004 (BACKLOG RT-03): `$AGENT.run(...)` matched `subprocess.run`,
    `asyncio.run` and `app.run`; the receiver must look like an agent."""

    _SRC = (
        "import asyncio\n"
        "import subprocess\n"
        "from flask import Flask, request\n"
        "from langchain.agents import initialize_agent\n\n"
        "app = Flask(__name__)\n"
        "agent = initialize_agent([])\n\n"
        "def a():\n"
        '    q = request.args.get("q")\n'
        '    subprocess.run(["echo", q])\n\n'
        "def b():\n"
        '    q = request.args.get("q")\n'
        "    asyncio.run(main(q))\n\n"
        "def c():\n"
        '    port = request.args.get("port")\n'
        '    app.run(host="0.0.0.0", port=port)\n\n'
        "def d():\n"
        '    q = request.args.get("q")\n'
        "    agent.run(q)\n"
    )

    def test_only_agent_receiver_is_a_sink(self, tmp_path):
        findings = _scan(
            tmp_path, "app.py", "python_taint_extended.yaml", self._SRC, "TNT-AIML-004", "python"
        )
        assert [f.start_line for f in findings] == [23]


class TestMultiArgSinkFocus:
    """RT-14: taint in a non-payload argument is not the sink's danger."""

    def test_getattr_tainted_object_is_not_reflection(self, tmp_path):
        source = (
            "from flask import request\n"
            "FIELD = 'upper'\n"
            "def view(field=FIELD):\n"
            "    obj = request.args.get('o')\n"
            "    return getattr(obj, field)()\n"
        )
        assert _scan(tmp_path, "a.py", "python_web_surface_taint.yaml", source,
                     "TNT-REFLECT-001", "python") == []

    def test_getattr_tainted_name_still_fires(self, tmp_path):
        source = (
            "from flask import request\n"
            "def view(handlers):\n"
            "    name = request.args.get('op')\n"
            "    return getattr(handlers, name, None)()\n"
        )
        assert _scan(tmp_path, "a.py", "python_web_surface_taint.yaml", source,
                     "TNT-REFLECT-001", "python")

    def test_model_tool_object_is_not_dispatch(self, tmp_path):
        source = (
            "def dispatch(tool_call, attr):\n"
            "    target = tool_call.function.name\n"
            "    return getattr(target, attr, None)\n"
        )
        assert _scan(tmp_path, "a.py", "agent_taint.yaml", source,
                     "TNT-ML-012", "python") == []

    def test_model_tool_name_still_fires(self, tmp_path):
        source = (
            "def dispatch(tool_call, registry):\n"
            "    name = tool_call.function.name\n"
            "    return getattr(registry, name, None)()\n"
        )
        assert _scan(tmp_path, "a.py", "agent_taint.yaml", source, "TNT-ML-012", "python")

    def test_llm_chosen_http_method_is_not_url_injection(self, tmp_path):
        source = (
            "import requests\n"
            "def act(client):\n"
            "    r = client.chat.completions.create(model='m', messages=[])\n"
            "    method = r.choices[0].message.content\n"
            "    return requests.request(method, 'https://api.example.com/x')\n"
        )
        assert _scan(tmp_path, "a.py", "llm_output_taint.yaml", source,
                     "TNT-LLMOUT-004", "python") == []

    def test_llm_chosen_url_still_fires(self, tmp_path):
        source = (
            "import requests\n"
            "def act(client):\n"
            "    r = client.chat.completions.create(model='m', messages=[])\n"
            "    url = r.choices[0].message.content\n"
            "    return requests.request('GET', url)\n"
        )
        assert _scan(tmp_path, "a.py", "llm_output_taint.yaml", source, "TNT-LLMOUT-004", "python")

    def test_hub_model_name_is_not_repo_injection(self, tmp_path):
        source = (
            "import torch\n"
            "from flask import request\n"
            "def load():\n"
            "    name = request.args.get('model')\n"
            "    return torch.hub.load('pytorch/vision', name)\n"
        )
        assert _scan(tmp_path, "a.py", "ml_taint.yaml", source, "TNT-ML-007", "python") == []

    def test_hub_repo_still_fires(self, tmp_path):
        source = (
            "import torch\n"
            "from flask import request\n"
            "def load():\n"
            "    repo = request.args.get('repo')\n"
            "    return torch.hub.load(repo, 'resnet18')\n"
        )
        assert _scan(tmp_path, "a.py", "ml_taint.yaml", source, "TNT-ML-007", "python")


class TestSsrfChainNeedsAFetch:
    """TNT-SSRF-003 claims a multi-step chain: a user-controlled URL is
    fetched and the response reaches a file write or deserializer. It used to
    fire on any direct request -> sink flow (196 false positives, 0 true, on
    RealVuln 2026-10-02). Taint labels now require the fetch in the middle."""

    _CHAIN = (
        "import pickle, requests\n"
        "from flask import request\n"
        "def load():\n"
        "    r = requests.get(request.args.get('u'))\n"
        "    data = r.content\n"
        "    return pickle.loads(data)\n"
    )

    def _hits(self, tmp_path, source, taint_intrafile=True):
        (tmp_path / "app.py").write_text(source, encoding="utf-8")
        outcome = OpengrepAdapter().scan_collect_with_rules(
            tmp_path, [RULES_DIR / "supply_chain_taint.yaml"], languages=["python"],
            taint_intrafile=taint_intrafile,
        )
        return [f for f in outcome.findings if f.rule_id == "TNT-SSRF-003"]

    def test_fetched_response_reaching_pickle_is_reported(self, tmp_path):
        assert self._hits(tmp_path, self._CHAIN, taint_intrafile=False)

    @pytest.mark.xfail(strict=True, reason=(
        "Opengrep 1.29 --taint-intrafile drops taint through an external call "
        "such as requests.get(...), so the chain is invisible in Rowan's default "
        "mode. Remove this marker when the engine propagates it."))
    def test_fetched_response_reaching_pickle_in_default_mode(self, tmp_path):
        assert self._hits(tmp_path, self._CHAIN)

    def test_direct_request_body_to_pickle_is_not_this_rule(self, tmp_path):
        source = (
            "import pickle\n"
            "from flask import request\n"
            "def load():\n"
            "    return pickle.loads(request.data)\n"
        )
        assert self._hits(tmp_path, source) == []

    def test_fixed_url_download_is_not_this_rule(self, tmp_path):
        source = (
            "import requests\n"
            "from flask import request\n"
            "def save(path):\n"
            "    r = requests.get('https://fixed.example/model.bin')\n"
            "    path.write_bytes(r.content)\n"
        )
        assert self._hits(tmp_path, source) == []


class TestSupplyChainRuleNeedsTheHub:
    """TNT-SUPPLY-001 claims a user-chosen Hub repo ID reaches a model loader.
    It used to fire on any direct request -> pickle.loads / eval flow (86
    false positives, 0 true, on RealVuln 2026-10-02)."""

    def _hits(self, tmp_path, source):
        return _scan(tmp_path, "app.py", "supply_chain_taint.yaml", source, "TNT-SUPPLY-001", "python")

    def test_user_repo_id_to_from_pretrained_is_reported(self, tmp_path):
        source = (
            "import os\n"
            "from transformers import AutoModel\n"
            "def load():\n"
            "    return AutoModel.from_pretrained(os.environ['MODEL_REPO'])\n"
        )
        assert self._hits(tmp_path, source)

    def test_direct_request_to_eval_is_not_this_rule(self, tmp_path):
        source = (
            "import os\n"
            "def run():\n"
            "    return eval(os.getenv('EXPR'))\n"
        )
        assert self._hits(tmp_path, source) == []
