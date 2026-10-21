"""BACKLOG.md JG-10: Go MCP and LLM taint rules.

`rules/go_ai_taint.yaml` carries eight taint rules: `tnt-go-ai-mcptool-
{exec,path,sql,ssrf}-001` (an MCP tool argument reaches a sink) and
`tnt-go-ai-llmout-{sql,exec,ssrf,path}-001` (LLM completion text reaches the
same sinks). `rules/go_ai_opengrep.yaml` carries the search-mode inventory
rule `tnt-go-ai-mcpbind-001` (SSE / streamable-HTTP MCP server bound on all
interfaces). Each rule gets a true positive on mcp-go, a true positive on the
official go-sdk typed-args handler where the source family applies, and a true
negative with a constant sink argument. The SQL rules also prove a
parameterised placeholder argument stays quiet, and the path rules prove the
mcp-filesystem-server `validatePath` idiom sanitizes.

Requires the Opengrep binary (skipped entirely if not installed, matching the
project's convention).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from rowan.config import ScanConfig
from rowan.core.findings import Severity
from rowan.pipeline import ScanPipeline
from rowan.taint.opengrep_adapter import OpengrepAdapter

RULES_DIR = Path(__file__).parent.parent / "rules"
TAINT_RULES = "go_ai_taint.yaml"
SEARCH_RULES = "go_ai_opengrep.yaml"

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


def _mcp_go(body: str, extra_imports: str = "") -> str:
    """An mcp-go tool handler with `request` as the CallToolRequest."""
    return (
        "package main\n\n"
        "import (\n"
        '\t"context"\n'
        f"{extra_imports}"
        '\n\t"github.com/mark3labs/mcp-go/mcp"\n'
        ")\n\n"
        "func handle(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {\n"
        f"{body}"
        "\treturn nil, nil\n"
        "}\n"
    )


def _go_sdk(body: str, extra_imports: str = "") -> str:
    """An official go-sdk typed-args tool handler with `args.Value`."""
    return (
        "package main\n\n"
        "import (\n"
        '\t"context"\n'
        f"{extra_imports}"
        '\n\t"github.com/modelcontextprotocol/go-sdk/mcp"\n'
        ")\n\n"
        "type Args struct {\n"
        '\tValue string `json:"value"`\n'
        "}\n\n"
        "func run(ctx context.Context, req *mcp.CallToolRequest, args Args) (*mcp.CallToolResult, any, error) {\n"
        f"{body}"
        "\treturn nil, nil, nil\n"
        "}\n"
    )


def _llm(body: str, extra_imports: str = "") -> str:
    """openai-go completion text bound to `text`."""
    return (
        "package main\n\n"
        "import (\n"
        '\t"context"\n'
        f"{extra_imports}"
        '\n\t"github.com/openai/openai-go"\n'
        ")\n\n"
        "func run(ctx context.Context, client *openai.Client) {\n"
        "\tresp, _ := client.Chat.Completions.New(ctx, openai.ChatCompletionNewParams{})\n"
        "\ttext := resp.Choices[0].Message.Content\n"
        f"{body}"
        "}\n"
    )


class TestMcpToolExec:
    RULE = "tnt-go-ai-mcptool-exec-001"

    def test_mcp_go_require_string_to_command_context(self, tmp_path):
        src = _mcp_go(
            '\tcmd, _ := request.RequireString("command")\n'
            '\tout, _ := exec.CommandContext(ctx, "bash", "-c", cmd).Output()\n'
            "\t_ = out\n",
            '\t"os/exec"\n',
        )
        assert _scan(tmp_path, "h.go", TAINT_RULES, src, self.RULE, "go")

    def test_go_sdk_typed_args_to_exec_command(self, tmp_path):
        src = _go_sdk(
            '\texec.Command("sh", "-c", args.Value).Run()\n',
            '\t"os/exec"\n',
        )
        assert _scan(tmp_path, "h.go", TAINT_RULES, src, self.RULE, "go")

    def test_constant_command_is_quiet(self, tmp_path):
        src = _mcp_go(
            '\t_, _ = request.RequireString("command")\n'
            '\tout, _ := exec.CommandContext(ctx, "uptime").Output()\n'
            "\t_ = out\n",
            '\t"os/exec"\n',
        )
        assert not _scan(tmp_path, "h.go", TAINT_RULES, src, self.RULE, "go")


class TestMcpToolPath:
    RULE = "tnt-go-ai-mcptool-path-001"

    @pytest.mark.parametrize(
        "sink",
        [
            "os.ReadFile(p)",
            'os.WriteFile(p, []byte("x"), 0644)',
            "os.Create(p)",
            "os.Remove(p)",
            "os.MkdirAll(p, 0755)",
            "ioutil.ReadFile(p)",
        ],
    )
    def test_mcp_go_path_to_each_file_sink(self, tmp_path, sink):
        src = _mcp_go(
            '\tp, _ := request.RequireString("path")\n'
            f"\t{sink}\n",
            '\t"io/ioutil"\n\t"os"\n',
        )
        assert _scan(tmp_path, "h.go", TAINT_RULES, src, self.RULE, "go"), sink

    def test_go_sdk_typed_args_to_read_file(self, tmp_path):
        src = _go_sdk("\tos.ReadFile(args.Value)\n", '\t"os"\n')
        assert _scan(tmp_path, "h.go", TAINT_RULES, src, self.RULE, "go")

    def test_validate_path_sanitizes(self, tmp_path):
        """The mcp-filesystem-server idiom: `validPath, err := fs.validatePath(path)`
        before every filesystem call. The rule must stay quiet on it."""
        src = (
            "package main\n\n"
            "import (\n"
            '\t"context"\n'
            '\t"os"\n\n'
            '\t"github.com/mark3labs/mcp-go/mcp"\n'
            ")\n\n"
            "type FS struct{}\n\n"
            "func (fs *FS) validatePath(p string) (string, error) { return p, nil }\n\n"
            "func (fs *FS) handle(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {\n"
            '\tpath, _ := request.RequireString("path")\n'
            "\tvalidPath, err := fs.validatePath(path)\n"
            "\tif err != nil {\n"
            "\t\treturn nil, err\n"
            "\t}\n"
            "\tdata, _ := os.ReadFile(validPath)\n"
            "\treturn mcp.NewToolResultText(string(data)), nil\n"
            "}\n"
        )
        assert not _scan(tmp_path, "h.go", TAINT_RULES, src, self.RULE, "go")

    def test_constant_path_is_quiet(self, tmp_path):
        src = _mcp_go(
            '\t_, _ = request.RequireString("path")\n'
            '\tos.ReadFile("/etc/hostname")\n',
            '\t"os"\n',
        )
        assert not _scan(tmp_path, "h.go", TAINT_RULES, src, self.RULE, "go")


class TestMcpToolArgTypedReceiver:
    """JG-08 corpus finding: `mcp_tool_arg_go`'s GetString/GetInt/GetBool/
    RequireString/RequireInt patterns had no receiver-type constraint, so
    they matched any object's identically-named method. github-mcp-server's
    cobra CLI flag parser (`cmd.Flags().GetString("stdio-server-cmd")`) and
    a GitHub App key path flag both got misread as MCP tool arguments,
    because cobra's *pflag.FlagSet exposes the same method names. Sources
    must now be typed `($REQ : mcp.CallToolRequest).GetString(...)` etc."""

    def test_cobra_flag_get_string_to_exec_is_quiet(self, tmp_path):
        """github-mcp-server cmd/mcpcurl/main.go shape: a `--stdio-server-cmd`
        flag value, read with cobra's `cmd.Flags().GetString`, reaches
        exec.Command. Not an MCP tool argument; must not fire."""
        src = (
            "package main\n\n"
            "import (\n"
            '\t"os/exec"\n\n'
            '\t"github.com/spf13/cobra"\n'
            ")\n\n"
            "func run(cmd *cobra.Command) {\n"
            '\tserverCmd, _ := cmd.Flags().GetString("stdio-server-cmd")\n'
            "\texec.Command(serverCmd).Run()\n"
            "}\n"
        )
        assert not _scan(tmp_path, "h.go", TAINT_RULES, src, "tnt-go-ai-mcptool-exec-001", "go")

    def test_cobra_flag_get_string_to_read_file_is_quiet(self, tmp_path):
        """github-mcp-server cmd/github-mcp-server/main.go shape: a GitHub
        App private-key path flag reaches os.ReadFile. Not an MCP tool
        argument; must not fire."""
        src = (
            "package main\n\n"
            "import (\n"
            '\t"os"\n\n'
            '\t"github.com/spf13/cobra"\n'
            ")\n\n"
            "func loadKey(cmd *cobra.Command) ([]byte, error) {\n"
            '\tpath, _ := cmd.Flags().GetString("app-private-key")\n'
            "\treturn os.ReadFile(path)\n"
            "}\n"
        )
        assert not _scan(tmp_path, "h.go", TAINT_RULES, src, "tnt-go-ai-mcptool-path-001", "go")

    def test_mcp_go_get_string_to_exec_still_fires(self, tmp_path):
        """The typed receiver must not lose the real mcp-go shape."""
        src = _mcp_go(
            '\tcmd, _ := request.GetString("command", "")\n'
            "\texec.Command(cmd).Run()\n",
            '\t"os/exec"\n',
        )
        assert _scan(tmp_path, "h.go", TAINT_RULES, src, "tnt-go-ai-mcptool-exec-001", "go")


class TestMcpToolSql:
    RULE = "tnt-go-ai-mcptool-sql-001"

    def test_mcp_go_concatenated_statement(self, tmp_path):
        src = _mcp_go(
            '\tname, _ := request.RequireString("name")\n'
            "\trows, _ := db.QueryContext(ctx, \"SELECT * FROM users WHERE name = '\"+name+\"'\")\n"
            "\t_ = rows\n",
            '\t"database/sql"\n',
        ).replace("func handle", "var db *sql.DB\n\nfunc handle")
        assert _scan(tmp_path, "h.go", TAINT_RULES, src, self.RULE, "go")

    def test_go_sdk_typed_args_to_exec(self, tmp_path):
        src = _go_sdk(
            '\tdb.Exec("DELETE FROM t WHERE id = " + args.Value)\n',
            '\t"database/sql"\n',
        ).replace("func run", "var db *sql.DB\n\nfunc run")
        assert _scan(tmp_path, "h.go", TAINT_RULES, src, self.RULE, "go")

    def test_parameterised_argument_is_quiet(self, tmp_path):
        src = _mcp_go(
            '\tname, _ := request.RequireString("name")\n'
            '\trows, _ := db.QueryContext(ctx, "SELECT * FROM users WHERE name = ?", name)\n'
            "\t_ = rows\n",
            '\t"database/sql"\n',
        ).replace("func handle", "var db *sql.DB\n\nfunc handle")
        assert not _scan(tmp_path, "h.go", TAINT_RULES, src, self.RULE, "go")

    def test_constant_statement_is_quiet(self, tmp_path):
        src = _mcp_go(
            '\t_, _ = request.RequireString("name")\n'
            '\trows, _ := db.Query("SELECT 1")\n'
            "\t_ = rows\n",
            '\t"database/sql"\n',
        ).replace("func handle", "var db *sql.DB\n\nfunc handle")
        assert not _scan(tmp_path, "h.go", TAINT_RULES, src, self.RULE, "go")


    def test_struct_options_to_a_query_method_is_quiet(self, tmp_path):
        """radar's timeline store: `store.Query(ctx, opts)` with a struct of
        options is not a SQL statement (MCP census, 2026-10-20)."""
        src = _mcp_go(
            '\tns, _ := request.RequireString("namespace")\n'
            "\topts := timeline.QueryOptions{Namespace: ns, Limit: 20}\n"
            "\tchanges, _ := store.Query(ctx, opts)\n"
            "\t_ = changes\n",
            '\t"example.com/app/timeline"\n',
        )
        assert not _scan(tmp_path, "h.go", TAINT_RULES, src, self.RULE, "go")

    def test_promql_query_on_a_metrics_client_is_quiet(self, tmp_path):
        """radar's prometheus tool runs a PromQL query by design: `p.Query(ctx, q)`."""
        src = _mcp_go(
            '\tq, _ := request.RequireString("query")\n'
            "\tresult, _ := p.Query(ctx, q)\n"
            "\t_ = result\n",
        )
        assert not _scan(tmp_path, "h.go", TAINT_RULES, src, self.RULE, "go")

    def test_pgx_context_first_statement_still_fires(self, tmp_path):
        src = _mcp_go(
            '\tname, _ := request.RequireString("name")\n'
            "\trows, _ := conn.Query(ctx, \"SELECT * FROM users WHERE name = '\"+name+\"'\")\n"
            "\t_ = rows\n",
        )
        assert _scan(tmp_path, "h.go", TAINT_RULES, src, self.RULE, "go")


class TestMcpToolSsrf:
    RULE = "tnt-go-ai-mcptool-ssrf-001"

    def test_url_parse_alone_is_not_a_request(self, tmp_path):
        # Parsing makes no request; only a fetch of the URL is SSRF (#56).
        src = _mcp_go(
            '\tu := request.GetString("url", "")\n'
            "\tp, _ := url.Parse(u)\n"
            "\t_ = p\n",
            '\t"net/url"\n',
        )
        assert not _scan(tmp_path, "h.go", TAINT_RULES, src, self.RULE, "go")

    @pytest.mark.parametrize(
        "sink",
        [
            "http.Get(u)",
            'http.NewRequest("GET", u, nil)',
            'http.NewRequestWithContext(ctx, "GET", u, nil)',
        ],
    )
    def test_mcp_go_url_to_each_sink(self, tmp_path, sink):
        src = _mcp_go(
            '\tu := request.GetString("url", "")\n'
            f"\t{sink}\n",
            '\t"net/http"\n\t"net/url"\n',
        )
        assert _scan(tmp_path, "h.go", TAINT_RULES, src, self.RULE, "go"), sink

    def test_go_sdk_typed_args_to_http_get(self, tmp_path):
        src = _go_sdk("\thttp.Get(args.Value)\n", '\t"net/http"\n')
        assert _scan(tmp_path, "h.go", TAINT_RULES, src, self.RULE, "go")

    def test_tainted_body_with_constant_url_is_quiet(self, tmp_path):
        src = _mcp_go(
            '\tbody := request.GetString("body", "")\n'
            '\treq, _ := http.NewRequestWithContext(ctx, "POST", "https://api.example.com/v1", strings.NewReader(body))\n'
            "\t_ = req\n",
            '\t"net/http"\n\t"strings"\n',
        )
        assert not _scan(tmp_path, "h.go", TAINT_RULES, src, self.RULE, "go")


class TestLlmOutput:
    def test_sql(self, tmp_path):
        src = _llm("\tdb.Query(text)\n", '\t"database/sql"\n').replace(
            "func run", "var db *sql.DB\n\nfunc run"
        )
        assert _scan(tmp_path, "h.go", TAINT_RULES, src, "tnt-go-ai-llmout-sql-001", "go")

    def test_sql_parameterised_is_quiet(self, tmp_path):
        src = _llm('\tdb.Query("SELECT * FROM t WHERE id = ?", text)\n', '\t"database/sql"\n').replace(
            "func run", "var db *sql.DB\n\nfunc run"
        )
        assert not _scan(tmp_path, "h.go", TAINT_RULES, src, "tnt-go-ai-llmout-sql-001", "go")

    def test_exec(self, tmp_path):
        src = _llm('\texec.Command("sh", "-c", text).Run()\n', '\t"os/exec"\n')
        assert _scan(tmp_path, "h.go", TAINT_RULES, src, "tnt-go-ai-llmout-exec-001", "go")

    def test_exec_langchaingo_return(self, tmp_path):
        src = (
            "package main\n\n"
            "import (\n"
            '\t"context"\n'
            '\t"os/exec"\n\n'
            '\t"github.com/tmc/langchaingo/llms"\n'
            ")\n\n"
            "func run(ctx context.Context, llm llms.Model) {\n"
            '\tcmd, _ := llms.GenerateFromSinglePrompt(ctx, llm, "which command?")\n'
            '\texec.Command("sh", "-c", cmd).Run()\n'
            "}\n"
        )
        assert _scan(tmp_path, "h.go", TAINT_RULES, src, "tnt-go-ai-llmout-exec-001", "go")

    def test_ssrf(self, tmp_path):
        src = _llm("\thttp.Get(text)\n", '\t"net/http"\n')
        assert _scan(tmp_path, "h.go", TAINT_RULES, src, "tnt-go-ai-llmout-ssrf-001", "go")

    def test_path(self, tmp_path):
        src = _llm("\tos.ReadFile(text)\n", '\t"os"\n')
        assert _scan(tmp_path, "h.go", TAINT_RULES, src, "tnt-go-ai-llmout-path-001", "go")

    @pytest.mark.parametrize(
        "rule_id, body, imp",
        [
            ("tnt-go-ai-llmout-sql-001", '\tdb.Query("SELECT 1")\n\t_ = text\n', '\t"database/sql"\n'),
            ("tnt-go-ai-llmout-exec-001", '\texec.Command("uptime").Run()\n\t_ = text\n', '\t"os/exec"\n'),
            ("tnt-go-ai-llmout-ssrf-001", '\thttp.Get("https://example.com")\n\t_ = text\n', '\t"net/http"\n'),
            ("tnt-go-ai-llmout-path-001", '\tos.ReadFile("/etc/hostname")\n\t_ = text\n', '\t"os"\n'),
        ],
    )
    def test_constant_sink_is_quiet(self, tmp_path, rule_id, body, imp):
        src = _llm(body, imp).replace("func run", "var db *sql.DB\n\nfunc run")
        assert not _scan(tmp_path, "h.go", TAINT_RULES, src, rule_id, "go")


class TestMcpBind:
    RULE = "tnt-go-ai-mcpbind-001"

    def test_all_interfaces_binds_fire(self, tmp_path):
        src = (
            "package main\n\n"
            "import (\n"
            '\t"net/http"\n\n'
            '\t"github.com/mark3labs/mcp-go/server"\n'
            '\tmcp "github.com/modelcontextprotocol/go-sdk/mcp"\n'
            ")\n\n"
            "func a(s *server.MCPServer) {\n"
            '\tserver.NewSSEServer(s).Start("0.0.0.0:8080")\n'
            "}\n\n"
            "func b(s *server.MCPServer) {\n"
            "\tsrv := server.NewStreamableHTTPServer(s)\n"
            '\tsrv.Start(":8080")\n'
            "}\n\n"
            "func c(s *server.MCPServer) {\n"
            '\taddr := ":9090"\n'
            "\tsse := server.NewSSEServer(s)\n"
            "\tsse.Start(addr)\n"
            "}\n\n"
            "func d(get func(*http.Request) *mcp.Server) {\n"
            '\thttp.ListenAndServe(":8080", mcp.NewStreamableHTTPHandler(get, nil))\n'
            "}\n\n"
            "func e(get func(*http.Request) *mcp.Server) {\n"
            "\th := mcp.NewSSEHandler(get, nil)\n"
            '\thttp.ListenAndServe("0.0.0.0:8080", h)\n'
            "}\n"
        )
        findings = _scan(tmp_path, "main.go", SEARCH_RULES, src, self.RULE, "go")
        assert sorted(f.start_line for f in findings) == [11, 16, 22, 26, 31]

    def test_loopback_binds_are_quiet(self, tmp_path):
        src = (
            "package main\n\n"
            "import (\n"
            '\t"net/http"\n\n'
            '\t"github.com/mark3labs/mcp-go/server"\n'
            '\tmcp "github.com/modelcontextprotocol/go-sdk/mcp"\n'
            ")\n\n"
            "func a(s *server.MCPServer) {\n"
            '\tserver.NewSSEServer(s).Start("127.0.0.1:8080")\n'
            "}\n\n"
            "func b(s *server.MCPServer) {\n"
            "\tsrv := server.NewStreamableHTTPServer(s)\n"
            '\tsrv.Start("localhost:8080")\n'
            "}\n\n"
            "func d(get func(*http.Request) *mcp.Server) {\n"
            '\thttp.ListenAndServe("127.0.0.1:8080", mcp.NewStreamableHTTPHandler(get, nil))\n'
            "}\n\n"
            "func f() {\n"
            '\thttp.ListenAndServe(":8080", nil)\n'
            "}\n"
        )
        assert not _scan(tmp_path, "main.go", SEARCH_RULES, src, self.RULE, "go")


class TestFullScanEnrichment:
    def test_mcp_exec_finding_is_high_with_llm_origin(self, tmp_path_factory):
        """End to end through ScanPipeline: the rule fires, the go-sdk import
        passes the AI-context gate, and the rule's `source_kind: tool_param`
        gives the finding an LLM-derived origin so it stays HIGH after
        enrichment (JG-02). The fixture directory avoids `test` in its path
        so `_suppress_test_findings` leaves it alone."""
        root = tmp_path_factory.mktemp("goai")
        (root / "main.go").write_text(
            _mcp_go(
                '\tcmd, _ := request.RequireString("command")\n'
                '\tout, _ := exec.CommandContext(ctx, "bash", "-c", cmd).Output()\n'
                "\t_ = out\n",
                '\t"os/exec"\n',
            ),
            encoding="utf-8",
        )
        config = ScanConfig(target=root, no_sca=True, languages=["go"])
        result = ScanPipeline(config).run()
        hits = [f for f in result.findings if f.rule_id == "tnt-go-ai-mcptool-exec-001"]
        assert len(hits) == 1, [f.rule_id for f in result.findings]
        (hit,) = hits
        assert hit.severity == Severity.HIGH
        assert hit.metadata.get("source_origin") == "llm_output"
        assert hit.confidence >= 0.7


class TestMcpSamplingApproval:
    RULE = "tnt-go-ai-mcpsampling-001"
    PREAMBLE = (
        "package main\n\n"
        "import (\n"
        '\t"context"\n\n'
        '\t"github.com/mark3labs/mcp-go/mcp"\n'
        ")\n\n"
        "type handler struct{ llm LLM }\n\n"
    )

    def test_unapproved_sampling_handler_fires(self, tmp_path):
        src = self.PREAMBLE + (
            "func (h *handler) CreateMessage(ctx context.Context, req mcp.CreateMessageRequest) (*mcp.CreateMessageResult, error) {\n"
            "\tout, err := h.llm.Complete(ctx, req.Messages)\n"
            "\tif err != nil {\n\t\treturn nil, err\n\t}\n"
            "\treturn &mcp.CreateMessageResult{Content: mcp.TextContent{Text: out}}, nil\n"
            "}\n"
        )
        findings = _scan(tmp_path, "sampling.go", "go_ai_opengrep.yaml", src, self.RULE, "go")
        assert len(findings) == 1, f"a sampling handler with no approval must fire, got: {findings}"

    def test_approval_gated_handler_is_quiet(self, tmp_path):
        src = self.PREAMBLE + (
            "func (h *handler) CreateMessage(ctx context.Context, req mcp.CreateMessageRequest) (*mcp.CreateMessageResult, error) {\n"
            "\tif !h.askUserApproval(req) {\n\t\treturn nil, ErrDenied\n\t}\n"
            "\tout, err := h.llm.Complete(ctx, req.Messages)\n"
            "\tif err != nil {\n\t\treturn nil, err\n\t}\n"
            "\treturn &mcp.CreateMessageResult{Content: mcp.TextContent{Text: out}}, nil\n"
            "}\n"
        )
        findings = _scan(tmp_path, "sampling.go", "go_ai_opengrep.yaml", src, self.RULE, "go")
        assert not findings, f"an approval-gated handler must not fire, got: {findings}"
