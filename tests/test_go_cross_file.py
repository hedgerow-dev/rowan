"""Tests for the Go cross-file taint pass (rowan.passes.go_cross_file).

Scenario tests build a small Go module on disk and run ``GoCrossFilePass``
directly, the way tests/test_js_cross_file.py drives ``JSCrossFilePass``.
The pipeline-level test checks stage placement and the not-applicable skip.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from rowan.config import ScanConfig
from rowan.core.findings import Category, Finding, ScanResult, Severity, TaintFlow, TaintNode
from rowan.passes.base import ScanContext, SourceFile, SourceInventory
from rowan.passes.go_cross_file import TREE_SITTER_GO_AVAILABLE, GoCrossFilePass
from rowan.pipeline import ScanPipeline
from rowan.scan_plan import build_scan_plan

pytestmark = pytest.mark.skipif(
    not TREE_SITTER_GO_AVAILABLE,
    reason="tree-sitter-go not installed (pip install rowan-sast[js-crossfile])",
)

GO_MOD = "module example.com/app\n\ngo 1.22\n"

HANDLER_EXEC = """package tools

import (
\t"context"

\t"github.com/mark3labs/mcp-go/mcp"

\t"example.com/app/internal/shell"
)

func GitStatus(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
\trepoPath := request.GetString("repo_path", ".")
\tout, err := shell.Run(ctx, "-C", repoPath, "status")
\tif err != nil {
\t\treturn mcp.NewToolResultError(err.Error()), nil
\t}
\treturn mcp.NewToolResultText(out), nil
}
"""

SHELL_RUN = """package shell

import (
\t"context"
\t"os/exec"
)

func Run(ctx context.Context, args ...string) (string, error) {
\tcmd := exec.CommandContext(ctx, "git", args...)
\tout, err := cmd.CombinedOutput()
\treturn string(out), err
}
"""


def _make_module(files: dict[str, str]) -> Path:
    root = Path(tempfile.mkdtemp(prefix="rowan_gocf_"))
    (root / "go.mod").write_text(GO_MOD, encoding="utf-8")
    for name, content in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    return root


def _run(root: Path, findings: list[Finding] | None = None) -> ScanResult:
    config = ScanConfig(target=root)
    ctx = ScanContext(target_path=root, config=config, result=ScanResult(findings=findings or []))
    return GoCrossFilePass().run(ctx)


def _cf(result: ScanResult) -> list[Finding]:
    return [f for f in result.findings if f.rule_id.startswith("CF-GO-")]


def test_two_file_handler_to_helper_exec_emits_one_finding_with_one_hop():
    root = _make_module(
        {
            "internal/tools/git.go": HANDLER_EXEC,
            "internal/shell/run.go": SHELL_RUN,
        }
    )
    findings = _cf(_run(root))
    assert [f.rule_id for f in findings] == ["CF-GO-EXEC-001"]
    f = findings[0]
    assert f.file_path.endswith("internal/shell/run.go")
    assert f.start_line == 9
    assert f.severity == Severity.HIGH
    assert f.category == Category.COMMAND_INJECTION
    assert f.cwe_ids == [78]
    assert f.engine == "crossfile"
    assert f.metadata["source_kind"] == "tool_param"
    assert f.metadata["hop_depth"] == 1
    assert f.taint_flow is not None
    assert f.taint_flow.source.file_path.endswith("internal/tools/git.go")
    assert f.taint_flow.source.line == 12
    assert f.taint_flow.sink.line == 9
    assert [n.line for n in f.taint_flow.intermediate] == [13]
    assert "GitStatus" in f.taint_flow.intermediate[0].snippet


def test_same_function_flow_emits_nothing():
    root = _make_module(
        {
            "internal/tools/exec.go": """package tools

import (
\t"context"
\t"os/exec"

\t"github.com/mark3labs/mcp-go/mcp"
)

func RunCommand(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
\tcommand, _ := request.RequireString("command")
\tout, err := exec.CommandContext(ctx, "bash", "-c", command).CombinedOutput()
\tif err != nil {
\t\treturn mcp.NewToolResultError(err.Error()), nil
\t}
\treturn mcp.NewToolResultText(string(out)), nil
}
""",
            "internal/tools/other.go": "package tools\n\nfunc Unused() {}\n",
        }
    )
    assert _cf(_run(root)) == []


def test_interface_dispatch_names_the_implementation_with_the_sink():
    root = _make_module(
        {
            "pkg/server.go": """package pkg

import (
\t"context"

\t"github.com/mark3labs/mcp-go/mcp"

\t"example.com/app/pkg/gitops"
)

type GitServer struct {
\tgitOps gitops.GitOps
}

func (s *GitServer) diffHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
\ttarget, _ := request.Params.Arguments["target"].(string)
\tdiff, err := s.gitOps.GetDiff(target)
\tif err != nil {
\t\treturn mcp.NewToolResultError(err.Error()), nil
\t}
\treturn mcp.NewToolResultText(diff), nil
}
""",
            "pkg/gitops/interface.go": """package gitops

type GitOps interface {
\tGetDiff(target string) (string, error)
}
""",
            "pkg/gitops/shell/operations.go": """package shell

import "os/exec"

type ShellGitOps struct{}

func (s *ShellGitOps) GetDiff(target string) (string, error) {
\tout, err := exec.Command("git", "diff", target).Output()
\treturn string(out), err
}
""",
            "pkg/gitops/gogit/operations.go": """package gogit

type GoGitOps struct{}

func (g *GoGitOps) GetDiff(target string) (string, error) {
\treturn "diff " + target, nil
}
""",
        }
    )
    findings = _cf(_run(root))
    assert [f.rule_id for f in findings] == ["CF-GO-EXEC-001"]
    f = findings[0]
    assert f.file_path.endswith("pkg/gitops/shell/operations.go")
    assert f.start_line == 8
    assert "ShellGitOps" in f.metadata["callee"]
    assert f.taint_flow is not None
    assert f.taint_flow.source.file_path.endswith("pkg/server.go")


def test_validate_path_guard_between_source_and_sink_emits_nothing():
    root = _make_module(
        {
            "handlers.go": """package main

import (
\t"context"

\t"github.com/mark3labs/mcp-go/mcp"
)

func (s *Server) readHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
\tpath, _ := request.RequireString("path")
\tvalidPath, err := s.validatePath(path)
\tif err != nil {
\t\treturn mcp.NewToolResultError(err.Error()), nil
\t}
\tdata, err := readAll(validPath)
\tif err != nil {
\t\treturn mcp.NewToolResultError(err.Error()), nil
\t}
\treturn mcp.NewToolResultText(data), nil
}
""",
            "fs.go": """package main

import "os"

type Server struct{}

func (s *Server) validatePath(p string) (string, error) {
\treturn p, nil
}

func readAll(p string) (string, error) {
\tb, err := os.ReadFile(p)
\treturn string(b), err
}
""",
        }
    )
    assert _cf(_run(root)) == []


def test_parameterised_sql_emits_nothing_and_concatenated_sql_does():
    unsafe = """package db

import "database/sql"

var DB *sql.DB

func UnsafeQuery(uid string) (*sql.Rows, error) {
\treturn DB.Query("SELECT * FROM users WHERE id = " + uid)
}

func SafeQuery(uid string) (*sql.Rows, error) {
\treturn DB.Query("SELECT * FROM users WHERE id = ?", uid)
}
"""
    handler = """package web

import (
\t"net/http"

\t"example.com/app/db"
)

func SafeHandler(w http.ResponseWriter, r *http.Request) {
\tuid := r.FormValue("uid")
\tdb.SafeQuery(uid)
}
"""
    root = _make_module({"db/function.go": unsafe, "web/sqli.go": handler})
    assert _cf(_run(root)) == []

    root = _make_module(
        {
            "db/function.go": unsafe,
            "web/sqli.go": handler.replace("SafeQuery", "UnsafeQuery").replace(
                "SafeHandler", "Handler"
            ),
        }
    )
    findings = _cf(_run(root))
    assert [f.rule_id for f in findings] == ["CF-GO-SQL-001"]
    assert findings[0].file_path.endswith("db/function.go")
    assert findings[0].start_line == 8
    assert findings[0].metadata["source_kind"] == "http_input"
    assert findings[0].category == Category.INJECTION


def test_three_file_chain_reports_two_intermediate_hops():
    root = _make_module(
        {
            "web/handler.go": """package web

import (
\t"net/http"

\t"example.com/app/svc"
)

func Handler(w http.ResponseWriter, r *http.Request) {
\tname := r.URL.Query().Get("name")
\tsvc.Process(name)
}
""",
            "svc/service.go": """package svc

import "example.com/app/shell"

func Process(name string) {
\tshell.Run(name)
}
""",
            "shell/run.go": """package shell

import "os/exec"

func Run(arg string) {
\texec.Command("tool", arg).Run()
}
""",
        }
    )
    findings = _cf(_run(root))
    assert [f.rule_id for f in findings] == ["CF-GO-EXEC-001"]
    f = findings[0]
    assert f.metadata["hop_depth"] == 2
    assert [Path(n.file_path).name for n in f.taint_flow.intermediate] == [
        "handler.go",
        "service.go",
    ]
    assert [n.line for n in f.taint_flow.intermediate] == [11, 6]


def test_sink_already_reported_by_opengrep_is_not_duplicated():
    root = _make_module(
        {
            "internal/tools/git.go": HANDLER_EXEC,
            "internal/shell/run.go": SHELL_RUN,
        }
    )
    existing = Finding(
        rule_id="tnt-go-ai-mcptool-exec-001",
        message="already found",
        severity=Severity.HIGH,
        category=Category.COMMAND_INJECTION,
        file_path=str((root / "internal/shell/run.go").resolve()),
        start_line=9,
        cwe_ids=[78],
        engine="opengrep",
        taint_flow=TaintFlow(
            sink=TaintNode(file_path=str((root / "internal/shell/run.go").resolve()), line=9)
        ),
    )
    assert _cf(_run(root, [existing])) == []

    existing.taint_flow = None  # a pattern-only regex match at the sink is not a flow
    assert [f.rule_id for f in _cf(_run(root, [existing]))] == ["CF-GO-EXEC-001"]


def test_pass_is_in_the_correlation_stage_and_skipped_without_go_sources(tmp_path):
    plan = build_scan_plan(ScanConfig(target=tmp_path))
    names = [item.name for item in plan.selected]
    assert names.index("go_crossfile") > names.index("js_crossfile")

    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
    result = ScanPipeline(
        ScanConfig(target=tmp_path, no_sca=True, no_taint=True, legacy_neuroscan=True)
    ).run()
    skipped = {item["name"]: item for item in result.metadata["inapplicable_passes"]}
    assert skipped["go_crossfile"]["status"] == "not_applicable"
    assert "Go" in skipped["go_crossfile"]["reason"]
    stages = {item["name"]: item["stage"] for item in result.metadata["pass_outcomes"]}
    assert "go_crossfile" not in stages


def test_pass_runs_in_correlation_stage_with_go_sources(tmp_path):
    (tmp_path / "go.mod").write_text(GO_MOD, encoding="utf-8")
    (tmp_path / "main.go").write_text("package main\n\nfunc main() {}\n", encoding="utf-8")
    result = ScanPipeline(
        ScanConfig(target=tmp_path, no_sca=True, no_taint=True, legacy_neuroscan=True)
    ).run()
    stages = {item["name"]: item["stage"] for item in result.metadata["pass_outcomes"]}
    assert stages["go_crossfile"] == "correlation"
    assert result.metadata["analysis_capability"]["cross_file_languages"] == ["go"]


def test_inventory_scopes_the_go_files():
    root = _make_module(
        {
            "internal/tools/git.go": HANDLER_EXEC,
            "internal/shell/run.go": SHELL_RUN,
        }
    )
    inventory = SourceInventory(
        files=(SourceFile(path=root / "internal/tools/git.go", languages=frozenset({"go"})),)
    )
    ctx = ScanContext(
        target_path=root,
        config=ScanConfig(target=root),
        result=ScanResult(),
        source_inventory=inventory,
    )
    assert _cf(GoCrossFilePass().run(ctx)) == []


def test_missing_grammar_records_a_degraded_pass_only_when_go_files_exist(monkeypatch):
    from rowan.passes import go_cross_file

    monkeypatch.setattr(go_cross_file, "TREE_SITTER_GO_AVAILABLE", False)
    root = _make_module({"a.go": "package a\n", "b.go": "package a\n"})
    result = _run(root)
    assert result.findings == []
    assert "tree-sitter-go" in result.degraded_passes["go_crossfile"]

    empty = Path(tempfile.mkdtemp(prefix="rowan_gocf_empty_"))
    assert _run(empty).degraded_passes == {}


def test_typed_tool_argument_struct_reaches_http_get_across_files():
    root = _make_module(
        {
            "tools/fetch.go": """package tools

import (
\t"context"

\t"github.com/modelcontextprotocol/go-sdk/mcp"

\t"example.com/app/web"
)

type FetchArgs struct {
\tURL string `json:"url"`
}

func Fetch(ctx context.Context, req *mcp.CallToolRequest, args FetchArgs) (*mcp.CallToolResult, any, error) {
\tbody, err := web.Download(args.URL)
\treturn &mcp.CallToolResult{}, body, err
}
""",
            "web/client.go": """package web

import (
\t"io"
\t"net/http"
)

func Download(target string) (string, error) {
\tresp, err := http.Get(target)
\tif err != nil {
\t\treturn "", err
\t}
\tdefer resp.Body.Close()
\tb, _ := io.ReadAll(resp.Body)
\treturn string(b), nil
}
""",
        }
    )
    findings = _cf(_run(root))
    assert [f.rule_id for f in findings] == ["CF-GO-SSRF-001"]
    assert findings[0].metadata["source_kind"] == "tool_param"
    assert findings[0].cwe_ids == [918]


def test_escape_helper_does_not_clear_exec_taint():
    """BACKLOG XF-14: an `escape*`/`sanitize*` name is not a guard for the
    exec, path, sql or ssrf families."""
    root = _make_module(
        {
            "handlers.go": """package main

import (
\t"context"

\t"github.com/mark3labs/mcp-go/mcp"
)

func (s *Server) runHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
\tcmd, _ := request.RequireString("cmd")
\tsafe := escapeHTML(cmd)
\tout, err := runIt(safe)
\tif err != nil {
\t\treturn mcp.NewToolResultError(err.Error()), nil
\t}
\treturn mcp.NewToolResultText(out), nil
}
""",
            "exec.go": """package main

import "os/exec"

type Server struct{}

func runIt(c string) (string, error) {
\tb, err := exec.Command("sh", "-c", c).Output()
\treturn string(b), err
}
""",
        }
    )
    assert len(_cf(_run(root))) == 1


_NORM = """package norm

func A(p string) string {
\tif len(p) > 200 {
\t\treturn B(p[:200])
\t}
\treturn p
}

func B(p string) string {
\treturn A(p)
}
"""

_TWO_TOOLS = """package tools

import (
\t"context"

\t"github.com/mark3labs/mcp-go/mcp"

\t"example.com/app/internal/norm"
\t"example.com/app/internal/shell"
)

func First(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
\trepoPath := request.GetString("repo_path", ".")
\tout, _ := shell.Run(ctx, "-C", norm.A(repoPath), "status")
\treturn mcp.NewToolResultText(out), nil
}

func Second(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
\trepoPath := request.GetString("repo_path", ".")
\tout, _ := shell.Run(ctx, "-C", norm.B(repoPath), "status")
\treturn mcp.NewToolResultText(out), nil
}
"""


def test_mutually_recursive_passthrough_keeps_second_flow():
    """XF-18: B's summary must not be memoised as empty while A was on the stack."""
    root = _make_module({
        "internal/norm/norm.go": _NORM,
        "internal/tools/git.go": _TWO_TOOLS,
        "internal/shell/run.go": SHELL_RUN,
    })
    sources = sorted(f.taint_flow.source.line for f in _cf(_run(root)))
    assert sources == [13, 19]


HANDLER_RENAME = """package tools

import (
\t"context"

\t"github.com/mark3labs/mcp-go/mcp"

\t"example.com/app/internal/files"
)

func MoveFile(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
\tdest := request.GetString("dest", "")
\tif err := files.Move("/tmp/upload", dest); err != nil {
\t\treturn mcp.NewToolResultError(err.Error()), nil
\t}
\treturn mcp.NewToolResultText("ok"), nil
}
"""

FILES_MOVE = """package files

import "os"

func Move(src string, dst string) error {
\treturn os.Rename(src, dst)
}
"""


def test_tool_param_reaching_os_rename_destination_is_flagged():
    """os.Rename's second argument is a path sink, as in rules/go_ai_taint.yaml."""
    root = _make_module(
        {
            "internal/tools/move.go": HANDLER_RENAME,
            "internal/files/move.go": FILES_MOVE,
        }
    )
    findings = _cf(_run(root))
    assert [f.category for f in findings] == [Category.PATH_TRAVERSAL]
    assert findings[0].file_path.endswith("internal/files/move.go")


HANDLER_CACHE = """package tools

import (
\t"context"

\t"github.com/mark3labs/mcp-go/mcp"

\t"example.com/app/internal/cache"
)

func Cache(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
\tname := request.GetString("image", "")
\tif err := cache.Store(name); err != nil {
\t\treturn mcp.NewToolResultError(err.Error()), nil
\t}
\treturn mcp.NewToolResultText("ok"), nil
}
"""


def _cache_module(store_body: str) -> Path:
    return _make_module(
        {
            "internal/tools/cache.go": HANDLER_CACHE,
            "internal/cache/store.go": (
                "package cache\n\n"
                'import (\n\t"crypto/sha256"\n\t"encoding/hex"\n\t"os"\n\t"path/filepath"\n)\n\n'
                "func Store(name string) error {\n" + store_body + "}\n"
            ),
        }
    )


def test_hashed_tool_argument_is_clean_for_a_path_sink():
    """A digest is hex: it cannot carry ../ (radar's image cache, MCP census)."""
    root = _cache_module(
        "\tsum := sha256.Sum256([]byte(name))\n"
        '\treturn os.MkdirAll(filepath.Join("/cache", hex.EncodeToString(sum[:])), 0o700)\n'
    )
    assert _cf(_run(root)) == []


def test_external_digest_method_result_is_clean_for_a_path_sink():
    """radar: the cache key is `img.Digest()` from go-containerregistry, an
    unresolved method on a value derived from the tool argument."""
    root = _make_module(
        {
            "internal/tools/cache.go": HANDLER_CACHE,
            "internal/cache/store.go": (
                "package cache\n\n"
                "import (\n\t\"os\"\n\t\"path/filepath\"\n\n"
                "\t\"github.com/google/go-containerregistry/pkg/name\"\n"
                "\t\"github.com/google/go-containerregistry/pkg/v1/remote\"\n)\n\n"
                "func Store(image string) error {\n"
                "\tref, _ := name.ParseReference(image)\n"
                "\timg, _ := remote.Image(ref)\n"
                "\td, _ := img.Digest()\n"
                "\treturn os.MkdirAll(filepath.Join(\"/cache\", d.String()), 0o700)\n"
                "}\n"
            ),
        }
    )
    assert _cf(_run(root)) == []


def test_unhashed_tool_argument_still_reaches_the_path_sink():
    root = _cache_module(
        '\t_ = sha256.Sum256\n\t_ = hex.EncodeToString\n'
        '\treturn os.MkdirAll(filepath.Join("/cache", name), 0o700)\n'
    )
    assert [f.category for f in _cf(_run(root))] == [Category.PATH_TRAVERSAL]


def test_numeric_sprintf_verb_does_not_carry_a_path_payload():
    """radar: `fmt.Sprintf("layer-%d.tar", idx)` is digits whatever idx came from."""
    root = _cache_module(
        '\t_ = sha256.Sum256\n\t_ = hex.EncodeToString\n'
        '\treturn os.MkdirAll(filepath.Join("/cache", fmt.Sprintf("layer-%d.tar", count(name))), 0o700)\n'
    )
    store = root / "internal/cache/store.go"
    store.write_text(store.read_text().replace('"crypto/sha256"', '"crypto/sha256"\n\t"fmt"'))
    assert _cf(_run(root)) == []


def test_string_sprintf_verb_still_carries_the_path_payload():
    root = _cache_module(
        '\t_ = sha256.Sum256\n\t_ = hex.EncodeToString\n'
        '\treturn os.MkdirAll(filepath.Join("/cache", fmt.Sprintf("layer-%d-%s.tar", 1, name)), 0o700)\n'
    )
    store = root / "internal/cache/store.go"
    store.write_text(store.read_text().replace('"crypto/sha256"', '"crypto/sha256"\n\t"fmt"'))
    assert [f.category for f in _cf(_run(root))] == [Category.PATH_TRAVERSAL]
