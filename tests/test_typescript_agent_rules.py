"""TypeScript agent-boundary rules: MCP, Vercel AI SDK, LangChain.js, model output."""

from __future__ import annotations

import importlib.util
import shutil
import sys
from pathlib import Path

import pytest

from rowan.config import ScanConfig
from rowan.core.findings import Severity
from rowan.pipeline import ScanPipeline
from rowan.taint.opengrep_adapter import OpengrepAdapter

ROOT = Path(__file__).parent.parent
CORPUS = ROOT / "benchmark" / "ground_truth" / "ts_agent_cases"

pytestmark = pytest.mark.skipif(
    not OpengrepAdapter().is_installed(), reason="Opengrep binary is required"
)


def _load_benchmark_module():
    spec = importlib.util.spec_from_file_location("benchmark_ts_agent", ROOT / "scripts" / "benchmark.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["benchmark_ts_agent"] = module
    spec.loader.exec_module(module)
    return module


def test_ts_agent_pairs_detect_only_vulnerable_files():
    report = _load_benchmark_module().run_ts_agent_cases(CORPUS)
    assert not report["degraded"]
    assert report["hits"] == report["total"] == 19
    assert report["false_positives"] == 0


def test_mcp_tool_ssrf_stays_high_in_a_library_without_web_imports(tmp_path):
    # An MCP server imports no web framework and can auto-detect as a
    # library; the tool argument itself is the external boundary.
    shutil.copy(CORPUS / "typescript" / "mcp_lowlevel_fetch_vulnerable.ts", tmp_path / "server.ts")

    result = ScanPipeline(ScanConfig(target=tmp_path, no_sca=True, report_view="full")).run()

    [finding] = [f for f in result.findings if f.rule_id == "TNT-TS-AGENT-SSRF-001"]
    assert finding.severity == Severity.HIGH
    assert finding.metadata["evidence_tier"] == "taint-flow"


def test_graphql_object_query_is_not_sql_text(tmp_path):
    (tmp_path / "docs.ts").write_text(
        'import { tool } from "ai";\n'
        "export const searchDocs = tool({\n"
        "  execute: async ({ graphql_query }) => client.query({ query: graphql_query }),\n"
        "});\n",
        encoding="utf-8",
    )

    result = ScanPipeline(ScanConfig(target=tmp_path, no_sca=True, report_view="full")).run()

    assert not [f for f in result.findings if f.rule_id == "TNT-TS-AGENT-SQLI-001"]


def test_confining_helper_assigned_later_sanitizes_the_path(tmp_path):
    # Opengrep anchors metavariable-regex at the start of the callee name, so
    # the camelCase `...Confined...` form needs its own leading `.*`.
    (tmp_path / "server.ts").write_text(
        'server.tool("import", { filePath: z.string() }, async ({ filePath }) => {\n'
        "  let safePath: string;\n"
        "  safePath = resolveConfinedImportPath(filePath);\n"
        '  return fs.readFileSync(safePath, "utf8");\n'
        "});\n",
        encoding="utf-8",
    )

    result = ScanPipeline(ScanConfig(target=tmp_path, no_sca=True, report_view="full")).run()

    assert not [f for f in result.findings if f.rule_id == "TNT-TS-AGENT-PATH-001"]


def test_assert_style_validators_clean_the_tool_argument(tmp_path):
    # A validator that throws (`validateMode(mode);`) cleans its argument for
    # the rest of the function, including inside a helper that validates
    # before building the path. The unguarded handler still reports.
    (tmp_path / "state.ts").write_text(
        "function getStatePath(mode: string): string {\n"
        "  validateMode(mode);\n"
        "  return path.join(getStateDir(), `${mode}-state.json`);\n"
        "}\n"
        'server.tool("clear", { mode: z.string() }, async ({ mode }) => {\n'
        "  fs.unlinkSync(getStatePath(mode));\n"
        "});\n"
        'server.tool("clear_raw", { mode: z.string() }, async ({ mode }) => {\n'
        "  fs.unlinkSync(path.join(getStateDir(), mode));\n"
        "});\n"
        'server.tool("clear_checked", { mode: z.string() }, async ({ mode }) => {\n'
        "  assertSafeName(mode);\n"
        "  fs.unlinkSync(path.join(getStateDir(), mode));\n"
        "});\n",
        encoding="utf-8",
    )

    result = ScanPipeline(ScanConfig(target=tmp_path, no_sca=True, report_view="full")).run()

    lines = sorted(f.start_line for f in result.findings if f.rule_id == "TNT-TS-AGENT-PATH-001")
    assert lines == [9]


def test_regex_exec_is_not_a_shell_command(tmp_path):
    # `RegExp.prototype.exec` shares the name with child_process.exec. In a
    # sample of MCP servers every `.exec(` on a regex literal or a regex
    # variable was reported as command injection; an SSH client's
    # `conn.exec(command)` really runs the command and still reports.
    (tmp_path / "server.ts").write_text(
        'server.tool("parse", { value: z.string() }, async ({ value }) => {\n'
        "  const m = /^(\\d+)([mhd])$/.exec(value.trim());\n"
        "  const regex = /secret/g;\n"
        "  const hit = regex.exec(value);\n"
        "  const datePattern = new RegExp('^\\\\d{4}');\n"
        "  return datePattern.exec(value) ?? this.pattern.exec(value) ?? m ?? hit;\n"
        "});\n"
        'server.tool("run", { command: z.string() }, async ({ command }) => {\n'
        "  conn.exec(command, (err, stream) => {});\n"
        "});\n",
        encoding="utf-8",
    )

    result = ScanPipeline(ScanConfig(target=tmp_path, no_sca=True, report_view="full")).run()

    lines = sorted(f.start_line for f in result.findings if f.rule_id == "TNT-TS-AGENT-CMDI-001")
    assert lines == [9]


def test_tool_argument_after_a_fixed_host_is_not_ssrf(tmp_path):
    # Shapes from a sample of MCP servers where the argument only fills the
    # path or query of a fixed host. `${API_BASE}${path}` stays: with no `/`
    # between them, a value like ".evil.com/" moves the host.
    (tmp_path / "server.ts").write_text(
        'const API_BASE = process.env.API_BASE || "https://api.acmeworks.com";\n'
        "async function callApi(path: string) {\n"
        "  const res = await fetch(`${API_BASE}${path}`);\n"
        "  return res.json();\n"
        "}\n"
        'server.tool("get_case", { caseId: z.string(), live: z.boolean() }, async ({ caseId, live }) => {\n'
        "  const r1 = await fetch(`${API_BASE}/cases/${caseId}/files`);\n"
        "  const url = live\n"
        "    ? `https://quotes.acmeworks.com/api/quote?amount=${caseId}`\n"
        "    : 'https://quotes.acmeworks.com/api/quote';\n"
        "  const r2 = await fetch(url);\n"
        '  const r3 = await fetch("https://api.acmeworks.com/search?q=" + caseId);\n'
        "  return callApi(`/cases/${caseId}`);\n"
        "});\n"
        'server.tool("fetch_url", { target: z.string(), host: z.string() }, async ({ target, host }) => {\n'
        "  await fetch(`https://${host}/status`);\n"
        "  const url = host ? `https://${host}/x` : `https://api.acmeworks.com/x`;\n"
        "  await fetch(url);\n"
        "  return fetch(target);\n"
        "});\n"
        "const PAGE = `https://api.acmeworks.com/page`;\n"
        'server.tool("shadow", { page: z.string() }, async ({ page }) => {\n'
        "  let PAGE = page;\n"
        "  return fetch(PAGE);\n"
        "});\n",
        encoding="utf-8",
    )

    result = ScanPipeline(ScanConfig(target=tmp_path, no_sca=True, report_view="full")).run()

    lines = sorted(f.start_line for f in result.findings if f.category.value == "ssrf")
    assert lines == [3, 16, 18, 19, 24]


def test_fixed_host_check_respects_shadowing(tmp_path):
    # A parameter or destructured local named like a fixed-host const is the
    # tool argument, not the const.
    (tmp_path / "server.ts").write_text(
        'const url = "https://api.acmeworks.com/";\n'
        "async function get(url: string) {\n"
        "  return fetch(url);\n"
        "}\n"
        'server.tool("a", { target: z.string(), opts: z.any() }, async ({ target, opts }) => {\n'
        "  await get(target);\n"
        "  const { url } = opts;\n"
        "  return fetch(url);\n"
        "});\n",
        encoding="utf-8",
    )

    result = ScanPipeline(ScanConfig(target=tmp_path, no_sca=True, report_view="full")).run()

    lines = sorted({f.start_line for f in result.findings if f.category.value == "ssrf"})
    assert lines == [3, 8]


def test_imported_base_url_is_a_fixed_host(tmp_path):
    # An imported binding is module configuration, not a tool argument.
    (tmp_path / "write.ts").write_text(
        'import { API_BASE_URL } from "../config.js";\n'
        'server.tool("upload", { caseId: z.string() }, async ({ caseId }) => {\n'
        "  return fetch(`${API_BASE_URL}/cases/${caseId}/files`);\n"
        "});\n"
        'server.tool("proxy", { path: z.string() }, async ({ path }) => {\n'
        "  return fetch(`${API_BASE_URL}${path}`);\n"
        "});\n",
        encoding="utf-8",
    )

    result = ScanPipeline(ScanConfig(target=tmp_path, no_sca=True, report_view="full")).run()

    lines = sorted({f.start_line for f in result.findings if f.category.value == "ssrf"})
    assert lines == [6]
