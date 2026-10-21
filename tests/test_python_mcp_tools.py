"""Python MCP servers: FastMCP tools and low-level call_tool handlers."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

from rowan.config import ScanConfig
from rowan.core.findings import Severity
from rowan.pipeline import ScanPipeline
from rowan.taint.opengrep_adapter import OpengrepAdapter

ROOT = Path(__file__).parent.parent
CORPUS = ROOT / "benchmark" / "ground_truth" / "py_agent_cases"

_SERVER = '''import subprocess

import requests
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("demo")


@mcp.tool()
def read_file(path: str) -> str:
    with open(path) as f:
        return f.read()


@mcp.tool()
def run(cmd: str) -> str:
    return subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout


@mcp.tool()
def fetch(url: str) -> str:
    return requests.get(url).text
'''


def test_single_file_fastmcp_server_reports_high_for_each_sink(tmp_path):
    # One-file servers are common; the model chooses every tool argument, so
    # file-level context (a library profile, no web import, a local `open(`)
    # must not demote these.
    (tmp_path / "server.py").write_text(_SERVER, encoding="utf-8")

    result = ScanPipeline(ScanConfig(target=tmp_path, no_sca=True, report_view="full")).run()

    tool_findings = {
        f.start_line: f.severity for f in result.findings if f.rule_id == "AGENT-TOOL-001"
    }
    assert tool_findings == {11: Severity.HIGH, 17: Severity.HIGH, 22: Severity.HIGH}


@pytest.mark.skipif(not OpengrepAdapter().is_installed(), reason="Opengrep binary is required")
def test_python_mcp_pairs_detect_only_vulnerable_files():
    spec = importlib.util.spec_from_file_location("benchmark_py_agent", ROOT / "scripts" / "benchmark.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["benchmark_py_agent"] = module
    spec.loader.exec_module(module)
    report = module.run_py_agent_cases(CORPUS)
    assert not report["degraded"]
    assert report["hits"] == report["total"] == 11
    assert report["false_positives"] == 0


def test_validator_statement_and_guard_hook_stop_the_tool_argument(tmp_path):
    (tmp_path / "net.py").write_text(
        "import httpx\n"
        "\n"
        "\n"
        "async def fetch_raw(url: str) -> bytes:\n"
        "    async with httpx.AsyncClient() as client:\n"
        "        return (await client.get(url)).content\n"
        "\n"
        "\n"
        "async def fetch_hooked(url: str) -> bytes:\n"
        '    async with httpx.AsyncClient(event_hooks={"request": [ssrf_guard]}) as client:\n'
        "        return (await client.get(url)).content\n",
        encoding="utf-8",
    )
    (tmp_path / "server.py").write_text(
        "from mcp.server.fastmcp import FastMCP\n"
        "\n"
        "from net import fetch_hooked, fetch_raw\n"
        "\n"
        'mcp = FastMCP("img")\n'
        "\n"
        "\n"
        "@mcp.tool()\n"
        "async def raw(url: str) -> int:\n"
        "    return len(await fetch_raw(url))\n"
        "\n"
        "\n"
        "@mcp.tool()\n"
        "async def checked(url: str) -> int:\n"
        "    validate_public_url(url)\n"
        "    return len(await fetch_raw(url))\n"
        "\n"
        "\n"
        "@mcp.tool()\n"
        "async def hooked(url: str) -> int:\n"
        "    return len(await fetch_hooked(url))\n",
        encoding="utf-8",
    )

    result = ScanPipeline(ScanConfig(target=tmp_path, no_sca=True, report_view="full")).run()

    callers = sorted(
        f.metadata["caller"] for f in result.findings if f.rule_id == "AGENT-TOOL-001"
    )
    assert callers == ["raw"]


# ---------------------------------------------------------------------------
# Indirect tool registration (MCP census 2026-10-20). Real servers rarely put
# @mcp.tool on every function: awslabs/mcp uses mcp.tool(...)(func) ~300
# times, excel-mcp-server wraps registration in its own decorators, serena's
# tools are Tool subclasses with an apply() method.
# ---------------------------------------------------------------------------

_READ_BODY = "    with open(path) as f:\n        return f.read()\n"


def _tool_lines(tmp_path: Path, files: dict[str, str]) -> set[tuple[str, int]]:
    from rowan.core.findings import ScanResult
    from rowan.passes.base import ScanContext
    from rowan.passes.cross_file import CrossFilePass

    for name, text in files.items():
        (tmp_path / name).write_text(text, encoding="utf-8")
    ctx = ScanContext(target_path=tmp_path, config=ScanConfig(target=tmp_path), result=ScanResult())
    return {
        (Path(f.file_path).name, f.start_line)
        for f in CrossFilePass().run(ctx).findings
        if f.rule_id == "AGENT-TOOL-001"
    }


def test_call_form_registration_marks_the_function_as_a_tool(tmp_path):
    hits = _tool_lines(tmp_path, {"server.py": (
        "from mcp.server.fastmcp import FastMCP\nmcp = FastMCP('demo')\n\n"
        "def read_file(path):\n" + _READ_BODY + "\nmcp.tool(name='read')(read_file)\n"
    )})
    assert hits == {("server.py", 5)}


def test_call_form_registration_of_an_imported_function(tmp_path):
    hits = _tool_lines(tmp_path, {
        "tools.py": "def read_file(path):\n" + _READ_BODY,
        "server.py": (
            "from mcp.server.fastmcp import FastMCP\nfrom tools import read_file\n"
            "mcp = FastMCP('demo')\nmcp.tool()(read_file)\n"
        ),
    })
    assert hits == {("tools.py", 2)}


def test_self_method_and_add_tool_registration(tmp_path):
    hits = _tool_lines(tmp_path, {"server.py": (
        "class Server:\n"
        "    def __init__(self, mcp):\n"
        "        self.mcp = mcp\n"
        "        self.mcp.tool(name='read')(self.read_file)\n"
        "        mcp.add_tool(other_read)\n\n"
        "    def read_file(self, path):\n" + _READ_BODY.replace("    ", "        ") + "\n"
        "def other_read(path):\n" + _READ_BODY
    )})
    assert hits == {("server.py", 8), ("server.py", 12)}


def test_wrapper_decorator_that_registers_a_tool(tmp_path):
    hits = _tool_lines(tmp_path, {
        "registry.py": (
            "class Tools:\n"
            "    def __init__(self, server):\n"
            "        self.server = server\n\n"
            "    def reader(self, title):\n"
            "        return self._register(title)\n\n"
            "    def _register(self, title):\n"
            "        def decorate(function):\n"
            "            self.server.tool(title=title)(function)\n"
            "            return function\n"
            "        return decorate\n"
        ),
        "file_tools.py": (
            "from registry import Tools\ntools = Tools(None)\n\n"
            "@tools.reader('Read a file')\n"
            "def read_file(path):\n" + _READ_BODY
        ),
    })
    assert hits == {("file_tools.py", 6)}


def test_tool_subclass_apply_method_is_a_tool(tmp_path):
    hits = _tool_lines(tmp_path, {"tools.py": (
        "class Tool:\n    pass\n\n"
        "class ReadFileTool(Tool):\n"
        "    def apply(self, path):\n" + _READ_BODY.replace("    ", "        ")
    )})
    assert hits == {("tools.py", 6)}


def test_unregistered_function_with_a_path_parameter_is_not_a_tool(tmp_path):
    hits = _tool_lines(tmp_path, {"util.py": "def read_file(path):\n" + _READ_BODY})
    assert hits == set()
