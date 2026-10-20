"""Multi-agent handoff trust boundary (issue #188, epic #183).

Nothing in the existing corpus modeled the edge that makes multi-agent
systems interesting: agent A's output becoming agent B's instruction.
`NS-AIML-025` flags a multi-agent framework without code-execution
restrictions as a bare presence signal; this file covers the actual
propagation.

Scope for this phase, and why: **CrewAI's `Task(context=[...])` handoff
only**, as `AGENT-HANDOFF-001` in `MultiAgentPass`
(`rowan/passes/multiagent.py`), an AST pass off by default
(`ScanConfig.enable_multiagent`). Verified empirically that the same shape
is NOT expressible for LangGraph/AutoGen/OpenAI Agents SDK/A2A: the actual
handoff in those happens through framework-internal execution (the graph
runtime, the Agents SDK runtime), not a directly-traceable object reference
in source. Modeling those needs a `CrossFilePass`-style armed channel (the
same shape already used for second-order ORM/vector-store persistence) --
filed as a follow-up issue rather than attempted here alongside a first,
narrower implementation.

`ns-aiml-138` (unbounded delegation topology) and `ns-aiml-139` (A2A agent
card trust) are NeuroScan rules in `rules/ai_security.yaml`, tested here in
both the legacy per-line engine and the real Opengrep binary against the
converted rules -- the actual default-scan path (see DEF-45 in BACKLOG.md
for why that distinction matters: a bare unanchored sanitizer term does not
suppress anything in the converted engine, only an anchored forward-span
pattern-not does).
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from rowan.config import ScanConfig
from rowan.core.findings import ScanResult
from rowan.core.rules import load_neuroscan_rules
from rowan.passes.base import ScanContext
from rowan.passes.multiagent import MultiAgentPass
from rowan.pipeline import ScanPipeline
from rowan.taint.opengrep_adapter import OpengrepAdapter

RULES_PATH = Path(__file__).parent.parent / "rules" / "ai_security.yaml"
CONVERTED_RULES_PATH = Path(__file__).parent.parent / "rules" / "converted" / "ai_security.yaml"
_NEUROSCAN_RULES = load_neuroscan_rules(RULES_PATH)

_adapter = OpengrepAdapter()
_needs_opengrep = pytest.mark.skipif(
    not _adapter.is_installed(),
    reason="Opengrep binary not installed; these tests need a live scan.",
)


# ---------------------------------------------------------------------------
# AGENT-HANDOFF-001 (CrewAI cross-agent injection propagation)
# ---------------------------------------------------------------------------


def _scan_multiagent(source: str, tmp_path: Path) -> list:
    fp = tmp_path / "crew.py"
    fp.write_text(source, encoding="utf-8")
    tree = ast.parse(source)
    return MultiAgentPass()._scan_tree(fp, tree)


def _run_multiagent_pass(source: str, tmp_path: Path, *, enabled: bool = True) -> list:
    fp = tmp_path / "crew.py"
    fp.write_text(source, encoding="utf-8")
    config = ScanConfig(target=tmp_path, enable_multiagent=enabled)
    ctx = ScanContext(target_path=tmp_path, config=config, result=ScanResult())
    return MultiAgentPass().run(ctx).findings


_CREWAI_IMPORTS = "from crewai import Agent, Task, Crew\n"


class TestAgentHandoffScrapeToShell:
    """TP: a task whose context carries a web-scraped value into a task
    with a code tool."""

    def test_scrape_tool_to_code_interpreter_flagged(self, tmp_path):
        src = _CREWAI_IMPORTS + (
            "from crewai_tools import ScrapeWebsiteTool, CodeInterpreterTool\n\n"
            "researcher = Agent(role='Researcher', tools=[ScrapeWebsiteTool()])\n"
            "executor = Agent(role='Executor', tools=[CodeInterpreterTool()])\n\n"
            "research_task = Task(description='scrape the target site', agent=researcher)\n"
            "exec_task = Task(description='run the recommended command', agent=executor, "
            "context=[research_task])\n\n"
            "crew = Crew(agents=[researcher, executor], tasks=[research_task, exec_task])\n"
            "crew.kickoff()\n"
        )
        findings = _scan_multiagent(src, tmp_path)
        assert len(findings) == 1
        assert findings[0].rule_id == "AGENT-HANDOFF-001"
        assert findings[0].metadata["handoff_kind"] == "handoff"

    def test_custom_shell_tool_by_name_flagged(self, tmp_path):
        """The receiving agent's privileged tool is a locally-defined
        function (`@tool`-decorated), resolved by its own body, not by a
        recognized class name."""
        src = _CREWAI_IMPORTS + (
            "from crewai.tools import tool\n"
            "import subprocess\n\n"
            "@tool('RunShell')\n"
            "def run_shell(cmd: str) -> str:\n"
            "    return subprocess.run(cmd, shell=True, capture_output=True).stdout\n\n"
            "researcher = Agent(role='Researcher', tools=[ScrapeWebsiteTool()])\n"
            "executor = Agent(role='Executor', tools=[run_shell])\n\n"
            "research_task = Task(description='scrape the target site', agent=researcher)\n"
            "exec_task = Task(description='run the recommended command', agent=executor, "
            "context=[research_task])\n\n"
            "crew = Crew(agents=[researcher, executor], tasks=[research_task, exec_task])\n"
            "crew.kickoff()\n"
        )
        findings = _scan_multiagent(src, tmp_path)
        assert len(findings) == 1
        assert findings[0].rule_id == "AGENT-HANDOFF-001"

    def test_direct_request_source_to_privileged_agent_flagged(self, tmp_path):
        src = "from flask import request\n" + _CREWAI_IMPORTS + (
            "from crewai_tools import CodeInterpreterTool\n\n"
            "executor = Agent(role='Executor', tools=[CodeInterpreterTool()])\n"
            "exec_task = Task(description=request.args.get('cmd'), agent=executor)\n\n"
            "crew = Crew(agents=[executor], tasks=[exec_task])\n"
            "crew.kickoff()\n"
        )
        findings = _scan_multiagent(src, tmp_path)
        assert len(findings) == 1
        assert findings[0].metadata["handoff_kind"] == "direct"


class TestAgentHandoffFalsePositiveAvoidance:
    """The cases that decide whether this rule is shippable."""

    def test_schema_validated_output_not_flagged(self, tmp_path):
        """TN: the handoff passes a structured-output schema between agents."""
        src = _CREWAI_IMPORTS + (
            "from crewai_tools import ScrapeWebsiteTool, CodeInterpreterTool\n"
            "from pydantic import BaseModel\n\n"
            "class ResearchOutput(BaseModel):\n"
            "    summary: str\n\n"
            "researcher = Agent(role='Researcher', tools=[ScrapeWebsiteTool()])\n"
            "executor = Agent(role='Executor', tools=[CodeInterpreterTool()])\n\n"
            "research_task = Task(description='scrape the target site', agent=researcher, "
            "output_pydantic=ResearchOutput)\n"
            "exec_task = Task(description='run the recommended command', agent=executor, "
            "context=[research_task])\n\n"
            "crew = Crew(agents=[researcher, executor], tasks=[research_task, exec_task])\n"
            "crew.kickoff()\n"
        )
        assert _scan_multiagent(src, tmp_path) == []

    def test_no_privileged_receiving_tool_not_flagged(self, tmp_path):
        """TN: a two-agent graph where B has no privileged tool. This is the
        false positive that decides shippability -- must not fire on every
        multi-agent app."""
        src = _CREWAI_IMPORTS + (
            "from crewai_tools import ScrapeWebsiteTool, WebsiteSearchTool\n\n"
            "researcher = Agent(role='Researcher', tools=[ScrapeWebsiteTool()])\n"
            "summarizer = Agent(role='Summarizer', tools=[WebsiteSearchTool()])\n\n"
            "research_task = Task(description='scrape the target site', agent=researcher)\n"
            "summary_task = Task(description='summarize the findings', agent=summarizer, "
            "context=[research_task])\n\n"
            "crew = Crew(agents=[researcher, summarizer], tasks=[research_task, summary_task])\n"
            "crew.kickoff()\n"
        )
        assert _scan_multiagent(src, tmp_path) == []

    def test_no_untrusted_source_not_flagged(self, tmp_path):
        """TN: the receiving agent is privileged, but nothing web-sourced or
        request-controlled feeds it."""
        src = _CREWAI_IMPORTS + (
            "from crewai_tools import CodeInterpreterTool\n\n"
            "planner = Agent(role='Planner')\n"
            "executor = Agent(role='Executor', tools=[CodeInterpreterTool()])\n\n"
            "plan_task = Task(description='draft a fixed report outline', agent=planner)\n"
            "exec_task = Task(description='run the fixed analysis script', agent=executor, "
            "context=[plan_task])\n\n"
            "crew = Crew(agents=[planner, executor], tasks=[plan_task, exec_task])\n"
            "crew.kickoff()\n"
        )
        assert _scan_multiagent(src, tmp_path) == []

    def test_single_agent_no_handoff_not_flagged(self, tmp_path):
        src = _CREWAI_IMPORTS + (
            "from crewai_tools import ScrapeWebsiteTool\n\n"
            "researcher = Agent(role='Researcher', tools=[ScrapeWebsiteTool()])\n"
            "research_task = Task(description='scrape the target site', agent=researcher)\n\n"
            "crew = Crew(agents=[researcher], tasks=[research_task])\n"
            "crew.kickoff()\n"
        )
        assert _scan_multiagent(src, tmp_path) == []

    def test_disabled_by_default_gate(self, tmp_path):
        src = _CREWAI_IMPORTS + (
            "from crewai_tools import ScrapeWebsiteTool, CodeInterpreterTool\n\n"
            "researcher = Agent(role='Researcher', tools=[ScrapeWebsiteTool()])\n"
            "executor = Agent(role='Executor', tools=[CodeInterpreterTool()])\n\n"
            "research_task = Task(description='scrape the target site', agent=researcher)\n"
            "exec_task = Task(description='run the recommended command', agent=executor, "
            "context=[research_task])\n\n"
            "crew = Crew(agents=[researcher, executor], tasks=[research_task, exec_task])\n"
            "crew.kickoff()\n"
        )
        assert _run_multiagent_pass(src, tmp_path, enabled=False) == []
        assert _run_multiagent_pass(src, tmp_path, enabled=True) != []


# ---------------------------------------------------------------------------
# ns-aiml-138: unbounded multi-agent delegation topology
# ---------------------------------------------------------------------------


def _neuroscan_scan(tmp_path: Path, filename: str, source: str, rule_id: str) -> list:
    fp = tmp_path / filename
    fp.write_text(source, encoding="utf-8")
    rule = next(r for r in _NEUROSCAN_RULES if r.metadata.id == rule_id)
    return rule.check(fp)


def _converted_scan(tmp_path: Path, filename: str, source: str, rule_id: str) -> list:
    fp = tmp_path / filename
    fp.write_text(source, encoding="utf-8")
    adapter = OpengrepAdapter()
    findings = adapter.scan_with_rules(tmp_path, [CONVERTED_RULES_PATH], languages=["python"])
    return [f for f in findings if f.rule_id == rule_id and Path(f.file_path).name == filename]


class TestNsAiml138UnboundedTopology:
    def test_cyclic_handoff_graph_no_recursion_limit_flagged(self, tmp_path):
        src = (
            "from langgraph.graph import StateGraph\n\n"
            "graph = StateGraph(AgentState)\n"
            "graph.add_node('researcher', researcher_node)\n"
            "graph.add_node('executor', executor_node)\n"
            "graph.add_edge('researcher', 'executor')\n"
            "graph.add_edge('executor', 'researcher')\n"
            "app = graph.compile()\n"
            "app.invoke({'input': 'start'})\n"
        )
        assert _neuroscan_scan(tmp_path, "graph.py", src, "ns-aiml-138")

    def test_groupchat_unbounded_flagged(self, tmp_path):
        src = (
            "from autogen import GroupChat, GroupChatManager\n\n"
            "groupchat = GroupChat(agents=[researcher, executor], messages=[])\n"
            "manager = GroupChatManager(groupchat=groupchat)\n"
            "manager.initiate_chat(researcher, message='start')\n"
        )
        assert _neuroscan_scan(tmp_path, "chat.py", src, "ns-aiml-138")

    def test_recursion_limit_present_not_flagged(self, tmp_path):
        src = (
            "from langgraph.graph import StateGraph\n\n"
            "graph = StateGraph(AgentState)\n"
            "graph.add_edge('researcher', 'executor')\n"
            "app = graph.compile()\n"
            "app.invoke({'input': 'start'}, config={'recursion_limit': 25})\n"
        )
        assert not _neuroscan_scan(tmp_path, "graph.py", src, "ns-aiml-138")

    def test_class_definition_not_flagged(self, tmp_path):
        """Regression: `class Crew(FlowTrackable, BaseModel):` is a class
        definition, not an instantiation -- found scanning CrewAI's own
        framework source during development."""
        src = "class Crew(FlowTrackable, BaseModel):\n    pass\n"
        assert not _neuroscan_scan(tmp_path, "crew.py", src, "ns-aiml-138")

    @_needs_opengrep
    def test_bounded_not_flagged_by_default_engine(self, tmp_path):
        """The converted (default) engine parity check -- see DEF-45."""
        src = (
            "from crewai import Crew\n\n"
            "crew = Crew(agents=[a, b], tasks=[t1, t2], max_iter=15)\n"
            "crew.kickoff()\n"
        )
        assert not _converted_scan(tmp_path, "crew.py", src, "ns-aiml-138")

    @_needs_opengrep
    def test_unbounded_still_flagged_by_default_engine(self, tmp_path):
        src = (
            "from crewai import Crew\n\n"
            "crew = Crew(agents=[a, b], tasks=[t1, t2])\n"
            "crew.kickoff()\n"
        )
        assert _converted_scan(tmp_path, "crew.py", src, "ns-aiml-138")

    @_needs_opengrep
    def test_def46_unbounded_with_adjacent_bounded_sibling_still_flagged(self, tmp_path):
        """DEF-46 (found via issue #197's benchmark work): the anchored-span
        pattern-not this rule uses (see #187/DEF-45) has no notion of a
        function boundary on its own -- an unbounded Crew() in one function
        sitting close to a BOUNDED Crew() in the very next function let the
        second function's own max_iter= term leak backward across the def
        line and suppress the first, unbounded one's finding. Reproduced
        against a real two-function fixture before the fix (a bare
        `[\\s\\S]{0,400}?` span, no `(?!\\ndef )` guard)."""
        src = (
            "from crewai import Crew\n\n"
            "def build_unbounded_crew():\n"
            "    crew = Crew(agents=[a, b], tasks=[t1, t2])\n"
            "    return crew\n\n"
            "def build_bounded_crew():\n"
            "    crew = Crew(agents=[a, b], tasks=[t1, t2], max_iter=15)\n"
            "    return crew\n"
        )
        findings = _converted_scan(tmp_path, "crews.py", src, "ns-aiml-138")
        assert findings, "the unbounded Crew() must still be flagged despite the bounded sibling nearby"
        assert findings[0].start_line == 4, "the finding must land on build_unbounded_crew, not its sibling"


# ---------------------------------------------------------------------------
# ns-aiml-139: A2A agent card trust
# ---------------------------------------------------------------------------


class TestNsAiml139AgentCardTrust:
    def test_unpinned_agent_card_fetch_flagged(self, tmp_path):
        src = (
            "import httpx\n\n"
            "def discover_agent(peer_url):\n"
            "    card = httpx.get(f'{peer_url}/.well-known/agent.json').json()\n"
            "    return AgentCard(**card)\n"
        )
        assert _neuroscan_scan(tmp_path, "a2a.py", src, "ns-aiml-139")

    def test_signature_verified_not_flagged(self, tmp_path):
        src = (
            "import httpx\n"
            "from a2a.crypto import verify_signature\n\n"
            "def discover_agent(peer_url):\n"
            "    resp = httpx.get(f'{peer_url}/.well-known/agent.json')\n"
            "    card = resp.json()\n"
            "    if not verify_signature(card, resp.headers['X-Signature']):\n"
            "        raise ValueError('untrusted agent card')\n"
            "    return AgentCard(**card)\n"
        )
        assert not _neuroscan_scan(tmp_path, "a2a.py", src, "ns-aiml-139")

    def test_unrelated_http_call_not_flagged(self, tmp_path):
        src = (
            "import httpx\n\n"
            "def fetch_weather(city):\n"
            "    return httpx.get(f'https://api.weather.com/{city}').json()\n"
        )
        assert not _neuroscan_scan(tmp_path, "weather.py", src, "ns-aiml-139")


# ---------------------------------------------------------------------------
# Clean-corpus baseline (issue #188's own acceptance criterion)
# ---------------------------------------------------------------------------


@_needs_opengrep
class TestCleanCorpusBaseline:
    """No new findings on the clean-corpus baseline, checked against the
    `scan-targets/autogen` checkout already in the repo."""

    _AUTOGEN_PATH = Path(__file__).parent.parent / "scan-targets" / "autogen"

    @pytest.mark.corpus
    def test_autogen_baseline_unaffected(self):
        if not self._AUTOGEN_PATH.is_dir():
            pytest.skip("scan-targets/autogen not present in this checkout")
        adapter = OpengrepAdapter()
        findings = adapter.scan_with_rules(
            self._AUTOGEN_PATH, [CONVERTED_RULES_PATH], languages=["python"]
        )
        new_rule_hits = [f for f in findings if f.rule_id in ("ns-aiml-138", "ns-aiml-139")]
        assert new_rule_hits == [], (
            f"new rules must not fire on the clean autogen baseline, got {new_rule_hits}"
        )

    @pytest.mark.corpus
    def test_multiagent_pass_baseline_unaffected(self):
        if not self._AUTOGEN_PATH.is_dir():
            pytest.skip("scan-targets/autogen not present in this checkout")
        pass_ = MultiAgentPass()
        findings = []
        for py_file in self._AUTOGEN_PATH.rglob("*.py"):
            try:
                tree = ast.parse(py_file.read_text(encoding="utf-8", errors="ignore"))
            except (SyntaxError, ValueError):
                continue
            findings.extend(pass_._scan_tree(py_file, tree))
        assert findings == []


def test_deep_policy_runs_handoff_detection(tmp_path):
    """--policy deep selects the pass with enable_multiagent left at None."""
    (tmp_path / "crew.py").write_text(
        _CREWAI_IMPORTS
        + "from crewai_tools import ScrapeWebsiteTool, CodeInterpreterTool\n\n"
        "researcher = Agent(role='Researcher', tools=[ScrapeWebsiteTool()])\n"
        "executor = Agent(role='Executor', tools=[CodeInterpreterTool()])\n\n"
        "research_task = Task(description='scrape the target site', agent=researcher)\n"
        "exec_task = Task(description='run the recommended command', agent=executor, "
        "context=[research_task])\n\n"
        "crew = Crew(agents=[researcher, executor], tasks=[research_task, exec_task])\n"
        "crew.kickoff()\n",
        encoding="utf-8",
    )
    result = ScanPipeline(ScanConfig(target=tmp_path, policy="deep", enable_sca=False)).run()
    assert "AGENT-HANDOFF-001" in {f.rule_id for f in result.findings}
