"""Cross-agent injection propagation detection (issue #188, epic #183).

Nothing in the existing corpus models the edge that makes multi-agent
systems interesting: agent A's output becoming agent B's instruction.
`NS-AIML-025` flags a multi-agent framework without code-execution
restrictions as a bare presence signal; nothing traces a value ACROSS the
handoff from a low-trust agent to a higher-privilege one.

Scope for this phase: **CrewAI only**, in the shape the framework's own API
makes source-visible within a single file --

    researcher = Agent(role=..., tools=[ScrapeWebsiteTool()])
    executor   = Agent(role=..., tools=[CodeInterpreterTool()])

    research_task = Task(description=..., agent=researcher)
    exec_task     = Task(description=..., agent=executor,
                          context=[research_task])   # <-- the handoff edge

    Crew(agents=[...], tasks=[research_task, exec_task]).kickoff()

`Task(context=[...])` is CrewAI's own documented mechanism for feeding one
task's output into another's prompt, and it is plainly visible in source as
object references between local variables -- tractable as an AST pass the
same way `AuthzPass` resolves ownership/guard relationships, without needing
a new taint engine.

**Deliberately NOT in this phase** (filed as a follow-up issue rather than
attempted here): LangGraph's `Command(goto=...)`/state-channel handoff,
AutoGen's `initiate_chat`/`send`, and OpenAI Agents SDK/A2A handoff. In all
three, the actual handoff happens through framework-internal execution (the
graph runtime decides which node runs next; the Agents SDK runtime decides
which agent receives control), not a directly-traceable object reference in
source the way CrewAI's `context=[task]` is. Modeling those needs a
project-wide "armed channel" the same shape `CrossFilePass` already uses
for second-order ORM/vector-store persistence (write in one place, read in
another, no call edge between them) -- a genuine architecture addition to
that pass, not something this module can absorb safely alongside a first,
narrower implementation.
"""

from __future__ import annotations

import ast
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path

from rowan.analysis.request_sources import expr_reads_source
from rowan.core.agent_privilege import (
    is_privileged_tool_expr,
    is_web_source_tool_expr,
    resolve_custom_tool_privilege,
)
from rowan.core.findings import Category, Finding, ScanResult, Severity
from rowan.passes.base import ScanContext, scan_span
from rowan.passes.sources import iter_python_sources

logger = logging.getLogger(__name__)

_RULE_ID = "AGENT-HANDOFF-001"
_CONFIDENCE = 0.55
_REMEDIATION = (
    "Validate or schema-constrain a task's output before it feeds another task's "
    "context, especially when the receiving task's agent holds a privileged tool "
    "(code execution, shell, filesystem write). Prefer `output_pydantic`/"
    "`output_json` on the emitting task so the handoff carries structured, "
    "schema-checked data rather than free-form text an attacker-influenced page "
    "or search result could steer."
)


@dataclass
class _AgentInfo:
    is_privileged: bool = False
    is_web_source: bool = False


@dataclass
class _TaskInfo:
    lineno: int
    agent_var: str | None = None
    context_vars: list[str] = field(default_factory=list)
    description_reads_source: bool = False
    has_output_schema: bool = False


@dataclass
class _Node:
    """A handoff participant (a CrewAI task, or an agent in the other
    frameworks), normalized so one finding routine works across frameworks."""

    name: str
    lineno: int
    framework: str = "crewai"
    is_privileged: bool = False       # holds a code-exec / shell / fs-write tool
    reads_source: bool = False        # instruction/description built from a request/CLI source
    is_web_source: bool = False       # holds a scrape/search tool (armed as a handoff source)
    has_output_schema: bool = False   # structured/schema-constrained output


@dataclass
class _Edge:
    """A directed handoff: content/control flows from `src` to `dst`, so a
    prompt injection reaching `src` can steer `dst`."""

    src: str
    dst: str
    lineno: int
    framework: str


def _call_named(node: ast.expr, name: str) -> ast.Call | None:
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == name:
        return node
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == name:
        return node
    return None


def _kwarg(call: ast.Call, name: str) -> ast.expr | None:
    for kw in call.keywords:
        if kw.arg == name:
            return kw.value
    return None


def _list_elts(expr: ast.expr | None) -> list[ast.expr]:
    if isinstance(expr, (ast.List, ast.Tuple)):
        return list(expr.elts)
    return []


def _agent_info(call: ast.Call, custom_privileged: frozenset[str]) -> _AgentInfo:
    info = _AgentInfo()
    for tool_expr in _list_elts(_kwarg(call, "tools")):
        if is_privileged_tool_expr(tool_expr) or (isinstance(tool_expr, ast.Name) and tool_expr.id in custom_privileged):
            info.is_privileged = True
        if is_web_source_tool_expr(tool_expr):
            info.is_web_source = True
    return info


def _task_info(call: ast.Call) -> _TaskInfo:
    agent_expr = _kwarg(call, "agent")
    agent_var = agent_expr.id if isinstance(agent_expr, ast.Name) else None

    context_vars = [
        elt.id for elt in _list_elts(_kwarg(call, "context")) if isinstance(elt, ast.Name)
    ]

    description_expr = _kwarg(call, "description")
    description_reads_source = bool(description_expr and expr_reads_source(description_expr))

    has_output_schema = _kwarg(call, "output_pydantic") is not None or _kwarg(call, "output_json") is not None

    return _TaskInfo(
        lineno=call.lineno,
        agent_var=agent_var,
        context_vars=context_vars,
        description_reads_source=description_reads_source,
        has_output_schema=has_output_schema,
    )


def _module_assignments(tree: ast.AST) -> list[tuple[str, ast.Call]]:
    """`var = SomeCall(...)` assignments (nested included, since ast.walk
    flattens scope), the shape every framework's agent/task construction uses."""
    out: list[tuple[str, ast.Call]] = []
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
            and isinstance(node.value, ast.Call)
        ):
            out.append((node.targets[0].id, node.value))
    return out


def _extract_crewai(tree: ast.AST) -> tuple[dict[str, _Node], list[_Edge]]:
    """CrewAI: nodes are Tasks (privilege/web-source inherited from the task's
    agent); the handoff edge is `Task(context=[other_task])`."""
    custom_privileged = resolve_custom_tool_privilege(tree)
    agents: dict[str, _AgentInfo] = {}
    tasks: dict[str, _TaskInfo] = {}
    for var_name, call in _module_assignments(tree):
        if _call_named(call, "Agent") is not None:
            agents[var_name] = _agent_info(call, custom_privileged)
        elif _call_named(call, "Task") is not None:
            tasks[var_name] = _task_info(call)

    nodes: dict[str, _Node] = {}
    edges: list[_Edge] = []
    for tvar, task in tasks.items():
        agent = agents.get(task.agent_var) if task.agent_var else None
        nodes[tvar] = _Node(
            name=tvar,
            lineno=task.lineno,
            framework="crewai",
            is_privileged=bool(agent and agent.is_privileged),
            reads_source=task.description_reads_source,
            is_web_source=bool(agent and agent.is_web_source),
            has_output_schema=task.has_output_schema,
        )
        for ctx_var in task.context_vars:
            edges.append(_Edge(src=ctx_var, dst=tvar, lineno=task.lineno, framework="crewai"))
    return nodes, edges


def _agent_ref_name(expr: ast.expr) -> str | None:
    """The agent variable named by a handoff-list element: a bare `agent`
    reference or a `handoff(agent)` / `handoff(agent=agent)` wrapper."""
    if isinstance(expr, ast.Name):
        return expr.id
    if isinstance(expr, ast.Call) and _call_named(expr, "handoff") is not None:
        if expr.args and isinstance(expr.args[0], ast.Name):
            return expr.args[0].id
        target = _kwarg(expr, "agent")
        if isinstance(target, ast.Name):
            return target.id
    return None


@dataclass(frozen=True)
class _RefsFramework:
    """A framework whose handoff is a source-visible list of agent references
    on the agent constructor (`A = Ctor(..., <refs_kwarg>=[B, ...])`, A hands
    control to B). Nodes are created only for agents in such a relationship,
    so an unrelated `Ctor(...)` elsewhere never becomes a node or a finding."""

    label: str
    ctor_names: frozenset[str]
    refs_kwarg: str
    instruction_kwarg: str
    schema_kwarg: str


_REFS_FRAMEWORKS = (
    _RefsFramework("openai_agents", frozenset({"Agent"}), "handoffs", "instructions", "output_type"),
    _RefsFramework("google_adk", frozenset({"Agent", "LlmAgent"}), "sub_agents", "instruction", "output_schema"),
)


def _extract_refs_handoff(tree: ast.AST, fw: _RefsFramework) -> tuple[dict[str, _Node], list[_Edge]]:
    custom_privileged = resolve_custom_tool_privilege(tree)
    agent_calls: dict[str, ast.Call] = {}
    for var_name, call in _module_assignments(tree):
        if any(_call_named(call, ctor) is not None for ctor in fw.ctor_names):
            agent_calls[var_name] = call

    edges: list[_Edge] = []
    participants: set[str] = set()
    for var_name, call in agent_calls.items():
        for elt in _list_elts(_kwarg(call, fw.refs_kwarg)):
            target = _agent_ref_name(elt)
            if target is not None and target in agent_calls:
                edges.append(_Edge(src=var_name, dst=target, lineno=call.lineno, framework=fw.label))
                participants.add(var_name)
                participants.add(target)

    nodes: dict[str, _Node] = {}
    for var_name in participants:
        call = agent_calls[var_name]
        info = _agent_info(call, custom_privileged)
        instructions = _kwarg(call, fw.instruction_kwarg)
        nodes[var_name] = _Node(
            name=var_name,
            lineno=call.lineno,
            framework=fw.label,
            is_privileged=info.is_privileged,
            reads_source=bool(instructions and expr_reads_source(instructions)),
            is_web_source=info.is_web_source,
            has_output_schema=_kwarg(call, fw.schema_kwarg) is not None,
        )
    return nodes, edges


def _extract_refs_frameworks(tree: ast.AST) -> tuple[dict[str, _Node], list[_Edge]]:
    nodes: dict[str, _Node] = {}
    edges: list[_Edge] = []
    for fw in _REFS_FRAMEWORKS:
        fw_nodes, fw_edges = _extract_refs_handoff(tree, fw)
        nodes.update(fw_nodes)
        edges.extend(fw_edges)
    return nodes, edges


# Privileged sinks a runtime-routed node/agent function body can reach. Kept
# to distinctive, receiver-anchored shapes so an unrelated `app.run()` or a
# framework's own `.call()` does not read as code execution.
_PRIV_SINK_RECEIVERS = frozenset({"subprocess", "os"})
_PRIV_SINK_METHODS = frozenset({"system", "popen", "run", "call", "check_output", "check_call", "Popen"})
_PRIV_SINK_BARE = frozenset({"eval", "exec"})
_WEB_FETCH_RECEIVERS = frozenset({"requests", "httpx", "aiohttp", "urllib"})
_WEB_FETCH_METHODS = frozenset({"get", "post", "request", "urlopen"})


def _body_is_privileged(fn: ast.AST) -> bool:
    """True if the function body reaches a code-exec / shell / process sink."""
    for node in ast.walk(fn):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if isinstance(func, ast.Name) and func.id in _PRIV_SINK_BARE:
            return True
        if (
            isinstance(func, ast.Attribute)
            and func.attr in _PRIV_SINK_METHODS
            and isinstance(func.value, ast.Name)
            and func.value.id in _PRIV_SINK_RECEIVERS
        ):
            return True
    return False


def _body_is_armed(fn: ast.AST) -> bool:
    """True if the function body reads an untrusted source: a request/CLI
    value, an outbound web fetch, or a web-scraping tool."""
    for node in ast.walk(fn):
        if not isinstance(node, ast.Call):
            continue
        if expr_reads_source(node) or is_web_source_tool_expr(node):
            return True
        func = node.func
        if (
            isinstance(func, ast.Attribute)
            and func.attr in _WEB_FETCH_METHODS
            and isinstance(func.value, ast.Name)
            and func.value.id in _WEB_FETCH_RECEIVERS
        ):
            return True
    return False


def _str_const(expr: ast.expr | None) -> str | None:
    if isinstance(expr, ast.Constant) and isinstance(expr.value, str):
        return expr.value
    return None


# LangGraph sentinel node names that are not agents.
_LANGGRAPH_SENTINELS = frozenset({"START", "END", "__start__", "__end__"})


def _extract_langgraph(tree: ast.AST) -> tuple[dict[str, _Node], list[_Edge]]:
    """LangGraph: `add_node("name", fn)` binds a node name to a function, and
    edges are string-node references (`add_edge`, `add_conditional_edges`, or a
    `Command(goto=...)` returned from a node body). Node privilege/arming is
    read from the mapped function's body -- the runtime-routed "armed channel"
    shape CrewAI's object references cannot express."""
    funcs: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            funcs[node.name] = node

    node_fn: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = {}
    edges: list[_Edge] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if _call_named(node, "add_node") is not None and node.args:
            name = _str_const(node.args[0])
            fn_ref = node.args[1] if len(node.args) > 1 else node.args[0]
            if name is None and isinstance(node.args[0], ast.Name):
                name = node.args[0].id  # add_node(fn) -> node named after fn
            if name and isinstance(fn_ref, ast.Name) and fn_ref.id in funcs:
                node_fn[name] = funcs[fn_ref.id]
        elif _call_named(node, "add_edge") is not None and len(node.args) >= 2:
            src, dst = _str_const(node.args[0]), _str_const(node.args[1])
            if src and dst:
                edges.append(_Edge(src=src, dst=dst, lineno=node.lineno, framework="langgraph"))
        elif _call_named(node, "add_conditional_edges") is not None and node.args:
            src = _str_const(node.args[0])
            mapping = node.args[2] if len(node.args) > 2 else None
            if src and isinstance(mapping, ast.Dict):
                for value in mapping.values:
                    dst = _str_const(value)
                    if dst:
                        edges.append(_Edge(src=src, dst=dst, lineno=node.lineno, framework="langgraph"))

    # `Command(goto="x")` returned inside a node body is an edge from that node.
    for name, fn in node_fn.items():
        for inner in ast.walk(fn):
            if isinstance(inner, ast.Call) and _call_named(inner, "Command") is not None:
                goto = _str_const(_kwarg(inner, "goto"))
                if goto:
                    edges.append(_Edge(src=name, dst=goto, lineno=inner.lineno, framework="langgraph"))

    referenced = {e.src for e in edges} | {e.dst for e in edges}
    nodes: dict[str, _Node] = {}
    for name in referenced:
        if name in _LANGGRAPH_SENTINELS:
            continue
        fn = node_fn.get(name)
        nodes[name] = _Node(
            name=name,
            lineno=fn.lineno if fn else 0,
            framework="langgraph",
            is_privileged=bool(fn and _body_is_privileged(fn)),
            reads_source=bool(fn and _body_is_armed(fn)),
            is_web_source=False,  # folded into reads_source for body-analyzed nodes
            has_output_schema=False,
        )
    return nodes, edges


_AUTOGEN_CTORS = frozenset({
    "AssistantAgent", "UserProxyAgent", "ConversableAgent",
    "CodeExecutorAgent",  # autogen_agentchat 0.4+: always runs code
})
#: autogen_agentchat 0.4+ team constructors: every participant's messages
#: reach every other participant (AZ-16).
_AUTOGEN_TEAMS = frozenset({
    "RoundRobinGroupChat", "SelectorGroupChat", "Swarm", "MagenticOneGroupChat",
})


def _autogen_code_exec(call: ast.Call) -> bool:
    """True if the agent's `code_execution_config` enables execution (present
    and not the literal `False`), or it is a 0.4 `CodeExecutorAgent`."""
    if _call_named(call, "CodeExecutorAgent") is not None:
        return True
    cec = _kwarg(call, "code_execution_config")
    if cec is None:
        return False
    return not (isinstance(cec, ast.Constant) and cec.value is False)


def _extract_autogen(tree: ast.AST) -> tuple[dict[str, _Node], list[_Edge]]:
    """AutoGen: agents converse via `X.initiate_chat(Y, ...)`. The chat is
    bidirectional (each side's messages reach the other), so both directions
    are edges: the finding fires whichever side is the code-executing proxy
    when the other side is armed by an untrusted source."""
    custom_privileged = resolve_custom_tool_privilege(tree)
    agent_calls: dict[str, ast.Call] = {}
    for var_name, call in _module_assignments(tree):
        if any(_call_named(call, ctor) is not None for ctor in _AUTOGEN_CTORS):
            agent_calls[var_name] = call

    edges: list[_Edge] = []
    participants: set[str] = set()
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and _call_named(node, "initiate_chat") is not None
            and isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.args
            and isinstance(node.args[0], ast.Name)
        ):
            a, b = node.func.value.id, node.args[0].id
            if a in agent_calls and b in agent_calls:
                edges.append(_Edge(src=a, dst=b, lineno=node.lineno, framework="autogen"))
                edges.append(_Edge(src=b, dst=a, lineno=node.lineno, framework="autogen"))
                participants.add(a)
                participants.add(b)
        elif isinstance(node, ast.Call) and any(
            _call_named(node, team) is not None for team in _AUTOGEN_TEAMS
        ):
            members_expr = node.args[0] if node.args else _kwarg(node, "participants")
            if not isinstance(members_expr, ast.List):
                continue
            members = [
                elt.id for elt in members_expr.elts
                if isinstance(elt, ast.Name) and elt.id in agent_calls
            ]
            for a in members:
                for b in members:
                    if a != b:
                        edges.append(_Edge(src=a, dst=b, lineno=node.lineno, framework="autogen"))
            participants.update(members)

    nodes: dict[str, _Node] = {}
    for var_name in participants:
        call = agent_calls[var_name]
        info = _agent_info(call, custom_privileged)
        system_message = _kwarg(call, "system_message")
        nodes[var_name] = _Node(
            name=var_name,
            lineno=call.lineno,
            framework="autogen",
            is_privileged=info.is_privileged or _autogen_code_exec(call),
            reads_source=bool(system_message and expr_reads_source(system_message)),
            is_web_source=info.is_web_source,
            has_output_schema=False,
        )
    return nodes, edges


#: Framework extractors, each mapping an AST to (nodes, edges) in the unified
#: handoff-graph model. Registering a new framework is adding one entry here.
_EXTRACTORS = (_extract_crewai, _extract_refs_frameworks, _extract_langgraph, _extract_autogen)


def _build_graph(tree: ast.AST) -> tuple[dict[str, _Node], list[_Edge]]:
    nodes: dict[str, _Node] = {}
    edges: list[_Edge] = []
    for extractor in _EXTRACTORS:
        fw_nodes, fw_edges = extractor(tree)
        nodes.update(fw_nodes)
        edges.extend(fw_edges)
    return nodes, edges


class MultiAgentPass:
    """CrewAI cross-agent injection propagation (`AGENT-HANDOFF-001`).

    Off by default (`ScanConfig.enable_multiagent`) until precision is
    measured against a labeled corpus, matching this project's convention
    for a new AST-emitted, non-YAML rule (see `AuthzPass`, issue #171).
    """

    name = "multiagent"

    def run(self, context: ScanContext) -> ScanResult:
        start = time.perf_counter()
        result = ScanResult()

        # None means the policy chose; the scan plan only runs this pass when enabled.
        if context.config.enable_multiagent is False:
            return result

        files_scanned = 0

        for py_file, tree in iter_python_sources(context, owner=self.name, skip_tests=False):
            files_scanned += 1
            result.findings.extend(self._scan_tree(py_file, tree))

        result.files_scanned = files_scanned
        duration = time.perf_counter() - start
        scan_span(self.name, duration)
        logger.info("MultiAgentPass: %d finding(s) in %.2fs", len(result.findings), duration)
        return result

    def _scan_tree(self, py_file: Path, tree: ast.AST) -> list[Finding]:
        nodes, edges = _build_graph(tree)
        return self._findings_from_graph(py_file, nodes, edges)

    def _findings_from_graph(
        self, py_file: Path, nodes: dict[str, _Node], edges: list[_Edge]
    ) -> list[Finding]:
        findings: list[Finding] = []
        # One finding per privileged receiver. The direct case (a node armed by
        # its own request/CLI source) takes precedence over an incoming handoff,
        # matching the pre-refactor per-task order.
        emitted: set[str] = set()

        for name, node in nodes.items():
            if node.is_privileged and node.reads_source and not node.has_output_schema:
                findings.append(self._finding(py_file, name, node.lineno, "direct", node.framework))
                emitted.add(name)

        armed_origin = {
            name: name
            for name, node in nodes.items()
            if (node.reads_source or node.is_web_source) and not node.has_output_schema
        }
        incoming_framework: dict[str, str] = {}
        while True:
            changed = False
            for edge in edges:
                src = nodes.get(edge.src)
                dst = nodes.get(edge.dst)
                if src is None or dst is None or edge.src not in armed_origin:
                    continue
                if src.has_output_schema or dst.has_output_schema or edge.dst in armed_origin:
                    continue
                armed_origin[edge.dst] = armed_origin[edge.src]
                incoming_framework[edge.dst] = edge.framework
                changed = True
            if not changed:
                break

        for name, origin in armed_origin.items():
            node = nodes[name]
            if name in emitted or name == origin or not node.is_privileged:
                continue
            findings.append(
                self._finding(
                    py_file,
                    name,
                    node.lineno,
                    "handoff",
                    incoming_framework.get(name, node.framework),
                    origin,
                )
            )
            emitted.add(name)

        return findings

    def _finding(
        self,
        py_file: Path,
        receiver: str,
        lineno: int,
        kind: str,
        framework: str,
        source: str | None = None,
    ) -> Finding:
        if kind == "direct":
            message = (
                f"'{receiver}' is built directly from a request/CLI-controlled value "
                "and holds a privileged tool (code execution, shell, or filesystem "
                "write). Anything that can influence that input can steer the "
                "privileged tool call."
            )
        else:
            message = (
                f"'{receiver}' receives a handoff from '{source}' and holds a "
                f"privileged tool, but '{source}' is fed by web-sourced content (a "
                "scrape/search tool) or a request-controlled value with no output "
                "schema constraining it. A prompt injection in that content can "
                "steer the privileged tool call."
            )
        metadata = {"handoff_kind": kind, "framework": framework, "remediation": _REMEDIATION}
        return Finding(
            rule_id=_RULE_ID,
            message=message,
            severity=Severity.HIGH,
            category=Category.AI_ML,
            file_path=str(py_file),
            start_line=lineno,
            confidence=_CONFIDENCE,
            cwe_ids=[74, 20],
            engine="multiagent",
            metadata=metadata,
        )
