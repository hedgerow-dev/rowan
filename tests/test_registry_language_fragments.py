"""Per-language registry fragments (BACKLOG JG-01).

Three guards, plus a live Opengrep check of the AI-port fragments:

* every ``SOURCES`` fragment renders to valid YAML under a ``pattern-either``;
* the seven ``llm_output`` rules expand to exactly the fragment render;
* no rule in java_taint.yaml / go_taint.yaml carries an inline copy of a
  fragment's first pattern outside sentinels (the four Java rules whose
  source list is a strict subset of the fragment are the documented exception);
* each shape in the four AI-port fragments matches its fixture line and none
  of the negative lines (skipped when the Opengrep binary is missing).
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

from rowan.rules_registry import SOURCES, render_pattern_either_block
from rowan.taint.opengrep_adapter import OpengrepAdapter

PROJECT_ROOT = Path(__file__).resolve().parent.parent
RULES_DIR = PROJECT_ROOT / "rules"

_RULE_SPLIT = re.compile(r"^  - id: ", re.MULTILINE)
_SENTINEL_REGION = re.compile(
    r"^[ ]*#\s*rowan-registry:begin\s+source=(?P<name>\S+)\s*$.*?"
    r"^[ ]*#\s*rowan-registry:end\s+source=(?P=name)\s*$",
    re.MULTILINE | re.DOTALL,
)


def _leaf_count(entries) -> int:
    n = 0
    for e in entries:
        if isinstance(e, str):
            n += 1
        elif "patterns" in e:
            n += sum(1 for item in e["patterns"] if isinstance(item, str)) + sum(
                _leaf_count([item]) for item in e["patterns"] if isinstance(item, dict)
            )
        elif "pattern-either" in e:
            n += _leaf_count(e["pattern-either"])
    return n


def _rules_by_id(path: Path) -> dict[str, str]:
    chunks = _RULE_SPLIT.split(path.read_text(encoding="utf-8"))[1:]
    return {c.split("\n", 1)[0].strip(): c for c in chunks}


# web_request_go_bind renders as top-level items (by-side-effect); see
# tests/test_go_request_sources.py.
@pytest.mark.parametrize("name", sorted(set(SOURCES) - {"web_request_go_bind"}))
def test_every_fragment_renders_to_valid_yaml(name):
    rendered = render_pattern_either_block("source", name, 6)
    data = yaml.safe_load("pattern-sources:\n" + rendered)
    block = data["pattern-sources"]
    assert len(block) == 1 and list(block[0]) == ["patterns"]
    either = block[0]["patterns"][0]["pattern-either"]
    assert len(either) == len(SOURCES[name])
    # every entry is a pattern or a nested patterns block, nothing else
    for item in either:
        assert set(item) <= {"pattern", "patterns"}, item


def test_fragment_pattern_counts():
    """Behaviour lock on the sizes documented in BACKLOG JG-01."""
    expected = {
        "llm_output": 34,  # PY-01: 17 original + 17 agent-SDK shapes
        "web_request_java": 11,  # EXT-19: System.getenv moved to operator_input_java
        "operator_input_java": 5,
        "web_request_go": 16,  # #56: router/framework getters; binds moved to web_request_go_bind
        "operator_input_go": 7,  # EXT-19: + LookupEnv, flag.Arg, viper x2
    }
    for name, count in expected.items():
        assert _leaf_count(SOURCES[name]) == count, name


def test_llm_output_rules_expand_to_the_fragment():
    rendered = render_pattern_either_block("source", "llm_output", 6)
    region = (
        "      # rowan-registry:begin source=llm_output\n"
        + rendered
        + "\n      # rowan-registry:end source=llm_output\n"
    )
    llmout = _rules_by_id(RULES_DIR / "llm_output_taint.yaml")
    agent = _rules_by_id(RULES_DIR / "agent_taint.yaml")
    for rule_id in [f"TNT-LLMOUT-00{i}" for i in range(1, 7)]:
        assert region in llmout[rule_id], rule_id
    assert region in agent["TNT-ML-019"]
    # the narrower variants deliberately stay inline
    for rule_id in ("TNT-ML-010", "TNT-ML-011", "TNT-ML-015", "TNT-ML-029", "TNT-AUTHZ-001"):
        assert "source=llm_output" not in agent[rule_id], rule_id


# Source lists that are a strict subset of web_request_java (they omit
# PathVariable, QueryParam, RequestBody or the @$MAPPING shape) and so cannot
# be expressed as the fragment plus an extra without widening the rule.
_JAVA_SUBSET_RULES = {"tnt-ja-deser-001", "tnt-ja-xxe-001", "tnt-ja-ldap-001", "tnt-ja-el-001"}


@pytest.mark.parametrize(
    ("file_name", "fragment", "allowed"),
    [
        ("java_taint.yaml", "web_request_java", _JAVA_SUBSET_RULES),
        ("java_taint.yaml", "operator_input_java", set()),
        ("go_taint.yaml", "web_request_go", set()),
        ("go_taint.yaml", "operator_input_go", set()),
    ],
)
def test_no_inline_copy_of_fragment_outside_sentinels(file_name, fragment, allowed):
    first = SOURCES[fragment][0]
    marker = f"- pattern: {first}"
    for rule_id, chunk in _rules_by_id(RULES_DIR / file_name).items():
        outside = _SENTINEL_REGION.sub("", chunk)
        if rule_id in allowed:
            continue
        assert marker not in outside, (
            f"{file_name}: {rule_id} carries {first!r} inline; wrap the block in "
            f"'# rowan-registry:begin source={fragment}' / end and run scripts/sync_registry.py"
        )


# --------------------------------------------------------------------------- #
# Live shape check for the AI-port fragments (no rule uses them yet).
# --------------------------------------------------------------------------- #

_JAVA_FIXTURE = """\
import java.util.function.Function;

public class Fixture {
    ChatClient chatClient;
    ChatLanguageModel lcModel;
    ChatModel newModel;

    void springAi(ChatResponse resp) {
        String a = chatClient.prompt().user("hi").call().content(); // SRC
        String b = chatClient.prompt("hi").call().chatResponse().getResult().getOutput().getText(); // SRC
        String c = resp.getResult().getOutput().getText(); // SRC
        String d = resp.getResult().getOutput().getContent(); // SRC
    }

    void langchain4j(AiMessage msg, Result<String> result, Response<AiMessage> response) {
        String a = lcModel.chat("hi"); // SRC
        String b = newModel.chat("hi"); // SRC
        var c = lcModel.generate("hi"); // SRC
        String d = msg.text(); // SRC
        String e = result.content(); // SRC
        String f = response.aiMessage().text(); // SRC
        String notLlm = other.text(); // NOT
    }

    void openai(ChatCompletion completion) {
        var a = completion.choices().get(0).message().content(); // SRC
        String b = completion.choices().get(0).message().content().orElse(""); // SRC
    }

    void anthropic(Message msg) {
        String a = msg.content().get(0).text().get().text(); // SRC
    }
}
"""

_JAVA_TOOL_FIXTURE = """\
import java.util.function.Function;

public class Tools {
    @Tool
    String bareTool(String cmd) {
        return run(cmd); // SRC
    }

    @Tool("does things")
    String argTool(String path, int n) {
        return read(path); // SRC
    }

    String toolParam(@ToolParam(description = "x") String q) {
        return q; // SRC
    }

    String plain(String notTainted) {
        return notTainted; // NOT
    }
}

class WeatherFn implements Function<WeatherFn.Request, WeatherFn.Response> {
    public Response apply(Request request) {
        return fetch(request.city); // SRC
    }
}

class NotAFn {
    public Response apply(Request request) {
        return fetch(request.city); // NOT
    }
}
"""

_GO_LLM_FIXTURE = """\
package main

func llmOut(ctx context.Context, msg *anthropic.Message, chatResp api.ChatResponse) {
	a := resp.Choices[0].Message.Content // SRC
	b := resp.Choices[0].Content // SRC
	c, _ := llms.GenerateFromSinglePrompt(ctx, llm, "hi") // SRC
	d := msg.Content[0].Text // SRC
	e := chatResp.Message.Content // SRC
	_ = client.Generate(ctx, req, func(gr api.GenerateResponse) error {
		f := gr.Response // SRC
		return nil
	})
	g, _ := genkit.Generate(ctx, g, ai.WithPrompt("hi")) // SRC
	var mr *ai.ModelResponse
	i := mr.Text() // SRC
	j := other.Response // NOT
	k := other.Text() // NOT
}
"""

_GO_MCP_FIXTURE = """\
package main

func mcpGo(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	a := request.Params.Arguments["cmd"] // SRC
	b := request.GetArguments()["cmd"] // SRC
	c := request.GetString("cmd", "") // SRC
	e, _ := request.RequireString("cmd") // SRC
	return nil, nil
}

type Args struct{ Cmd string }

func typedHandler(ctx context.Context, req *mcp.CallToolRequest, args Args) (*mcp.CallToolResult, any, error) {
	run(args.Cmd) // SRC
	return nil, nil, nil
}

var anon = func(ctx context.Context, req *mcp.CallToolRequest, args Args) (*mcp.CallToolResult, Out, error) {
	run(args.Cmd) // SRC
	return nil, nil, nil
}

func notHandler(ctx context.Context, args Args) {
	run(args.Cmd) // NOT
}
"""

_adapter = OpengrepAdapter()


def _search_rule(name: str, language: str) -> str:
    return (
        f"rules:\n  - id: probe-{name}\n    languages: [{language}]\n"
        "    severity: WARNING\n    message: hit\n    patterns:\n"
        + render_pattern_either_block("source", name, 6)
        + "\n"
    )


@pytest.mark.skipif(not _adapter.is_installed(), reason="Opengrep binary not installed")
@pytest.mark.parametrize(
    ("name", "language", "filename", "fixture"),
    [
        ("llm_output_java", "java", "Fixture.java", _JAVA_FIXTURE),
        ("llm_tool_param_java", "java", "Tools.java", _JAVA_TOOL_FIXTURE),
        ("llm_output_go", "go", "llm.go", _GO_LLM_FIXTURE),
        ("mcp_tool_arg_go", "go", "mcp.go", _GO_MCP_FIXTURE),
    ],
)
def test_ai_port_fragment_shapes_match_fixture(tmp_path, name, language, filename, fixture):
    src_dir = tmp_path / "src"
    src_dir.mkdir()
    (src_dir / filename).write_text(fixture, encoding="utf-8")
    rule_file = tmp_path / f"{name}.yaml"
    rule_file.write_text(_search_rule(name, language), encoding="utf-8")

    hit_lines = {
        f.start_line for f in _adapter.scan_with_rules(src_dir, [rule_file], languages=[language])
    }
    lines = fixture.split("\n")
    expected = {i + 1 for i, line in enumerate(lines) if line.rstrip().endswith("// SRC")}
    forbidden = {i + 1 for i, line in enumerate(lines) if line.rstrip().endswith("// NOT")}
    assert expected <= hit_lines, f"{name}: missed lines {sorted(expected - hit_lines)}"
    assert not (forbidden & hit_lines), f"{name}: matched negatives {sorted(forbidden & hit_lines)}"
