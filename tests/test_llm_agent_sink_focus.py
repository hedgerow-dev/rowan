"""LLM and agent sinks are the dangerous argument, not the whole call (#72).

Without focus-metavariable a sink fires when taint reaches any argument:
a constant max_tokens with a tainted message (TNT-ML-022), a tainted query
vector with a constant filter (TNT-ML-020), a tainted USER message reported
as system-prompt injection (TNT-AIML-002), a tainted prompt inside a bounded
`range(3)` loop (TNT-ML-013) and a fixed sampling message from a tool whose
context parameter is tainted (TNT-ML-036). Requires the Opengrep binary.
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

WEB = "from flask import request\n\ndef h(client, index, llm):\n    u = request.get_json()['u']\n"
MCP = "from mcp.server.fastmcp import FastMCP\nmcp = FastMCP('x')\n\n@mcp.tool()\nasync def t(c, topic):\n"


def _fires(tmp_path, rule_file, rule_id, header, line):
    src = header + "    " + line + "\n"
    (tmp_path / "app.py").write_text(src, encoding="utf-8")
    findings = OpengrepAdapter().scan_with_rules(tmp_path, [RULES_DIR / rule_file], languages=["python"])
    return any(f.rule_id == rule_id for f in findings)


CASES = [
    # (rule file, rule id, header, dangerous line, harmless line)
    ("ml_taint.yaml", "TNT-ML-022", WEB,
     "client.chat.completions.create(model='m', max_tokens=u, messages=[])",
     "client.chat.completions.create(model='m', max_tokens=5, messages=[{'role': 'user', 'content': u}])"),
    ("ml_taint.yaml", "TNT-ML-020", WEB,
     "index.query(vector=[0.1], top_k=3, filter=u)",
     "index.query(vector=u, top_k=3, filter={'tenant': 't1'})"),
    ("ai_ml_taint.yaml", "TNT-AIML-002", WEB,
     "client.chat.completions.create(model='m', messages=[{'role': 'system', 'content': u}])",
     "client.chat.completions.create(model='m', messages=[{'role': 'system', 'content': 'fixed'}, {'role': 'user', 'content': u}])"),
    ("ai_ml_taint.yaml", "TNT-AIML-002", WEB,
     "client.messages.create(model='m', max_tokens=5, system=u, messages=[])",
     "client.messages.create(model='m', max_tokens=5, system='fixed', messages=[{'role': 'user', 'content': u}])"),
    ("agent_taint.yaml", "TNT-ML-013", WEB,
     "for i in range(u):\n        llm.invoke('x')",
     "for i in range(3):\n        llm.invoke(u)"),
    ("agent_taint.yaml", "TNT-ML-036", MCP,
     "await c.session.create_message(messages=[topic], max_tokens=50)",
     "await c.session.create_message(messages=['fixed'], max_tokens=50)"),
    ("agent_taint.yaml", "TNT-ML-036", MCP,
     "await c.session.create_message([topic], max_tokens=50)",
     "await c.session.create_message(['fixed'], max_tokens=topic)"),
]


@pytest.mark.parametrize("rule_file,rule_id,header,dangerous,harmless", CASES)
def test_dangerous_argument_fires(tmp_path, rule_file, rule_id, header, dangerous, harmless):
    assert _fires(tmp_path, rule_file, rule_id, header, dangerous), dangerous


@pytest.mark.parametrize("rule_file,rule_id,header,dangerous,harmless", CASES)
def test_harmless_argument_does_not_fire(tmp_path, rule_file, rule_id, header, dangerous, harmless):
    assert not _fires(tmp_path, rule_file, rule_id, header, harmless), harmless
