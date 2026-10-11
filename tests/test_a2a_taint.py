"""Positive/negative fixtures for the A2A taint rules (rules/a2a_taint.yaml,
issue #289): Agent-to-Agent protocol attack surface.

Requires the Opengrep binary (skipped entirely if not installed, matching the
project's convention -- CI does not install it, see .github/workflows/ci.yml).

  - TNT-A2A-001: a request/config value or a peer-advertised agent-card url
    flows into an outbound A2A peer-client construction (A2AClient /
    A2ACardResolver) -- SSRF into internal agents.
  - TNT-A2A-002: an inbound A2A task/message payload (task.artifacts /
    message.parts / RequestContext input) flows into an unsafe deserializer
    (pickle/yaml.unsafe_load/eval/torch.load) -- untrusted-peer RCE.
  - TNT-A2A-003: inbound A2A peer/task TEXT flows into a system-prompt slot or
    a tool-dispatch sink -- cross-agent prompt injection. The source is the
    peer/task channel specifically, not request.* (the differentiator from
    TNT-AIML-002 / TNT-ML-005).

Each rule has a vulnerable fixture that fires plus a sanitized/safe fixture
that does not. TNT-A2A-001 also carries a generalization fixture whose code
shape differs from the first (different variable names, a config-env source,
and the A2ACardResolver wrapper instead of A2AClient) to prove the rule keys
off the A2A library identifiers, not a single PoC's variable names.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from rowan.taint.opengrep_adapter import OpengrepAdapter

RULES_DIR = Path(__file__).parent.parent / "rules"
RULE_FILE = "a2a_taint.yaml"

_adapter = OpengrepAdapter()
pytestmark = pytest.mark.skipif(
    not _adapter.is_installed(),
    reason="Opengrep binary not installed; these tests need a live scan.",
)


def _scan(tmp_path, filename, source, rule_id):
    fp = tmp_path / filename
    fp.write_text(source, encoding="utf-8")
    adapter = OpengrepAdapter()
    findings = adapter.scan_with_rules(
        tmp_path, [RULES_DIR / RULE_FILE], languages=["python"]
    )
    return [f for f in findings if f.rule_id == rule_id]


class TestA2ASsrfTNTA2A001:
    """TNT-A2A-001: request/config/agent-card url -> A2A peer client."""

    def test_request_url_into_a2a_client_flagged(self, tmp_path):
        src = (
            "from a2a.client import A2AClient\n"
            "def delegate():\n"
            "    peer = request.json.get('peer_url')\n"
            "    return A2AClient(url=peer)\n"
        )
        findings = _scan(tmp_path, "a2a_ssrf.py", src, "TNT-A2A-001")
        assert findings, "request.json.get(...) into A2AClient(url=...) must be flagged"

    def test_generalizes_to_card_url_and_resolver(self, tmp_path):
        """Different shape than the first PoC: different var names, an
        agent-card url source, and the A2ACardResolver wrapper instead of
        A2AClient. Proves the rule keys off the A2A library identifiers, not
        one PoC's names. The env-configured peer is operator input (#73)."""
        src = (
            "import os\n"
            "from a2a.client import A2ACardResolver\n"
            "class PeerDiscovery:\n"
            "    def resolve_peer(self, discovered_card):\n"
            "        endpoint = discovered_card.url\n"
            "        return A2ACardResolver(base_url=endpoint)\n"
            "    def from_env(self):\n"
            "        target = os.getenv('A2A_PEER')\n"
            "        return A2ACardResolver(base_url=target)\n"
        )
        findings = _scan(tmp_path, "a2a_ssrf_general.py", src, "TNT-A2A-001")
        lines = {f.start_line for f in findings}
        assert 6 in lines, "agent-card url into A2ACardResolver must be flagged"
        assert 9 not in lines, "an env-configured peer URL is operator input, not attacker input"

    def test_validated_url_not_flagged(self, tmp_path):
        src = (
            "from a2a.client import A2AClient\n"
            "def delegate():\n"
            "    peer = validate_url_for_ssrf(request.json.get('peer_url'))\n"
            "    return A2AClient(url=peer)\n"
        )
        findings = _scan(tmp_path, "a2a_ssrf_safe.py", src, "TNT-A2A-001")
        assert findings == [], (
            "a peer url run through validate_url_for_ssrf() must not be flagged"
        )


class TestA2ADeserTNTA2A002:
    """TNT-A2A-002: inbound A2A payload -> unsafe deserializer."""

    def test_task_artifacts_into_pickle_flagged(self, tmp_path):
        src = (
            "import pickle\n"
            "def on_task(task):\n"
            "    blob = task.artifacts[0].parts[0].data\n"
            "    return pickle.loads(blob)\n"
        )
        findings = _scan(tmp_path, "a2a_deser_pickle.py", src, "TNT-A2A-002")
        assert findings, "task.artifacts payload into pickle.loads() must be flagged"

    def test_message_parts_into_yaml_unsafe_flagged(self, tmp_path):
        src = (
            "import yaml\n"
            "def on_message(message):\n"
            "    raw = message.parts[0].data\n"
            "    return yaml.unsafe_load(raw)\n"
        )
        findings = _scan(tmp_path, "a2a_deser_yaml.py", src, "TNT-A2A-002")
        assert findings, "message.parts payload into yaml.unsafe_load() must be flagged"

    def test_generalizes_multistatement_artifact_into_eval(self, tmp_path):
        """Different shape than the first PoC: an artifact bound to its own
        local across statements, different names, and an eval() sink instead of
        pickle -- proves the bare .artifacts source generalizes, not just the
        single chained expression."""
        src = (
            "def handle_delegated(incoming_task):\n"
            "    artifact = incoming_task.artifacts[0]\n"
            "    expr = artifact.parts[0].text\n"
            "    return eval(expr)\n"
        )
        findings = _scan(tmp_path, "a2a_deser_general.py", src, "TNT-A2A-002")
        assert findings, (
            "a peer artifact carried across statements into eval() must be flagged"
        )

    def test_safe_load_not_flagged(self, tmp_path):
        src = (
            "import yaml\n"
            "def on_ctx(context):\n"
            "    payload = context.get_user_input()\n"
            "    return yaml.safe_load(payload)\n"
        )
        findings = _scan(tmp_path, "a2a_deser_safe.py", src, "TNT-A2A-002")
        assert findings == [], (
            "an A2A payload routed through yaml.safe_load() must not be flagged"
        )


class TestA2APromptInjectionTNTA2A003:
    """TNT-A2A-003: inbound A2A peer text -> system prompt / tool dispatch."""

    def test_peer_text_into_system_prompt_flagged(self, tmp_path):
        src = (
            "def handle(message, llm):\n"
            "    peer_text = message.parts[0].text\n"
            "    llm.generate('do this', system_prompt=peer_text)\n"
        )
        findings = _scan(tmp_path, "a2a_prompt.py", src, "TNT-A2A-003")
        assert findings, (
            "peer message text into an LLM system_prompt slot must be flagged"
        )

    def test_peer_text_into_shell_flagged(self, tmp_path):
        src = (
            "import subprocess\n"
            "def dispatch(message):\n"
            "    cmd = message.parts[0].text\n"
            "    subprocess.run(cmd, shell=True)\n"
        )
        findings = _scan(tmp_path, "a2a_tool_dispatch.py", src, "TNT-A2A-003")
        assert findings, (
            "peer message text into subprocess.run(shell=True) must be flagged"
        )

    def test_generalizes_multistatement_part_into_shell(self, tmp_path):
        """Different shape: the part bound to its own local first (bare .parts
        source), different names, RequestContext-style access -- proves the
        source is the peer channel, not one PoC's expression."""
        src = (
            "import subprocess\n"
            "def run_delegated(ctx):\n"
            "    first_part = ctx.message.parts[0]\n"
            "    action = first_part.text\n"
            "    subprocess.run(action, shell=True)\n"
        )
        findings = _scan(tmp_path, "a2a_prompt_general.py", src, "TNT-A2A-003")
        assert findings, (
            "peer part text carried across statements into a shell must be flagged"
        )

    def test_peer_text_in_user_role_not_flagged(self, tmp_path):
        """The safe pattern: peer text kept in a delimited user-role slot, the
        system content a fixed constant. No system-prompt/tool-dispatch sink is
        reached, so nothing fires."""
        src = (
            "def handle(message, client):\n"
            "    peer_text = message.parts[0].text\n"
            "    client.chat.completions.create(\n"
            "        messages=[{'role': 'user', 'content': peer_text}]\n"
            "    )\n"
        )
        findings = _scan(tmp_path, "a2a_prompt_safe.py", src, "TNT-A2A-003")
        assert findings == [], (
            "peer text kept in a user-role message (no system slot) must not be flagged"
        )
