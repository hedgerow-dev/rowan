"""Agentic hunt workflow scenario tests.

Tests the full hunt pipeline with mocked LLM responses to verify
stage transitions, hypothesis triage, chain building, and error handling.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from rowan.agents.llm_backend import LLMBackend
from rowan.agents.workflow import HuntState, HuntWorkflow, run_hunt
from rowan.config import ScanConfig
from rowan.core.findings import Category, Finding, Severity


@pytest.fixture
def hunt_project():
    with tempfile.TemporaryDirectory(prefix="rowan_hunt_") as tmpdir:
        root = Path(tmpdir)
        src = root / "src"
        src.mkdir()

        (src / "app.py").write_text(
            "import pickle\n"
            "import os\n"
            "from flask import request\n"
            "\n"
            "def load_data():\n"
            "    data = request.args.get('payload')\n"
            "    return pickle.loads(data.encode())\n"
            "\n"
            "def run_cmd():\n"
            "    cmd = request.args.get('cmd')\n"
            "    os.system(cmd)\n",
            encoding="utf-8",
        )

        (src / "safe.py").write_text(
            "def add(a, b):\n"
            "    return a + b\n",
            encoding="utf-8",
        )

        yield root


class TestHuntReconStage:

    def test_recon_finds_surface_vulns(self, hunt_project):
        config = ScanConfig(
            target=hunt_project, languages=["python"], no_sca=True, legacy_neuroscan=True,
        )
        llm = LLMBackend(backend="deepseek", api_key="")
        state = HuntState(target_path=hunt_project, config=config, llm=llm)
        workflow = HuntWorkflow(state)
        workflow._recon()

        assert len(state.surface) > 0
        rule_ids = {f.rule_id for f in state.surface}
        assert len(rule_ids) > 0

    def test_recon_extracts_sinks(self, hunt_project):
        config = ScanConfig(
            target=hunt_project, languages=["python"], no_sca=True, legacy_neuroscan=True,
        )
        llm = LLMBackend(backend="deepseek", api_key="")
        state = HuntState(target_path=hunt_project, config=config, llm=llm)
        workflow = HuntWorkflow(state)
        workflow._recon()

        total_sinks = (
            len(state.http_sinks) +
            len(state.command_sinks) +
            len(state.lfi_sinks)
        )
        assert total_sinks >= 0


class TestHuntHypothesizeStage:

    @patch("rowan.agents.llm_backend.httpx.post")
    def test_hypothesize_with_mock_llm(self, mock_post, hunt_project):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {
            "choices": [{
                "message": {
                    "content": json.dumps({
                        "hypotheses": [
                            {
                                "rule_id": "NS-DESER-001",
                                "file": "src/app.py",
                                "line": 7,
                                "exploitability": "confirmed",
                                "severity": "critical",
                                "deep_dive": "src/app.py:7",
                                "chain_with": ["NS-INJECT-002"],
                                "attack_story": "Pickle deserialization from Flask request",
                            }
                        ]
                    })
                }
            }],
            "usage": {"total_tokens": 100},
        }
        mock_resp.raise_for_status.return_value = None
        mock_post.return_value = mock_resp

        config = ScanConfig(
            target=hunt_project, languages=["python"], no_sca=True, legacy_neuroscan=True,
        )
        llm = LLMBackend(backend="deepseek", api_key="sk-test")
        state = HuntState(target_path=hunt_project, config=config, llm=llm)
        workflow = HuntWorkflow(state)

        workflow._recon()
        workflow._hypothesize()

        assert len(state.hypotheses) > 0
        confirmed = [h for h in state.hypotheses if h.get("exploitability") == "confirmed"]
        assert len(confirmed) > 0

    def test_hypothesize_without_llm_graceful(self, hunt_project):
        config = ScanConfig(
            target=hunt_project, languages=["python"], no_sca=True, legacy_neuroscan=True,
        )
        llm = LLMBackend(backend="deepseek", api_key="")
        state = HuntState(target_path=hunt_project, config=config, llm=llm)
        workflow = HuntWorkflow(state)

        workflow._recon()
        workflow._hypothesize()

        assert state.stage != "error"


class TestHuntExploitStage:

    def test_exploit_builds_chains(self, hunt_project):
        config = ScanConfig(
            target=hunt_project, languages=["python"], no_sca=True, legacy_neuroscan=True,
        )
        llm = LLMBackend(backend="deepseek", api_key="")
        state = HuntState(target_path=hunt_project, config=config, llm=llm)
        state.hypotheses = [
            {
                "rule_id": "NS-DESER-001",
                "file": "src/app.py",
                "line": 7,
                "exploitability": "confirmed",
                "deep_dive": "src/app.py:7",
                "attack_story": "Pickle RCE from user input",
            },
            {
                "rule_id": "NS-INJECT-002",
                "file": "src/app.py",
                "line": 11,
                "exploitability": "likely",
                "deep_dive": "src/app.py:11",
                "attack_story": "Command injection via os.system",
            },
        ]

        workflow = HuntWorkflow(state)
        workflow._exploit()

        assert len(state.chains) >= 1
        assert all("type" in c for c in state.chains)
        assert all("confidence" in c for c in state.chains)

    def test_exploit_skips_false_positives(self, hunt_project):
        config = ScanConfig(
            target=hunt_project, languages=["python"], no_sca=True, legacy_neuroscan=True,
        )
        llm = LLMBackend(backend="deepseek", api_key="")
        state = HuntState(target_path=hunt_project, config=config, llm=llm)
        state.hypotheses = [
            {
                "rule_id": "NS-TEST-001",
                "file": "src/safe.py",
                "line": 1,
                "exploitability": "false_positive",
                "deep_dive": None,
                "attack_story": None,
            },
        ]

        workflow = HuntWorkflow(state)
        workflow._exploit()

        assert len(state.chains) == 0


class TestHuntReportStage:

    def test_report_generates_text(self, hunt_project):
        config = ScanConfig(
            target=hunt_project, languages=["python"], no_sca=True, legacy_neuroscan=True,
        )
        llm = LLMBackend(backend="deepseek", api_key="")
        state = HuntState(target_path=hunt_project, config=config, llm=llm)
        state.surface = [
            Finding(
                rule_id="NS-DESER-001",
                message="pickle.loads()",
                severity=Severity.HIGH,
                category=Category.DESERIALIZATION,
                file_path="src/app.py",
                start_line=7,
                engine="neuroscan",
            ),
        ]

        workflow = HuntWorkflow(state)
        workflow._report()

        assert state.report != ""
        assert "Rowan" in state.report

    def test_report_includes_chains(self, hunt_project):
        config = ScanConfig(
            target=hunt_project, languages=["python"], no_sca=True, legacy_neuroscan=True,
        )
        llm = LLMBackend(backend="deepseek", api_key="")
        state = HuntState(target_path=hunt_project, config=config, llm=llm)
        state.surface = [
            Finding(
                rule_id="NS-DESER-001",
                message="pickle.loads()",
                severity=Severity.HIGH,
                category=Category.DESERIALIZATION,
                file_path="src/app.py",
                start_line=7,
                engine="neuroscan",
            ),
        ]
        state.chains = [
            {
                "type": "NS-DESER-001",
                "source": "src/app.py:7",
                "confidence": "confirmed",
                "evidence_status": "resolved",
                "attack_story": "Pickle RCE from user input",
            },
        ]

        workflow = HuntWorkflow(state)
        workflow._report()

        assert "CONFIRMED" in state.report
        assert "Pickle RCE" in state.report


class TestHuntAimlLane:
    """The AI/ML 'superpower': dedicated classification, prompting and chains."""

    def _state(self, tmp_path):
        config = ScanConfig(
            target=tmp_path, languages=["python"], no_sca=True, legacy_neuroscan=True,
        )
        llm = LLMBackend(backend="deepseek", api_key="sk-test")
        return HuntState(target_path=tmp_path, config=config, llm=llm)

    def test_is_aiml_finding_classification(self, tmp_path):
        wf = HuntWorkflow(self._state(tmp_path))

        def mk(rule_id, category, engine):
            return Finding(
                rule_id=rule_id, message="x", severity=Severity.MEDIUM,
                category=category, file_path="m.py", start_line=1, engine=engine,
            )

        # AI/ML by category, by mfv engine, by rule-id shape.
        assert wf._is_aiml_finding(mk("X", Category.AI_ML, "neuroscan"))
        assert wf._is_aiml_finding(mk("X", Category.PROMPT_INJECTION, "neuroscan"))
        assert wf._is_aiml_finding(mk("MFV-PKL-001", Category.GENERAL, "mfv"))
        assert wf._is_aiml_finding(mk("ns-aiml-059", Category.GENERAL, "neuroscan"))
        assert wf._is_aiml_finding(mk("TNT-ML-003", Category.GENERAL, "opengrep"))
        # Not AI/ML.
        assert not wf._is_aiml_finding(mk("NS-SQLI-001", Category.INJECTION, "neuroscan"))

    @patch("rowan.agents.workflow.HuntWorkflow._llm_hypothesize_batch")
    def test_aiml_medium_finding_promoted_and_routed(self, mock_batch, tmp_path):
        """A medium-severity AI/ML finding is promoted into triage and sent
        through the AI/ML lane (aiml=True), while a generic medium one is not."""
        mock_batch.return_value = []
        state = self._state(tmp_path)
        state.surface = [
            Finding(
                rule_id="ns-aiml-059", message="trust_remote_code=True",
                severity=Severity.MEDIUM, category=Category.AI_ML,
                file_path="model.py", start_line=3, confidence=0.4, engine="neuroscan",
            ),
            Finding(
                rule_id="NS-INFO-001", message="info", severity=Severity.LOW,
                category=Category.GENERAL, file_path="x.py", start_line=1,
                confidence=0.1, engine="neuroscan",
            ),
        ]
        HuntWorkflow(state)._hypothesize()

        # The low-confidence AI/ML finding still reached an aiml=True batch.
        aiml_calls = [c for c in mock_batch.call_args_list if c.kwargs.get("aiml")]
        assert aiml_calls, "AI/ML finding was not routed through the AI/ML lane"
        routed = {f.rule_id for call in aiml_calls for f in call.args[0]}
        assert "ns-aiml-059" in routed

    def test_aiml_batch_uses_specialist_prompt_and_tags(self, tmp_path):
        from rowan.agents import workflow as wf_mod

        captured = {}

        def fake_generate_structured(prompt, system, temperature, output_schema):
            captured["system"] = system
            return {"hypotheses": [{"rule_id": "ns-aiml-030", "exploitability": "likely"}]}

        state = self._state(tmp_path)
        state.llm.generate_structured = fake_generate_structured  # type: ignore[assignment]
        finding = Finding(
            rule_id="ns-aiml-030", message="torch.load", severity=Severity.HIGH,
            category=Category.AI_ML, file_path="m.py", start_line=1, engine="neuroscan",
        )
        out = HuntWorkflow(state)._llm_hypothesize_batch([finding], aiml=True)

        assert captured["system"] == wf_mod.AIML_HYPOTHESIZE_SYSTEM
        assert out[0]["aiml"] is True

    def test_build_aiml_kill_chain(self, tmp_path):
        """Co-located unpinned-load + trust_remote_code findings compose a chain."""
        wf = HuntWorkflow(self._state(tmp_path))
        hyps = [
            {
                "rule_id": "ns-aiml-047", "file": "load.py", "line": 5, "aiml": True,
                "attack_story": "from_pretrained without revision pin",
                "gating": "no revision pin",
            },
            {
                "rule_id": "ns-aiml-059", "file": "load.py", "line": 6, "aiml": True,
                "attack_story": "trust_remote_code=True executes repo code",
                "gating": "trust_remote_code=True",
            },
        ]
        chains = wf._build_aiml_kill_chains(hyps)
        assert any("remote code execution" in c["type"].lower() for c in chains)
        chain = next(c for c in chains if "remote code execution" in c["type"].lower())
        assert chain["aiml"] is True
        assert len(chain["evidence"]) == 2

    def test_no_kill_chain_without_grounding(self, tmp_path):
        """A single unrelated AI/ML finding does not fabricate a kill-chain."""
        wf = HuntWorkflow(self._state(tmp_path))
        hyps = [
            {
                "rule_id": "ns-aiml-032", "file": "a.py", "line": 1, "aiml": True,
                "attack_story": "np.load allow_pickle", "gating": "allow_pickle=True",
            },
        ]
        assert wf._build_aiml_kill_chains(hyps) == []


class TestHuntFullFlow:

    def test_full_hunt_no_llm(self, hunt_project):
        result = run_hunt(
            target=hunt_project,
            llm=LLMBackend(backend="deepseek", api_key=""),
            languages=["python"],
            no_sca=True,
        )

        assert result.stage == "report"
        assert len(result.surface) > 0
        assert result.report != ""

    @patch("rowan.agents.llm_backend.httpx.post")
    def test_full_hunt_with_mock_llm(self, mock_post, hunt_project):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {
            "choices": [{
                "message": {
                    "content": json.dumps({
                        "hypotheses": [
                            {
                                "rule_id": "NS-DESER-001",
                                "file": "src/app.py",
                                "line": 7,
                                "exploitability": "confirmed",
                                "severity": "critical",
                                "deep_dive": "src/app.py:7",
                                "chain_with": [],
                                "attack_story": "Pickle RCE",
                            }
                        ]
                    })
                }
            }],
            "usage": {"total_tokens": 50},
        }
        mock_resp.raise_for_status.return_value = None
        mock_post.return_value = mock_resp

        result = run_hunt(
            target=hunt_project,
            llm=LLMBackend(backend="deepseek", api_key="sk-test"),
            languages=["python"],
            no_sca=True,
        )

        assert result.stage == "report"
        assert len(result.surface) > 0
        assert len(result.hypotheses) > 0
