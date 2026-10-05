"""Tests for the opt-in LLM discovery stage (ADR-0004, DISC-1 through DISC-5).

The load-bearing test in this file is
`TestProvenanceGate::test_fabricated_snippet_is_rejected`: the entire premise
of the stage is that a model claim survives only if the code it cites
provably exists on disk. If that gate regresses, the stage is emitting
hallucinations with a confidence score attached.

Covers:
- Flow is unchanged when the stage is not opted into
- Stage is skipped with no LLM backend
- Provenance gate: fabricated snippets, bad lines, escaped paths, stub snippets
- Line correction within tolerance (we report where the code IS, not where the
  model said it was)
- Dedupe against the rule corpus
- Verify pass keeps only "upheld"; "uncertain" is dropped, not downgraded
- Discovered findings are quarantined (engine tag, confidence cap)
- Scope is finding-density-bounded, never a repo walk
- hunt_to_json emits discovered findings and keeps them filterable
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from unittest.mock import MagicMock

from rowan.agents.workflow import (
    _DISCOVERY_MAX_FILES,
    HuntState,
    HuntWorkflow,
)
from rowan.config import ScanConfig
from rowan.core.confidence import LLM_DISCOVERY_CAP, PATTERN_ONLY_CAP
from rowan.core.findings import Category, Finding, ScanResult, Severity

# A small file with one genuinely dangerous line to cite.
SAMPLE_CODE = """\
import os
import subprocess


def handler(request):
    name = request.args.get("name")
    subprocess.run("echo " + name, shell=True)
    return "ok"


def safe_handler(request):
    return os.path.basename(request.args.get("f", ""))
"""
# subprocess.run(...) is on line 7.
SNIPPET_LINE = 7
REAL_SNIPPET = 'subprocess.run("echo " + name, shell=True)'


def _finding(file_path: str, line: int, rule_id: str = "NS-CMD-001", cwe: int = 78) -> Finding:
    return Finding(
        rule_id=rule_id,
        message="command injection",
        severity=Severity.HIGH,
        category=Category.COMMAND_INJECTION,
        file_path=file_path,
        start_line=line,
        cwe_ids=[cwe],
        engine="opengrep",
    )


def _make(
    tmp: Path,
    *,
    llm_configured: bool = True,
    enable_discovery: bool = True,
    no_verify: bool = False,
    surface: list[Finding] | None = None,
) -> tuple[HuntWorkflow, HuntState, MagicMock]:
    config = ScanConfig(target=tmp, no_verify=no_verify)
    llm = MagicMock()
    llm.is_configured = llm_configured
    llm._backend = "deepseek"
    state = HuntState(
        target_path=tmp,
        config=config,
        llm=llm,
        enable_discovery=enable_discovery,
    )
    state.surface = surface or []
    return HuntWorkflow(state), state, llm


def _write_sample(tmp: Path) -> Path:
    path = tmp / "app.py"
    path.write_text(SAMPLE_CODE, encoding="utf-8")
    return path


def _claim(**overrides) -> dict:
    claim = {
        "line": SNIPPET_LINE,
        "snippet": REAL_SNIPPET,
        "cwe": 78,
        "severity": "high",
        "title": "shell=True with request-controlled input",
        "reachability": "request.args flows into the shell string",
        "why_rules_missed_it": "the concatenation happens across two statements",
    }
    claim.update(overrides)
    return claim


# ── Opt-in gating ─────────────────────────────────────────────────


class TestGating:
    def test_flag_off_never_enters_stage(self):
        """With --discover absent the pipeline is what it was before ADR-0004."""
        with tempfile.TemporaryDirectory() as td:
            workflow, state, llm = _make(Path(td), enable_discovery=False)
            assert workflow._after_deepdive() == "exploit"
            assert state.discovered == []
            llm.generate_structured.assert_not_called()

    def test_flag_on_routes_through_discover(self):
        with tempfile.TemporaryDirectory() as td:
            workflow, _, _ = _make(Path(td), enable_discovery=True)
            # The routing table is gone (HN-17); deepdive's own helper routes.
            assert workflow._after_deepdive() == "discover"

    def test_skipped_without_llm(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            path = _write_sample(tmp)
            workflow, state, llm = _make(
                tmp, llm_configured=False, surface=[_finding(str(path), SNIPPET_LINE)]
            )
            assert workflow._discover() == "exploit"
            assert state.discovered == []
            llm.generate_structured.assert_not_called()

    def test_no_candidate_files_skips(self):
        with tempfile.TemporaryDirectory() as td:
            workflow, state, llm = _make(Path(td), surface=[])
            assert workflow._discover() == "exploit"
            assert state.discovered == []
            llm.generate_structured.assert_not_called()


# ── The provenance gate (DISC-3) ──────────────────────────────────


class TestProvenanceGate:
    def test_real_snippet_survives(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            path = _write_sample(tmp)
            workflow, state, _ = _make(tmp)
            out = workflow._validate_discovered(path, [_claim()])
            assert len(out) == 1
            assert out[0].start_line == SNIPPET_LINE
            assert state.discovery_stats["bad_snippet"] == 0

    def test_fabricated_snippet_is_rejected(self):
        """The whole point of the stage. A plausible-sounding line that is not
        in the file must never reach the report, however confident the model
        sounds about it."""
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            path = _write_sample(tmp)
            workflow, state, _ = _make(tmp)
            out = workflow._validate_discovered(
                path,
                [_claim(snippet='os.system("rm -rf " + user_input)  # never in the file')],
            )
            assert out == []
            assert state.discovery_stats["bad_snippet"] == 1
            assert state.discovery_stats["raw"] == 1

    def test_line_outside_file_is_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            path = _write_sample(tmp)
            workflow, state, _ = _make(tmp)
            out = workflow._validate_discovered(path, [_claim(line=9999)])
            assert out == []
            assert state.discovery_stats["bad_line"] == 1

    def test_stub_snippet_is_rejected(self):
        """A snippet short enough to occur anywhere proves nothing about
        whether the model read the code, so it cannot buy provenance."""
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            path = _write_sample(tmp)
            workflow, state, _ = _make(tmp)
            out = workflow._validate_discovered(path, [_claim(snippet="return")])
            assert out == []
            assert state.discovery_stats["bad_snippet"] == 1

    def test_off_by_one_line_is_corrected_not_trusted(self):
        """Within tolerance we keep the claim but report the line where the
        snippet actually is, so the emitted finding is true to the file."""
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            path = _write_sample(tmp)
            workflow, _, _ = _make(tmp)
            out = workflow._validate_discovered(path, [_claim(line=SNIPPET_LINE + 2)])
            assert len(out) == 1
            assert out[0].start_line == SNIPPET_LINE
            assert out[0].metadata["claimed_line"] == SNIPPET_LINE + 2

    def test_far_away_snippet_is_rejected(self):
        """A snippet found far from the claim is not evidence the model read
        the code, so it is dropped rather than searched for file-wide."""
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            path = tmp / "big.py"
            path.write_text(
                "\n".join(["x = 1"] * 60) + f"\n{REAL_SNIPPET}\n", encoding="utf-8"
            )
            workflow, state, _ = _make(tmp)
            out = workflow._validate_discovered(path, [_claim(line=2)])
            assert out == []
            assert state.discovery_stats["bad_snippet"] == 1

    def test_whitespace_difference_still_matches(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            path = _write_sample(tmp)
            workflow, _, _ = _make(tmp)
            noisy = "   subprocess.run( \"echo \" + name,  shell=True )   "
            out = workflow._validate_discovered(path, [_claim(snippet=noisy)])
            # Normalization handles indentation, not re-spacing inside the
            # expression; either outcome is acceptable, but a match must land
            # on the real line rather than somewhere else.
            assert all(f.start_line == SNIPPET_LINE for f in out)

    def test_unreadable_file_counts_every_claim_as_bad_path(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            workflow, state, _ = _make(tmp)
            out = workflow._validate_discovered(tmp / "missing.py", [_claim(), _claim()])
            assert out == []
            assert state.discovery_stats["bad_path"] == 2


# ── Dedupe against the rule corpus ────────────────────────────────


class TestDedupe:
    def test_same_line_already_reported_is_dropped(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            path = _write_sample(tmp)
            workflow, state, _ = _make(tmp, surface=[_finding(str(path), SNIPPET_LINE)])
            out = workflow._validate_discovered(path, [_claim()])
            assert out == []
            assert state.discovery_stats["duplicate"] == 1

    def test_different_line_survives(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            path = _write_sample(tmp)
            workflow, _, _ = _make(tmp, surface=[_finding(str(path), 1)])
            out = workflow._validate_discovered(path, [_claim()])
            assert len(out) == 1

    def test_different_file_does_not_dedupe(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            path = _write_sample(tmp)
            workflow, _, _ = _make(tmp, surface=[_finding(str(tmp / "other.py"), SNIPPET_LINE)])
            out = workflow._validate_discovered(path, [_claim()])
            assert len(out) == 1


# ── Quarantine (DISC-5) ───────────────────────────────────────────


class TestQuarantine:
    def test_discovered_findings_are_tagged_and_capped(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            path = _write_sample(tmp)
            workflow, _, _ = _make(tmp)
            f = workflow._validate_discovered(path, [_claim()])[0]
            assert f.engine == "llm-discovery"
            assert f.rule_id == "LLM-DISCOVERY-CWE-78"
            assert f.confidence == LLM_DISCOVERY_CAP
            assert f.category == Category.COMMAND_INJECTION
            assert f.cwe_ids == [78]

    def test_confidence_sits_below_the_weakest_rule_tier(self):
        """A pattern match at least encodes a reviewed hypothesis about what
        the pattern means; a discovered finding does not."""
        assert LLM_DISCOVERY_CAP < PATTERN_ONLY_CAP

    def test_unclassified_cwe_still_produces_a_finding(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            path = _write_sample(tmp)
            workflow, _, _ = _make(tmp)
            f = workflow._validate_discovered(path, [_claim(cwe=None)])[0]
            assert f.rule_id == "LLM-DISCOVERY-UNCLASSIFIED"
            assert f.category == Category.GENERAL


# ── Verify pass (DISC-4) ──────────────────────────────────────────


def _verdict_response(*verdicts: str) -> dict:
    return {
        "verdicts": [
            {"_claim_idx": i, "verdict": v, "reason": "because the code says so",
             "reachability_assessment": {"status": "reachable", "entrypoint": "app.py:5" if i == 0 else "app.py:11"},
             "evidence": {key: ("app.py:7 inspected source" if i == 0 else "app.py:12 inspected source") for key in (
                 "attacker_control", "path", "sink", "protection", "protection_failure", "impact")}}
            for i, v in enumerate(verdicts)
        ]
    }


class TestDiscoveryVerify:
    def _one(self, tmp: Path) -> Finding:
        path = _write_sample(tmp)
        workflow, _, _ = _make(tmp)
        return workflow._validate_discovered(path, [_claim()])[0]

    def test_upheld_survives(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            f = self._one(tmp)
            workflow, state, llm = _make(tmp)
            llm.generate_structured.return_value = _verdict_response("upheld")
            out = workflow.verify_discovered_findings([f])
            assert len(out) == 1
            assert out[0].metadata["llm_verdict"] == "upheld"
            assert state.discovery_stats["refuted"] == 0

    def test_refuted_is_dropped(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            f = self._one(tmp)
            workflow, state, llm = _make(tmp)
            llm.generate_structured.return_value = _verdict_response("refuted")
            assert workflow.verify_discovered_findings([f]) == []
            assert state.discovery_stats["refuted"] == 1

    def test_uncertain_is_dropped_not_downgraded(self):
        """Diverges from the general verify pass on purpose: a hypothesis has
        a rule behind it to fall back on, a discovered finding has nothing."""
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            f = self._one(tmp)
            workflow, state, llm = _make(tmp)
            llm.generate_structured.return_value = _verdict_response("uncertain")
            assert workflow.verify_discovered_findings([f]) == []
            assert state.discovery_stats["uncertain"] == 1

    def test_missing_verdict_is_dropped(self):
        """A batch that failed or returned short must not leak an unverified
        finding through as if it had been upheld."""
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            f = self._one(tmp)
            workflow, state, llm = _make(tmp)
            llm.generate_structured.return_value = {"verdicts": []}
            assert workflow.verify_discovered_findings([f]) == []
            assert state.discovery_stats["uncertain"] == 1

    def test_llm_exception_drops_rather_than_emits(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            f = self._one(tmp)
            workflow, state, llm = _make(tmp)
            llm.generate_structured.side_effect = RuntimeError("boom")
            assert workflow.verify_discovered_findings([f]) == []
            assert any("discovery_verify_batch" in e for e in state.errors)

    def test_no_verify_emits_nothing(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            f = self._one(tmp)
            workflow, _, llm = _make(tmp, no_verify=True)
            assert workflow.verify_discovered_findings([f]) == []
            llm.generate_structured.assert_not_called()

    def test_verdicts_match_the_right_claim(self):
        """Two claims in one file share a rule_id shape, so verdicts must be
        matched by _claim_idx, never by rule_id."""
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            path = _write_sample(tmp)
            workflow, _, _ = _make(tmp)
            findings = workflow._validate_discovered(
                path,
                [
                    _claim(),
                    _claim(
                        line=12,
                        snippet='return os.path.basename(request.args.get("f", ""))',
                        title="second claim",
                    ),
                ],
            )
            assert len(findings) == 2

            workflow2, _, llm = _make(tmp)
            llm.generate_structured.return_value = _verdict_response("refuted", "upheld")
            out = workflow2.verify_discovered_findings(findings)
            assert len(out) == 1
            assert out[0].message == "second claim"


# ── Scope (DISC-1) ────────────────────────────────────────────────


class TestScope:
    def test_scope_is_bounded_by_findings_not_repo(self):
        """A repo full of files with no findings yields no candidates. This is
        the constraint that keeps `estimate` predictive."""
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            for i in range(50):
                (tmp / f"mod{i}.py").write_text("x = 1\n", encoding="utf-8")
            workflow, _, _ = _make(tmp, surface=[])
            assert workflow._discovery_candidate_files() == {}

    def test_candidate_files_capped(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            surface = []
            for i in range(_DISCOVERY_MAX_FILES + 15):
                p = tmp / f"mod{i}.py"
                p.write_text(SAMPLE_CODE, encoding="utf-8")
                surface.append(_finding(str(p), SNIPPET_LINE))
            workflow, _, _ = _make(tmp, surface=surface)
            assert len(workflow._discovery_candidate_files()) == _DISCOVERY_MAX_FILES

    def test_anchors_carry_every_reported_finding_in_the_file(self):
        """The prompt's "do not repeat these" list is only as good as its
        completeness."""
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            path = _write_sample(tmp)
            surface = [
                _finding(str(path), SNIPPET_LINE),
                _finding(str(path), 12, rule_id="NS-PATH-001", cwe=22),
            ]
            workflow, _, _ = _make(tmp, surface=surface)
            candidates = workflow._discovery_candidate_files()
            assert len(candidates[path.resolve()]) == 2

    def test_payload_sends_whole_small_file(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            path = _write_sample(tmp)
            workflow, _, _ = _make(tmp)
            code, already = workflow._discovery_file_payload(
                path, [_finding(str(path), SNIPPET_LINE)]
            )
            assert "def safe_handler" in code  # the tail of the file, not a window
            assert "subprocess.run" in code
            assert "NS-CMD-001" in already

    def test_payload_windows_large_file(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            path = tmp / "big.py"
            body = ["# filler"] * 1000
            body[500] = REAL_SNIPPET
            path.write_text("\n".join(body), encoding="utf-8")
            workflow, _, _ = _make(tmp)
            code, _ = workflow._discovery_file_payload(path, [_finding(str(path), 501)])
            assert REAL_SNIPPET in code
            assert len(code.split("\n")) < 1000


# ── End-to-end through the stage node ─────────────────────────────


class TestDiscoverNode:
    """Exercises `_discover()` itself, not just its pieces -- the wiring
    between selection, the LLM call, the provenance gate and the verify pass
    is where an integration bug would hide."""

    def _state_with_file(self, tmp: Path):
        path = _write_sample(tmp)
        surface = [_finding(str(path), 1, rule_id="NS-IMPORT-001", cwe=0)]
        return path, _make(tmp, surface=surface)

    def test_full_pass_emits_verified_finding(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            _, (workflow, state, llm) = self._state_with_file(tmp)

            llm.generate_structured.side_effect = [
                {"findings": [_claim()]},          # the discovery call
                _verdict_response("upheld"),        # the verification call
            ]

            assert workflow._discover() == "exploit"
            assert len(state.discovered) == 1
            f = state.discovered[0]
            assert f.engine == "llm-discovery"
            assert f.start_line == SNIPPET_LINE
            assert f.metadata["llm_verdict"] == "upheld"
            assert state.discovery_stats["files_examined"] == 1
            assert state.discovery_stats["raw"] == 1
            assert state.discovery_stats["verified"] == 1

    def test_fabrication_never_reaches_verification(self):
        """A fabricated claim must be discarded by the gate, not merely
        refuted later -- otherwise the verify pass is doing the gate's job
        and a lucky 'upheld' would emit an invented finding."""
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            _, (workflow, state, llm) = self._state_with_file(tmp)

            llm.generate_structured.side_effect = [
                {"findings": [_claim(snippet="eval(totally_made_up_variable_name)")]},
            ]

            assert workflow._discover() == "exploit"
            assert state.discovered == []
            assert state.discovery_stats["bad_snippet"] == 1
            # One call only: the discovery call. No verification was needed.
            assert llm.generate_structured.call_count == 1

    def test_empty_model_response_is_normal(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            _, (workflow, state, llm) = self._state_with_file(tmp)
            llm.generate_structured.return_value = {"findings": []}

            assert workflow._discover() == "exploit"
            assert state.discovered == []
            assert state.errors == []

    def test_malformed_response_does_not_crash_the_run(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            _, (workflow, state, llm) = self._state_with_file(tmp)
            llm.generate_structured.return_value = {"raw": "sorry, I can't do that"}

            assert workflow._discover() == "exploit"
            assert state.discovered == []

    def test_llm_error_is_recorded_not_raised(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            _, (workflow, state, llm) = self._state_with_file(tmp)
            llm.generate_structured.return_value = {"error": "connection refused"}

            assert workflow._discover() == "exploit"
            assert state.discovered == []
            assert any("discover" in e for e in state.errors)

    def test_prompt_tells_the_model_what_not_to_repeat(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            path = _write_sample(tmp)
            surface = [_finding(str(path), SNIPPET_LINE, rule_id="NS-CMD-001")]
            workflow, _, llm = _make(tmp, surface=surface)
            llm.generate_structured.return_value = {"findings": []}

            workflow._discover()

            prompt = llm.generate_structured.call_args[0][0]
            assert "NS-CMD-001" in prompt
            assert f"line {SNIPPET_LINE}" in prompt
            assert "subprocess.run" in prompt  # the file itself was sent


# ── Reporting (DISC-5) ────────────────────────────────────────────


class TestReporting:
    def test_hunt_json_emits_discovered_and_keeps_them_filterable(self):
        from rowan.reporters import hunt_to_json

        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            path = _write_sample(tmp)
            workflow, state, _ = _make(tmp)
            state.recon_result = ScanResult(findings=[_finding(str(path), 1)])
            state.surface = list(state.recon_result.findings)
            state.discovered = workflow._validate_discovered(path, [_claim()])

            payload = json.loads(hunt_to_json(state))

            assert payload["summary"]["discovered"] == 1
            engines = [f["engine"] for f in payload["findings"]]
            assert "llm-discovery" in engines
            rule_only = [f for f in payload["findings"] if f["engine"] != "llm-discovery"]
            assert len(rule_only) == 1
            assert "discovery_stats" in payload["hunt"]

    def test_hunt_json_unchanged_when_nothing_discovered(self):
        from rowan.reporters import hunt_to_json

        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            _, state, _ = _make(tmp, enable_discovery=False)
            state.recon_result = ScanResult(findings=[_finding("a.py", 1)])
            payload = json.loads(hunt_to_json(state))
            assert payload["summary"]["discovered"] == 0
            assert len(payload["findings"]) == 1

    def test_text_summary_reports_attrition(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            path = _write_sample(tmp)
            workflow, state, _ = _make(tmp)
            state.discovered = workflow._validate_discovered(path, [_claim()])
            summary = workflow._text_summary()
            assert "Discovered (LLM, unrule'd)" in summary
            assert "shell=True with request-controlled input" in summary
