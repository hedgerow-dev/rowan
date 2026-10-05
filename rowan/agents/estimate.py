"""Free, zero-LLM-spend scope/cost preview for the hunt pipeline.

Runs exactly the static-scan (recon) stage `hunt` runs, then applies hunt's
own priority-filtering and batching logic (`HuntWorkflow._select_priority_findings`,
`_BATCH_SIZES`) to project how many LLM calls -- and roughly how many tokens --
a real `hunt` run against this target would make. Spends nothing: no network
call to any LLM backend is made.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from rowan.agents.hunt_inventory import HuntBudgets
from rowan.agents.llm_backend import LLMBackend
from rowan.agents.workflow import (
    _BATCH_SIZES,
    HuntState,
    HuntWorkflow,
    _verification_batch_size,
    resolve_hunt_scan_config,
)
from rowan.pipeline import ScanPipeline

# Rough chars-per-token ratio for English/code text -- a floor, not a tokenizer.
_CHARS_PER_TOKEN = 4

# hypothesize/verify system prompts run several hundred tokens each; counted
# once per batch (system prompt is sent with every call, not just the first).
_SYSTEM_PROMPT_TOKENS = 650

# Rough size of one hypothesis/verdict JSON object in the model's response.
_OUTPUT_TOKENS_PER_FINDING = 120

# _finding_with_context sends ~15 lines of code context on each side of the
# match, at a rough 80 chars/line -- this is what actually drives input cost,
# not the size of the repo itself (hunt never sends whole files).
_CONTEXT_CHARS_PER_FINDING = 15 * 2 * 80

# Historical rule of thumb from real hunt runs: roughly half to two-thirds of
# priority findings clear hypothesize as confirmed/likely and proceed to
# verify. Used as a rough projection, not a guarantee -- actual rate depends
# heavily on the target's false-positive density.
_VERIFY_SURVIVAL_RATE = 0.6

# Discovery (ADR-0004) is the one stage that sends whole files, so unlike
# every other stage its input cost is measured directly off disk rather than
# projected from a per-finding context window. One LLM call per candidate file.
#
# Claims per file that survive the provenance gate and reach the verify pass.
# A deliberately conservative placeholder: there is no run history to derive
# it from yet, and the estimate is a floor for scoping, not a bill. Revisit
# once DISC-6 has produced real numbers.
_DISCOVERY_CLAIMS_PER_FILE = 1.5
_DISCOVERY_OUTPUT_TOKENS_PER_CLAIM = 180  # richer JSON than a triage verdict


def _batch_count(n: int, batch_size: int) -> int:
    if n <= 0:
        return 0
    return (n + batch_size - 1) // batch_size


@dataclass
class HuntEstimate:
    target: Path
    files_scanned: int
    total_findings: int
    priority_findings: int
    aiml_findings: int
    generic_findings: int
    hypothesize_batches: int
    verify_candidates_estimate: int
    verify_batches_estimate: int
    input_tokens_estimate: int
    output_tokens_estimate: int
    scan_errors: list[str] = field(default_factory=list)
    # Discovery stage (ADR-0004); all zero unless discover=True.
    discover: bool = False
    discover_files: int = 0
    discover_calls: int = 0
    discover_skipped_surfaces: int = 0

    def render(self) -> str:
        lines = [
            f"scope estimate for {self.target}",
            f"  files scanned          : {self.files_scanned}",
            f"  static findings        : {self.total_findings}",
            f"  priority findings      : {self.priority_findings} "
            f"({self.aiml_findings} AI/ML, {self.generic_findings} generic)",
            f"  hypothesize batches    : {self.hypothesize_batches}",
            f"  verify candidates (est): {self.verify_candidates_estimate} "
            f"(assumes ~{int(_VERIFY_SURVIVAL_RATE * 100)}% of priority findings "
            "clear hypothesize as confirmed/likely)",
            f"  verify batches (est)   : {self.verify_batches_estimate}",
        ]
        if self.discover:
            lines += [
                f"  discover files         : {self.discover_files} "
                "(whole-file or bounded excerpts; same budgets as hunt)",
                f"  discover calls (est)   : {self.discover_calls} "
                "(one per file, plus verification of what it finds)",
            ]
        lines += [
            f"  ~input tokens          : {self.input_tokens_estimate:,} "
            "(rough: code context chars/4 + per-batch prompt overhead)",
            f"  ~output tokens         : {self.output_tokens_estimate:,} "
            f"(rough: ~{_OUTPUT_TOKENS_PER_FINDING} tokens per JSON hypothesis/verdict)",
            "  note: real usage depends on the backend's tokenizer, code context",
            "  density, and how many findings actually survive triage. This is a",
            "  floor for scoping, not a bill -- deepdive/report/webexploit calls",
            "  add more on top and aren't modeled here.",
        ]
        if self.discover:
            lines.append(f"  budget-skipped surfaces : {self.discover_skipped_surfaces}")
            lines.append(
                "  note: discover file count is a floor -- it omits this run's "
                "deep-dive\n  targets (they don't exist until hypothesize runs) "
                "(LLM-selected paths can change the schedule)."
            )
        if self.scan_errors:
            lines.append(f"  scan errors             : {len(self.scan_errors)} (see -v for detail)")
        return "\n".join(lines)


def estimate_hunt(
    target: Path,
    languages: list[str] | None = None,
    no_sca: bool = False,
    backend: str = "deepseek",
    discover: bool = False,
    project_config: bool = True,
    discovery_files: int = 25,
    discovery_lines: int = 400,
    verification_lines: int = 240,
    verification_files: int = 4,
) -> HuntEstimate:
    """Run hunt's recon stage only and project the LLM cost of a full run.

    This is the same static pipeline `hunt` itself runs first -- so the
    estimate reflects this exact target's real finding density, not a blind
    bytes-in-the-repo heuristic. No LLM backend is contacted.
    """
    # Mirrors the CLI `hunt` command's own config construction exactly (no_taint
    # is always False -- hunt's recon always runs taint analysis by design) so
    # the estimate reflects what a real `hunt` invocation will actually scan.
    config = resolve_hunt_scan_config(
        target,
        languages=languages,
        no_sca=no_sca,
        no_taint=False,
        project_config=project_config,
    )

    pipeline = ScanPipeline(config)
    result = pipeline.run()

    priority = HuntWorkflow._select_priority_findings(result.findings)
    aiml = [f for f in priority if HuntWorkflow._is_aiml_finding(f)]
    generic = [f for f in priority if not HuntWorkflow._is_aiml_finding(f)]

    batch_size = _BATCH_SIZES.get(backend, 10)
    hyp_batches = _batch_count(len(aiml), batch_size) + _batch_count(len(generic), batch_size)

    verify_estimate = round(len(priority) * _VERIFY_SURVIVAL_RATE)
    verify_batch_size = _verification_batch_size(backend)
    verify_batches = _batch_count(verify_estimate, verify_batch_size)

    input_tokens = (
        (len(priority) * _CONTEXT_CHARS_PER_FINDING // _CHARS_PER_TOKEN)
        + (hyp_batches + verify_batches) * _SYSTEM_PROMPT_TOKENS
    )
    output_tokens = (len(priority) + verify_estimate) * _OUTPUT_TOKENS_PER_FINDING

    state = HuntState(target_path=target.resolve(), config=config,
                      llm=LLMBackend(backend=backend), enable_discovery=discover,
                      budgets=HuntBudgets(discovery_files, discovery_lines, verification_lines, verification_files))
    state.surface = result.findings
    workflow = HuntWorkflow(state)
    # Measure retrieval with the same per-claim budgets rather than silently
    # pricing the old narrow source window. Survival remains an estimate.
    verification_chars = sum(len(json.dumps(workflow._verify_claim_context({
        "file": f.file_path, "line": f.start_line, "rule_id": f.rule_id,
    }))) for f in priority)
    input_tokens += round(verification_chars * _VERIFY_SURVIVAL_RATE) // _CHARS_PER_TOKEN
    discover_files = 0
    discover_calls = 0
    discover_skipped = 0
    if discover:
        state.http_sinks = workflow._extract_http_sinks(result)
        state.command_sinks = workflow._extract_command_sinks(result)
        state.lfi_sinks = workflow._extract_lfi_sinks(result)
        candidates = workflow._discovery_candidate_files()
        discover_files = len(candidates)
        discover_skipped = sum(r["reason"] == "file_budget" for r in state.inventory)
        discover_chars = 0
        for path, anchors in candidates.items():
            payload = workflow._discovery_file_payload(path, anchors)
            if payload:
                discover_chars += sum(len(x) for x in payload)

        discover_claims = round(discover_files * _DISCOVERY_CLAIMS_PER_FILE)
        discover_verify_batches = _batch_count(discover_claims, verify_batch_size)
        discover_calls = discover_files + discover_verify_batches

        input_tokens += (
            (discover_chars // _CHARS_PER_TOKEN)
            + (discover_files + discover_verify_batches) * _SYSTEM_PROMPT_TOKENS
        )
        output_tokens += discover_claims * _DISCOVERY_OUTPUT_TOKENS_PER_CLAIM * 2

    return HuntEstimate(
        target=target,
        files_scanned=result.files_scanned,
        total_findings=len(result.findings),
        priority_findings=len(priority),
        aiml_findings=len(aiml),
        generic_findings=len(generic),
        hypothesize_batches=hyp_batches,
        verify_candidates_estimate=verify_estimate,
        verify_batches_estimate=verify_batches,
        input_tokens_estimate=input_tokens,
        output_tokens_estimate=output_tokens,
        scan_errors=list(result.errors),
        discover=discover,
        discover_files=discover_files,
        discover_calls=discover_calls,
        discover_skipped_surfaces=discover_skipped,
    )
