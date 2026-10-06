"""Pipeline coordinator: orchestrates scan passes."""

from __future__ import annotations

import ast
import hashlib
import json
import logging
import threading
import time
from collections import Counter
from collections.abc import Iterable
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import yaml

from rowan import __version__
from rowan.analysis.request_sources import is_http_route
from rowan.config import ScanConfig
from rowan.core.findings import Category, Finding, ScanResult
from rowan.core.rule_class import is_dangerous_rule, is_inventory_rule
from rowan.core.rules import NeuroScanRule, load_neuroscan_rules
from rowan.passes.base import ScanContext
from rowan.passes.sources import iter_python_sources
from rowan.reporters import write_report
from rowan.scan_plan import EXECUTION_STAGES, PlanRuntime, build_scan_plan, execution_stage

logger = logging.getLogger("rowan")

# Languages that are dataflow candidates: only these can appear in the
# capability manifest's patterns-only list. Config/prose formats (yaml, json,
# markdown, ai_instructions, dockerfile, terraform) have no dataflow to run.
_CODE_LANGUAGES: frozenset[str] = frozenset({
    "python", "javascript", "typescript", "java", "kotlin", "go",
    "csharp", "ruby", "php", "rust",
    # Templates carry a real vulnerability class (escaping turned off) and
    # are scanned for it, but by pattern rules only -- there is no template
    # dataflow engine, so a quiet .html result must say so (#268).
    "html",
})


def _dataflow_languages(taint_rules_dir: Path) -> set[str]:
    """Languages covered by at least one `mode: taint` rule in the rules dir."""
    langs: set[str] = set()
    for tf in sorted(taint_rules_dir.glob("*taint*.yaml")):
        try:
            data = yaml.safe_load(tf.read_text(encoding="utf-8")) or {}
        except (OSError, yaml.YAMLError):
            continue
        for rule in data.get("rules", []):
            if rule.get("mode") == "taint":
                langs.update(str(lang).lower() for lang in rule.get("languages", []))
    return langs


def _rule_set_digest(rule_dirs: list[Path], extra_file: Path | None) -> str:
    """Hash the rule files a scan used (names and bytes) so runs can be compared."""
    files: set[Path] = {extra_file} if extra_file else set()
    for rule_dir in rule_dirs:
        files.update(rule_dir.glob("*.yaml"))
        files.update(rule_dir.glob("converted/*.yaml"))
    digest = hashlib.sha256()
    for path in sorted(files):
        digest.update(path.parent.name.encode("utf-8") + b"/" + path.name.encode("utf-8") + b"\0")
        try:
            digest.update(path.read_bytes())
        except OSError:
            digest.update(b"<unreadable>")
    return digest.hexdigest()


class ScanPipeline:
    def __init__(self, config: ScanConfig):
        # ScanConfig validates at construction time; validate again here in
        # case a project-config loader or programmatic caller mutated the
        # dataclass afterward. This happens before rule loading or any pass.
        config.validate()
        self._config = config
        self._context = self._new_context()

    def _new_context(self) -> ScanContext:
        config = self._config
        return ScanContext(
            target_path=config.target.resolve(),
            config=config,
            result=ScanResult(metadata={"source_root": str(config.target.resolve())}),
            network_semaphore=threading.BoundedSemaphore(
                config.network_concurrency or config.concurrency
            ),
        )

    def run(self) -> ScanResult:
        start = time.perf_counter()
        # Per-run state: a second run() must not start from the first's
        # findings, inventory or metadata (PL-14).
        self._context = self._new_context()

        rules_dir = self._config.rules_dir or ScanConfig.default_rules_dir()

        # Load all NeuroScan rule files from the rules directory
        neuroscan_rules: list[NeuroScanRule] = []
        if self._config.neuroscan_rules:
            rule_files = [self._config.neuroscan_rules]
        else:
            rule_files = sorted(rules_dir.glob("*.yaml"))
        for rf in rule_files:
            neuroscan_rules.extend(load_neuroscan_rules(rf))
        logger.info("Loaded %d NeuroScan rules from %d files", len(neuroscan_rules), len(rule_files))
        self._context.neuroscan_rules = neuroscan_rules
        if self._config.legacy_neuroscan:
            logger.info("Regex engine: legacy (Python re)")
        else:
            logger.info("Regex engine: converted (Opengrep pattern-regex)")
            self._load_conversion_manifest(rules_dir)

        taint_dir = self._config.taint_rules_dir or rules_dir
        plan = build_scan_plan(self._config)
        passes = plan.instantiate(PlanRuntime(
            neuroscan_rules=neuroscan_rules,
            taint_rules_dir=taint_dir,
        ))

        pass_outcomes: list[dict[str, object]] = []
        analysis_counts: dict[str, int] = {}
        inapplicable_passes: list[dict[str, str]] = []

        # A pass may use the inventory and snapshot after discovery, but only
        # correlation/enrichment is allowed to inspect or mutate accumulated
        # findings.  Executing those phases separately makes the dependency
        # contract explicit while safely overlapping independent detectors.
        # Results are always merged in plan order, never completion order.
        stages = self._execution_stages(passes)
        discovery_name, discovery_steps = stages[0]
        self._run_stage(
            discovery_name,
            discovery_steps,
            pass_outcomes=pass_outcomes,
            analysis_counts=analysis_counts,
        )
        stages, inapplicable_passes = self._filter_inapplicable_stages(
            stages, start_after=0
        )
        for stage_name, steps in stages[1:]:
            self._run_stage(
                stage_name,
                steps,
                pass_outcomes=pass_outcomes,
                analysis_counts=analysis_counts,
            )

        self._context.result.metadata["pass_outcomes"] = pass_outcomes
        self._context.result.metadata["skipped_passes"] = [
            item.as_dict() for item in plan.disabled
        ]
        if inapplicable_passes:
            self._context.result.metadata["inapplicable_passes"] = inapplicable_passes
        incomplete = [
            {
                "name": str(item["name"]),
                "status": str(item["status"]),
            }
            for item in pass_outcomes
            if item.get("status") != "completed"
        ]
        self._context.result.metadata["coverage_summary"] = {
            "status": "partial" if incomplete else "complete",
            "selected_passes": len(plan.selected),
            "completed_passes": sum(
                item.get("status") == "completed" for item in pass_outcomes
            ),
            "not_applicable_passes": len(inapplicable_passes),
            "explicitly_disabled_passes": len(plan.disabled),
            "incomplete_passes": incomplete,
        }
        inventory = self._context.source_inventory
        language_counts: Counter[str] = Counter()
        if inventory is not None:
            for source in inventory.files:
                language_counts.update(source.languages)
        self._context.result.metadata["scope_summary"] = {
            "source_files": len(inventory.files) if inventory is not None else 0,
            "languages": dict(sorted(language_counts.items())),
        }
        snapshot_stats = self._context.source_snapshot.stats()
        self._context.result.metadata["source_snapshot"] = snapshot_stats
        read_failures = snapshot_stats["read_failures"]
        parse_failures = snapshot_stats["parse_failures"]
        if read_failures or parse_failures:
            reason = (
                "source coverage incomplete: "
                f"{read_failures} read failure(s), "
                f"{parse_failures} Python parse failure(s)"
            )
            if parse_failures:
                # Stay degraded (the file's AST passes did not run), but say
                # which files and how to skip a known-bad one (PL-09).
                root = self._context.target_path
                names = [
                    str(path.relative_to(root)) if path.is_relative_to(root) else str(path)
                    for path in self._context.source_snapshot.parse_failed_paths()
                ]
                shown = ", ".join(names[:5]) + (f" and {len(names) - 5} more" if len(names) > 5 else "")
                reason += f": {shown}. Skip a known-bad file with --exclude PATH"
            self._context.result.degraded_passes["source_snapshot"] = reason
        # Preserve the public scan-result policy shape while the plan exposes
        # the more explicit taint_dataflow/opengrep distinction.
        self._context.result.metadata["resolved_policy"] = {
            "report_view": plan.effective_policy["report_view"],
            "name": plan.effective_policy["name"],
            "contract": plan.effective_policy["contract"],
            "languages": plan.effective_policy["languages"],
            "sca": plan.effective_policy["sca"],
            "taint": plan.effective_policy["taint_dataflow"],
            "converted_regex": plan.effective_policy["converted_regex"],
            "cross_file": plan.effective_policy["cross_file"],
            "authz": plan.effective_policy["authz"],
            "multiagent": plan.effective_policy["multiagent"],
            "profile": plan.effective_policy["profile"],
        }

        self._context.result.duration_seconds = time.perf_counter() - start

        # Analysis-capability manifest: state which scanned languages got real
        # dataflow analysis and which only pattern rules, instead of letting a
        # coverage cliff (e.g. no Ruby taint support) report indistinguishably
        # from full analysis. Same falsifiability posture as MFV's coverage
        # skips: never let "not analysed" read as "clean".
        execution = self._context.result.metadata.get("opengrep_execution")
        if execution is None and plan.effective_policy["taint_dataflow"]:
            # Taint was planned but left no execution record: the pass crashed
            # or found no rules. That is a failure, not "not requested" (PL-06).
            execution = {
                "status": "failed",
                "mode": "taint",
                "reason": self._context.result.degraded_passes.get(
                    "taint", "taint pass produced no execution record"
                ),
            }
        elif execution is None:
            # Legacy --no-taint is an explicit request not to invoke
            # Opengrep. It is not an engine failure and must not read as one.
            execution = {"status": "not-requested", "mode": "none"}

        declared_dataflow_langs = _dataflow_languages(taint_dir)
        dataflow_langs: set[str] = set()
        incomplete_dataflow_langs: set[str] = set()
        if plan.effective_policy["taint_dataflow"]:
            if execution.get("target_count") == 0:
                # An authoritative empty scope is complete without exercising
                # any frontend; do not advertise languages as analyzed.
                pass
            elif execution["status"] == "ok":
                dataflow_langs = declared_dataflow_langs
            else:
                incomplete_dataflow_langs = declared_dataflow_langs
        seen = self._context.metadata.get("languages_seen", {})
        patterns_only = {
            lang: count for lang, count in sorted(seen.items())
            if lang in _CODE_LANGUAGES and lang not in dataflow_langs and count > 0
        }
        unsupported_seen = self._context.metadata.get("unsupported_languages_seen", {})
        unsupported = {
            lang: count for lang, count in sorted(unsupported_seen.items()) if count > 0
        }
        completed_passes = {
            str(item["name"])
            for item in pass_outcomes
            if item.get("status") == "completed"
        }
        cross_file_languages: set[str] = set()
        if "crossfile" in completed_passes and seen.get("python", 0) > 0:
            cross_file_languages.add("python")
        if "js_crossfile" in completed_passes:
            cross_file_languages.update(
                language
                for language in ("javascript", "typescript")
                if seen.get(language, 0) > 0
            )
        if "go_crossfile" in completed_passes and seen.get("go", 0) > 0:
            cross_file_languages.add("go")
        self._context.result.metadata["analysis_capability"] = {
            "dataflow_languages": sorted(dataflow_langs),
            "cross_file_languages": sorted(cross_file_languages),
            "incomplete_dataflow_languages": sorted(incomplete_dataflow_langs),
            "opengrep_status": execution["status"],
            "opengrep_mode": execution["mode"],
            "patterns_only_languages": patterns_only,
            "unsupported_languages": unsupported,
        }
        self._context.result.metadata["scan_manifest"] = {
            "rowan_version": __version__,
            "opengrep_version": execution.get("opengrep_version"),
            "rule_set_sha256": _rule_set_digest(
                [rules_dir, taint_dir], self._config.neuroscan_rules
            ),
        }

        # VEX/SBOM are supply-chain artifacts of the *complete* dependency
        # inventory, so emit them from the full result before the severity/
        # baseline/ignore filters below prune it -- otherwise a `--severity
        # high` run would silently drop VEX statements for filtered findings.
        sca_degraded = self._context.result.degraded_passes.get("sca")
        if self._config.vex_path and sca_degraded:
            # An empty VEX from a failed OSV lookup reads as "no known
            # vulnerabilities" once attached to a release (PL-04). Remove any
            # older file at this path so a stale one is not attached either.
            self._config.vex_path.unlink(missing_ok=True)
            message = f"VEX not written ({self._config.vex_path}): dependency scan degraded: {sca_degraded}"
            self._context.result.errors.append(message)
            logger.error(message)
        elif self._config.vex_path:
            from rowan.reporters import to_vex
            self._config.vex_path.write_text(
                json.dumps(to_vex(self._context.result), indent=2), encoding="utf-8"
            )
            logger.info("Wrote VEX document: %s", self._config.vex_path)
        if self._config.sbom_path:
            from rowan.reporters import to_cyclonedx
            self._config.sbom_path.write_text(
                json.dumps(to_cyclonedx(self._context.result), indent=2), encoding="utf-8"
            )
            logger.info("Wrote CycloneDX SBOM: %s", self._config.sbom_path)

        # The baseline is the full result, taken before the view and severity
        # filters: a baseline written from a filtered run made every hidden
        # finding look new to a later --audit or --severity run (PL-03).
        if self._config.write_baseline_path:
            from rowan import baseline
            count = baseline.write_baseline(
                self._context.result,
                self._config.write_baseline_path,
                self._config.target,
                view=self._config.report_view,
                severity=self._config.severity.value if self._config.severity else None,
            )
            logger.info("Wrote baseline (%d fingerprints): %s", count, self._config.write_baseline_path)

        # The library defaults to the full report; CLI defaults to actionable.
        # Confirmed requires finding-level evidence at every severity and can
        # hide real vulnerabilities supported only by pattern rules. Hidden
        # counts remain visible and the full/audit view retains those leads.
        filter_counts: dict[str, int] = {
            **analysis_counts,
            "pre_view": len(self._context.result.findings),
        }
        self._context.result.metadata["view"] = self._config.report_view
        if self._config.report_view in ("actionable", "confirmed"):
            predicate = (
                self._in_confirmed_view if self._config.report_view == "confirmed"
                else self._in_actionable_view
            )
            view_name = self._config.report_view
            # Single pass: partition into kept vs. a per-severity tally of the
            # hidden, so the predicate runs once per finding, not twice.
            kept: list[Finding] = []
            hidden_by_sev: Counter[str] = Counter()
            for f in self._context.result.findings:
                if predicate(f):
                    kept.append(f)
                else:
                    hidden_by_sev[f.severity.value] += 1
            hidden = sum(hidden_by_sev.values())
            if hidden:
                self._context.result.metadata["actionable_hidden"] = hidden
                self._context.result.metadata["actionable_hidden_by_severity"] = dict(hidden_by_sev)
                logger.info(
                    "%s view: %d shown, %d hidden (surface/informational); "
                    "--audit shows all",
                    view_name.capitalize(), len(kept), hidden,
                )
            self._context.result.findings = kept
        filter_counts["post_view"] = len(self._context.result.findings)

        if self._config.severity:
            self._context.result.findings = [
                f for f in self._context.result.findings
                if self._matches_severity(f, self._config.severity)
            ]
        filter_counts["post_severity"] = len(self._context.result.findings)

        self._context.result.findings.sort(
            key=lambda f: (f.severity_order, f.file_path, f.start_line, f.rule_id, f.message)
        )

        if self._config.baseline_path:
            from rowan import baseline
            known = baseline.load_baseline(self._config.baseline_path)
            suppressed = baseline.filter_new(self._context.result, known, self._config.target)
            self._context.result.metadata["baseline_suppressed"] = suppressed
            logger.info(
                "Baseline diff: %d new finding(s), %d suppressed",
                len(self._context.result.findings), suppressed,
            )
        filter_counts["post_baseline"] = len(self._context.result.findings)

        from rowan.ignore import apply_ignore, find_ignore_file, load_ignore_file
        _ignore_path = find_ignore_file(self._config.target)
        if _ignore_path and self._config.ci_mode:
            # In CI the suppression file comes from the repository under
            # review, so honouring it lets a pull request silence the gate
            # (PL-02). Record that it was seen and skipped.
            logger.info("CI mode: ignoring %s", _ignore_path)
            self._context.result.metadata["ignore_file_skipped"] = str(_ignore_path)
            _ignore_path = None
        if _ignore_path:
            from rowan import baseline as _bl
            _fps = {id(f): _bl.fingerprint(f, self._config.target)
                    for f in self._context.result.findings}
            _entries = load_ignore_file(_ignore_path)
            self._context.result.findings, _ignored = apply_ignore(
                self._context.result.findings, _entries, _fps, self._config.target
            )
            if _ignored:
                self._context.result.metadata["ignore_suppressed"] = _ignored
                logger.info("Ignore file suppressed %d finding(s)", _ignored)
        filter_counts["post_ignore"] = len(self._context.result.findings)
        self._context.result.metadata["filter_counts"] = filter_counts

        if self._config.output and self._config.output_format:
            write_report(
                self._context.result,
                self._config.output,
                self._config.output_format,
                str(self._config.target),
            )

        return self._context.result

    _PYTHON_PASSES = frozenset({
        "sibling_gate", "crossfile", "pii_egress", "training_disclosure",
        "model_extraction", "membership_inference", "dormant-code",
        "training-approval", "config-taint", "authz", "serialization-scope",
        "web-security", "agent-flow", "multiagent", "mcp-network-exposure",
        "mcp-sampling-approval", "mcp_tool_metadata", "mcp-stored-content",
        "ast_enrichment",
    })
    _JAVASCRIPT_PASSES = frozenset({"js_crossfile", "js_authz"})
    _GO_PASSES = frozenset({"go_crossfile"})
    _PROSE_PASSES = frozenset({"instruction_smuggling"})
    #: Passes that only report on HTTP route handlers (see is_http_route).
    _HTTP_ROUTE_PASSES = frozenset({"model_extraction", "membership_inference"})

    def _filter_inapplicable_stages(
        self,
        stages: list[tuple[str, list[object]]],
        *,
        start_after: int,
    ) -> tuple[list[tuple[str, list[object]]], list[dict[str, str]]]:
        """Remove proven-empty artifact/language passes after one discovery walk."""
        inventory = self._context.source_inventory
        if inventory is None:
            return stages, []
        languages = {
            language for source in inventory.files for language in source.languages
        }
        has_python = bool(inventory.paths_for("python", suffix=".py"))
        has_javascript = bool({"javascript", "typescript"} & languages)
        has_go = bool(inventory.paths_for("go", suffix=".go"))
        has_prose = bool({"ai_instructions", "markdown", "text"} & languages)
        skipped: list[dict[str, str]] = []
        route_found: list[bool] = []

        def has_http_route() -> bool:
            # Same files the route-only passes read; stops at the first route.
            if not route_found:
                route_found.append(any(
                    isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                    and is_http_route(node)
                    for _path, tree in iter_python_sources(
                        self._context, owner="route-precheck", skip_tests=False
                    )
                    for node in ast.walk(tree)
                ))
            return route_found[0]

        def reason_for(step: object) -> str | None:
            if step.name == "sca" and not inventory.dependency_manifests:
                return "no dependency manifests in resolved inventory"
            if step.name == "mfv" and not inventory.model_artifacts:
                return "no model artifacts in resolved inventory"
            if step.name == "mcpconfig" and not inventory.mcp_config_files:
                return "no MCP configuration files in resolved inventory"
            if step.name in self._PYTHON_PASSES and not has_python:
                return "no Python sources in resolved inventory"
            if step.name in self._HTTP_ROUTE_PASSES and not has_http_route():
                return "no HTTP route handlers in Python sources"
            if step.name in self._JAVASCRIPT_PASSES and not has_javascript:
                return "no JavaScript/TypeScript sources in resolved inventory"
            if step.name in self._GO_PASSES and not has_go:
                return "no Go sources in resolved inventory"
            if step.name in self._PROSE_PASSES and not has_prose:
                return "no instruction/prose files in resolved inventory"
            return None

        filtered: list[tuple[str, list[object]]] = []
        for index, (stage_name, steps) in enumerate(stages):
            if index <= start_after:
                filtered.append((stage_name, steps))
                continue
            selected: list[object] = []
            for step in steps:
                reason = reason_for(step)
                if reason is None:
                    selected.append(step)
                else:
                    skipped.append({"name": step.name, "status": "not_applicable", "reason": reason})
            filtered.append((stage_name, selected))
        return filtered, skipped

    def _execution_stages(self, passes: Iterable[object]) -> list[tuple[str, list[object]]]:
        """Partition the ordered plan into ``EXECUTION_STAGES`` (see
        ``scan_plan.execution_stage``), keeping plan order within a stage."""
        stages: dict[str, list[object]] = {name: [] for name in EXECUTION_STAGES}
        for step in passes:
            stages[execution_stage(step.name)].append(step)
        return list(stages.items())

    def _run_stage(
        self,
        stage_name: str,
        steps: list[object],
        *,
        pass_outcomes: list[dict[str, object]],
        analysis_counts: dict[str, int],
    ) -> None:
        """Run a stage and merge each completed result in deterministic order."""
        if not steps:
            return
        parallel = stage_name in {"detection", "correlation"} and len(steps) > 1
        worker_count = min(self._config.concurrency, len(steps)) if parallel else 1
        logger.info(
            "Running %s stage: %d pass(es), shared budget %d worker(s)",
            stage_name, len(steps), worker_count,
        )
        if parallel:
            with ThreadPoolExecutor(max_workers=worker_count, thread_name_prefix="rowan") as executor:
                futures = {step: executor.submit(self._run_pass_safely, step) for step in steps}
                completed = {step: futures[step].result() for step in steps}
        else:
            completed = {step: self._run_pass_safely(step) for step in steps}

        # This remains deliberately serial: ScanResult.merge updates shared
        # metadata, and several downstream passes require a stable complete
        # finding collection.  Using the declared plan order makes serial and
        # staged runs byte-for-byte comparable after normal sorting.
        for step in steps:
            result, duration = completed[step]
            findings_before = len(self._context.result.findings)
            if step.name == "ast_enrichment":
                analysis_counts["pre_ast_enrichment"] = findings_before
            elif step.name == "enrichment":
                analysis_counts["pre_enrichment"] = findings_before
            self._context.result.merge(result)
            if step.name == "ast_enrichment":
                analysis_counts["post_ast_enrichment"] = len(self._context.result.findings)
            elif step.name == "enrichment":
                analysis_counts["post_enrichment"] = len(self._context.result.findings)
            outcome: dict[str, object] = {
                "name": step.name,
                "stage": stage_name,
                "status": "degraded" if result.degraded else "completed",
                "duration_seconds": round(duration, 4),
                "files_scanned": result.files_scanned,
                "findings_delta": len(self._context.result.findings) - findings_before,
            }
            if result.degraded_passes:
                outcome["degraded_reasons"] = dict(result.degraded_passes)
            if result.errors:
                outcome["errors"] = list(result.errors)
            pass_outcomes.append(outcome)

    def _run_pass_safely(self, step: object) -> tuple[ScanResult, float]:
        """Contain a detector failure so unrelated stage work is retained."""
        logger.info("Running pass: %s", step.name)
        pass_start = time.perf_counter()
        try:
            return step.run(self._context), time.perf_counter() - pass_start
        except Exception as exc:  # pragma: no cover - exercised by integration callers
            logger.exception("Pass %s failed", step.name)
            return ScanResult(
                errors=[f"{step.name}: {exc}"],
                degraded_passes={step.name: f"pass failed: {exc}"},
            ), time.perf_counter() - pass_start

    def _matches_severity(self, finding, min_severity) -> bool:
        order = {v: i for i, v in enumerate(["critical", "high", "medium", "low", "info"])}
        return order.get(finding.severity.value, 5) <= order.get(min_severity.value, 5)

    #: Categories whose sink is inherently dangerous once present, so a MEDIUM
    #: finding here is worth acting on even from a bare pattern match (no
    #: proven taint flow) -- confirmed on the labeled vuln_cases corpus, where
    #: pickle RCE, eval/exec, os.system, SQLi, SSTI and zip-slip fixtures are
    #: detected pattern-only yet are all real. Gating these OUT (as an
    #: evidence-tier-only gate did) hid 16/26 known-vuln files.
    _DANGEROUS_VIEW_CATEGORIES = frozenset({
        Category.INJECTION, Category.DESERIALIZATION, Category.SSTI, Category.XSS,
        Category.COMMAND_INJECTION, Category.PATH_TRAVERSAL,
        Category.NOSQL_INJECTION, Category.PROTOTYPE_POLLUTION,
    })
    #: Self-evident-exposure categories (the matched text IS the whole finding)
    #: kept at MEDIUM: a hardcoded secret or a weak-crypto primitive is
    #: actionable on sight. Surface/inventory self-evident categories (ai_ml
    #: presence signals, config) are intentionally NOT here -- they are the
    #: medium-severity noise this view exists to hide.
    _KEEP_SELF_EVIDENT_CATEGORIES = frozenset({Category.SECRETS, Category.CRYPTO})
    #: Evidence tiers carrying a computed basis (a taint flow or an
    #: evidence-bearing engine). Set by EnrichmentPass._cap_unverified_severity.
    _COMPUTED_TIERS = frozenset({"taint-flow", "engine"})
    #: CWEs a reviewer does not need to act on now, so their findings are
    #: audit-only regardless of how they were detected. Log forging (CWE-117)
    #: is a real hygiene issue (log poisoning / ANSI injection) but not an
    #: exploitation primitive, and taint-confirmed it is the single largest
    #: source of low-value findings in the actionable view across repos.
    _AUDIT_ONLY_CWES = frozenset({117})

    def _in_actionable_view(self, finding: Finding) -> bool:
        """`--actionable`: keep dangerous-sink MEDIUM even pattern-only."""
        return self._in_view(finding, strict=False)

    def _in_confirmed_view(self, finding: Finding) -> bool:
        """`--confirmed`: dangerous-sink MEDIUM must be taint-confirmed."""
        return self._in_view(finding, strict=True)

    def _in_view(self, finding: Finding, *, strict: bool) -> bool:
        """Filter by urgency and, in confirmed view, finding-level evidence.

        Confirmed requires a computed or self-evident tier at every severity;
        HIGH/CRITICAL is not an evidence bypass. Actionable also keeps
        dangerous-category pattern matches for review. Both hide LOW/INFO.
        """
        # Low-urgency hygiene classes (log forging) are audit-only regardless of
        # severity or evidence: real, but not what a reviewer acts on now.
        if any(c in self._AUDIT_ONLY_CWES for c in (finding.cwe_ids or ())):
            return False
        rank = finding.severity_order  # 0 critical .. 4 info
        tier = (finding.metadata or {}).get("evidence_tier")
        if strict and (
            tier not in self._COMPUTED_TIERS | {"self-evident"}
            or (finding.metadata or {}).get("taint_unconfirmed")
        ):
            return False
        if finding.engine == "authz" and tier == "authorization-gap":
            return rank <= 2
        if rank <= 1:
            return True
        if rank >= 3:
            return False
        # MEDIUM. Computed evidence (an intra- or cross-file taint flow / an
        # evidence-bearing engine) is always kept, even for an inventory rule
        # -- that is a surface signal backed by a real dataflow.
        if tier in self._COMPUTED_TIERS:
            return True
        # A dependency CVE whose vulnerable function the code actually calls
        # is evidence of the same kind (PL-01); an unreachable or unknown one
        # stays audit-only at MEDIUM.
        if (finding.metadata or {}).get("reachability") == "reachable":
            return True
        # Pattern-only from here down.
        if is_inventory_rule(finding.rule_id):
            return False
        # Self-evident exposures kept in every view: a secret/crypto match, or a
        # rule whose match is itself a code-exec condition (trust_remote_code).
        if (
            finding.category in self._KEEP_SELF_EVIDENT_CATEGORIES
            or is_dangerous_rule(finding.rule_id)
        ):
            return True
        if strict:
            # --confirmed: an unconfirmed dangerous-sink MEDIUM is dropped.
            return False
        return finding.category in self._DANGEROUS_VIEW_CATEGORIES

    def _load_conversion_manifest(self, rules_dir: Path) -> None:
        """Load the converter manifest for metadata enrichment."""
        # The manifest of the rules actually in use, not the package default (PL-05).
        manifest_path = rules_dir / "converted" / "_manifest.json"
        try:
            data = json.loads(manifest_path.read_text(encoding="utf-8"))
            rule_map: dict[str, dict] = {}
            for rule in data.get("rules", []):
                rule_map[rule["id"]] = rule
            self._context.metadata["conversion_manifest"] = {
                "rule_map": rule_map,
                "meta": data.get("meta", {}),
            }
            logger.info("Loaded conversion manifest: %d rules", len(rule_map))
        except (OSError, ValueError, KeyError) as e:
            logger.warning("Could not load conversion manifest: %s", e)
