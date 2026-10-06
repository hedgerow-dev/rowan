"""Taint analysis pass: uses Opengrep for dataflow-based vulnerability detection."""

from __future__ import annotations

import logging
import time
from pathlib import Path

from rowan.config import ScanConfig
from rowan.core.findings import ScanResult
from rowan.passes.base import ScanContext, scan_span
from rowan.taint import OpengrepAdapter

logger = logging.getLogger(__name__)


class TaintPass:
    name = "taint"

    def __init__(
        self,
        rules_dir: Path | None = None,
        legacy_neuroscan: bool = True,
        regex_only: bool = False,
    ):
        self._rules_dir = rules_dir or ScanConfig.default_rules_dir()
        self._legacy_neuroscan = legacy_neuroscan
        # regex_only=True: include converted regex rules but skip *_taint.yaml
        # files. Used when --no-taint is set in default (converted) mode so that
        # the regex rules still run even though dataflow analysis is skipped.
        self._regex_only = regex_only
        self._adapter = OpengrepAdapter()

    def run(self, context: ScanContext) -> ScanResult:
        start = time.perf_counter()
        result = ScanResult()

        inventory = context.source_inventory
        candidates = (
            tuple(source.path for source in inventory.files)
            if inventory is not None
            else None
        )
        if candidates == ():
            # Discovery has already established an authoritative empty scope.
            # Do not probe or configure an engine that cannot receive a batch.
            result.metadata["opengrep_execution"] = {
                "status": "ok",
                "mode": "regex-only" if self._regex_only else "taint",
                "target_count": 0,
                "reason": "no applicable source targets",
            }
            scan_span(self.name, time.perf_counter() - start)
            logger.info("TaintPass: no applicable source targets; engine not invoked")
            return result

        if not self._adapter.is_installed():
            mode = "converted regex rules" if self._regex_only else "taint and converted regex rules"
            message = f"Opengrep is unavailable; {mode} were not run"
            result.degraded_passes[self.name] = message  # one key per pass (TE-16)
            result.metadata["opengrep_execution"] = {
                "status": "unavailable",
                "mode": "regex-only" if self._regex_only else "taint",
            }
            logger.warning("TaintPass DEGRADED: %s", message)
            return result

        config = context.config
        languages = config.languages if config.languages else None

        if self._regex_only:
            # regex_only mode: converted rules only, no taint rules
            taint_rule_files = sorted((self._rules_dir / "converted").glob("*.yaml"))
            logger.info("TaintPass (regex-only): %d converted rule files", len(taint_rule_files))
        else:
            # `*_opengrep.yaml` holds hand-written Opengrep *search*-mode rules:
            # same engine, but they express a structural property rather than a
            # source-to-sink flow, so they are neither `mode: taint` nor named
            # `*_taint*.yaml` (which `tests/test_taint_rules.py` rightly requires
            # to be real taint rules). See rules/guardrail_opengrep.yaml, #186.
            taint_rule_files = sorted(
                set(self._rules_dir.glob("*_taint.yaml"))
                | set(self._rules_dir.glob("*_taint_*.yaml"))
                | set(self._rules_dir.glob("*_opengrep.yaml"))
            )
            if not self._legacy_neuroscan:
                converted_files = sorted((self._rules_dir / "converted").glob("*.yaml"))
                taint_rule_files = taint_rule_files + converted_files
                logger.info("TaintPass: including %d converted regex rule files", len(converted_files))
                if not converted_files and context.neuroscan_rules:
                    # Regex rules were loaded but none were converted for the
                    # default engine, so none of them will run (PL-05).
                    result.degraded_passes["converted-regex"] = (
                        f"no converted rules under {self._rules_dir / 'converted'}; run "
                        "scripts/convert_neuroscan_to_opengrep.py or use the legacy regex engine"
                    )
        if not taint_rule_files:
            logger.info("No taint rules found in %s. Skipping taint analysis.", self._rules_dir)
            return result

        logger.info("TaintPass: %d rule files, languages=%s", len(taint_rule_files), languages)

        if config.taint_timeout is not None:
            logger.info("TaintPass: using configured timeout %ds", config.taint_timeout)
        else:
            # The adapter computes this after applying the exact language and
            # inventory scope, when it knows every target's aggregate size.
            # Do not use the Python-only preflight count as a proxy: YAML,
            # JS, templates, and instruction files are valid Opengrep inputs.
            logger.info("TaintPass: using target-aware Opengrep timeout policy")

        self._adapter.configure(
            timeout=config.taint_timeout,
            workers=config.taint_workers,
            jobs=config.taint_jobs,
            cpu_budget=config.concurrency,
        )

        outcome = self._adapter.scan_collect_with_rules(
            context.target_path,
            taint_rule_files,
            languages=languages,
            workers=config.taint_workers,
            extra_configs=config.opengrep_configs,
            candidates=candidates,
        )

        findings = outcome.findings
        result.add_findings(findings)
        # What Opengrep actually scanned, across languages (TE-15).
        result.files_scanned = outcome.target_count
        result.metadata["opengrep_execution"] = {
            "status": outcome.status,
            "mode": "regex-only" if self._regex_only else "taint",
            "target_count": outcome.target_count,
            "target_bytes": outcome.target_bytes,
            "batches_total": outcome.batches_total,
            "workers": outcome.workers,
            "jobs_per_batch": outcome.jobs_per_batch,
            "timeout": outcome.timeout,
            "cpu_budget": config.concurrency,
            "opengrep_version": self._adapter.get_version(),
        }

        if outcome.status in ("timeout", "partial", "error"):
            # Only blame the timeout when every failed batch actually timed
            # out -- "raise --taint-timeout or --taint-workers" is actively
            # misleading advice for a batch that failed for some other
            # reason (e.g. a locale/encoding error reading the rule config),
            # since no timeout value will ever fix that. outcome.message
            # already carries the real cause opengrep reported in that case.
            if outcome.timeouts and outcome.timeouts == outcome.batches_failed:
                effective_timeout = outcome.timeout or config.taint_timeout
                timeout_label = f"{effective_timeout}s" if effective_timeout else "auto"
                message = (
                    f"opengrep timeout on {outcome.batches_failed}/{outcome.batches_total} "
                    f"batches (timeout={timeout_label}); taint results are incomplete: "
                    f"raise --taint-timeout or --taint-workers"
                )
            else:
                cause = outcome.message or "no further detail captured"
                message = (
                    f"opengrep {outcome.status} on {outcome.batches_failed}/{outcome.batches_total} "
                    f"batches; taint results are incomplete: {cause}"
                )
            result.degraded_passes["taint"] = message
            logger.warning("TaintPass DEGRADED: %s", message)

        duration = time.perf_counter() - start
        scan_span(self.name, duration)
        logger.info(
            "TaintPass: %d findings in %.1fs (status=%s)",
            len(findings),
            duration,
            outcome.status,
        )
        return result
