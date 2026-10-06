"""Opengrep subprocess adapter: bridges Rowan to the Opengrep taint engine."""

from __future__ import annotations

import json
import logging
import math
import os
import re
import shutil
import subprocess
import tempfile
import threading
from collections.abc import Iterable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, ClassVar

import yaml

from rowan.core.findings import (
    Category,
    Finding,
    Severity,
    TaintFlow,
    TaintNode,
)
from rowan.languages import (
    OPENGREP_LANGUAGE_EXACT_NAMES,
    OPENGREP_LANGUAGE_EXTENSIONS,
    OPENGREP_LANGUAGE_INCLUDE_GLOBS,
    normalize_languages,
)

logger = logging.getLogger(__name__)
_UNSET = object()

# Successful `--version` probes, shared by every adapter in the process and
# keyed by the binary's path, mtime and size so a replaced binary is probed
# again. Failures are not shared: an engine may be installed later.
_VERSION_PROBES: dict[tuple[str, int, int], str] = {}


def _probe_key(binary: str) -> tuple[str, int, int] | None:
    try:
        st = os.stat(binary)
    except OSError:
        return None
    return (binary, st.st_mtime_ns, st.st_size)


_SEVERITY_MAP: dict[str, Severity] = {
    "ERROR": Severity.HIGH,
    "WARNING": Severity.MEDIUM,
    "INFO": Severity.INFO,
}

_CONFIDENCE_MAP: dict[str, float] = {
    "HIGH": 0.95,
    "MEDIUM": 0.85,
    "LOW": 0.70,
}

_CATEGORY_PATTERNS: list[tuple[re.Pattern, Category]] = [
    (re.compile(r"deserial|pickle|dill|torch\.load|yaml\.load|unpickle", re.I), Category.DESERIALIZATION),
    (re.compile(r"ssrf|server.side.request.forgery|httpx\.get|requests\.get", re.I), Category.SSRF),
    (re.compile(r"ssti|server.side.template|jinja2|template\.render|from_string", re.I), Category.SSTI),
    (re.compile(r"xss|cross.site.script|v-html|dangerouslySetInnerHTML", re.I), Category.XSS),
    (re.compile(r"nosql.injection|nosql|mongo.*inject|\$COLLECTION", re.I), Category.NOSQL_INJECTION),
    (re.compile(r"sql.injection|sqli|execute\(.*sql|raw.*query", re.I), Category.INJECTION),
    (re.compile(r"command.injection|os\.system|subprocess|shell", re.I), Category.COMMAND_INJECTION),
    (re.compile(r"path.traversal|directory.traversal", re.I), Category.PATH_TRAVERSAL),
    (re.compile(r"secret|key|token|password|api.key|credential", re.I), Category.SECRETS),
    (re.compile(r"prompt.injection|llm.*inject|system.prompt", re.I), Category.PROMPT_INJECTION),
    (re.compile(r"supply.chain|dependency|package|import.*remote", re.I), Category.SUPPLY_CHAIN),
    (re.compile(r"crypto|md5|sha1|weak.*hash|broken.*algo", re.I), Category.CRYPTO),
    (re.compile(r"auth|permission|idor|bola|access.control", re.I), Category.AUTH),
    (re.compile(r"trust_remote_code|weights_only|apply_chat_template|langchain", re.I), Category.AI_ML),
]


def _clean_rule_id(raw: str | None, external_ids: Iterable[str] = ()) -> str:
    """Strip opengrep's config-path namespace from a raw rule/check id.

    opengrep namespaces every rule as ``<dotted.path.segments>.<RULE_ID>`` when
    run with ``--config <dir>``. The real rowan rule ids (e.g.
    ``TNT-LOG-001``) never contain dots, so taking the segment after the last
    ``.`` recovers the clean id. Already-clean ids (no ``.``) pass through.

    External ``--opengrep-config`` rules often do contain dots
    (``python.lang.security.sqli``), so an id from ``external_ids`` that the
    raw id ends with is kept whole; otherwise ``a.sqli`` and ``b.sqli`` would
    both become ``sqli`` and merge in dedup (TE-17).
    """
    if not raw:
        return "unknown"
    matches = [rule_id for rule_id in external_ids if raw == rule_id or raw.endswith("." + rule_id)]
    if matches:
        return max(matches, key=len)
    return raw.rsplit(".", 1)[-1]


def _config_rule_ids(configs: Iterable[str]) -> frozenset[str]:
    """Rule ids declared in local ``--opengrep-config`` files or directories.

    Registry names (``p/python``) are not local and contribute nothing.
    """
    ids: set[str] = set()
    for cfg in configs:
        path = Path(cfg)
        if path.is_file():
            files = [path]
        elif path.is_dir():
            files = [*path.rglob("*.yaml"), *path.rglob("*.yml")]
        else:
            continue
        for rule_file in files:
            try:
                data = yaml.safe_load(rule_file.read_text(encoding="utf-8"))
            except (OSError, UnicodeDecodeError, yaml.YAMLError):
                continue
            rules = data.get("rules") if isinstance(data, dict) else None
            for rule in rules if isinstance(rules, list) else []:
                if isinstance(rule, dict) and isinstance(rule.get("id"), str):
                    ids.add(rule["id"])
    return frozenset(ids)


def _infer_category(rule_id: str, message: str) -> Category:
    combined = f"{rule_id} {message}"
    for pattern, category in _CATEGORY_PATTERNS:
        if pattern.search(combined):
            return category
    return Category.GENERAL


def _parse_cwe_ids(extra: dict[str, Any]) -> list[int]:
    cwe_ids: list[int] = []
    if "cwe" in extra:
        cwe_val = extra["cwe"]
        if isinstance(cwe_val, list):
            for item in cwe_val:
                if isinstance(item, str):
                    m = re.search(r"(\d+)", item)
                    if m:
                        cwe_ids.append(int(m.group(1)))
                elif isinstance(item, int):
                    cwe_ids.append(item)
    return cwe_ids


def _resolve_category(rule_id: str, message: str, metadata: dict[str, Any]) -> Category:
    """A rule's own declared category wins when it's a valid Category value;
    otherwise fall back to inferring one from the rule id/message text."""
    declared = str(metadata.get("category", "")).lower()
    if declared:
        try:
            return Category(declared)
        except ValueError:
            pass
    return _infer_category(rule_id, message)


_CHILD_ENV_ALLOW = frozenset({
    "PATH", "HOME", "USER", "LOGNAME", "SHELL", "TERM", "TZ",
    "TMPDIR", "TEMP", "TMP",
    "USERPROFILE", "APPDATA", "LOCALAPPDATA", "SYSTEMROOT", "SYSTEMDRIVE",
    "COMSPEC", "PATHEXT", "WINDIR",
    "SSL_CERT_FILE", "SSL_CERT_DIR", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE",
    "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY",
})
_CHILD_ENV_PREFIXES = ("LC_", "XDG_", "OPENGREP_")


@dataclass
class ScanOutcome:
    """Result of a (possibly batched) opengrep scan, including health status."""

    findings: list[Finding] = field(default_factory=list)
    status: str = "ok"  # ok | timeout | partial | error | skipped
    batches_total: int = 0
    batches_failed: int = 0
    # Of batches_failed, how many failed specifically because the subprocess
    # hit the per-batch wall-clock timeout. Callers use this (rather than
    # just `status == "timeout"`) to decide whether "raise --taint-timeout"
    # is actually relevant advice -- `status` collapses to "partial" for any
    # mix of failure causes, which would otherwise hide a batch that failed
    # for a real, non-timeout reason (e.g. a config/encoding error) behind
    # timeout-flavored status.
    timeouts: int = 0
    message: str = ""
    # Effective values are emitted so JSON/SARIF scan telemetry can explain
    # an automatic decision without conflating it with an explicit override.
    target_count: int = 0
    target_bytes: int = 0
    workers: int = 1
    jobs_per_batch: int | None = None
    timeout: int | None = None


class OpengrepAdapter:
    """Wraps the Opengrep/Semgrep CLI for taint analysis."""

    BINARY_NAME = "opengrep"
    FALLBACK_BINARY = "semgrep"

    _SKIP_DIRS: frozenset[str] = frozenset({"node_modules", "site-packages", "dist", "build"})

    # Dotfiles are otherwise excluded wholesale by _discover_files (any
    # dot-prefixed path component is skipped, e.g. .git/, .venv/). These
    # recognized instruction/config files and GitHub workflow paths are the
    # intentional exceptions. Workflows are source input to the CI/CD rules;
    # allowing the whole .github tree would unnecessarily scan unrelated
    # GitHub metadata.
    _ALLOWED_DOTFILES: ClassVar[frozenset[str]] = frozenset({".cursorrules", ".env"})

    _LANG_EXTENSIONS: ClassVar[dict[str, tuple[str, ...]]] = OPENGREP_LANGUAGE_EXTENSIONS

    # Exact (case-insensitive) filenames, matched in addition to
    # _LANG_EXTENSIONS's suffix-style entries -- these have no distinguishing
    # extension of their own (CLAUDE.md/AGENTS.md share ".md" with ordinary
    # prose, so they must be matched by full name instead).
    _LANG_EXACT_NAMES: ClassVar[dict[str, tuple[str, ...]]] = OPENGREP_LANGUAGE_EXACT_NAMES

    # One or more --include globs per language. Opengrep's --include only
    # accepts one pattern per flag occurrence -- a single comma-joined value
    # (the old shape here) silently matches zero files. Verified empirically:
    # `--include "*.py,*.js"` scans nothing, while repeated `--include "*.py"
    # --include "*.js"` flags work. See _run_batch, which now emits one
    # --include per glob instead of joining this tuple with commas.
    _LANG_INCLUDE_GLOBS: ClassVar[dict[str, tuple[str, ...]]] = OPENGREP_LANGUAGE_INCLUDE_GLOBS
    _DEFAULT_BATCH_SIZE = 150
    _MAX_AUTO_WORKERS = 4
    _MAX_AUTO_CPU = 8
    _BYTES_PER_COMPLEXITY_UNIT = 512 * 1024

    def __init__(
        self,
        timeout: int | None = None,
        max_file_lines: int = 5000,
        workers: int | None = None,
        jobs: int | None = None,
        cpu_budget: int | None = None,
        extra_configs: list[str] | None = None,
    ):
        self._timeout = timeout
        self._max_file_lines = max_file_lines
        self._workers = max(1, workers) if workers is not None else None
        self._jobs = max(1, jobs) if jobs is not None else None
        self._cpu_budget = max(1, cpu_budget) if cpu_budget is not None else None
        self._extra_configs = list(extra_configs or [])
        self._binary: str | None = None
        self._version: str | None = None
        # ``None`` means the binary has not been probed yet.  Both successful
        # and failed probes are cached for the lifetime of this adapter: a
        # scan currently asks about availability at several layers, and each
        # uncached check otherwise pays for another ``opengrep --version``
        # subprocess (or repeats the same failed lookup).
        self._installed: bool | None = None
        self._availability_lock = threading.Lock()

    def configure(
        self,
        timeout: int | object | None = _UNSET,
        workers: int | object | None = _UNSET,
        jobs: int | object | None = _UNSET,
        cpu_budget: int | object | None = _UNSET,
    ) -> None:
        """Set effective controls; pass ``None`` to restore automatic policy.

        The sentinel keeps an omitted argument distinct from an explicit
        ``None``.  That matters when a reusable TaintPass first scans with an
        expert override and then scans again with the default policy.
        """
        if timeout is not _UNSET:
            self._timeout = timeout
        if workers is not _UNSET:
            self._workers = max(1, workers) if workers is not None else None
        if jobs is not _UNSET:
            self._jobs = max(1, jobs) if jobs is not None else None
        if cpu_budget is not _UNSET:
            self._cpu_budget = max(1, cpu_budget) if cpu_budget is not None else None

    @property
    def binary(self) -> str:
        if self._binary is None:
            self._binary = self._find_binary()
        return self._binary

    def _find_binary(self) -> str:
        import sys

        # Prefer the managed Opengrep installation (~/.opengrep/cli/latest/)
        ext = ".exe" if sys.platform == "win32" else ""
        managed = Path.home() / ".opengrep" / "cli" / "latest" / f"{self.BINARY_NAME}{ext}"
        if managed.exists():
            return str(managed)
        # `rowan install-engine`'s actual default destination
        # (install_opengrep.py defaults --prefix to ~/.local). Checked before
        # a bare PATH lookup so a scan always uses the binary that was just
        # installed and cosign-verified, not an unrelated `opengrep` that
        # happens to be earlier on PATH (issue #224).
        local_install = Path.home() / ".local" / "bin" / f"{self.BINARY_NAME}{ext}"
        if local_install.exists():
            return str(local_install)
        # Fall back to PATH lookup
        for name in (self.BINARY_NAME, self.FALLBACK_BINARY):
            path = shutil.which(name)
            if path:
                return path
        return self.BINARY_NAME

    def is_installed(self) -> bool:
        if self._installed is not None:
            return self._installed

        # An adapter may be shared by concurrent callers.  Re-check inside
        # the lock so even their first calls cannot launch duplicate probes.
        with self._availability_lock:
            if self._installed is not None:
                return self._installed
            key = _probe_key(self.binary)
            if key in _VERSION_PROBES:
                self._version = _VERSION_PROBES[key]
                self._installed = True
                return True
            try:
                # List-form args, no shell=True; self.binary is either a resolved
                # absolute path (managed install) or looked up via shutil.which,
                # never attacker-controlled.
                result = subprocess.run(  # noqa: S603
                    [self.binary, "--version"],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                if result.returncode == 0:
                    self._version = result.stdout.strip()
                    logger.info("Opengrep binary: %s (%s)", self.binary, self._version)
                    self._installed = True
                    if key is not None:
                        _VERSION_PROBES[key] = self._version
                else:
                    self._installed = False
            except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
                self._installed = False
        return self._installed

    def get_version(self) -> str:
        if self._version is None:
            self.is_installed()
        return self._version or "unknown"

    def refresh_availability(self) -> bool:
        """Discard the instance-local probe cache and check the engine again.

        Normal scans must use the cached result. This explicit escape hatch is
        for long-lived diagnostic/install flows that need to observe an engine
        installed or replaced after the adapter was created.
        """
        with self._availability_lock:
            self._installed = None
            self._version = None
            self._binary = None
            _VERSION_PROBES.clear()
        return self.is_installed()

    def scan(
        self,
        target: Path,
        rules_dir: Path,
        languages: list[str] | None = None,
        taint_intrafile: bool = True,
        candidates: Iterable[Path] | None = None,
    ) -> list[Finding]:
        return self.scan_collect(
            target,
            rules_dir,
            languages=languages,
            taint_intrafile=taint_intrafile,
            candidates=candidates,
        ).findings

    def scan_with_rules(
        self,
        target: Path,
        rule_files: list[Path],
        languages: list[str] | None = None,
        candidates: Iterable[Path] | None = None,
    ) -> list[Finding]:
        return self.scan_collect_with_rules(
            target,
            rule_files,
            languages=languages,
            candidates=candidates,
        ).findings

    def scan_collect_with_rules(
        self,
        target: Path,
        rule_files: list[Path],
        languages: list[str] | None = None,
        taint_intrafile: bool = True,
        workers: int | None = None,
        batch_size: int = _DEFAULT_BATCH_SIZE,
        extra_configs: list[str] | None = None,
        candidates: Iterable[Path] | None = None,
    ) -> ScanOutcome:
        """Copy rule files into a temp dir and run a batched, resilient scan."""
        languages = self._validate_languages(languages)
        if not self.is_installed():
            logger.warning("Opengrep not found. Taint analysis skipped.")
            return ScanOutcome(status="skipped", message="Opengrep not installed")

        with tempfile.TemporaryDirectory(prefix="rowan_rules_") as tmpdir:
            tmp = Path(tmpdir)
            for rf in rule_files:
                if rf.exists():
                    shutil.copy(rf, tmp / rf.name)
            return self.scan_collect(
                target,
                tmp,
                languages=languages,
                taint_intrafile=taint_intrafile,
                workers=workers,
                batch_size=batch_size,
                extra_configs=extra_configs,
                candidates=candidates,
            )

    def scan_collect(
        self,
        target: Path,
        rules_dir: Path,
        languages: list[str] | None = None,
        taint_intrafile: bool = True,
        workers: int | None = None,
        batch_size: int = _DEFAULT_BATCH_SIZE,
        extra_configs: list[str] | None = None,
        candidates: Iterable[Path] | None = None,
    ) -> ScanOutcome:
        """Run opengrep in resilient batches.

        Files are discovered and chunked into batches; each batch is scanned
        independently with the full per-batch timeout budget. A timeout or error
        in one batch never zeroes the findings from the batches that succeeded.
        """
        languages = self._validate_languages(languages)
        if not self.is_installed():
            logger.warning("Opengrep not found. Taint analysis skipped.")
            return ScanOutcome(status="skipped", message="Opengrep not installed")

        requested_workers = self._workers if workers is None else max(1, workers)
        configs = self._extra_configs if extra_configs is None else list(extra_configs)
        target = Path(target)

        files = self._discover_files(target, languages, candidates=candidates)
        if not files:
            # An explicit language selection or an authoritative inventory is
            # closed scope.  Never turn an empty result into a directory scan.
            if candidates is not None or languages:
                batches: list[list[Path]] = []
            else:
                batches = [[target]]
        else:
            workers = (
                requested_workers
                if requested_workers is not None
                else self._auto_workers(files, batch_size)
            )
            # An explicit jobs value is an expert control over each child
            # process, but automatic batch concurrency must still respect the
            # bounded CPU budget.  When both controls are explicit, preserve
            # them exactly -- that is the caller's intentional trade-off.
            if requested_workers is None and self._jobs is not None:
                workers = min(
                    workers,
                    max(1, self._bounded_cpu_count() // self._jobs),
                )
            batches = self._chunk_files(files, workers, batch_size)
        total = len(batches)

        target_count, target_bytes = self._target_metrics(files)
        effective_timeout = self._timeout or self._auto_timeout(target_count, target_bytes)

        # Cap opengrep's internal job count when we run batches concurrently.
        # Each opengrep process otherwise defaults to one core-worker per CPU, so
        # N parallel batches would spawn N * cpu workers and thrash the machine
        # (this made --taint-workers slower than sequential). Keep total core
        # workers ~= cpu count. When running sequentially, leave opengrep's default.
        # A no-target scan launches no worker and is reported as a normal
        # empty outcome.  This is important for a language-filtered inventory.
        concurrency = min((requested_workers or 1), total) if not files else min(workers, total)
        jobs_per_batch: int | None = self._jobs
        if jobs_per_batch is None and concurrency > 1:
            cpu = self._bounded_cpu_count()
            jobs_per_batch = max(1, cpu // concurrency)

        external_ids = _config_rule_ids(configs)

        def run_one(batch: list[Path]) -> tuple[list[Finding], str, str]:
            return self._run_batch(
                batch, rules_dir, languages, taint_intrafile, configs, jobs_per_batch,
                timeout=effective_timeout, external_ids=external_ids,
            )

        if concurrency > 1:
            with ThreadPoolExecutor(max_workers=concurrency) as executor:
                batch_results = list(executor.map(run_one, batches))
        else:
            batch_results = [run_one(b) for b in batches]

        all_findings: list[Finding] = []
        failed = 0
        timeouts = 0
        # The actual cause(s) reported by failed batches (e.g. the stderr
        # snippet from a config-read UnicodeDecodeError), deduplicated so a
        # batch of 40 files that all fail identically doesn't repeat the
        # same line 40 times.
        failure_causes: list[str] = []
        for findings, status, detail in batch_results:
            # A "partial" batch still counts as failed, but the findings
            # Opengrep did report are kept.
            all_findings.extend(findings)
            if status != "ok":
                failed += 1
                if status == "timeout":
                    timeouts += 1
                if detail and detail not in failure_causes:
                    failure_causes.append(detail)

        if failed == 0:
            status = "ok"
            message = ""
        elif failed >= total:
            status = "timeout" if timeouts == failed else "error"
            message = f"all {total} opengrep batch(es) failed"
        else:
            status = "partial"
            message = f"{failed}/{total} opengrep batch(es) failed"

        if timeouts:
            message = (message + f" ({timeouts} timed out)").lstrip()

        # Surface the real cause for any non-timeout failure so callers
        # don't have to guess (or, worse, wrongly assume every failure is a
        # timeout). failure_causes never contains an entry for a pure
        # timeout (see _run_batch), so this is exactly the non-timeout
        # causes. Capped at 3 distinct causes to keep the message bounded
        # when many batches fail for many different reasons.
        if failure_causes:
            message = f"{message} -- {'; '.join(failure_causes[:3])}"

        return ScanOutcome(
            findings=all_findings,
            status=status,
            batches_total=total,
            batches_failed=failed,
            timeouts=timeouts,
            message=message,
            target_count=target_count,
            target_bytes=target_bytes,
            workers=concurrency,
            jobs_per_batch=jobs_per_batch,
            timeout=effective_timeout,
        )

    def _bounded_cpu_count(self) -> int:
        """Return the CPU budget available to automatic Opengrep batching.

        The cap intentionally leaves room for the pipeline and host.  It also
        makes automatic behavior stable on very large CI executors instead of
        spawning one process per advertised vCPU.
        """
        host_limit = min(max(1, os.cpu_count() or 1), self._MAX_AUTO_CPU)
        return min(host_limit, self._cpu_budget) if self._cpu_budget else host_limit

    def _auto_workers(self, files: list[Path], batch_size: int) -> int:
        """Choose bounded parallelism from the exact selected targets.

        Small scopes stay single-process to avoid startup cost.  Larger scopes
        gain at most four batches, and only when there is enough work to keep
        each batch meaningful.  Explicit ``--taint-workers`` never reaches
        this policy.
        """
        target_count, target_bytes = self._target_metrics(files)
        if target_count <= batch_size and target_bytes <= 4 * 1024 * 1024:
            return 1
        count_batches = math.ceil(target_count / max(1, batch_size))
        size_batches = math.ceil(target_bytes / (4 * 1024 * 1024))
        useful_batches = max(1, count_batches, size_batches)
        return min(self._MAX_AUTO_WORKERS, self._bounded_cpu_count(), useful_batches)

    @classmethod
    def _target_metrics(cls, files: Iterable[Path]) -> tuple[int, int]:
        count = 0
        total_bytes = 0
        for path in files:
            count += 1
            try:
                total_bytes += max(0, path.stat().st_size)
            except OSError:
                # The batch runner remains the authority for a target that
                # disappeared after discovery; don't fail planning for it.
                continue
        return count, total_bytes

    @classmethod
    def _auto_timeout(cls, target_count: int, target_bytes: int) -> int:
        """Target-aware subprocess timeout with a conservative legacy floor."""
        complexity = max(
            target_count,
            math.ceil(target_bytes / cls._BYTES_PER_COMPLEXITY_UNIT),
        )
        if complexity <= 500:
            return 600
        if complexity <= 1500:
            return 900
        if complexity <= 3000:
            return 1200
        return 1800

    def _build_batches(
        self,
        target: Path,
        languages: list[str] | None,
        workers: int,
        batch_size: int,
        *,
        candidates: Iterable[Path] | None = None,
    ) -> list[list[Path]]:
        languages = self._validate_languages(languages)
        if candidates is None and target.is_file():
            return [[target]]

        files = self._discover_files(target, languages, candidates=candidates)
        if not files:
            # An explicit language selection defines a closed file scope.  An
            # empty match must stay empty; handing the directory to Opengrep
            # here would let its own discovery escape that scope.
            if candidates is not None or languages:
                return []
            # Fall back to scanning the whole directory as a single target so
            # opengrep still applies its own file discovery for edge cases.
            return [[target]]

        return self._chunk_files(files, workers, batch_size)

    @classmethod
    def _validate_languages(cls, languages: list[str] | None) -> list[str]:
        """Reject an explicit language scope that the adapter cannot honor.

        Silently ignoring an unknown name can produce an empty extension set;
        the directory fallback in ``_build_batches`` then broadens a typo such
        as ``pythn`` into an unrestricted repository scan.  Reject the entire
        request, including mixed known/unknown lists, so callers never receive
        results outside the scope they asked for.
        """
        return normalize_languages(languages)

    def _discover_files(
        self,
        target: Path,
        languages: list[str] | None,
        *,
        candidates: Iterable[Path] | None = None,
    ) -> list[Path]:
        if languages:
            exts: set[str] = set()
            exact_names: set[str] = set()
            for lang in languages:
                exts.update(self._LANG_EXTENSIONS.get(lang.lower(), ()))
                exact_names.update(self._LANG_EXACT_NAMES.get(lang.lower(), ()))
        else:
            exts = {ext for group in self._LANG_EXTENSIONS.values() for ext in group}
            exact_names = {name for group in self._LANG_EXACT_NAMES.values() for name in group}

        if not exts and not exact_names:
            return []

        files: list[Path] = []
        source_paths = target.rglob("*") if candidates is None else candidates
        for path in source_paths:
            if not path.is_file():
                continue
            # Opengrep will not follow a symlink handed to it as an explicit
            # target: it reports "File not found" and exits 2, and because that
            # status is per-batch it zeroes every finding from the other files
            # in the batch. One symlinked payload in a fixture directory was
            # enough to turn an 80-finding scan into a silent 0. The link's
            # target is walked on its own merits anyway, so skipping the link
            # loses no coverage and avoids double-reporting the same content.
            if path.is_symlink():
                continue
            try:
                relative_parts = path.relative_to(target).parts
            except ValueError:
                # A path outside the target can only arise from a future
                # discovery implementation; do not treat it as in-scope.
                continue
            hidden_parts = [
                part for part in relative_parts
                if part.startswith(".") and part not in self._ALLOWED_DOTFILES
            ]
            is_workflow = relative_parts[:2] == (".github", "workflows")
            if hidden_parts and not (is_workflow and hidden_parts == [".github"]):
                continue
            if any(skip in relative_parts for skip in self._SKIP_DIRS):
                continue
            name_lower = path.name.lower()
            # endswith, not suffix: Path.suffix only ever captures the last
            # dot segment, so it can't match multi-part extensions like
            # ".prompt.md" or dot-only names like ".cursorrules" (whose
            # .suffix is "").
            if name_lower in exact_names or any(name_lower.endswith(e) for e in exts):
                files.append(path)
        return files

    @staticmethod
    def _describe_json_errors(stdout: str, limit: int = 3) -> str:
        """Summarise opengrep's own `errors` array for the log line."""
        try:
            errors = json.loads(stdout).get("errors") or []
        except (json.JSONDecodeError, AttributeError):
            return ""
        if not errors:
            return ""
        shown = []
        for err in errors[:limit]:
            msg = str(err.get("message") or err.get("type") or "unknown").strip()
            shown.append(msg[:200])
        suffix = f" (+{len(errors) - limit} more)" if len(errors) > limit else ""
        return f"opengrep reported {len(errors)} error(s): " + "; ".join(shown) + suffix

    @staticmethod
    def _chunk_files(files: list[Path], workers: int, batch_size: int) -> list[list[Path]]:
        n = len(files)
        if n == 0:
            return []
        batch_size = max(1, batch_size)
        by_size = math.ceil(n / batch_size)
        num_batches = min(max(by_size, workers), n)
        chunk_len = math.ceil(n / num_batches)
        return [files[i : i + chunk_len] for i in range(0, n, chunk_len)]

    def _run_batch(
        self,
        batch: list[Path],
        rules_dir: Path,
        languages: list[str] | None,
        taint_intrafile: bool,
        extra_configs: list[str],
        jobs: int | None = None,
        *,
        timeout: int | None = None,
        external_ids: frozenset[str] = frozenset(),
    ) -> tuple[list[Finding], str, str]:
        args = [
            self.binary,
            "scan",
            "--config",
            str(rules_dir),
        ]
        for cfg in extra_configs:
            args.extend(["--config", cfg])

        args.extend([
            # Opengrep's own --json output (not --sarif) carries each rule's
            # full metadata: block (category/cwe/fix/confidence/etc.) inline
            # per result -- SARIF 1.22.0 does not propagate arbitrary
            # metadata: into its `properties` at all (confirmed empirically;
            # see GitHub issue #118), which is why category/severity/cwe/fix
            # used to need a separate conversion-manifest side-channel just
            # to recover what the rule already declared. --sarif is kept
            # only for the external `-f sarif` reporter (built independently
            # from our own Finding objects in reporters.py::to_sarif, not
            # from Opengrep's own SARIF output).
            "--json",
            # Without this flag Opengrep's output omits the dataflow trace
            # entirely, so _extract_taint_flow() always returns None -- every
            # taint-mode finding loses its source/sink/intermediate path.
            # That silently breaks _apply_source_confidence and the
            # taint-hop confidence boost in EnrichmentPass (both gated on
            # `finding.taint_flow is not None`), and empties the `Taint:`
            # line in every report format.
            "--dataflow-traces",
            "--no-git-ignore",
            "--max-target-bytes",
            str(self._max_file_lines * 200),
            # Opengrep's own defaults are a 5s-per-rule-per-file wall-clock
            # timeout, and silently skipping a file entirely once 3 rules
            # have timed out on it (--timeout-threshold). Both are disabled
            # here (0 = unlimited) -- they're wall-clock-based, so under
            # system load the same rule/file pair can silently produce
            # fewer findings on one run than another with no code change
            # in between, which is exactly the kind of scan-to-scan
            # non-reproducibility a security tool must not have. The
            # per-batch subprocess timeout below (self._timeout, adaptively
            # scaled to 600-1800s by TaintPass) is already a far more
            # generous safety net against a genuinely pathological rule.
            "--timeout",
            "0",
            "--timeout-threshold",
            "0",
        ])

        if jobs is not None:
            args.extend(["--jobs", str(jobs)])

        if taint_intrafile:
            args.append("--taint-intrafile")

        if languages:
            globs = [
                glob
                for lang in languages
                for glob in self._LANG_INCLUDE_GLOBS.get(lang.lower(), ())
            ]
            # One --include flag per glob -- opengrep (like semgrep) treats
            # a comma-joined value as a single literal pattern that matches
            # nothing, it does not split on commas.
            for glob in globs:
                args.append("--include")
                args.append(glob)

        # "--" stops opengrep from interpreting a target path that happens to
        # start with "-" as a flag. Batch paths are expected to be absolute
        # (from an already-resolved target), but this is cheap defense in
        # depth against any future caller that passes a relative one.
        args.append("--")
        args.extend(str(p) for p in batch)

        logger.info("Running Opengrep batch (%d targets): %s", len(batch), " ".join(args[:8]))

        # Opengrep's bundled Python reads rule config files (this run's
        # temp-dir copy of our own rule YAML) via Path.read_text() with no
        # explicit encoding, so it decodes using the process locale's
        # codeset. Under a C/POSIX locale -- the default in many slim
        # container images and some CI runners when LANG is unset -- that
        # codeset is ASCII, and any non-ASCII byte in a rule file's
        # comments/messages (this repo's own rule corpus has plenty, e.g.
        # typographic dashes) makes opengrep raise UnicodeDecodeError while
        # reading its own config, *before scanning anything*, silently
        # zeroing every taint finding.
        #
        # Verified empirically against this exact binary (not assumed):
        #   - PYTHONUTF8=1 alone: does NOT fix it -- config read still
        #     raises UnicodeDecodeError. Opengrep's bundled interpreter
        #     does not honor UTF-8 mode for this path the way a stock
        #     CPython build does.
        #   - PYTHONIOENCODING=utf-8 alone: does NOT fix it either -- it
        #     only affects stdio text encoding, not Path.read_text()'s
        #     locale-derived default.
        #   - LC_ALL=C.UTF-8: fixes it. "C.UTF-8" (rather than e.g.
        #     en_US.UTF-8) is deliberate -- it keeps every other locale
        #     category (collation, numeric/date formatting) at the same
        #     "C"/POSIX behavior opengrep already runs under, changing only
        #     the character-decoding codeset that was actually broken.
        #
        # Only an allowlisted slice of the parent environment is passed on
        # (PATH, HOME, temp dirs, TLS and proxy settings, ...) so API keys and
        # tokens in the scanner's environment never reach the child process.
        child_env = {
            k: v
            for k, v in os.environ.items()
            if k.upper() in _CHILD_ENV_ALLOW or k.upper().startswith(_CHILD_ENV_PREFIXES)
        }
        child_env["LC_ALL"] = "C.UTF-8"
        child_env["LANG"] = "C.UTF-8"

        try:
            # List-form args (built above, always self.binary + fixed flags +
            # resolved target paths after "--"), no shell=True.
            result = subprocess.run(  # noqa: S603
                args,
                capture_output=True,
                text=True,
                timeout=timeout or self._auto_timeout(*self._target_metrics(batch)),
                encoding="utf-8",
                errors="replace",
                env=child_env,
            )
        except subprocess.TimeoutExpired:
            logger.error(
                "Opengrep batch timed out after %ds (%d targets)",
                timeout or self._auto_timeout(*self._target_metrics(batch)),
                len(batch),
            )
            # No detail string here (left "") -- the timeout itself *is*
            # the cause, already conveyed via status="timeout"; callers
            # append "(N timed out)" rather than repeating this per batch.
            return [], "timeout", ""
        except OSError as e:
            logger.error("Failed to run Opengrep batch: %s", e)
            return [], "error", str(e)
        except Exception as e:  # never let one batch crash the whole scan
            logger.error("Unexpected Opengrep batch error: %s", e)
            return [], "error", str(e)

        if result.returncode not in (0, 1):
            if result.returncode == 2 and result.stdout.strip():
                # On a code-2 partial, opengrep reports *why* in the JSON
                # `errors` array and leaves stderr empty, so logging stderr
                # alone says "something failed" and nothing more. Surface the
                # actual messages -- that is the difference between a
                # diagnosable failure and a silent zero.
                logger.warning(
                    "Opengrep batch exited with code 2 (partial); parsing findings anyway. %s",
                    self._describe_json_errors(result.stdout) or f"stderr: {result.stderr[:200]}",
                )
                return self._parse_json_output(result.stdout, external_ids), "partial", ""
            detail = result.stderr.strip() or f"opengrep exited with code {result.returncode}"
            logger.warning("Opengrep batch exited with code %d: %s", result.returncode, result.stderr[:500])
            return [], "error", detail[:300]

        return self._parse_json_output(result.stdout, external_ids), "ok", ""

    def _parse_json_output(
        self, json_text: str, external_ids: frozenset[str] = frozenset()
    ) -> list[Finding]:
        """Parse Opengrep's native `--json` output.

        Unlike SARIF, `--json` carries each rule's full `metadata:` block
        (category/cwe/fix/confidence/original_severity/etc.) inline under
        `extra.metadata` on every single result -- no separate rules index
        or manifest lookup needed to recover what the rule already
        declared (see GitHub issue #118).
        """
        try:
            data = json.loads(json_text)
        except json.JSONDecodeError as e:
            logger.warning("Failed to parse Opengrep JSON output: %s", e)
            return []
        if not isinstance(data, dict):
            logger.warning("Opengrep JSON output is not an object; ignoring it")
            return []

        findings: list[Finding] = []
        for result in data.get("results", []):
            # One malformed result must not discard the rest of the batch.
            try:
                finding = self._parse_json_result(result, external_ids)
            except (AttributeError, KeyError, TypeError, ValueError) as e:
                logger.warning("Skipping malformed Opengrep result: %s", e)
                continue
            if finding:
                findings.append(finding)
        return findings

    def _parse_json_result(
        self, result: dict[str, Any], external_ids: frozenset[str] = frozenset()
    ) -> Finding | None:
        raw_rule_id = result.get("check_id", "unknown")
        rule_id = _clean_rule_id(raw_rule_id, external_ids)

        extra = result.get("extra", {})
        metadata = extra.get("metadata", {}) or {}
        message = extra.get("message", "")

        severity_str = str(extra.get("severity", "WARNING")).upper()
        severity = _SEVERITY_MAP.get(severity_str, Severity.MEDIUM)
        # A regex rule converted from NeuroScan's 5-tier severity down to
        # Opengrep's 3-tier ERROR/WARNING/INFO loses the "critical"/"low"
        # ends of the original scale; the converter preserves the original
        # value under metadata.original_severity precisely so it can be
        # restored here, directly, with no external manifest lookup.
        orig_sev = str(metadata.get("original_severity", "")).lower()
        if orig_sev == "critical":
            severity = Severity.CRITICAL
        elif orig_sev == "low":
            severity = Severity.LOW

        file_path = result.get("path", "")
        start = result.get("start", {})
        end = result.get("end", {})
        start_line = start.get("line", 1)
        end_line = end.get("line", start_line)
        start_col = start.get("col")
        end_col = end.get("col")
        if not file_path or not start_line:
            return None

        category = _resolve_category(rule_id, message, metadata)
        cwe_ids = _parse_cwe_ids(metadata)
        taint_flow = self._extract_taint_flow(extra.get("dataflow_trace"), metadata)

        confidence_str = str(metadata.get("confidence", "")).upper()
        base_confidence = _CONFIDENCE_MAP.get(confidence_str, 0.85)
        if taint_flow and taint_flow.source and taint_flow.sink:
            base_confidence = min(1.0, base_confidence + 0.05)

        # Promote findings where the taint flow crosses a file boundary to
        # engine="crossfile" so they're reported distinctly and counted.
        engine = "opengrep"
        if (taint_flow and taint_flow.source and taint_flow.sink
                and taint_flow.source.file_path != taint_flow.sink.file_path):
            engine = "crossfile"

        finding_metadata = {"rule_name": metadata.get("rule_name") or rule_id}
        fix = metadata.get("fix")
        if fix:
            finding_metadata["remediation"] = fix
        # Passthrough only: EnrichmentPass maps `source_kind` onto a taint
        # origin for files the Python AST tracer cannot parse (JG-02).
        source_kind = metadata.get("source_kind")
        if source_kind:
            finding_metadata["source_kind"] = str(source_kind)

        return Finding(
            rule_id=rule_id,
            message=message,
            severity=severity,
            category=category,
            file_path=file_path,
            start_line=start_line,
            end_line=end_line,
            start_column=start_col,
            end_column=end_col,
            confidence=base_confidence,
            cwe_ids=cwe_ids,
            taint_flow=taint_flow,
            engine=engine,
            metadata=finding_metadata,
        )

    @staticmethod
    def _json_node(entry: dict[str, Any]) -> TaintNode | None:
        loc = entry.get("location")
        if not loc:
            return None
        start = loc.get("start", {})
        return TaintNode(
            file_path=loc.get("path", ""),
            line=start.get("line", 0),
            column=start.get("col"),
            snippet=entry.get("content", ""),
        )

    @staticmethod
    def _json_endpoint_node(tagged: Any) -> TaintNode | None:
        """taint_source/taint_sink are ["CliLoc"|"Call"|..., [location_dict, snippet]]."""
        if not isinstance(tagged, list) or len(tagged) != 2:
            return None
        payload = tagged[1]
        if not isinstance(payload, list) or len(payload) != 2:
            return None
        loc, snippet = payload
        start = loc.get("start", {})
        return TaintNode(
            file_path=loc.get("path", ""),
            line=start.get("line", 0),
            column=start.get("col"),
            snippet=snippet if isinstance(snippet, str) else "",
        )

    def _extract_taint_flow(
        self, trace: dict[str, Any] | None, rule_metadata: dict[str, Any]
    ) -> TaintFlow | None:
        if not trace:
            return None

        source = self._json_endpoint_node(trace.get("taint_source"))
        sink = self._json_endpoint_node(trace.get("taint_sink"))
        intermediate = [
            node
            for entry in trace.get("intermediate_vars", [])
            if (node := self._json_node(entry)) is not None
        ]

        sanitizers: list[str] = []
        rule_sanitizers = rule_metadata.get("sanitizers", [])
        if isinstance(rule_sanitizers, list):
            sanitizers.extend(str(s) for s in rule_sanitizers)

        if not source and not sink:
            return None
        return TaintFlow(source=source, sink=sink, intermediate=intermediate, sanitizers=sanitizers)
