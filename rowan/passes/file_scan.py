"""File scan pass: runs NeuroScan regex rules against project files."""

from __future__ import annotations

import fnmatch
import functools
import logging
import re
import time
from pathlib import Path

from rowan.artifacts import (
    DEPENDENCY_SKIP_DIRS,
    MODEL_ARTIFACT_EXTENSIONS,
    is_dependency_manifest,
    is_model_artifact,
)
from rowan.config import ScanConfig
from rowan.core.findings import Finding, ScanResult
from rowan.core.mcp_config import MCP_CONFIG_FILENAMES
from rowan.core.paths import is_within_root
from rowan.core.rules import NeuroScanRule
from rowan.languages import LANGUAGE_EXTENSIONS, UNSUPPORTED_SOURCE_EXTENSIONS
from rowan.passes.base import ScanContext, SourceFile, SourceInventory, scan_span

logger = logging.getLogger(__name__)

DOCKERFILE_NAMES = frozenset({"Dockerfile", "dockerfile"})


def is_ai_instruction_file(path: Path | str) -> bool:
    """True if `path` is a recognized AI instruction / prompt file.

    These are scanned (issue #134, ns-aiml-107/108) but their *contents* are
    attacker-authored text addressed at an agent, so anything that forwards
    file bodies to an LLM must treat them as data rather than as code to
    reason over. `hunt --discover` excludes them from its candidate set for
    exactly that reason: a finding in AGENTS.md would otherwise nominate the
    file and send its full instruction text into the discovery prompt.

    Single source of truth is LANGUAGE_EXTENSIONS["ai_instructions"]; keep
    the two in step by deriving from it rather than restating the names.
    """
    name = Path(path).name
    for entry in LANGUAGE_EXTENSIONS["ai_instructions"]:
        if entry.startswith("."):
            # Extension-style: ".cursorrules" also matches a file literally
            # named ".cursorrules" (glob "*" matches zero characters).
            if name == entry or name.endswith(entry):
                return True
        elif name == entry:
            return True
    return False

# Dotfiles are skipped by _should_skip's hidden-file check by default; these
# specific recognized AI-instruction dotfiles are the sole exception (issue
# #134) since they carry no other allowlisting mechanism in this pipeline.
ALLOWED_DOTFILES = frozenset({".cursorrules", ".env"})

BASE_SKIP_DIRS = frozenset({
    ".git", "node_modules", "venv", ".venv", "env",
    "__pycache__", ".tox", ".mypy_cache", ".pytest_cache",
    ".ruff_cache", "dist", "build", ".eggs",
})

# Skips that can hide the project's own code, so the report names them
# (a published package often ships nothing but a minified dist/ bundle).
_BUILD_OUTPUT_DIRS = frozenset({"dist", "build"})
_COVERAGE_SKIP_REASONS = frozenset({"build_output", "minified_or_generated", "oversized"})
_CODE_SKIP_LANGUAGES = (
    "python", "javascript", "typescript", "java", "kotlin", "go", "csharp", "ruby", "php", "rust",
)

VENDORED_DIR_NAMES = frozenset({
    "vendor", "vendored", "third_party", "third-party",
    "bower_components", ".yarn", ".pnp", "jspm_packages",
    "bundle", "bundles",
})

VENDORED_PATH_SEGMENTS: tuple[tuple[str, ...], ...] = (
    ("assets", "vendor"),
)

MINIFIED_FILENAME_PATTERNS = (
    "*.min.js", "*.min.css", "*-bundle.js", "*.bundle.js",
    "*-bundle.min.js", "*.map", "*.lock",
)

_MINIFIED_PEEK_BYTES = 50_000
_MINIFIED_SINGLE_LINE = 2000
_MINIFIED_MAX_LINE = 5000
_MINIFIED_EXTENSIONS = frozenset(
    {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".css"}
)


def _contains_consecutive(parts: tuple[str, ...], segment: tuple[str, ...]) -> bool:
    n = len(segment)
    lowered = [p.lower() for p in parts]
    target = [s.lower() for s in segment]
    return any(lowered[i:i + n] == target for i in range(len(lowered) - n + 1))


def _is_minified_or_generated(path: Path) -> bool:
    """Detect minified/generated files by filename pattern or content shape."""
    name = path.name.lower()
    if any(fnmatch.fnmatch(name, pat) for pat in MINIFIED_FILENAME_PATTERNS):
        return True
    if ".min." in name:
        return True

    if path.suffix.lower() not in _MINIFIED_EXTENSIONS:
        return False

    try:
        with open(path, "rb") as fh:
            chunk = fh.read(_MINIFIED_PEEK_BYTES)
    except OSError:
        return False

    text = chunk.decode("utf-8", errors="ignore")
    if not text:
        return False

    lines = text.splitlines()
    if not lines:
        return False
    if max(len(line) for line in lines) > _MINIFIED_MAX_LINE:
        return True
    if len(lines) == 1 and len(lines[0]) > _MINIFIED_SINGLE_LINE:
        return True
    return (
        len(chunk) >= _MINIFIED_PEEK_BYTES
        and "\n" not in text
        and len(text) > _MINIFIED_SINGLE_LINE
    )


def _user_excluded(parts: tuple[str, ...], config: ScanConfig) -> bool:
    """Whether a path (as parts below the scan root) matches --exclude."""
    rel_posix = "/".join(parts)
    for pat in getattr(config, "extra_excludes", None) or []:
        # Same matcher as .rowanignore, so `app/` and `legacy/old.py` work,
        # plus a bare directory name (TE-18).
        if pat in parts or _matches_pattern(rel_posix, pat):
            return True
    return False


def load_ignore_patterns(target: Path, config: ScanConfig | None = None) -> list[str]:
    """Patterns from the repo's `.rowanignore`.

    Under `--ci` the file is not read: it lives in the scanned repository, so
    a pull request could exclude its own files from the gate (PL-02). The
    project config is already distrusted in CI for the same reason.
    """
    ignore_file = target / ".rowanignore"
    if not ignore_file.is_file():
        return []
    if config is not None and getattr(config, "ci_mode", False):
        logger.info("CI mode: ignoring in-repo %s", ignore_file)
        return []
    patterns: list[str] = []
    try:
        for raw_line in ignore_file.read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            patterns.append(line)
    except OSError:
        pass
    return patterns


@functools.lru_cache(maxsize=256)
def _path_pattern_regex(pattern: str) -> re.Pattern[str]:
    """gitignore-style path glob: ``**/`` spans zero or more directories,
    ``**`` anything, ``*`` and ``?`` stay within one segment (TE-18)."""
    out: list[str] = []
    i = 0
    while i < len(pattern):
        if pattern.startswith("**/", i):
            # Repeated `**/` means the same thing; stacking `(?:.*/)?` groups
            # would backtrack badly on a hostile repo's ignore file.
            if not out or out[-1] != "(?:.*/)?":
                out.append("(?:.*/)?")
            i += 3
        elif pattern.startswith("**", i):
            out.append(".*")
            i += 2
        elif pattern[i] == "*":
            out.append("[^/]*")
            i += 1
        elif pattern[i] == "?":
            out.append("[^/]")
            i += 1
        elif pattern[i] == "[" and "]" in pattern[i + 2:]:
            # fnmatch character class, `[!..]` negated.
            end = pattern.index("]", i + 2)
            body = pattern[i + 1:end]
            if body.startswith("!"):
                body = "^" + body[1:]
            out.append("[" + body.replace("\\", "\\\\") + "]")
            i = end + 1
        else:
            out.append(re.escape(pattern[i]))
            i += 1
    return re.compile("".join(out))


def _matches_pattern(rel_path_str: str, pattern: str) -> bool:
    if pattern.endswith("/"):
        dir_name = pattern.rstrip("/")
        parts = rel_path_str.replace("\\", "/").split("/")
        return dir_name in parts[:-1]
    rel_posix = rel_path_str.replace("\\", "/")
    if "/" in pattern:
        return _path_pattern_regex(pattern).fullmatch(rel_posix) is not None
    filename = rel_posix.rsplit("/", 1)[-1] if "/" in rel_posix else rel_posix
    return fnmatch.fnmatch(filename, pattern)


def is_ignored(rel_path: str, patterns: list[str]) -> bool:
    ignored = False
    for pattern in patterns:
        if pattern.startswith("!"):
            if _matches_pattern(rel_path, pattern[1:]):
                ignored = False
        else:
            if _matches_pattern(rel_path, pattern):
                ignored = True
    return ignored


def _parts_under(path: Path, root: Path | None) -> tuple[str, ...]:
    """Path components below ``root``; the absolute parts when ``root`` is
    None or ``path`` is not under it (symlink escape)."""
    if root is None:
        return path.parts
    try:
        return path.relative_to(root).parts
    except ValueError:
        return path.parts


def is_hidden_under(path: Path, root: Path) -> bool:
    """True when a component of ``path`` *below the scan root* is dot-prefixed.

    Always test hidden-ness relative to the root: the absolute path's ancestors
    belong to whoever hosts the project, not to the project. A checkout under
    ``.claude/worktrees/`` or ``~/.cache/`` is not a hidden file, and treating
    it as one skips every file in the scan and reports zero findings.
    """
    try:
        parts = path.relative_to(root).parts
    except ValueError:
        # Not under root (symlink escape); judge the file on its own name only.
        parts = (path.name,)
    return any(part.startswith(".") for part in parts)


class FileScanPass:
    name = "file_scan"

    def __init__(self, rules: list[NeuroScanRule], legacy_neuroscan: bool = True):
        if not legacy_neuroscan:
            logger.info("legacy_neuroscan=False: all %d NeuroScan rules replaced by converted opengrep rules; FileScanPass discovery-only", len(rules))
            rules = []
        self._rules = rules

    def _load_ignore_patterns(self, target: Path, config: ScanConfig | None = None) -> list[str]:
        return load_ignore_patterns(target, config)

    def run(self, context: ScanContext) -> ScanResult:
        start = time.perf_counter()
        result = ScanResult()

        all_files, dependency_manifests, model_artifacts, mcp_config_files, unsupported_counts = (
            self._discover_files(context.target_path, context.config)
        )
        result.files_scanned = len(all_files)

        # Publish the already-filtered scope before any rule work. Downstream
        # passes can distinguish this (including an intentionally empty
        # inventory) from standalone execution where discovery has not run.
        inventory_files: list[SourceFile] = []
        lang_counts: dict[str, int] = {}
        for f in all_files:
            name_lower = f.name.lower()
            matched_languages = frozenset(
                lang
                for lang in LANGUAGE_EXTENSIONS
                if self._file_matches_languages(name_lower, [lang])
            )
            inventory_files.append(SourceFile(path=f, languages=matched_languages))
            for lang in LANGUAGE_EXTENSIONS:
                if lang in matched_languages:
                    lang_counts[lang] = lang_counts.get(lang, 0) + 1
                    break
        context.source_inventory = SourceInventory(
            files=tuple(inventory_files),
            dependency_manifests=tuple(dependency_manifests),
            model_artifacts=tuple(model_artifacts),
            mcp_config_files=tuple(mcp_config_files),
        )

        # Per-language file histogram, consumed by the pipeline's analysis-
        # capability manifest (which languages got dataflow vs patterns only).
        context.metadata["languages_seen"] = lang_counts
        # Source files in languages Rowan cannot analyse at all, so the report
        # can say they exist rather than looking identical to a clean scan.
        context.metadata["unsupported_languages_seen"] = unsupported_counts
        # Code skipped as build output, minified or oversized: named in the
        # report so an empty scan of a bundle is not read as clean.
        context.metadata["skipped_code_files"] = self.skipped_code_files

        if not self._rules:
            logger.info("No NeuroScan rules loaded. Skipping file scan (discovered %d files).", len(all_files))
            return result

        logger.info("FileScanPass: %d files, %d rules", len(all_files), len(self._rules))

        for file_path in all_files:
            file_findings = self._scan_file(file_path)
            result.add_findings(file_findings)

        duration = time.perf_counter() - start
        scan_span(self.name, duration)
        logger.info("FileScanPass: %d findings in %.1fs", len(result.findings), duration)
        return result

    def _collect_files(self, target: Path, config: ScanConfig) -> list[Path]:
        """Collect source-rule inputs (compatibility wrapper for callers/tests)."""

        files, _, _, _, _ = self._discover_files(target, config)
        return files

    def _discover_files(
        self, target: Path, config: ScanConfig
    ) -> tuple[list[Path], list[Path], list[Path], list[Path], dict[str, int]]:
        """Traverse once and classify source, dependency, and model inputs."""

        files: list[Path] = []
        dependency_manifests: list[Path] = []
        mcp_config_files: list[Path] = []
        unsupported_counts: dict[str, int] = {}
        self.skipped_code_files: dict[str, dict] = {}
        code_suffixes = tuple(
            entry
            for lang in _CODE_SKIP_LANGUAGES
            for entry in LANGUAGE_EXTENSIONS.get(lang, ())
            if entry.startswith(".")
        )
        model_artifacts_by_extension: dict[str, list[Path]] = {
            extension: [] for extension in MODEL_ARTIFACT_EXTENSIONS
        }
        target_langs = {lang.lower() for lang in config.languages} if config.languages else set()

        entries = self._all_extensions(target_langs)
        suffixes = tuple(entry for entry in entries if entry.startswith("."))
        exact_names = {entry for entry in entries if not entry.startswith(".")}

        patterns = self._load_ignore_patterns(target, config)
        # Negation patterns (!...) in .rowanignore explicitly un-ignore files
        # and must override the default vendored/minified/size excludes below.
        negations = [p[1:] for p in patterns if p.startswith("!")]

        # Enumerate the tree once, then apply the same two matching modes that
        # the former per-entry rglob loop used: leading-dot entries are
        # suffixes (including multipart ones such as ``.prompt.md``), while
        # entries without a leading dot are exact filenames (for example,
        # ``Dockerfile`` and ``AGENTS.md``).  Keeping the matching here
        # case-sensitive preserves pathlib's glob semantics.
        for f in target.rglob("*"):
            rel_parts = _parts_under(f, target)
            if (
                f.name in MCP_CONFIG_FILENAMES
                and f.is_file()
                and not any(part in BASE_SKIP_DIRS for part in rel_parts)
                and (not f.is_symlink() or is_within_root(f, target))
            ):
                mcp_config_files.append(f)

            if (
                not any(part in DEPENDENCY_SKIP_DIRS for part in rel_parts)
                and is_dependency_manifest(f)
                and f.is_file()
                and (not f.is_symlink() or is_within_root(f, target))
            ):
                dependency_manifests.append(f)

            if is_model_artifact(f) and f.is_file():
                model_parts = rel_parts
                model_skip_dirs = (
                    BASE_SKIP_DIRS
                    | VENDORED_DIR_NAMES
                    | {"site-packages", "dist-packages"}
                )
                # --exclude and .rowanignore apply as they do to source files;
                # load_ignore_patterns already drops .rowanignore under --ci, so
                # a scanned repo cannot hide its own model files from the gate.
                if (
                    not any(part in model_skip_dirs for part in model_parts)
                    and (not f.is_symlink() or is_within_root(f, target))
                    and not _user_excluded(model_parts, config)
                    and not (patterns and is_ignored("/".join(model_parts), patterns))
                ):
                    model_artifacts_by_extension[f.suffix.lower()].append(f)

            name = f.name
            if name not in exact_names and not name.endswith(suffixes):
                unsupported_lang = UNSUPPORTED_SOURCE_EXTENSIONS.get(f.suffix.lower())
                if (
                    unsupported_lang
                    and f.is_file()
                    and not self._should_skip(f, config, target, negations)
                ):
                    unsupported_counts[unsupported_lang] = (
                        unsupported_counts.get(unsupported_lang, 0) + 1
                    )
                continue
            # A directory can legally be named ``app.py`` or ``Dockerfile``;
            # discovery should never count it as a scan input or hand it to a
            # rule as though it were readable source code.
            if not f.is_file():
                continue
            reason = self._skip_reason(f, config, target, negations)
            if reason is not None:
                if reason in _COVERAGE_SKIP_REASONS and name.endswith(code_suffixes):
                    entry = self.skipped_code_files.setdefault(reason, {"count": 0, "examples": []})
                    entry["count"] += 1
                    if len(entry["examples"]) < 5:
                        entry["examples"].append("/".join(rel_parts))
                continue
            files.append(f)

        # Deduplicate
        seen = set()
        unique: list[Path] = []
        for f in files:
            key = str(f.resolve())
            if key not in seen:
                seen.add(key)
                unique.append(f)

        if patterns:
            filtered: list[Path] = []
            for f in unique:
                try:
                    rel = f.relative_to(target)
                except ValueError:
                    filtered.append(f)
                    continue
                if not is_ignored(str(rel), patterns):
                    filtered.append(f)
            logger.debug(
                "Ignore patterns filtered %d -> %d files",
                len(unique),
                len(filtered),
            )
            files = filtered

        else:
            files = unique

        model_artifacts = [
            path
            for extension in MODEL_ARTIFACT_EXTENSIONS
            for path in model_artifacts_by_extension[extension]
        ]
        return files, dependency_manifests, model_artifacts, mcp_config_files, unsupported_counts

    def _all_extensions(self, target_langs: set[str]) -> set[str]:
        exts: set[str] = set()
        if not target_langs:
            for exts_list in LANGUAGE_EXTENSIONS.values():
                exts.update(exts_list)
        else:
            for lang in target_langs:
                if lang in LANGUAGE_EXTENSIONS:
                    exts.update(LANGUAGE_EXTENSIONS[lang])
        return exts

    def _should_skip(
        self,
        file_path: Path,
        config: ScanConfig,
        target: Path | None = None,
        negations: list[str] | None = None,
    ) -> bool:
        return self._skip_reason(file_path, config, target, negations) is not None

    def _skip_reason(
        self,
        file_path: Path,
        config: ScanConfig,
        target: Path | None = None,
        negations: list[str] | None = None,
    ) -> str | None:
        """Why a file is skipped, or None: hidden dirs, build/vendored dirs,
        minified bundles, oversized files, and any user-configured extra excludes.

        Explicit ``!`` negation patterns from ``.rowanignore`` override the
        default vendored/minified/size excludes (but not base build dirs).
        """
        # Judge skip dirs on the path below the scan root: the absolute
        # path's ancestors (``~/build/``, ``~/.cache/``) belong to the host,
        # not the project, and matching them scans zero files (TE-01).
        parts = _parts_under(file_path, target)

        # Skip symlinks whose target escapes the scan root, so a hostile repo
        # can't get files outside the target read into findings (CWE-59/22).
        if file_path.is_symlink() and target is not None:
            try:
                resolved = file_path.resolve()
                root = target.resolve()
                if resolved != root and root not in resolved.parents:
                    return "symlink_escape"
            except OSError:
                return "symlink_escape"

        if any(p in BASE_SKIP_DIRS - _BUILD_OUTPUT_DIRS for p in parts):
            return "skip_dir"
        if any(p in _BUILD_OUTPUT_DIRS for p in parts):
            return "build_output"
        if file_path.name.startswith(".") and file_path.name not in ALLOWED_DOTFILES:
            return "hidden"

        if negations and target is not None:
            try:
                rel = str(file_path.relative_to(target))
            except ValueError:
                rel = None
            if rel is not None and any(_matches_pattern(rel, neg) for neg in negations):
                return None

        if _user_excluded(parts, config):
            return "user_excluded"

        max_bytes = getattr(config, "max_file_bytes", 2_000_000)
        if max_bytes and max_bytes > 0:
            try:
                if file_path.stat().st_size > max_bytes:
                    return "oversized"
            except OSError:
                pass

        if getattr(config, "scan_vendored", False):
            return None

        if any(p in VENDORED_DIR_NAMES for p in parts):
            return "vendored"
        if any(_contains_consecutive(parts, seg) for seg in VENDORED_PATH_SEGMENTS):
            return "vendored"
        return "minified_or_generated" if _is_minified_or_generated(file_path) else None

    def _scan_file(self, file_path: Path) -> list[Finding]:
        findings: list[Finding] = []
        name_lower = file_path.name.lower()

        # Pre-filter rules by file extension/language to avoid running JS rules on Python files
        applicable_rules = [
            r for r in self._rules
            if not r.metadata.languages
            or self._file_matches_languages(name_lower, r.metadata.languages)
            or (name_lower in DOCKERFILE_NAMES and "dockerfile" in r.metadata.languages)
        ]
        for rule in applicable_rules:
            try:
                findings.extend(rule.check(file_path))
            except Exception:
                logger.debug("Rule %s failed on %s", rule.metadata.id, file_path, exc_info=True)
        return findings

    @staticmethod
    def _file_matches_languages(name_lower: str, languages: list[str]) -> bool:
        """Check whether a (lowercased) filename matches any of a rule's
        declared languages, per LANGUAGE_EXTENSIONS.

        LANGUAGE_EXTENSIONS entries are either extension-style (leading dot,
        possibly multi-part like ".prompt.md" -- matched via endswith, not
        Path.suffix, since suffix only ever captures the last dot segment
        and would miss both ".prompt.md" and dot-prefixed-only names like
        ".cursorrules") or exact-filename-style (e.g. "CLAUDE.md", matched
        case-insensitively against the full name).
        """
        for lang in languages:
            for entry in LANGUAGE_EXTENSIONS.get(lang, []):
                entry_lower = entry.lower()
                if entry_lower.startswith("."):
                    if name_lower.endswith(entry_lower):
                        return True
                elif name_lower == entry_lower:
                    return True
        return False
