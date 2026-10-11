"""Deployment profile filtering: controls which rule categories are active."""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from pathlib import Path

from rowan.core.findings import Category
from rowan.core.paths import is_within_root
from rowan.languages import LANGUAGE_REGISTRY

DISABLED_CATEGORIES: dict[str, set[Category]] = {
    "server": set(),
    "library": {Category.SSRF, Category.XSS, Category.AUTH},
    "cli": {Category.SSRF, Category.XSS, Category.AUTH},
    "desktop": {Category.SSRF, Category.AUTH},
}

_WEB_FRAMEWORK_RE = re.compile(
    r"(?:^|\s)(?:import|from)\s+"
    r"(?:flask|django|fastapi|starlette|tornado|aiohttp|sanic|bottle|falcon|quart)",
    re.MULTILINE,
)

# Java/Kotlin: server-side web frameworks and JAX-RS/Servlet markers. Kotlin
# uses the same regex -- `io.ktor.server` already covers the more specific
# `io.ktor.server.application` package.
_JVM_SERVER_RE = re.compile(
    r"import\s+org\.springframework\.web|"
    r"org\.springframework\.boot\.autoconfigure\.SpringBootApplication|"
    r"@SpringBootApplication|@RestController|@Controller|"
    r"jakarta\.servlet|javax\.servlet|"
    r"javax\.ws\.rs|jakarta\.ws\.rs|"
    r"io\.javalin|io\.ktor\.server|io\.micronaut\.http|"
    r"io\.vertx\.ext\.web|spark\.Spark"
)

_CSHARP_SERVER_RE = re.compile(r"Microsoft\.AspNetCore|\[ApiController\]|System\.Web\.Mvc")

_GO_SERVER_FRAMEWORK_RE = re.compile(
    r"github\.com/gin-gonic/gin|github\.com/labstack/echo|"
    r"github\.com/gofiber/fiber|github\.com/go-chi/chi|"
    r"github\.com/gorilla/mux|gopkg\.in/macaron|github\.com/go-macaron/macaron|"
    r"github\.com/mark3labs/mcp-go/server|"
    r"github\.com/modelcontextprotocol/go-sdk/mcp"
)
_GO_NET_HTTP_USE_RE = re.compile(r"http\.ListenAndServe|http\.HandleFunc|http\.Handle\(")
_GO_CLI_RE = re.compile(r"flag\.Parse\(\)|github\.com/spf13/cobra|github\.com/urfave/cli")
_GO_MAIN_PACKAGE_RE = re.compile(r"^package\s+main\b", re.MULTILINE)

_SKIP_DIRS = {".git", "node_modules", "venv", ".venv", "__pycache__", "dist", "build"}
_HEAD_LINES = 50


def get_disabled_categories(profile: str) -> set[Category]:
    return DISABLED_CATEGORIES.get(profile, set())


def _read_head(file_path: Path, target: Path) -> str | None:
    """Read a bounded head of ``file_path``, or ``None`` if it should be skipped."""
    if any(p in _SKIP_DIRS for p in file_path.parts):
        return None
    # A symlinked source file can point outside the scan root (CWE-59): its
    # content would otherwise be read here to sniff a web framework.
    if file_path.is_symlink() and not is_within_root(file_path, target):
        return None
    try:
        with open(file_path, encoding="utf-8", errors="ignore") as f:
            return "".join(f.readline() for _ in range(_HEAD_LINES))
    except OSError:
        return None


def _matches_in_files(
    files: Iterable[Path], target: Path, pattern: re.Pattern[str]
) -> bool:
    # Every file, in sorted order: checking only the first N in directory
    # enumeration order made the verdict depend on the filesystem (#63).
    for file_path in sorted(files):
        head = _read_head(file_path, target)
        if head is not None and pattern.search(head):
            return True
    return False


def _rglob_suffixes(target: Path, language: str) -> Iterable[Path]:
    for suffix in LANGUAGE_REGISTRY[language].file_scan_entries:
        yield from target.rglob(f"*{suffix}")


def _detect_go_profile(target: Path, files: Iterable[Path] | None = None) -> str | None:
    """Scan Go sources for server frameworks, falling back to a CLI marker."""
    cli_candidate = False
    source_files = _rglob_suffixes(target, "go") if files is None else files
    for file_path in sorted(source_files):
        head = _read_head(file_path, target)
        if head is None:
            continue
        if _GO_SERVER_FRAMEWORK_RE.search(head) or (
            '"net/http"' in head and _GO_NET_HTTP_USE_RE.search(head)
        ):
            return "server"
        if _GO_MAIN_PACKAGE_RE.search(head) and _GO_CLI_RE.search(head):
            cli_candidate = True
    return "cli" if cli_candidate else None


def auto_detect_profile(
    target_path: Path | str,
    candidates: Iterable[Path] | None = None,
    *,
    candidates_by_language: Mapping[str, Iterable[Path]] | None = None,
) -> str:
    """Infer a deployment profile from the resolved source scope.

    ``candidates`` retains the historical Python-only injection point.
    ``candidates_by_language`` lets the pipeline reuse its authoritative
    inventory for every supported profile language without another walk.
    Direct callers retain the historical bounded discovery fallback.
    """
    target = Path(target_path)
    def language_files(language: str) -> Iterable[Path]:
        if candidates_by_language is not None:
            return candidates_by_language.get(language, ())
        if language == "python" and candidates is not None:
            return candidates
        return _rglob_suffixes(target, language)

    py_files = language_files("python")
    if _matches_in_files(py_files, target, _WEB_FRAMEWORK_RE):
        return "server"
    jvm_files = (*language_files("java"), *language_files("kotlin"))
    if _matches_in_files(jvm_files, target, _JVM_SERVER_RE):
        return "server"
    if _matches_in_files(language_files("csharp"), target, _CSHARP_SERVER_RE):
        return "server"
    go_profile = _detect_go_profile(target, language_files("go"))
    if go_profile is not None:
        return go_profile
    return "library"
