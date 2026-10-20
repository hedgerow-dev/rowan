"""Canonical language names and scanner-specific file matching metadata."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from types import MappingProxyType


@dataclass(frozen=True)
class LanguageDefinition:
    """File matching rules for one supported language.

    ``file_scan_entries`` preserves the legacy regex scanner's matching
    surface.  Opengrep has separate discovery and include-glob fields because
    its historically supported surface is narrower for a few languages (for
    example ``.py`` but not ``.pyi``).  Keeping those differences explicit
    avoids changing scan coverage while making the supported language names a
    single source of truth.
    """

    file_scan_entries: tuple[str, ...]
    opengrep_suffixes: tuple[str, ...]
    opengrep_exact_names: tuple[str, ...] = ()
    opengrep_include_globs: tuple[str, ...] = ()


_REGISTRY = {
    "python": LanguageDefinition((".py", ".pyi"), (".py",), opengrep_include_globs=("*.py",)),
    "javascript": LanguageDefinition(
        (".js", ".jsx", ".mjs", ".cjs"),
        (".js", ".jsx", ".mjs", ".cjs"),
        opengrep_include_globs=("*.js",),
    ),
    "typescript": LanguageDefinition(
        (".ts", ".tsx"), (".ts", ".tsx"), opengrep_include_globs=("*.ts",)
    ),
    "java": LanguageDefinition((".java",), (".java",), opengrep_include_globs=("*.java",)),
    "kotlin": LanguageDefinition(
        (".kt", ".kts"), (".kt", ".kts"), opengrep_include_globs=("*.kt", "*.kts")
    ),
    "go": LanguageDefinition((".go",), (".go",), opengrep_include_globs=("*.go",)),
    "csharp": LanguageDefinition((".cs",), (".cs",), opengrep_include_globs=("*.cs",)),
    "ruby": LanguageDefinition((".rb",), (".rb",), opengrep_include_globs=("*.rb",)),
    "php": LanguageDefinition((".php",), (".php",), opengrep_include_globs=("*.php",)),
    "rust": LanguageDefinition((".rs",), (".rs",), opengrep_include_globs=("*.rs",)),
    "terraform": LanguageDefinition(
        (".tf", ".tfvars"), (".tf",), opengrep_include_globs=("*.tf",)
    ),
    "dockerfile": LanguageDefinition(
        ("Dockerfile", ".dockerfile"),
        (),
        opengrep_exact_names=("dockerfile",),
        opengrep_include_globs=("Dockerfile*",),
    ),
    "yaml": LanguageDefinition(
        (".yaml", ".yml"), (".yaml", ".yml"), opengrep_include_globs=("*.yaml",)
    ),
    "json": LanguageDefinition((".json",), (".json",), opengrep_include_globs=("*.json",)),
    "html": LanguageDefinition(
        (".html", ".htm", ".jinja", ".jinja2", ".j2"),
        (".html", ".htm", ".jinja", ".jinja2", ".j2"),
        opengrep_include_globs=("*.html", "*.htm", "*.jinja", "*.jinja2", "*.j2"),
    ),
    "ai_instructions": LanguageDefinition(
        ("CLAUDE.md", "AGENTS.md", "SKILL.md", ".cursorrules", "copilot-instructions.md", ".prompt.md"),
        (".cursorrules", ".prompt.md"),
        opengrep_exact_names=("claude.md", "agents.md", "skill.md", "copilot-instructions.md"),
        opengrep_include_globs=(
            "CLAUDE.md", "AGENTS.md", "SKILL.md", ".cursorrules", "copilot-instructions.md", "*.prompt.md",
        ),
    ),
    "markdown": LanguageDefinition((".md",), (".md",), opengrep_include_globs=("*.md",)),
    "text": LanguageDefinition((".txt",), (".txt",), opengrep_include_globs=("*.txt",)),
    "dotenv": LanguageDefinition((".env",), (".env",), opengrep_include_globs=(".env",)),
}

LANGUAGE_REGISTRY: Mapping[str, LanguageDefinition] = MappingProxyType(_REGISTRY)
SUPPORTED_LANGUAGES: frozenset[str] = frozenset(LANGUAGE_REGISTRY)

# Source languages Rowan does not analyse at all.  Discovery counts these so a
# report can say "these files exist and were not analysed" instead of looking
# identical to a clean scan.  Lowercase suffix to language name; nothing here
# may also appear in _REGISTRY.
UNSUPPORTED_SOURCE_EXTENSIONS: Mapping[str, str] = MappingProxyType({
    ".scala": "scala", ".sc": "scala",
    ".swift": "swift",
    ".c": "c", ".h": "c",
    ".cc": "cpp", ".cpp": "cpp", ".cxx": "cpp", ".hpp": "cpp", ".hh": "cpp",
    ".m": "objective-c", ".mm": "objective-c",
    ".dart": "dart",
    ".ex": "elixir", ".exs": "elixir",
    ".erl": "erlang",
    ".clj": "clojure", ".cljs": "clojure",
    ".lua": "lua",
    ".pl": "perl", ".pm": "perl",
    ".sh": "shell", ".bash": "shell", ".zsh": "shell",
    ".ps1": "powershell",
    ".sql": "sql",
    ".groovy": "groovy",
    ".r": "r",
    ".jl": "julia",
    ".zig": "zig",
    ".vue": "vue",
    ".svelte": "svelte",
    ".hs": "haskell",
    ".ml": "ocaml",
})

# Compatibility views used by scanner implementations and downstream callers.
# They are derived here so adding a language cannot update one engine while
# accidentally leaving the other engine's supported-name registry behind.
LANGUAGE_EXTENSIONS: dict[str, list[str]] = {
    name: list(definition.file_scan_entries)
    for name, definition in LANGUAGE_REGISTRY.items()
}
OPENGREP_LANGUAGE_EXTENSIONS: dict[str, tuple[str, ...]] = {
    name: definition.opengrep_suffixes
    for name, definition in LANGUAGE_REGISTRY.items()
}
OPENGREP_LANGUAGE_EXACT_NAMES: dict[str, tuple[str, ...]] = {
    name: definition.opengrep_exact_names
    for name, definition in LANGUAGE_REGISTRY.items()
    if definition.opengrep_exact_names
}
OPENGREP_LANGUAGE_INCLUDE_GLOBS: dict[str, tuple[str, ...]] = {
    name: definition.opengrep_include_globs
    for name, definition in LANGUAGE_REGISTRY.items()
}


def normalize_languages(languages: Iterable[str] | None) -> list[str]:
    """Return canonical language names or reject the complete explicit scope.

    ``None`` and an empty iterable retain the public meaning "all supported
    languages".  Empty entries, non-string values, and mixed valid/invalid
    lists fail closed rather than being ignored and broadening the scan.
    """
    if languages is None:
        return []
    if isinstance(languages, str):
        values: list[object] = [languages]
    else:
        values = list(languages)
    if not values:
        return []

    normalized: list[str] = []
    unsupported: list[str] = []
    for value in values:
        if not isinstance(value, str):
            unsupported.append(repr(value))
            continue
        language = value.strip().lower()
        if not language or language not in SUPPORTED_LANGUAGES:
            unsupported.append(language or "<empty>")
            continue
        normalized.append(language)

    if unsupported:
        requested = ", ".join(sorted(set(unsupported)))
        available = ", ".join(sorted(SUPPORTED_LANGUAGES))
        raise ValueError(
            f"Unsupported language(s): {requested}. Supported languages: {available}"
        )
    return normalized
