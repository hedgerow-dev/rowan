"""Shared test/example path recognition (extracted from `passes/enrichment.py`).

Whether a file is test, example or fixture code is consumed by more than one
pass, and the two consumers must agree: `EnrichmentPass` uses it to downgrade a
finding's severity and confidence, while `CrossFilePass` uses it to decline to
emit at all when the *caller* (the entry point a cross-file finding anchors on)
is a test function. Keeping a second copy is the duplicated-definition drift
ADR-0002 warns against, so both import from here.

`EnrichmentPass` re-imports these under its historical private names.
"""

from __future__ import annotations

import re
from pathlib import Path

TEST_PATH_SEGMENTS = frozenset({
    "test", "tests", "testing", "example", "examples", "demo", "demos",
    "fixture", "fixtures", "spec", "specs", "testdata", "mock", "mocks",
    "stubs", "fake", "fakes", "__tests__", "__test__",
    # Compound Go-convention names. Listed explicitly rather than via an
    # "ends with test" rule, which would also catch contest/latest/attest.
    "dbtest", "httptest", "testutil", "testutils", "testhelpers", "testkit",
    "testsupport",
})

TEST_FILE_PREFIXES = ("test_",)
TEST_FILE_NAMES = frozenset({"conftest.py"})
# JS/TS `name.test.ts`, `name.spec.jsx`.
TEST_FILE_RE = re.compile(r"\.(?:test|spec)\.[cm]?[jt]sx?$")
TEST_FILE_SUFFIXES = ("_test.py", "_spec.py", "_test.js", "_spec.js", "_test.rb", "_spec.rb", "_test.go")

PATH_SEGMENT_SPLIT_RE = re.compile(r"[-_.]")

# Directories whose code never runs in an attacker-facing context: operator-run
# maintenance scripts, schema migrations, data importers and benchmarks. A
# finding there may be real code, but there is no request that reaches it, so
# it must not compete with deployed-surface findings at high/critical.
NO_ATTACKER_PATH_SEGMENTS = frozenset({
    "script", "scripts", "benchmark", "benchmarks", "bench",
    "migrate", "migrations", "import_scripts", "importers",
    # Operator/dev tooling directories (Go and general convention): a `tools/`
    # or `cli/` binary is run by a developer/operator from a shell, so a path
    # or arg "user input" there is the operator's own, not an attacker's.
    # Deliberately NOT `cmd`: Go's `cmd/<name>/main.go` also holds the SERVER
    # entrypoint, which IS attacker-facing, so blanket-capping it would hide
    # real deployed-surface findings.
    "tools", "cli",
})

# Build-tool configuration files executed at build time, never serving traffic.
BUILD_CONFIG_FILE_RE = re.compile(
    r"^(?:rollup|rolldown|webpack|vite|esbuild|gulpfile|gruntfile|rspack)"
    r"(?:\.config)?\.[cm]?[jt]s$"
)


def is_no_attacker_path(file_path: str) -> bool:
    """True if `file_path` is operator tooling with no attacker-facing surface."""
    path = Path(file_path)
    name = path.name.lower()
    if BUILD_CONFIG_FILE_RE.match(name):
        return True
    return any(p.lower() in NO_ATTACKER_PATH_SEGMENTS for p in path.parts)


# Example and demo directories. Unlike tests, many AI repositories deploy
# what lives there (a Gradio or Streamlit demo), so consumers exempt a file
# under them that is itself an entrypoint (#65).
EXAMPLE_PATH_SEGMENTS = frozenset({"example", "examples", "demo", "demos"})

# A file that serves requests itself: a route decorator with a literal path,
# a server or UI launch, or an MCP server/tool definition.
ENTRYPOINT_RE = re.compile(
    r"@\w+(?:\.\w+)*\.(?:route|get|post|put|patch|delete|websocket|api_route)\(\s*[\'\"]/"
    r"|\.launch\(|\buvicorn\.run\(|\bapp\.run\(|\bFastMCP\(|@\w+\.tool\("
    r"|^\s*(?:import|from)\s+streamlit\b",
    re.MULTILINE,
)


def _test_path(file_path: str, segments: frozenset[str]) -> bool:
    path = Path(file_path)
    name = path.name.lower()
    for p in path.parts[:-1]:
        tokens = PATH_SEGMENT_SPLIT_RE.split(p.lower())
        if any(t in segments for t in tokens):
            return True
    if name in TEST_FILE_NAMES or TEST_FILE_RE.search(name):
        return True
    if any(name.startswith(p) for p in TEST_FILE_PREFIXES):
        return True
    return any(name.endswith(s) for s in TEST_FILE_SUFFIXES)


def is_test_path(file_path: str) -> bool:
    """True if `file_path` is test, example, fixture or mock code.

    Directory names are split into words (`unit-tests`, `api-examples`); the
    file name is not. It counts only by explicit test-file convention, so a
    production `demo_server.py` or `mock_server.py` is not test code (#65).
    """
    return _test_path(file_path, TEST_PATH_SEGMENTS)


def is_example_only_path(file_path: str) -> bool:
    """True if `file_path` is test-like only because of an example/demo directory."""
    return is_test_path(file_path) and not _test_path(
        file_path, TEST_PATH_SEGMENTS - EXAMPLE_PATH_SEGMENTS
    )
