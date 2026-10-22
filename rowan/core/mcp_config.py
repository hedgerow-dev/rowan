"""MCP deployment-config scanner.

Everything else in this codebase that understands MCP looks at *source
code* -- ``mcp.run(``, ``@mcp.tool``, tool-description poisoning, and so on
(``rules/ai_security.yaml``, ``cross_file.py``'s structural trust-boundary
detectors). None of it opens the actual MCP *config* artifact -- the JSON
file a client (Claude Desktop, an IDE, a custom host) reads to decide which
MCP servers to launch, with what command, what arguments, and what
environment. That artifact is where the two things an operator actually
gets wrong live: a literal secret checked into ``env`` instead of an env-var
reference, and a server granted far more filesystem/permission scope than
the client needs (Agent Audit's "structured config parsing" +
"privilege-risk checks" categories -- see arxiv.org/abs/2603.22853 -- cover
exactly this class, and we had zero equivalent).

Recognizes the common client config filenames (Claude Desktop's
``claude_desktop_config.json``, the emerging ``mcp.json``/``.mcp.json``
convention used by several IDEs and CLI hosts) and either their
``mcpServers`` map or a bare top-level server map.
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from urllib.parse import urlsplit

from rowan.core.findings import Category, Finding, Severity
from rowan.core.paths import is_within_root
from rowan.core.rules import _is_env_reference, _is_placeholder, _shannon_entropy

logger = logging.getLogger(__name__)

MCP_CONFIG_FILENAMES = frozenset({
    "mcp.json", ".mcp.json", "mcp_config.json", "mcp-config.json",
    "claude_desktop_config.json",
})

_SKIP_DIRS = frozenset({
    ".git", "node_modules", "venv", ".venv", "env",
    "__pycache__", ".tox", ".mypy_cache", ".pytest_cache",
    ".ruff_cache", "dist", "build", ".eggs",
})

#: Flags/args that grant a server broad, unscoped access -- distinct from a
#: normal, narrowly-scoped invocation. Matched against each arg individually
#: (not substring-in-joined-string) to avoid a legitimate path component
#: incidentally containing one of these as a substring.
_PRIVILEGE_FLAGS = frozenset({
    "--allow-all", "--full-access", "--dangerously-skip-permissions",
    "--no-sandbox", "--yolo", "--unrestricted", "--allow-dangerous",
    "--disable-sandbox", "--skip-confirmation",
})

#: A bare root or home-directory path handed to a filesystem-flavored server
#: (heuristic on the command/args mentioning "filesystem"/"fs") grants the
#: entire disk rather than a project directory -- the single most common
#: real MCP misconfiguration (`npx @modelcontextprotocol/server-filesystem /`).
_ROOT_SCOPE_PATHS = frozenset({"/", "~", "C:\\", "C:/"})
_FILESYSTEM_SERVER_HINT = "filesystem"


def find_mcp_config_files(
    target: Path, candidates: tuple[Path, ...] | None = None
) -> list[Path]:
    """Recursively find recognized MCP client config files under `target`."""
    if candidates is not None:
        return list(candidates)

    found: list[Path] = []
    for path in target.rglob("*"):
        if not path.is_file():
            continue
        if path.name not in MCP_CONFIG_FILENAMES:
            continue
        if any(part in _SKIP_DIRS for part in path.parts):
            continue
        # A symlinked config can point outside the scan root (CWE-59); rglob
        # does not follow a symlinked directory but does yield a symlinked
        # file as is_file()==True, so this must be checked explicitly.
        if path.is_symlink() and not is_within_root(path, target):
            continue
        found.append(path)
    return found


def _line_containing(text: str, needle: str) -> int:
    """Best-effort 1-indexed line number of the first line containing
    `needle`, or 1 if not found -- JSON has no stable AST-to-source-line
    mapping without a custom parser, so this is an approximation, same
    spirit as other structurally-detected findings in this codebase that
    report a location without a real AST node backing it."""
    for i, line in enumerate(text.splitlines(), 1):
        if needle in line:
            return i
    return 1


def _looks_like_secret(value: str) -> bool:
    """True if a JSON string value looks like a real credential rather than
    an env-var reference or a placeholder -- same threshold philosophy as
    `core.rules`'s `NS-SECRET-*` value check (entropy >= 3.0, length-gated,
    not a known placeholder pattern), reused here since it's the exact same
    judgment call applied to a JSON value instead of a source-code literal."""
    # Judge only the literal part: `${user_config.token}` is a reference.
    value = _SUBSTITUTION_RE.sub("", value)
    if not value or _is_env_reference(value) or _is_placeholder(value):
        return False
    if len(value) < 16 or _is_non_secret_shape(value):
        return False
    return _shannon_entropy(value) >= 3.0


#: Host substitutions: `${user_config.x}` (desktop extensions), `${input:x}`
#: and `${env:X}` (VS Code), beyond the `${UPPER_CASE}` form rules.py knows.
_SUBSTITUTION_RE = re.compile(r"\$\{[^}]+\}")
_PLACEHOLDER_PASSWORDS = frozenset({"password", "pass", "passwd", "secret", "changeme"})


def _is_non_secret_shape(value: str) -> bool:
    """Values that pass the entropy bar without being credentials: a
    `your-...` placeholder, and a URL or path made only of
    words and numbers (a base URL, a data directory, a DSN whose password is
    a placeholder). A URL with a real password, or a random-looking path or
    query segment (a webhook token), is not exempt."""
    if value.lower().startswith("your-"):
        return True
    if "/" not in value:
        return False
    try:
        password = urlsplit(value).password if "://" in value else None
    except ValueError:
        return False
    if password is not None and password.lower() not in _PLACEHOLDER_PASSWORDS:
        return False
    return all(t.isalpha() or t.isdigit() for t in re.findall(r"[A-Za-z0-9]+", value))


def _server_entries(config: dict) -> dict:
    """Return the server-name -> server-config map, whether it's nested
    under `mcpServers` (Claude Desktop convention) or is the top-level dict
    itself (some hosts use a bare map)."""
    servers = config.get("mcpServers")
    if isinstance(servers, dict):
        return servers
    return {k: v for k, v in config.items() if isinstance(v, dict)}


def scan_mcp_config_file(path: Path) -> list[Finding]:
    """Scan one MCP config file for hardcoded secrets and over-privileged
    server invocations. Returns an empty list on any parse failure --
    malformed JSON isn't this scanner's problem to report."""
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
        config = json.loads(text)
    except (OSError, json.JSONDecodeError):
        return []
    if not isinstance(config, dict):
        return []

    findings: list[Finding] = []
    for server_name, server in _server_entries(config).items():
        if not isinstance(server, dict):
            continue

        env = server.get("env")
        if isinstance(env, dict):
            for key, value in env.items():
                if not isinstance(value, str) or not _looks_like_secret(value):
                    continue
                findings.append(Finding(
                    rule_id="MCP-CONFIG-001",
                    message=(
                        f"MCP server '{server_name}' has a hardcoded credential-shaped "
                        f"value in env.{key} instead of an env-var reference "
                        f"(e.g. \"${{{key}}}\"). Anyone with read access to this config "
                        f"file -- including it being accidentally committed -- gets the "
                        f"credential in plaintext."
                    ),
                    severity=Severity.HIGH,
                    category=Category.SECRETS,
                    file_path=str(path),
                    start_line=_line_containing(text, key),
                    confidence=0.7,
                    engine="mcpconfig",
                    metadata={"server": server_name, "env_key": key},
                ))

        args = server.get("args") if isinstance(server.get("args"), list) else []
        command = server.get("command", "")
        arg_strs = [a for a in args if isinstance(a, str)]
        haystack = " ".join([str(command), *arg_strs]).lower()

        hit_flags = [f for f in _PRIVILEGE_FLAGS if f in arg_strs]
        if hit_flags:
            findings.append(Finding(
                rule_id="MCP-CONFIG-002",
                message=(
                    f"MCP server '{server_name}' is launched with unscoped-privilege "
                    f"flag(s) {hit_flags}. This grants the server broader access than "
                    f"a typical scoped invocation -- confirm this is intentional, not a "
                    f"copy-pasted example config."
                ),
                severity=Severity.HIGH,
                category=Category.AI_ML,
                file_path=str(path),
                start_line=_line_containing(text, hit_flags[0]),
                confidence=0.75,
                engine="mcpconfig",
                metadata={"server": server_name, "flags": hit_flags},
            ))
        elif _FILESYSTEM_SERVER_HINT in haystack and any(a in _ROOT_SCOPE_PATHS for a in arg_strs):
            findings.append(Finding(
                rule_id="MCP-CONFIG-002",
                message=(
                    f"MCP server '{server_name}' looks like a filesystem-access server "
                    f"scoped to the root/home directory instead of a specific project "
                    f"path -- grants the connected LLM read/write access to the entire "
                    f"filesystem, not just the intended project."
                ),
                severity=Severity.HIGH,
                category=Category.AI_ML,
                file_path=str(path),
                start_line=_line_containing(text, str(command)),
                confidence=0.65,
                engine="mcpconfig",
                metadata={"server": server_name},
            ))

        url = server.get("url")
        if isinstance(url, str) and url.lower().startswith("http://"):
            findings.append(Finding(
                rule_id="MCP-CONFIG-003",
                message=(
                    f"MCP server '{server_name}' uses an unencrypted http:// transport "
                    f"URL. Tool calls and results -- including anything the connected "
                    f"LLM is fed -- travel in plaintext."
                ),
                severity=Severity.MEDIUM,
                category=Category.AI_ML,
                file_path=str(path),
                start_line=_line_containing(text, url),
                confidence=0.7,
                engine="mcpconfig",
                metadata={"server": server_name},
            ))

    return findings


def scan_directory(
    target: Path, candidates: tuple[Path, ...] | None = None
) -> list[Finding]:
    findings: list[Finding] = []
    for path in find_mcp_config_files(target, candidates):
        findings.extend(scan_mcp_config_file(path))
    return findings
