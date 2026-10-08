"""RealVuln parser for Rowan JSON output (`rowan scan --format json`).

Loaded by score.py from this directory; RealVuln itself needs no changes.

Rowan's JSON differs from Semgrep format in three ways that matter here:
- findings live under "findings", not "results";
- file paths are whatever the scan target produced (absolute, or prefixed
  with the path the runner passed) rather than repo-relative;
- CWEs are bare integer lists ([89]), not "CWE-89" strings.

The runner (run.sh) invokes the scan with cwd set to the repo root and
target ".", so paths normally arrive as "./app/x.py". As a fallback for
absolute paths, anything up to and including "repos/<slug>/" is stripped.
"""
from __future__ import annotations

import json
import re

from parsers.base import BaseParser, NormalisedFinding, normalise_path

_REPOS_PREFIX_RE = re.compile(r"^.*?/repos/[^/]+/")


class RowanParser(BaseParser):
    """Parse rowan --format json output."""

    scanner_name: str = "rowan"

    def __init__(self, scanner_slug: str = "rowan"):
        self.scanner_name = scanner_slug

    def parse(self, file_path: str) -> list[NormalisedFinding]:
        with open(file_path) as f:
            data = json.load(f)

        findings: list[NormalisedFinding] = []
        for row in data.get("findings", []):
            path = row.get("file", "")
            path = _REPOS_PREFIX_RE.sub("", path.replace("\\", "/"))
            path = normalise_path(path)
            if not path:
                continue

            cwes = row.get("cwe") or []
            if isinstance(cwes, (int, str)):
                cwes = [cwes]

            for raw in cwes:
                try:
                    cwe = f"CWE-{int(raw)}"
                except (TypeError, ValueError):
                    continue
                findings.append(
                    NormalisedFinding(
                        file=path,
                        cwe=cwe,
                        line=row.get("line"),
                        function=None,
                        severity=(row.get("severity") or "").lower() or None,
                        rule_id=row.get("rule_id"),
                        message=row.get("message"),
                        scanner=self.scanner_name,
                    )
                )
        return findings
