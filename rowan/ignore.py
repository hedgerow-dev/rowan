"""Managed ignore file (.rowan-ignore.yml).

Lets teams persistently dismiss findings with a reason that survives re-scans,
without editing source. Works alongside inline ``# rowan:disable``.

File format (.rowan-ignore.yml):
    ignore:
      - fingerprint: <sha256 from baseline>
        reason: "Accepted risk: model loaded from trusted internal registry"
        expires: "2027-01-01"   # optional ISO date; entry silently lapses after this date
      - rule_id: NS-PATH-003
        path: "backend/chainlit/server.py"
        reason: "FileResponse path is validated by the auth middleware upstream"

Two matching strategies:
- ``fingerprint``: exact baseline fingerprint match (most precise, survives line shifts)
- ``rule_id`` + optional ``path`` glob: rule-level suppression for a file or prefix
"""

from __future__ import annotations

import fnmatch
import logging
from datetime import date
from pathlib import Path
from typing import Any

import yaml

from rowan.core.paths import repo_search_dirs

logger = logging.getLogger(__name__)

_IGNORE_NAMES = (".rowan-ignore.yml", ".rowan-ignore.yaml")


def find_ignore_file(start: Path) -> Path | None:
    for candidate in repo_search_dirs(start):
        for name in _IGNORE_NAMES:
            p = candidate / name
            if p.is_file():
                return p
    return None


def load_ignore_file(path: Path) -> list[dict[str, Any]]:
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    entries = (raw.get("ignore") or []) if isinstance(raw, dict) else []
    today = date.today().isoformat()
    active: list[dict[str, Any]] = []
    for e in entries:
        if not isinstance(e, dict):
            continue
        expires = e.get("expires")
        if expires and str(expires) < today:
            continue
        active.append(e)
    logger.info("Loaded ignore file %s: %d active entries", path, len(active))
    return active


def apply_ignore(findings, entries: list[dict[str, Any]], fingerprints: dict, root: Path) -> tuple[list, int]:
    """Return (kept_findings, suppressed_count)."""
    if not entries:
        return findings, 0
    kept = []
    suppressed = 0
    for f in findings:
        if _is_ignored(f, entries, fingerprints, root):
            suppressed += 1
        else:
            kept.append(f)
    return kept, suppressed


def _is_ignored(finding, entries: list[dict[str, Any]], fingerprints: dict, root: Path) -> bool:
    fp = fingerprints.get(id(finding))
    try:
        rel = str(Path(finding.file_path).resolve().relative_to(root.resolve()))
    except (ValueError, OSError):
        rel = finding.file_path

    for e in entries:
        if "fingerprint" in e:
            if fp and e["fingerprint"] == fp:
                return True
        elif "rule_id" in e:
            if e["rule_id"] != finding.rule_id:
                continue
            path_pat = e.get("path")
            # A bare startswith() would match "app2/utils.py" against a
            # path_pat of "app" -- require an exact match or a real
            # directory-boundary prefix instead.
            if (
                path_pat is None
                or fnmatch.fnmatch(rel, path_pat)
                or rel == path_pat
                or rel.startswith(path_pat.rstrip("/") + "/")
            ):
                return True
    return False
