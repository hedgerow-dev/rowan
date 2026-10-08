"""ns-auth-002 must see the auth decorator above a sensitive handler.

The pattern matched only the `def` line, and pattern-not exclusions only
inspect the matched text, so `@login_required` on the line above never
excluded anything: every protected handler was reported as unprotected.
The match now starts at the decorator lines directly above the def.
"""

from __future__ import annotations

import pytest

from rowan.config import ScanConfig
from rowan.pipeline import ScanPipeline
from rowan.taint.opengrep_adapter import OpengrepAdapter

pytestmark = pytest.mark.skipif(
    not OpengrepAdapter().is_installed(), reason="converted rules run on Opengrep"
)

# Handlers are far apart so proximity deduplication cannot merge them.
_GAP = "\n" + "x = 1\n" * 12

SOURCE = (
    "from django.contrib.auth.decorators import login_required\n"
    "from django.views.decorators.http import require_POST\n"
    "\n"
    "@login_required\n"
    "@require_POST\n"
    "def delete_protected(request, pk):\n"
    "    return pk\n"
    + _GAP
    + "def delete_unprotected(request, pk):\n"
    "    return pk\n"
    + _GAP
    + "@require_POST\n"
    "def update_without_auth(request, pk):\n"
    "    return pk\n"
)


def _flagged_handlers(tmp_path) -> set[str]:
    (tmp_path / "views.py").write_text(SOURCE, encoding="utf-8")
    result = ScanPipeline(
        ScanConfig(target=tmp_path, no_sca=True, no_cross_file=True, report_view="full")
    ).run()
    lines = SOURCE.splitlines()
    flagged = set()
    for finding in result.findings:
        if finding.rule_id != "ns-auth-002":
            continue
        # The finding starts at the first decorator; name the def that follows.
        for line in lines[finding.start_line - 1:]:
            if line.startswith("def "):
                flagged.add(line.split("(")[0].removeprefix("def "))
                break
    return flagged


def test_decorated_handler_is_not_flagged_but_unprotected_ones_are(tmp_path):
    assert _flagged_handlers(tmp_path) == {"delete_unprotected", "update_without_auth"}
