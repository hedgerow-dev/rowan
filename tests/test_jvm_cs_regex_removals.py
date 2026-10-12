"""Java and C# regex rules that fired on safe or constant code are removed (#55).

Each fired on an ordinary line (the HttpURLConnection type name, any
`.execute(` concatenation, `Process.Start("notepad.exe")`, a literal `WebRequest.Create`). The named
taint rule covers the real flow. CS-XXE-001 and CS-PATH-001 stay until the
regex-only vuln_cases gate can credit taint rules (see #55).
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

RULES = Path(__file__).parent.parent / "rules"
ALL = "".join(p.read_text(encoding="utf-8") for p in RULES.glob("*.yaml"))

REPLACED_BY = {
    "JA-SSRF-001": "tnt-ja-ssrf-001",
    "JA-INJECT-003": "tnt-ja-sqli-001",
    "CS-INJECT-001": "tnt-cs-cmdi-001",
    "CS-SSRF-001": "tnt-cs-ssrf-001",
}


@pytest.mark.parametrize("removed,replacement", REPLACED_BY.items())
def test_removed_rule_is_gone_and_taint_rule_exists(removed, replacement):
    assert not re.search(rf"id: {re.escape(removed)}\s*$", ALL, re.M)
    assert re.search(rf"id: {re.escape(replacement)}\s*$", ALL, re.M)
