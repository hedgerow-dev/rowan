"""Framework regex rules removed in favour of real rules (#53).

Each matched a single token on its own line (any `res.send(`, any
`@ModelAttribute`) and claimed a flow it never computed. The taint or regex
rule named here covers the real case. ns-fw-sess-001 is not removed: it is
now a structural rule in framework_opengrep.yaml.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

RULES = Path(__file__).parent.parent / "rules"

REPLACED_BY = {
    "ns-fw-js-003": None,  # CSRF absence cannot be seen per line
    "ns-fw-js-004": "tnt-js-sqli-001",
    "ns-fw-js-005": "tnt-js-xss-001",
    "ns-fw-java-005": None,  # @ModelAttribute / BeanUtils.copyProperties are ordinary APIs
    "ns-fw-go-001": "tnt-go-sqli-001",
    "ns-fw-py-001": "NS-CONFIG-101",
    "ns-fw-py-003": "TNT-REDIR-001",
    "ns-fw-cs-003": "tnt-cs-sqli-001",
}

ALL_RULE_TEXT = "".join(p.read_text(encoding="utf-8") for p in RULES.glob("*.yaml"))


@pytest.mark.parametrize("removed,replacement", REPLACED_BY.items())
def test_removed_rule_is_gone_and_replacement_exists(removed, replacement):
    assert not re.search(rf"id: {re.escape(removed)}\s*$", ALL_RULE_TEXT, re.M)
    if replacement:
        assert re.search(rf"id: {re.escape(replacement)}\s*$", ALL_RULE_TEXT, re.M)
