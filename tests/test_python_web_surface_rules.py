"""Behavioral tests for rules/python_web_surface.yaml."""

from __future__ import annotations

from pathlib import Path

import pytest

from rowan.core.rules import load_neuroscan_rules

RULES_DIR = Path(__file__).parent.parent / "rules"


def _rule(rule_id: str):
    rules = load_neuroscan_rules(RULES_DIR / "python_web_surface.yaml")
    matches = [r for r in rules if r.metadata.id == rule_id]
    if not matches:
        pytest.fail(f"{rule_id} not found")
    return matches[0]


class TestLxmlXxe:
    """ns-websec-611-001."""

    @pytest.mark.parametrize(
        "body",
        [
            "parser = etree.XMLParser(resolve_entities=True, load_dtd=True)\n",
            'OPTS = {"resolve_entities": True, "no_network": False}\nparser = etree.XMLParser(**OPTS)\n',
            "OPTS = {'no_network': False}\nparser = etree.XMLParser(**OPTS)\n",
            "OPTS = dict(resolve_entities=True)\nparser = etree.XMLParser(**OPTS)\n",
        ],
    )
    def test_unsafe_options_are_flagged(self, tmp_path, body):
        f = tmp_path / "app.py"
        f.write_text("from lxml import etree\n" + body)
        assert len(_rule("ns-websec-611-001").check(f)) >= 1

    @pytest.mark.parametrize(
        "body",
        [
            "parser = etree.XMLParser()\n",
            "parser = etree.XMLParser(resolve_entities=False, no_network=True)\n",
            'OPTS = {"resolve_entities": False, "no_network": True}\nparser = etree.XMLParser(**OPTS)\n',
        ],
    )
    def test_safe_options_are_not_flagged(self, tmp_path, body):
        f = tmp_path / "app.py"
        f.write_text("from lxml import etree\n" + body)
        assert _rule("ns-websec-611-001").check(f) == []
