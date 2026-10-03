"""Behavioral tests for rules/python_web_surface.yaml."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from rowan.analysis.python_functions import FunctionIndex
from rowan.analysis.xml_parser_options import parser_option_findings
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
        assert parser_option_findings(FunctionIndex({f: ast.parse(f.read_text())}))

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
        assert not parser_option_findings(FunctionIndex({f: ast.parse(f.read_text())}))


@pytest.mark.parametrize('body', [
    'UNUSED = {"resolve_entities": True}\nparser = etree.XMLParser()\n',
    'options = {"resolve_entities": True}\noptions["resolve_entities"] = False\nparser = etree.XMLParser(**options)\n',
    'options = {"resolve_entities": True}\noptions.update(external)\nparser = etree.XMLParser(**options)\n',
])
def test_unused_or_unproven_parser_options_do_not_report(tmp_path, body):
    path = tmp_path / 'xml.py'
    tree = ast.parse('from lxml import etree\n' + body)
    assert not parser_option_findings(FunctionIndex({path: tree}))


def test_parser_import_alias_and_spread_at_call(tmp_path):
    path = tmp_path / 'xml.py'
    tree = ast.parse('from lxml.etree import XMLParser as Parser\nOPTIONS = {"resolve_entities": True}\nBASE = {**OPTIONS, "load_dtd": True}\ndef parse():\n    return Parser(**BASE)\n')
    findings = parser_option_findings(FunctionIndex({path: tree}))
    assert len(findings) == 1
    assert findings[0].start_line == 5
