"""Every rule must declare a category the scanner actually understands.

An unknown category silently becomes `general` (NeuroScan) or a guess from
the rule id (Opengrep). `general` pattern findings are left out of the
default report view, so a typo here can hide a code-execution rule.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from rowan.core.findings import Category

RULES_DIR = Path(__file__).parent.parent / "rules"
VALID = {c.value for c in Category}


def _rules():
    for path in sorted(RULES_DIR.glob("*.yaml")):
        for rule in (yaml.safe_load(path.read_text(encoding="utf-8")) or {}).get("rules", []) or []:
            yield path.name, rule


@pytest.mark.parametrize(("file", "rule"), list(_rules()), ids=lambda v: v if isinstance(v, str) else v["id"])
def test_rule_category_is_valid(file, rule):
    category = rule.get("category") or (rule.get("metadata") or {}).get("category")
    assert str(category).lower() in VALID, f"{file}:{rule['id']} has category {category!r}"


def test_rule_files_have_no_duplicate_keys():
    """YAML keeps the last duplicate key, so a pasted block silently replaces a rule's metadata."""
    duplicates = []

    class Loader(yaml.SafeLoader):
        pass

    def construct_mapping(loader, node, deep=False):
        seen = set()
        for key_node, _ in node.value:
            key = loader.construct_object(key_node, deep=deep)
            if key in seen:
                duplicates.append(f"{loader.name}:{key_node.start_mark.line + 1} {key}")
            seen.add(key)
        return yaml.SafeLoader.construct_mapping(loader, node, deep)

    Loader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, construct_mapping)
    for path in sorted(RULES_DIR.glob("*.yaml")):
        with path.open(encoding="utf-8") as stream:
            yaml.load(stream, Loader=Loader)
    assert duplicates == []


def test_converted_manifest_categories_are_valid():
    manifest = json.loads((RULES_DIR / "converted" / "_manifest.json").read_text(encoding="utf-8"))
    bad = [r["id"] for r in manifest["rules"] if r["category"] not in VALID]
    assert bad == []
