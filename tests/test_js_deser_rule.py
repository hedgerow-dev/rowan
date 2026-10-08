"""tnt-js-deser-001: request input reaches an unsafe JS deserializer.

JavaScript had only a presence rule (JS-DESER-001). The taint rule claims
sinks that execute code whatever the library version: node-serialize
unserialize (CVE-2017-5941), funcster deepDeserialize, cryo.parse, and
js-yaml load with an explicit DEFAULT_FULL_SCHEMA. Plain yaml.load is safe in
js-yaml 4, and the version is not visible, so it is not a taint sink.
Requires the Opengrep binary.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from rowan.taint.opengrep_adapter import OpengrepAdapter

RULES_DIR = Path(__file__).parent.parent / "rules"
RULE = "tnt-js-deser-001"

pytestmark = pytest.mark.skipif(
    not OpengrepAdapter().is_installed(),
    reason="Opengrep binary not installed; these tests need a live scan.",
)


def _hits(tmp_path, body: str):
    src = "const express = require('express');\nconst app = express();\n" + body + "\n"
    (tmp_path / "app.js").write_text(src, encoding="utf-8")
    findings = OpengrepAdapter().scan_with_rules(
        tmp_path, [RULES_DIR / "javascript_taint.yaml"], languages=["javascript"]
    )
    return [f for f in findings if f.rule_id == RULE]


class TestFlagged:
    def test_node_serialize_cookie(self, tmp_path):
        body = (
            "const serialize = require('node-serialize');\n"
            "app.get('/', (req, res) => {\n"
            "  const raw = Buffer.from(req.cookies.profile, 'base64').toString();\n"
            "  const obj = serialize.unserialize(raw);\n"
            "  res.send(obj.name);\n"
            "});"
        )
        assert _hits(tmp_path, body)

    def test_node_serialize_body(self, tmp_path):
        body = (
            "const ns = require('node-serialize');\n"
            "app.post('/import', (req, res) => { ns.unserialize(req.body.data); res.end(); });"
        )
        assert _hits(tmp_path, body)

    def test_js_yaml_full_schema(self, tmp_path):
        body = (
            "const yaml = require('js-yaml');\n"
            "app.post('/cfg', (req, res) => {\n"
            "  yaml.load(req.body.doc, { schema: yaml.DEFAULT_FULL_SCHEMA });\n"
            "  res.end();\n"
            "});"
        )
        assert _hits(tmp_path, body)


class TestNotFlagged:
    def test_json_parse_is_safe(self, tmp_path):
        assert not _hits(tmp_path, "app.post('/x', (req, res) => { JSON.parse(req.body.data); res.end(); });")

    def test_plain_yaml_load_is_not_a_taint_sink(self, tmp_path):
        body = (
            "const yaml = require('js-yaml');\n"
            "app.post('/cfg', (req, res) => { yaml.load(req.body.doc); res.end(); });"
        )
        assert not _hits(tmp_path, body)

    def test_constant_input(self, tmp_path):
        body = (
            "const serialize = require('node-serialize');\n"
            "app.get('/', (req, res) => { serialize.unserialize('{\"a\":1}'); res.end(); });"
        )
        assert not _hits(tmp_path, body)
