"""XML external entity (CWE-611) taint rule for C#.

Unlike Java, modern .NET parses safely by default, and the runtime version is
not visible. The rule only flags a parser whose external entities or DTD
processing is explicitly turned on, which is unsafe in every version. Python's
equivalent (an explicitly unsafe lxml XMLParser) is ns-websec-611-001.
Requires the Opengrep binary.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from rowan.taint.opengrep_adapter import OpengrepAdapter

RULES_DIR = Path(__file__).parent.parent / "rules"

pytestmark = pytest.mark.skipif(
    not OpengrepAdapter().is_installed(),
    reason="Opengrep binary not installed; these tests need a live scan.",
)


def _hits(tmp_path, filename, rule_file, source, rule_id, language):
    (tmp_path / filename).write_text(source, encoding="utf-8")
    findings = OpengrepAdapter().scan_with_rules(
        tmp_path, [RULES_DIR / rule_file], languages=[language]
    )
    return [f for f in findings if f.rule_id == rule_id]


class TestCSharp:
    RULE = "tnt-cs-xxe-001"

    def _scan(self, tmp_path, body):
        src = (
            "using System.IO;\nusing System.Xml;\nusing Microsoft.AspNetCore.Mvc;\n"
            "public class ImportController : Controller {\n"
            "  public IActionResult Import([FromBody] string xml) {\n"
            f"{body}"
            "    return Ok();\n  }\n}\n"
        )
        return _hits(tmp_path, "ImportController.cs", "csharp_taint.yaml", src, self.RULE, "csharp")

    def test_xml_document_with_url_resolver(self, tmp_path):
        body = (
            "    var doc = new XmlDocument();\n"
            "    doc.XmlResolver = new XmlUrlResolver();\n"
            "    doc.LoadXml(xml);\n"
        )
        assert self._scan(tmp_path, body)

    def test_xml_reader_with_dtd_parse(self, tmp_path):
        body = (
            "    var settings = new XmlReaderSettings();\n"
            "    settings.DtdProcessing = DtdProcessing.Parse;\n"
            "    var reader = XmlReader.Create(new StringReader(xml), settings);\n"
        )
        assert self._scan(tmp_path, body)

    def test_default_xml_document_is_safe(self, tmp_path):
        body = "    var doc = new XmlDocument();\n    doc.LoadXml(xml);\n"
        assert not self._scan(tmp_path, body)

