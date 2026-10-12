"""Java XXE-factory and cookie-flag rules as structural rules (#55, #71).

The regex versions fired on every factory and every `new Cookie(` because
the hardening calls are on later lines. Requires the Opengrep binary.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from rowan.taint.opengrep_adapter import OpengrepAdapter

RULES = Path(__file__).parent.parent / "rules"

pytestmark = pytest.mark.skipif(
    not OpengrepAdapter().is_installed(),
    reason="Opengrep binary not installed; these tests need a live scan.",
)


def _fires(tmp_path, rule_id, body):
    src = "class C {\n    void f(HttpServletResponse resp, String v) throws Exception {\n" + body + "    }\n}\n"
    (tmp_path / "C.java").write_text(src, encoding="utf-8")
    findings = OpengrepAdapter().scan_with_rules(tmp_path, [RULES / "java_opengrep.yaml"], languages=["java"])
    return any(f.rule_id == rule_id for f in findings)


XXE_FIRES = [
    "        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();\n        dbf.newDocumentBuilder();\n",
    "        SAXParserFactory spf = SAXParserFactory.newInstance();\n        spf.newSAXParser();\n",
    "        XMLInputFactory xif = XMLInputFactory.newInstance();\n        xif.createXMLStreamReader(in);\n",
    "        TransformerFactory tf = TransformerFactory.newInstance();\n        tf.newTransformer();\n",
    # One feature alone is partial hardening.
    "        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();\n"
    '        dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);\n'
    "        dbf.newDocumentBuilder();\n",
]
XXE_QUIET = [
    "        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();\n"
    '        dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);\n'
    "        dbf.newDocumentBuilder();\n",
    "        SAXParserFactory spf = SAXParserFactory.newInstance();\n"
    '        spf.setFeature("http://xml.org/sax/features/external-general-entities", false);\n'
    '        spf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);\n'
    "        spf.newSAXParser();\n",
    "        XMLInputFactory xif = XMLInputFactory.newInstance();\n"
    "        xif.setProperty(XMLInputFactory.SUPPORT_DTD, false);\n"
    "        xif.createXMLStreamReader(in);\n",
    "        TransformerFactory tf = TransformerFactory.newInstance();\n"
    '        tf.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");\n'
    "        tf.newTransformer();\n",
]
COOKIE_FIRES = [
    '        Cookie c = new Cookie("sid", v);\n        resp.addCookie(c);\n',
    '        Cookie c = new Cookie("sid", v);\n        c.setSecure(true);\n        resp.addCookie(c);\n',
]
COOKIE_QUIET = [
    '        Cookie c = new Cookie("sid", v);\n        c.setHttpOnly(true);\n        c.setSecure(true);\n        resp.addCookie(c);\n',
    '        Cookie c = new Cookie("sid", v);\n        c.setSecure(true);\n        c.setHttpOnly(true);\n        resp.addCookie(c);\n',
]


@pytest.mark.parametrize("body", XXE_FIRES)
def test_unhardened_xml_factory_fires(tmp_path, body):
    assert _fires(tmp_path, "JA-XXE-001", body), body


@pytest.mark.parametrize("body", XXE_QUIET)
def test_hardened_xml_factory_is_quiet(tmp_path, body):
    assert not _fires(tmp_path, "JA-XXE-001", body), body


@pytest.mark.parametrize("body", COOKIE_FIRES)
def test_cookie_missing_a_flag_fires(tmp_path, body):
    assert _fires(tmp_path, "JA-AUTH-001", body), body


@pytest.mark.parametrize("body", COOKIE_QUIET)
def test_cookie_with_both_flags_is_quiet(tmp_path, body):
    assert not _fires(tmp_path, "JA-AUTH-001", body), body
