"""SSTI sinks are the template string, not the render context (#72).

A tainted template string runs attacker code; a tainted value passed to
render() is data that Jinja escapes. TNT-SSTI-001/003 treated any
`.render(...)` with a tainted argument as SSTI, TNT-SSTI-002 matched whole
calls, and TNT-ML-001 matched the stdlib `string.Template`, which has no code
execution. Requires the Opengrep binary.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from rowan.taint.opengrep_adapter import OpengrepAdapter

RULES = [Path(__file__).parent.parent / "rules" / n for n in (
    "ai_ml_taint.yaml", "python_taint.yaml", "python_taint_extended.yaml", "ml_taint.yaml", "web_taint.yaml",
)]
SSTI = {"TNT-SSTI-001", "TNT-SSTI-002", "TNT-SSTI-003", "TNT-ML-001"}

pytestmark = pytest.mark.skipif(
    not OpengrepAdapter().is_installed(),
    reason="Opengrep binary not installed; these tests need a live scan.",
)


def _rules_hit(tmp_path, imports, line):
    src = f"{imports}\nfrom flask import request, render_template_string\n\ndef h(env):\n    t = request.args.get('t')\n    {line}\n"
    (tmp_path / "app.py").write_text(src, encoding="utf-8")
    findings = OpengrepAdapter().scan_with_rules(tmp_path, RULES, languages=["python"])
    return {f.rule_id for f in findings if f.start_line == 6}


@pytest.mark.parametrize("imports,line", [
    ("import jinja2", "render_template_string(t)"),
    ("import jinja2", "jinja2.Template(t).render()"),
    ("import jinja2", "jinja2.Environment().from_string(t)"),
    ("import jinja2", "env.from_string(t)"),
    ("from jinja2 import Template", "Template(t).render()"),
    ("import django.template", "django.template.Template(t)"),
])
def test_tainted_template_string_is_ssti(tmp_path, imports, line):
    assert _rules_hit(tmp_path, imports, line) & SSTI, line


@pytest.mark.parametrize("imports,line", [
    ("import jinja2", "render_template_string('<p>{{ x }}</p>', x=t)"),
    ("import jinja2", "env.get_template('a.html').render(user=t)"),
    ("from jinja2 import Template", "Template('hi {{ u }}').render(u=t)"),
    ("from string import Template", "Template(t).substitute(x=1)"),
    ("from packaging.version import Version", "Version.from_string(t)"),
])
def test_tainted_context_or_non_jinja_template_is_not_ssti(tmp_path, imports, line):
    assert not _rules_hit(tmp_path, imports, line) & SSTI, line


def test_constant_template_with_tainted_context_is_not_xss(tmp_path):
    # Jinja autoescapes {{ x }}; only the template string is dangerous.
    assert "TNT-XSS-001" not in _rules_hit(tmp_path, "import jinja2", "render_template_string('<p>{{ x }}</p>', x=t)")
