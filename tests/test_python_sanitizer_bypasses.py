"""Sanitizers that cleared taint on values that are still dangerous (#74).

Each case is a real vulnerability that a "sanitizer" silenced, next to the
guard that genuinely makes it safe. Requires the Opengrep binary.
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

WEB = "import subprocess, shlex, requests, pathlib\nfrom urllib.parse import urlparse\nfrom flask import request\n\ndef h(cur):\n    x = request.args.get('x')\n"
DJANGO = "from django.utils.html import strip_tags, escape\nfrom django.utils.safestring import mark_safe\n\ndef v(request):\n    x = request.GET.get('x')\n"
LLM = "import os, json\n\ndef h(client, cursor):\n    r = client.chat.completions.create(model='m', messages=[])\n    text = r.choices[0].message.content\n"


def _fires(tmp_path, rule_file, rule_id, header, line):
    src = header + "    " + line + "\n"
    (tmp_path / "app.py").write_text(src, encoding="utf-8")
    findings = OpengrepAdapter().scan_with_rules(tmp_path, [RULES_DIR / rule_file], languages=["python"])
    sink_line = src.count("\n")
    return any(f.rule_id == rule_id and f.start_line == sink_line for f in findings)


@pytest.mark.parametrize("rule_file,rule_id,header,line", [
    # Bound parameters do not make an f-string query safe.
    ("python_taint_extended.yaml", "TNT-SQLI-002", WEB, "cur.execute(f\"SELECT * FROM t WHERE n = '{x}' AND a = %s\", (1,))"),
    # shlex.quote("--upload-pack=x") is unchanged: still an injected option.
    ("python_taint.yaml", "TNT-ARG-001", WEB, "subprocess.run(['git', 'log', shlex.quote(x)])"),
    # Django: strip_tags gives no guarantee the result is safe HTML.
    ("web_taint.yaml", "TNT-XSS-002", DJANGO, "return mark_safe(strip_tags(x))"),
    # Parsing a URL does not validate where it points.
    ("python_taint_extended.yaml", "TNT-SSRF-002", WEB, "requests.get(urlparse(x).geturl())"),
    # resolve() without a containment check does not confine.
    ("python_framework_hardening_taint.yaml", "TNT-PY-FWK-PATH-001",
     "import pathlib\nfrom flask import request\n\ndef h(root):\n    x = request.get_json()['p']\n",
     "pathlib.Path('/srv').glob(str(root.joinpath(x).resolve()))"),
    # A model that returns JSON still chooses the command and the SQL.
    ("llm_output_taint.yaml", "TNT-LLMOUT-002", LLM, "data = json.loads(text); os.system(data['command'])"),
    ("llm_output_taint.yaml", "TNT-LLMOUT-001", LLM, "cursor.execute(text, (1,))"),
])
def test_bypassed_sanitizer_no_longer_hides_the_flow(tmp_path, rule_file, rule_id, header, line):
    assert _fires(tmp_path, rule_file, rule_id, header, line), line


@pytest.mark.parametrize("rule_file,rule_id,header,line", [
    ("python_taint_extended.yaml", "TNT-SQLI-002", WEB, "cur.execute('SELECT * FROM t WHERE n = %s', (x,))"),
    ("web_taint.yaml", "TNT-XSS-002", DJANGO, "return mark_safe(escape(x))"),
])
def test_real_guards_still_clear(tmp_path, rule_file, rule_id, header, line):
    assert not _fires(tmp_path, rule_file, rule_id, header, line), line
