"""SSRF sinks are the URL argument, with any other arguments (#72).

TNT-SSRF-001 matched only one-argument calls, so `requests.get(u, timeout=5)`
and `requests.post(u, json=...)` were missed. TNT-SSRF-002 matched the whole
call, so a tainted `params=` or JSON body sent to a fixed URL was reported as
SSRF. Requires the Opengrep binary.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from rowan.taint.opengrep_adapter import OpengrepAdapter

RULES = [Path(__file__).parent.parent / "rules" / n
         for n in ("ai_ml_taint.yaml", "python_taint_extended.yaml")]
SSRF = {"TNT-SSRF-001", "TNT-SSRF-002"}

pytestmark = pytest.mark.skipif(
    not OpengrepAdapter().is_installed(),
    reason="Opengrep binary not installed; these tests need a live scan.",
)

HEADER = "import requests, httpx, urllib.request\nfrom flask import request\n\ndef h(session):\n    u = request.args.get('u')\n"


def _ssrf(tmp_path, line):
    (tmp_path / "app.py").write_text(HEADER + "    " + line + "\n", encoding="utf-8")
    findings = OpengrepAdapter().scan_with_rules(tmp_path, RULES, languages=["python"])
    return {f.rule_id for f in findings if f.rule_id in SSRF}


@pytest.mark.parametrize("line", [
    "requests.get(u)",
    "requests.get(u, timeout=5)",
    "requests.post(u, json={'a': 1})",
    "requests.get(url=u)",
    "requests.request('GET', u)",
    "httpx.post(u, data=b'x')",
    "session.get(u, timeout=3)",
    "urllib.request.urlopen(u, timeout=3)",
])
def test_tainted_url_is_ssrf(tmp_path, line):
    assert _ssrf(tmp_path, line), line


@pytest.mark.parametrize("line", [
    "requests.get('https://api.example.com/x', params={'q': u})",
    "requests.post('https://api.example.com/x', json={'q': u})",
    "httpx.post('https://api.example.com/x', headers={'X-Q': u})",
    "session.get('https://api.example.com/x', params={'q': u})",
])
def test_tainted_non_url_argument_is_not_ssrf(tmp_path, line):
    assert not _ssrf(tmp_path, line), line
