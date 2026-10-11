"""Regex rules see a keyword argument after a nested call (#71).

`\\([^)]*shell\\s*=\\s*True` stops at the first `)`, so in
`subprocess.run(build_cmd(x), shell=True)` it never reaches `shell=True`.
The argument span now allows one level of nested parentheses. Runs the
converted rules, the default engine. Requires the Opengrep binary.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from rowan.taint.opengrep_adapter import OpengrepAdapter

CONVERTED = Path(__file__).parent.parent / "rules" / "converted"

needs_opengrep = pytest.mark.skipif(
    not OpengrepAdapter().is_installed(),
    reason="Opengrep binary not installed; these tests need a live scan.",
)

CASES = [
    ("neuroscan.yaml", "NS-INJECT-003", "import subprocess\nsubprocess.run(build_cmd(x), shell=True)\n"),
    ("neuroscan.yaml", "NS-CONFIG-001", "import os\napp.run(host=os.getenv('H'), debug=True)\n"),
    ("ai_security.yaml", "ns-aiml-032", "import numpy as np\nnp.load(path_for(x), allow_pickle=True)\n"),
    ("security_surface.yaml", "NS-AUTH-101", "import jwt\njwt.decode(tok, get_key(), verify=False)\n"),
    ("ai_security.yaml", "ns-aiml-113", "load_dataset(name_for(x), trust_remote_code=True)\n"),
]


@needs_opengrep
@pytest.mark.parametrize("rule_file,rule_id,src", CASES)
def test_keyword_after_nested_call_is_seen(tmp_path, rule_file, rule_id, src):
    (tmp_path / "app.py").write_text(src, encoding="utf-8")
    findings = OpengrepAdapter().scan_with_rules(tmp_path, [CONVERTED / rule_file], languages=["python"])
    assert rule_id in {f.rule_id for f in findings}, src


def test_no_rule_stops_at_first_paren_before_a_keyword():
    """Lint: `\\([^)]*kw=` misses a keyword after any nested call."""
    bad = re.compile(r"\\\(\[\^\)\]\*\??(?:\\s\*)?[a-z_]+(?:\\s\*)?=")
    rules_dir = Path(__file__).parent.parent / "rules"
    offenders = [
        f"{path.name}:{n}"
        for path in sorted(rules_dir.glob("*.yaml"))
        for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1)
        if bad.search(line)
    ]
    assert not offenders, "use \\((?:[^()]|\\([^()]*\\))* instead of \\([^)]*: " + ", ".join(offenders)
