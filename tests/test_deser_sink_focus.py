"""Deserialization and code-execution sinks: the data argument, any arity (#72).

TNT-DESER-001, TNT-DESER-003 and TNT-INJECT-001 matched only one-argument
calls, missing `pickle.load(f, encoding=...)`, `yaml.load(d, Loader=...)`,
`exec(code, {})` and `eval(code, g)`. TNT-DESER-002 matched the whole call, so
a tainted `map_location=` fired. Requires the Opengrep binary.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from rowan.taint.opengrep_adapter import OpengrepAdapter

RULES = [Path(__file__).parent.parent / "rules" / "ai_ml_taint.yaml"]
IDS = {"TNT-DESER-001", "TNT-DESER-002", "TNT-DESER-003", "TNT-INJECT-001"}

pytestmark = pytest.mark.skipif(
    not OpengrepAdapter().is_installed(),
    reason="Opengrep binary not installed; these tests need a live scan.",
)

HEADER = "import pickle, torch, yaml\nfrom flask import request\n\ndef h():\n    d = request.args.get('d')\n"


def _hits(tmp_path, line):
    (tmp_path / "app.py").write_text(HEADER + "    " + line + "\n", encoding="utf-8")
    findings = OpengrepAdapter().scan_with_rules(tmp_path, RULES, languages=["python"])
    return {f.rule_id for f in findings if f.rule_id in IDS}


@pytest.mark.parametrize("line", [
    "pickle.loads(d)",
    "pickle.loads(d, encoding='latin1')",
    "torch.load(d)",
    "torch.load(d, map_location='cpu')",
    "yaml.load(d)",
    "yaml.load(d, Loader=yaml.Loader)",
    "yaml.load(d, yaml.UnsafeLoader)",
    "yaml.load_all(d, Loader=yaml.FullLoader)",
    "eval(d)",
    "eval(d, {'__builtins__': {}})",
    "exec(d, {})",
])
def test_tainted_data_argument_fires(tmp_path, line):
    assert _hits(tmp_path, line), line


@pytest.mark.parametrize("line", [
    "torch.load('model.pt', map_location=d)",
    "yaml.load(d, Loader=yaml.SafeLoader)",
    "yaml.load(d, yaml.CSafeLoader)",
    "exec('print(1)', {'x': d})",
])
def test_tainted_other_argument_or_safe_loader_does_not_fire(tmp_path, line):
    assert not _hits(tmp_path, line), line
