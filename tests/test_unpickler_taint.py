"""TNT-DESER-001 (rules/ai_ml_taint.yaml): untrusted bytes reaching
pickle.Unpickler(stream).load() are flagged, same as pickle.loads(...).

Requires the Opengrep binary (skipped if not installed).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from rowan.taint.opengrep_adapter import OpengrepAdapter

RULES_DIR = Path(__file__).parent.parent / "rules"

_adapter = OpengrepAdapter()
pytestmark = pytest.mark.skipif(
    not _adapter.is_installed(),
    reason="Opengrep binary not installed; these tests need a live scan.",
)


def _scan(tmp_path, body):
    (tmp_path / "app.py").write_text(
        "import io, pickle\n"
        "from flask import request\n"
        "def call():\n"
        f"    {body}\n",
        encoding="utf-8",
    )
    findings = OpengrepAdapter().scan_with_rules(
        tmp_path, [RULES_DIR / "ai_ml_taint.yaml"], languages=["python"]
    )
    return [f for f in findings if f.rule_id == "TNT-DESER-001"]


@pytest.mark.parametrize(
    "body",
    [
        "return pickle.Unpickler(io.BytesIO(request.data)).load()",
        "return cloudpickle.loads(request.data)",
    ],
)
def test_unsafe_unpickling_is_flagged(tmp_path, body):
    assert _scan(tmp_path, body)


def test_restricted_unpickler_subclass_is_not_flagged(tmp_path):
    (tmp_path / "app.py").write_text(
        "import io, pickle\n"
        "from flask import request\n"
        "class Restricted(pickle.Unpickler):\n"
        "    def find_class(self, module, name):\n"
        "        raise pickle.UnpicklingError(name)\n"
        "def call():\n"
        "    return Restricted(io.BytesIO(request.data)).load()\n",
        encoding="utf-8",
    )
    findings = OpengrepAdapter().scan_with_rules(
        tmp_path, [RULES_DIR / "ai_ml_taint.yaml"], languages=["python"]
    )
    assert not [f for f in findings if f.rule_id == "TNT-DESER-001"]


def test_local_bytes_are_not_flagged(tmp_path):
    assert not _scan(tmp_path, "return pickle.Unpickler(io.BytesIO(b'x')).load()")
