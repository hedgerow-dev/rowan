"""ReDoS and HDF5 external-storage rules (#53, #71). Requires the Opengrep binary."""

from __future__ import annotations

from pathlib import Path

import pytest

from rowan.taint.opengrep_adapter import OpengrepAdapter

RULES = Path(__file__).parent.parent / "rules"

pytestmark = pytest.mark.skipif(
    not OpengrepAdapter().is_installed(),
    reason="Opengrep binary not installed; these tests need a live scan.",
)


def _fires(tmp_path, rule_file, rule_id, src):
    (tmp_path / "app.py").write_text(src, encoding="utf-8")
    findings = OpengrepAdapter().scan_with_rules(tmp_path, [RULES / rule_file], languages=["python"])
    return any(f.rule_id == rule_id for f in findings)


REDOS = "ns-websec-1333-001"
WEB = "python_web_surface_opengrep.yaml"


@pytest.mark.parametrize(
    "src",
    [
        "import re\nEMAIL = re.compile(r'^([a-zA-Z0-9]+)*@x\\.com$')\n",
        "import re\nre.match(r'(\\w+)*$', s)\n",
        "import re\nre.search('(a+)+b', s)\n",
        "import re\nre.fullmatch(r'(a|a)*', s)\n",
    ],
)
def test_nested_quantifier_in_a_regex_call_fires(tmp_path, src):
    assert _fires(tmp_path, WEB, REDOS, src), src


@pytest.mark.parametrize(
    "src",
    [
        # Prose about ReDoS is not a regex.
        'def f():\n    """Avoid patterns like (\\w+)* in user input."""\n',
        "import re\nre.compile(r'^[a-z0-9]+(?:[._-][a-z0-9]+)*$')\n",
        "MSG = 'see (x*)* in the docs'\n",
    ],
)
def test_non_regex_or_safe_pattern_is_quiet(tmp_path, src):
    assert not _fires(tmp_path, WEB, REDOS, src), src


def test_wrapped_create_dataset_external_fires(tmp_path):
    src = (
        "import h5py\n"
        "with h5py.File('a.h5', 'w') as f:\n"
        "    f.create_dataset(\n"
        "        'd', shape=(10,),\n"
        "        external=[('data.bin', 0, 80)],\n"
        "    )\n"
    )
    assert _fires(tmp_path, "converted/ingest_surface.yaml", "ns-aiml-133", src)
