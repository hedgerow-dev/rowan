"""Taint preflight reuses the scan-owned Python inventory."""


from rowan.config import ScanConfig
from rowan.core.findings import ScanResult
from rowan.passes.base import (
    ScanContext,
    SourceFile,
    SourceInventory,
)
from rowan.passes.taint import TaintPass
from rowan.taint.opengrep_adapter import ScanOutcome


class _CapturingAdapter:
    def __init__(self):
        self.candidates = None
        self.probes = 0

    def is_installed(self):
        self.probes += 1
        return True

    def get_version(self):
        return "0.0-test"

    def configure(self, **kwargs):
        return None

    def scan_collect_with_rules(self, *args, **kwargs):
        self.candidates = kwargs.get("candidates")
        return ScanOutcome(status="ok")


def _run_with_inventory(tmp_path, inventory):
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "test_taint.yaml").write_text("rules: []\n", encoding="utf-8")
    target = tmp_path / "target"
    target.mkdir()
    context = ScanContext(
        target_path=target,
        config=ScanConfig(target=target),
        result=ScanResult(),
        source_inventory=inventory,
    )
    taint_pass = TaintPass(rules_dir=rules)
    adapter = _CapturingAdapter()
    taint_pass._adapter = adapter
    result = taint_pass.run(context)
    return adapter, result


def test_taint_pass_forwards_exact_published_inventory(tmp_path):
    target = tmp_path / "target"
    python_file = target / "app.py"
    js_file = target / "app.js"
    inventory = SourceInventory(files=(
        SourceFile(path=python_file, languages=frozenset({"python"})),
        SourceFile(path=js_file, languages=frozenset({"javascript"})),
    ))

    adapter, _ = _run_with_inventory(tmp_path, inventory)

    assert adapter.candidates == (python_file, js_file)


def test_taint_pass_forwards_empty_inventory_without_widening(tmp_path):
    adapter, result = _run_with_inventory(tmp_path, SourceInventory())

    assert adapter.candidates is None
    assert adapter.probes == 0
    assert result.files_scanned == 0
    assert result.metadata["opengrep_execution"] == {
        "status": "ok",
        "mode": "taint",
        "target_count": 0,
        "reason": "no applicable source targets",
    }
