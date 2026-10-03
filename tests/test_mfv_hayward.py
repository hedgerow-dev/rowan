"""Rowan's model-file pass delegates to Hayward."""

import pickle

from rowan.config import ScanConfig
from rowan.pipeline import ScanPipeline


class _Evil:
    def __reduce__(self):
        import os

        return (os.system, ("echo pwned",))


def test_scan_reports_hayward_findings_for_a_malicious_pickle(tmp_path):
    (tmp_path / "model.pkl").write_bytes(pickle.dumps(_Evil()))
    result = ScanPipeline(ScanConfig(target=tmp_path, no_sca=True)).run()
    mfv = [f for f in result.findings if f.engine == "mfv"]
    assert any(f.rule_id == "MFV-PICKLE-001" and f.severity.value == "critical" for f in mfv)


def _onnx_external_data(location: str) -> bytes:
    """Minimal ModelProto whose one initializer stores its data externally."""

    def field(num: int, raw: bytes) -> bytes:
        return bytes([(num << 3) | 2, len(raw)]) + raw

    entry = field(1, b"location") + field(2, location.encode())
    tensor = field(8, b"w") + field(13, entry) + bytes([(14 << 3), 1])
    return field(7, field(5, tensor))


def test_model_file_findings_skip_web_code_gates(tmp_path):
    # A model file is dangerous on load whatever app it ships in, so the
    # deployment-profile and web-import gates for source code must not
    # demote it. Hayward rates an off-host external_data location HIGH.
    (tmp_path / "model.onnx").write_bytes(_onnx_external_data("http://marker.invalid/w"))
    result = ScanPipeline(ScanConfig(target=tmp_path, no_sca=True)).run()
    onnx = [f for f in result.findings if f.rule_id == "MFV-ONNX-004"]
    assert onnx, [f.rule_id for f in result.findings]
    assert all(f.severity.value == "high" for f in onnx)


def _evil_in(tmp_path, rel):
    path = tmp_path / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(pickle.dumps(_Evil()))


def _mfv_files(result):
    return {f.file_path.rsplit("/", 1)[-1] for f in result.findings if f.engine == "mfv"}


def test_exclude_applies_to_model_files(tmp_path):
    _evil_in(tmp_path, "fixtures/evil.pkl")
    result = ScanPipeline(ScanConfig(target=tmp_path, no_sca=True, extra_excludes=["fixtures"])).run()
    assert "evil.pkl" not in _mfv_files(result)


def test_rowanignore_applies_to_model_files_locally(tmp_path):
    _evil_in(tmp_path, "fixtures/evil.pkl")
    (tmp_path / ".rowanignore").write_text("fixtures/\n", encoding="utf-8")
    result = ScanPipeline(ScanConfig(target=tmp_path, no_sca=True)).run()
    assert "evil.pkl" not in _mfv_files(result)


def test_ci_does_not_let_the_repo_hide_its_model_files(tmp_path):
    _evil_in(tmp_path, "fixtures/evil.pkl")
    (tmp_path / ".rowanignore").write_text("fixtures/\n", encoding="utf-8")
    result = ScanPipeline(ScanConfig(target=tmp_path, no_sca=True, ci_mode=True)).run()
    assert "evil.pkl" in _mfv_files(result)


def test_model_source_presence_keeps_inventory_evidence():
    import json

    import hayward

    from rowan.core.findings import ScanResult
    from rowan.passes.enrichment import EnrichmentPass
    from rowan.passes.mfv import _to_rowan
    from rowan.reporters import to_json

    raw = hayward.Finding(
        rule_id="MFV-EXAMPLE-PRESENCE", message="Source is present",
        severity=hayward.Severity.LOW,
        category=hayward.Category.DESERIALIZATION, file_path="example.pt",
        metadata={"rule_class": "presence", "evidence_tier": "presence"},
    )
    finding = _to_rowan(raw)
    EnrichmentPass()._cap_unverified_severity([finding])
    assert finding.metadata["evidence_tier"] == "presence"
    report = json.loads(to_json(ScanResult(findings=[finding])))
    assert report["findings"][0]["rule_class"] == "inventory"
    assert finding.severity.value == "low"


def test_model_execution_evidence_is_not_inventory():
    import json

    import hayward

    from rowan.core.findings import ScanResult
    from rowan.passes.enrichment import EnrichmentPass
    from rowan.passes.mfv import _to_rowan
    from rowan.reporters import to_json

    raw = hayward.Finding(
        rule_id="MFV-EXAMPLE-EXEC", message="Explicit execution operation",
        severity=hayward.Severity.HIGH,
        category=hayward.Category.DESERIALIZATION, file_path="example.pt",
        metadata={"evidence_tier": "static-operation"},
    )
    finding = _to_rowan(raw)
    EnrichmentPass()._cap_unverified_severity([finding])
    report = json.loads(to_json(ScanResult(findings=[finding])))
    assert report["findings"][0]["rule_class"] == "vulnerability"
    assert finding.severity.value == "high"
