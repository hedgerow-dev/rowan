"""Dedup must not move the surviving finding to another line (BACKLOG TE-04)."""

from __future__ import annotations

from pathlib import Path

from rowan.config import ScanConfig
from rowan.pipeline import ScanPipeline


def test_placeholder_neighbour_does_not_hide_real_secret(tmp_path: Path):
    (tmp_path / "config.py").write_text(
        'password = "xxxxxxxxxxxxxxxxxxxx"\napi_key = "sk-9Xq2vB7mLp4RtY8wZc3nHd6kFj1sAe5g"\n',
        encoding="utf-8",
    )
    (tmp_path / "control.py").write_text(
        'api_key = "sk-9Xq2vB7mLp4RtY8wZc3nHd6kFj1sAe5g"\n', encoding="utf-8"
    )
    result = ScanPipeline(ScanConfig(target=tmp_path, enable_sca=False)).run()
    by_file = {}
    for f in result.findings:
        if f.category.value == "secrets":
            by_file.setdefault(Path(f.file_path).name, []).append(f)
    assert "control.py" in by_file, [f.rule_id for f in result.findings]
    assert by_file.get("config.py"), "the real key on line 2 must survive its placeholder neighbour"
    assert {f.start_line for f in by_file["config.py"]} == {2}


def test_deserialization_dedup_uses_sink_not_file_proximity():
    from rowan.core.findings import Category, Finding, Severity, TaintFlow, TaintNode
    from rowan.passes.enrichment import EnrichmentPass

    def finding(source, sink):
        return Finding(
            rule_id='TNT-DESER-001', message='unpickling', severity=Severity.HIGH,
            category=Category.DESERIALIZATION, file_path='codec.py', start_line=sink,
            confidence=0.9, taint_flow=TaintFlow(
                source=TaintNode('api.py', source), sink=TaintNode('codec.py', sink, 4),
            ),
        )

    result = EnrichmentPass()._deduplicate([finding(1, 10), finding(2, 10), finding(3, 11)])
    assert {f.start_line for f in result} == {10, 11}
    assert len(result) == 2


def _sqli(source, sink):
    from rowan.core.findings import Category, Finding, Severity, TaintFlow, TaintNode

    return Finding(
        rule_id="TNT-SQLI-002", message="sqli", severity=Severity.HIGH,
        category=Category.INJECTION, file_path="app.py", start_line=sink, confidence=0.9,
        taint_flow=TaintFlow(source=TaintNode("app.py", source), sink=TaintNode("app.py", sink, 4)),
    )


def test_distinct_taint_sinks_are_not_collapsed_by_proximity():
    # #62: two execute() calls two lines apart, fed by two request reads,
    # used to become one finding; the second sink vanished from the report.
    from rowan.passes.enrichment import EnrichmentPass

    result = EnrichmentPass()._deduplicate([_sqli(9, 11), _sqli(12, 13)])
    assert sorted(f.start_line for f in result) == [11, 13]


def test_sources_reaching_one_sink_still_merge_and_report_the_count():
    import json

    from rowan.core.findings import ScanResult
    from rowan.passes.enrichment import EnrichmentPass
    from rowan.reporters import to_json

    result = EnrichmentPass()._deduplicate([_sqli(9, 11), _sqli(10, 11)])
    assert len(result) == 1
    [row] = json.loads(to_json(ScanResult(findings=result)))["findings"]
    assert row["occurrence_count"] == 2
