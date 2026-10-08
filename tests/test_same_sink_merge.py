"""EnrichmentPass._merge_same_sink_findings: one sink, one finding.

Different rules often report the same call: a taint rule with a source-to-sink
flow and a pattern rule for the same API, or two taint rules whose sinks
overlap. On RealVuln most duplicate reports were exactly this shape: same
file, same line, same category, a shared CWE. The survivor is the finding
with the strongest evidence, so a proven flow is never replaced by a pattern
match.
"""

from __future__ import annotations

from rowan.core.findings import Category, Finding, Severity, TaintFlow, TaintNode
from rowan.passes.enrichment import EnrichmentPass


def _finding(rule_id, *, line=10, category=Category.SSTI, cwe=(1336,), severity=Severity.HIGH,
             tier="pattern-only", flow=False, file_path="app.py"):
    return Finding(
        rule_id=rule_id,
        message=rule_id,
        severity=severity,
        category=category,
        file_path=file_path,
        start_line=line,
        cwe_ids=list(cwe),
        taint_flow=TaintFlow(source=TaintNode(file_path, 3), sink=TaintNode(file_path, line)) if flow else None,
        metadata={"evidence_tier": tier},
    )


def _merge(findings, thresholds=None):
    return EnrichmentPass._merge_same_sink_findings(findings, thresholds or {})


def test_taint_finding_survives_and_absorbs_pattern_finding_on_same_sink():
    pattern = _finding("NS-SSTI-001", severity=Severity.CRITICAL, cwe=(94, 1336))
    taint = _finding("TNT-SSTI-001", tier="taint-flow", flow=True)

    result = _merge([pattern, taint])

    assert [f.rule_id for f in result] == ["TNT-SSTI-001"]
    assert result[0].taint_flow is not None
    assert result[0].metadata["duplicate_rule_ids"] == ["NS-SSTI-001", "TNT-SSTI-001"]


def test_same_line_and_category_without_shared_cwe_stay_separate():
    # Missing HttpOnly and missing Secure on one set_cookie call are two issues.
    httponly = _finding("ns-websec-1004-001", category=Category.CONFIG, cwe=(1004,), tier="self-evident")
    secure = _finding("ns-websec-614-001", category=Category.CONFIG, cwe=(614,), tier="self-evident")

    assert len(_merge([httponly, secure])) == 2


def test_different_line_category_or_file_stay_separate():
    base = _finding("TNT-SSTI-001", tier="taint-flow", flow=True)
    other_line = _finding("NS-SSTI-001", line=11)
    other_category = _finding("NS-INJECT-001", category=Category.INJECTION)
    other_file = _finding("NS-SSTI-102", file_path="other.py")

    assert len(_merge([base, other_line, other_category, other_file])) == 4


def test_same_rule_twice_is_left_to_same_rule_deduplication():
    assert len(_merge([_finding("NS-SSTI-001"), _finding("NS-SSTI-001")])) == 2


def test_finding_below_min_confidence_does_not_absorb_others():
    # _apply_thresholds drops it next, which used to take the absorbed
    # finding with it (Langfail V58: ns-aiml-168 vanished inside NS-AIML-010).
    doomed = _finding("NS-AIML-010", category=Category.AI_ML, cwe=(78,), tier="self-evident")
    doomed.confidence = 0.3
    kept = _finding("ns-aiml-168", category=Category.AI_ML, cwe=(94, 78), tier="self-evident")
    kept.confidence = 0.3

    result = _merge([doomed, kept], {"NS-AIML-010": {"min_confidence": 0.5}})

    assert {f.rule_id for f in result} == {"NS-AIML-010", "ns-aiml-168"}
    assert "duplicate_rule_ids" not in kept.metadata


def test_disabled_rule_takes_no_part_in_the_merge():
    # _apply_thresholds runs next and deletes disabled rules outright.
    disabled = _finding("TNT-SSTI-002", tier="taint-flow", flow=True)
    enabled = _finding("NS-SSTI-001")

    result = _merge([disabled, enabled], {"TNT-SSTI-002": {"enabled": False}})

    assert {f.rule_id for f in result} == {"TNT-SSTI-002", "NS-SSTI-001"}
    assert "duplicate_rule_ids" not in enabled.metadata

