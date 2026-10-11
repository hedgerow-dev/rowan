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



# Different rules tag one eval/exec call as CWE-94 or 95, under different
# categories; on RealVuln that was the most common unmerged duplicate.
def test_related_code_execution_cwes_merge_across_categories():
    inject = _finding("TNT-INJECT-004", category=Category.INJECTION, cwe=(94,), tier="taint-flow", flow=True)
    route = _finding("HTTP-ROUTE-001", category=Category.INJECTION, cwe=(95,), tier="taint-flow")
    aiml = _finding("ns-aiml-137", category=Category.AI_ML, cwe=(94, 693), tier="pattern-only")

    result = _merge([inject, route, aiml])

    assert len(result) == 1
    assert len(result[0].metadata["duplicate_rule_ids"]) == 3


def test_debug_mode_cwes_merge():
    a = _finding("NS-CONFIG-001", category=Category.CONFIG, cwe=(215,), tier="self-evident")
    b = _finding("ns-fw-py-004", category=Category.CONFIG, cwe=(489,), tier="self-evident")

    assert len(_merge([a, b])) == 1


def _flow(sink_line, through, cwe=(79,), category=Category.XSS):
    f = _finding("TNT-XSS-001", line=sink_line, category=category, cwe=cwe, tier="taint-flow", flow=True)
    f.taint_flow.intermediate = [TaintNode("app.py", line) for line in through]
    return f


# `body = Template(...).render(card=card)` then `return HTMLResponse(body)`:
# a pattern rule flags the first line, the taint rule the second, one bug.
def test_pattern_finding_on_the_taint_trace_is_absorbed():
    pattern = _finding("NS-XSS-001", line=87, category=Category.XSS, cwe=(79,))
    taint = _flow(88, through=[87])

    result = _merge([pattern, taint])

    assert [f.rule_id for f in result] == ["TNT-XSS-001"]
    assert result[0].metadata["duplicate_rule_ids"] == ["NS-XSS-001", "TNT-XSS-001"]


def test_trace_line_with_unrelated_cwe_stays_separate():
    ssti = _finding("NS-SSTI-001", line=87, category=Category.SSTI, cwe=(94, 1336))
    assert len(_merge([ssti, _flow(88, through=[87])])) == 2


def test_taint_finding_on_the_trace_is_never_absorbed():
    # Its own proven flow to its own sink: a second issue, not a duplicate.
    earlier_sink = _flow(87, through=[])
    assert len(_merge([earlier_sink, _flow(88, through=[87])])) == 2


def test_pattern_finding_off_the_trace_stays_separate():
    pattern = _finding("NS-XSS-001", line=80, category=Category.XSS, cwe=(79,))
    assert len(_merge([pattern, _flow(88, through=[87])])) == 2


def test_survivor_keeps_a_trace_when_evidence_ties():
    # HTTP-ROUTE-001 is taint-flow tier but has no trace to show; it used to
    # win on rule id alone.
    route = _finding("HTTP-ROUTE-001", category=Category.INJECTION, cwe=(95,), tier="taint-flow")
    inject = _finding("TNT-INJECT-004", category=Category.INJECTION, cwe=(94,), tier="taint-flow", flow=True)

    result = _merge([route, inject])

    assert [f.rule_id for f in result] == ["TNT-INJECT-004"]


def test_merged_finding_keeps_every_cwe_its_duplicates_had():
    # Rules label one issue with related but different CWEs; the merged
    # finding reports all of them rather than whichever rule survived.
    cmdi = _finding("TNT-CMDI-001", category=Category.COMMAND_INJECTION, cwe=(78,), tier="taint-flow", flow=True)
    aiml = _finding("ns-aiml-168", category=Category.AI_ML, cwe=(94, 78), tier="pattern-only")

    [merged] = _merge([cmdi, aiml])

    assert merged.rule_id == "TNT-CMDI-001"
    assert merged.cwe_ids[0] == 78
    assert sorted(merged.cwe_ids) == [78, 94]


def test_merged_finding_is_as_severe_and_confident_as_its_strongest_member():
    # An INFO survivor (stronger evidence tier) absorbing a MEDIUM injection
    # finding hid the issue from the default view.
    info = _finding("ns-aiml-168", category=Category.AI_ML, cwe=(94, 78), severity=Severity.INFO, tier="self-evident")
    info.confidence = 0.3
    medium = _finding("NS-INJECT-004", category=Category.INJECTION, cwe=(78,), severity=Severity.MEDIUM)
    medium.confidence = 0.7

    [merged] = _merge([info, medium])

    # Without a proven flow on either side, the most severe report represents
    # the issue, so the default view treats it as injection, not inventory.
    assert merged.rule_id == "NS-INJECT-004"
    assert merged.severity == Severity.MEDIUM
    assert merged.confidence == 0.7


# #61: a taint finding that enrichment marked taint_unconfirmed (its source
# could not be traced to external input) is not a proven flow.
def test_unconfirmed_taint_finding_does_not_outrank_a_pattern_finding():
    unconfirmed = _finding("TNT-CMDI-001", category=Category.COMMAND_INJECTION, cwe=(78,),
                           severity=Severity.INFO, tier="taint-flow", flow=True)
    unconfirmed.metadata["taint_unconfirmed"] = True
    pattern = _finding("NS-CMDI-002", category=Category.COMMAND_INJECTION, cwe=(78,),
                       severity=Severity.MEDIUM)

    [merged] = _merge([unconfirmed, pattern])

    assert merged.rule_id == "NS-CMDI-002"
    assert not merged.metadata.get("taint_unconfirmed")


def test_unconfirmed_taint_finding_does_not_absorb_along_its_trace():
    taint = _flow(88, through=[87])
    taint.metadata["taint_unconfirmed"] = True
    pattern = _finding("NS-XSS-001", line=87, category=Category.XSS, cwe=(79,))

    assert len(_merge([pattern, taint])) == 2


def test_code_and_command_injection_on_one_line_stay_separate():
    # `eval(x); os.system(y)`: CWE-95 and CWE-78 are two different issues.
    code = _finding("TNT-INJECT-001", category=Category.INJECTION, cwe=(95,), tier="taint-flow", flow=True)
    cmd = _finding("TNT-CMDI-001", category=Category.COMMAND_INJECTION, cwe=(78,), tier="taint-flow", flow=True)

    assert len(_merge([code, cmd])) == 2


def test_command_injection_merges_across_categories_on_cwe_78():
    cmd = _finding("TNT-CMDI-001", category=Category.COMMAND_INJECTION, cwe=(78,), tier="taint-flow", flow=True)
    aiml = _finding("ns-aiml-168", category=Category.AI_ML, cwe=(94, 78), tier="pattern-only")

    assert len(_merge([cmd, aiml])) == 1
