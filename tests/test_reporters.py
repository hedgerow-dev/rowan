"""Tests for reporters (SARIF, JSON, text output)."""

import json
import types

import pytest

from rowan.core.findings import Category, Finding, ScanResult, Severity, TaintFlow, TaintNode
from rowan.reporters import hunt_to_json, to_html, to_json, to_sarif, to_text, write_report


@pytest.fixture
def sample_result():
    return ScanResult(
        findings=[
            Finding(
                rule_id="NS-DESER-001",
                message="Unsafe pickle loads detected",
                severity=Severity.CRITICAL,
                category=Category.DESERIALIZATION,
                file_path="src/app.py",
                start_line=15,
                end_line=15,
                confidence=0.95,
                cwe_ids=[502],
                engine="neuroscan",
            ),
            Finding(
                rule_id="TNT-SSRF-001",
                message="User URL reaches HTTP request",
                severity=Severity.HIGH,
                category=Category.SSRF,
                file_path="src/api.py",
                start_line=42,
                end_line=42,
                confidence=0.80,
                cwe_ids=[918],
                engine="opengrep",
            ),
        ],
        files_scanned=12,
        duration_seconds=2.5,
    )


def test_sarif_output(sample_result):
    sarif = to_sarif(sample_result)

    assert sarif["version"] == "2.1.0"
    assert "$schema" in sarif
    runs = sarif["runs"]
    assert len(runs) == 1

    driver = runs[0]["tool"]["driver"]
    assert driver["name"] == "Rowan"
    assert len(driver["rules"]) == 2

    results = runs[0]["results"]
    assert len(results) == 2

    assert results[0]["ruleId"] == "NS-DESER-001"
    assert results[0]["locations"][0]["physicalLocation"]["region"]["startLine"] == 15


def test_sarif_file_level_finding_omits_invalid_text_region():
    result = ScanResult(
        findings=[
            Finding(
                rule_id="SCA-GHSA-example",
                message="Dependency advisory",
                severity=Severity.HIGH,
                category=Category.SUPPLY_CHAIN,
                file_path="requirements.txt",
                start_line=0,
                engine="depguard",
            ),
        ],
    )

    location = to_sarif(result)["runs"][0]["results"][0]["locations"][0]["physicalLocation"]

    assert location["artifactLocation"]["uri"] == "requirements.txt"
    assert "region" not in location


def test_sarif_relativizes_paths_inside_source_root(tmp_path):
    source = tmp_path / "src" / "app.py"
    source.parent.mkdir()
    source.write_text("pass\n", encoding="utf-8")
    result = ScanResult(findings=[
        Finding(
            rule_id="TEST-001", message="test", severity=Severity.HIGH,
            category=Category.GENERAL, file_path=str(source), start_line=1,
        )
    ])

    sarif = to_sarif(result, str(tmp_path))
    driver_rule = sarif["runs"][0]["tool"]["driver"]["rules"][0]
    location = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]

    assert location["artifactLocation"]["uri"] == "src/app.py"
    assert driver_rule["defaultConfiguration"]["level"] == "error"
    assert driver_rule["help"]["text"] == "test"


def test_sarif_uri_uses_forward_slashes_for_relative_paths(tmp_path):
    root = tmp_path / "project"
    path = root / "src" / "app.py"
    path.parent.mkdir(parents=True)
    path.write_text("pass\n", encoding="utf-8")

    assert to_sarif(
        ScanResult(findings=[Finding(
            rule_id="TEST-001", message="test", severity=Severity.HIGH,
            category=Category.GENERAL, file_path=str(path), start_line=1,
        )]),
        str(root),
    )["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "src/app.py"


def test_sarif_output_includes_code_flows_for_taint_flow_findings():
    """Issue #154 Defect 1 acceptance: a finding carrying a TaintFlow (e.g. a
    cross-file CF-SINK-001 finding) must surface a SARIF codeFlows entry so
    GitHub code scanning / IDE SARIF viewers can render the hop story,
    instead of a bare location."""
    result = ScanResult(
        findings=[
            Finding(
                rule_id="CF-SINK-001",
                message="handler() reaches a sink via helper() from b.py.",
                severity=Severity.HIGH,
                category=Category.GENERAL,
                file_path="a.py",
                start_line=6,
                confidence=0.75,
                engine="crossfile",
                taint_flow=TaintFlow(
                    source=TaintNode(file_path="a.py", line=6),
                    sink=TaintNode(file_path="c.py", line=4),
                    intermediate=[TaintNode(file_path="b.py", line=3)],
                ),
                metadata={"caller": "handler", "callee_name": "helper"},
            ),
            Finding(
                rule_id="NS-DESER-001",
                message="no taint flow at all",
                severity=Severity.HIGH,
                category=Category.DESERIALIZATION,
                file_path="src/app.py",
                start_line=1,
                engine="neuroscan",
            ),
        ],
    )
    sarif = to_sarif(result)
    results = sarif["runs"][0]["results"]

    cf_result = next(r for r in results if r["ruleId"] == "CF-SINK-001")
    assert "codeFlows" in cf_result
    locations = cf_result["codeFlows"][0]["threadFlows"][0]["locations"]
    assert len(locations) == 3  # source + 1 intermediate + sink
    uris = [
        loc["location"]["physicalLocation"]["artifactLocation"]["uri"]
        for loc in locations
    ]
    assert uris == ["a.py", "b.py", "c.py"]
    assert locations[-1]["location"]["physicalLocation"]["region"]["startLine"] == 4

    no_flow_result = next(r for r in results if r["ruleId"] == "NS-DESER-001")
    assert "codeFlows" not in no_flow_result


def test_json_output(sample_result):
    output = to_json(sample_result)
    data = json.loads(output)

    assert data["scanner"] == "rowan"
    assert data["summary"]["total"] == 2
    assert data["summary"]["critical"] == 1
    assert data["summary"]["high"] == 1
    assert len(data["findings"]) == 2

    f = data["findings"][0]
    assert f["rule_id"] == "NS-DESER-001"
    assert f["severity"] == "critical"
    assert f["line"] == 15


def test_text_output(sample_result):
    text = to_text(sample_result)

    assert "Rowan Scan Report" in text
    assert "Files scanned:  12" in text
    assert "CRITICAL" in text
    assert "NS-DESER-001" in text
    assert "src/app.py:15" in text


def test_json_output_splits_sca_and_code_counts():
    """SCA (depguard) findings carry no file/line context and must be
    reported separately from code-analysis findings so consumers can tell
    dependency-CVE noise apart from actual source findings."""
    result = ScanResult(
        findings=[
            Finding(
                rule_id="NS-DESER-001",
                message="Unsafe pickle loads detected",
                severity=Severity.CRITICAL,
                category=Category.DESERIALIZATION,
                file_path="src/app.py",
                start_line=15,
                engine="neuroscan",
            ),
            Finding(
                rule_id="SCA-GHSA-xxxx",
                message="CVE in aiohttp: ",
                severity=Severity.MEDIUM,
                category=Category.SUPPLY_CHAIN,
                file_path="",
                start_line=0,
                engine="depguard",
            ),
            Finding(
                rule_id="SCA-GHSA-yyyy",
                message="CVE in pillow: ",
                severity=Severity.MEDIUM,
                category=Category.SUPPLY_CHAIN,
                file_path="",
                start_line=0,
                engine="depguard",
            ),
        ],
    )

    data = json.loads(to_json(result))
    assert data["summary"]["code_findings"] == 1
    assert data["summary"]["sca_findings"] == 2
    assert data["summary"]["total"] == 3

    text = to_text(result)
    assert "Code findings:  1" in text
    assert "SCA findings:   2" in text


def test_text_reports_unsupported_languages_banner():
    result = ScanResult(metadata={
        "analysis_capability": {"unsupported_languages": {"kotlin": 303, "scala": 2}},
    })
    text = to_text(result)
    assert (
        "ANALYSIS COVERAGE: not analysed (unsupported language) for: "
        "kotlin (303 files), scala (2 files)."
    ) in text
    assert "absence of findings there is NOT evidence of absence" in text

    empty = ScanResult(metadata={"analysis_capability": {"unsupported_languages": {}}})
    assert "unsupported language" not in to_text(empty)


def test_empty_result():
    result = ScanResult(files_scanned=0, duration_seconds=0.1)
    text = to_text(result)
    assert "No vulnerabilities found" in text

    js = to_json(result)
    data = json.loads(js)
    assert data["summary"]["total"] == 0


def test_json_includes_pass_outcomes():
    result = ScanResult(metadata={
        "resolved_policy": {"report_view": "actionable"},
        "pass_outcomes": [{
            "name": "file_scan",
            "status": "completed",
            "duration_seconds": 0.0123,
            "files_scanned": 2,
            "findings_delta": 1,
        }],
        "skipped_passes": [{
            "name": "sca",
            "status": "explicitly_disabled",
            "reason": "no_sca",
        }],
        "scope_summary": {"source_files": 2, "languages": {"python": 2}},
        "source_snapshot": {"text_hits": 3, "parse_failures": 0},
        "filter_counts": {"pre_view": 3, "post_view": 1},
        "coverage_summary": {"status": "complete", "incomplete_passes": []},
        "view": "actionable",
    })

    data = json.loads(to_json(result))

    assert data["pass_outcomes"] == result.metadata["pass_outcomes"]
    assert data["skipped_passes"] == result.metadata["skipped_passes"]
    assert data["scope_summary"] == result.metadata["scope_summary"]
    assert data["source_snapshot"] == result.metadata["source_snapshot"]
    assert data["resolved_policy"] == result.metadata["resolved_policy"]
    assert data["filter_counts"] == result.metadata["filter_counts"]
    assert data["coverage_summary"] == result.metadata["coverage_summary"]
    assert data["report_view"] == "actionable"


def test_write_report(tmp_path, sample_result):
    output = tmp_path / "results.json"
    write_report(sample_result, output, "json")
    assert output.exists()

    data = json.loads(output.read_text())
    assert data["summary"]["total"] == 2

    output_sarif = tmp_path / "results.sarif"
    write_report(sample_result, output_sarif, "sarif")
    assert output_sarif.exists()

    sarif = json.loads(output_sarif.read_text())
    assert sarif["version"] == "2.1.0"


def test_hunt_to_json(sample_result):
    state = types.SimpleNamespace(
        recon_result=sample_result,
        hypotheses=[
            {"rule_id": "TNT-SSRF-001", "exploitability": "confirmed", "attack_story": "..."},
        ],
        chains=[{
            "type": "TNT-SSRF-001",
            "source": "target.py:10",
            "confidence": "confirmed",
            "evidence_state": "statically_validated",
        }],
        report="# Vulnerability Report\nConfirmed SSRF.",
        vulnerable=True,
        errors=[],
    )

    data = json.loads(hunt_to_json(state))

    # Scan-compatible portion (parsed by the rowan adapter the same as `scan`)
    assert data["mode"] == "hunt"
    assert data["scanner"] == "rowan"
    assert data["summary"]["total"] == 2
    assert data["summary"]["critical"] == 1
    assert data["summary"]["high"] == 1
    assert len(data["findings"]) == 2
    assert data["findings"][0]["rule_id"] == "NS-DESER-001"

    # Hunt-specific portion
    assert data["summary"]["hypotheses"] == 1
    assert data["summary"]["chains"] == 1
    assert data["summary"]["vulnerable"] is True
    assert data["hunt"]["vulnerable"] is True
    assert data["hunt"]["report"] == "# Vulnerability Report\nConfirmed SSRF."
    assert data["hunt"]["hypotheses"][0]["exploitability"] == "confirmed"
    assert data["hunt"]["chains"][0]["type"] == "TNT-SSRF-001"
    assert data["hunt"]["hypotheses"][0]["evidence_state"] == "triaged"
    assert data["hunt"]["chains"][0]["evidence_state"] == "statically_validated"
    assert data["summary"]["evidence_states"] == {
        "triaged": 1,
        "statically_validated": 1,
    }


def test_hunt_to_json_no_recon_result():
    state = types.SimpleNamespace(
        recon_result=None,
        hypotheses=[],
        chains=[],
        report="",
        vulnerable=False,
        errors=["recon: boom"],
    )

    data = json.loads(hunt_to_json(state))

    assert data["mode"] == "hunt"
    assert data["summary"]["total"] == 0
    assert data["findings"] == []
    assert data["summary"]["hypotheses"] == 0
    assert data["summary"]["vulnerable"] is False
    assert data["hunt"]["errors"] == ["recon: boom"]


def test_hunt_to_json_labels_verified_discovered_findings():
    discovered = Finding(
        rule_id="LLM-DISCOVERED-001",
        message="Verified business-logic finding",
        severity=Severity.HIGH,
        category=Category.GENERAL,
        file_path="app.py",
        start_line=4,
        engine="llm-discovery",
    )
    state = types.SimpleNamespace(
        recon_result=ScanResult(), hypotheses=[], chains=[], discovered=[discovered],
        model_findings=[], report="", vulnerable=False, errors=[], discovery_stats={},
    )

    data = json.loads(hunt_to_json(state))

    assert data["hunt"]["discovered_findings"][0]["evidence_state"] == (
        "verifier_upheld"
    )
    assert data["hunt"]["evidence_states"] == {"verifier_upheld": 1}


@pytest.fixture
def sca_result_with_reachability():
    return ScanResult(
        findings=[
            Finding(
                rule_id="SCA-GHSA-test-reachable",
                message="CVE in requests: test",
                severity=Severity.MEDIUM,
                category=Category.SUPPLY_CHAIN,
                file_path="",
                start_line=0,
                confidence=0.8,
                engine="depguard",
                metadata={
                    "package": "requests",
                    "reachability": "reachable",
                    "reachability_evidence": "requests.get",
                },
            ),
            Finding(
                rule_id="SCA-GHSA-test-unreachable",
                message="CVE in flask: test",
                severity=Severity.LOW,
                category=Category.SUPPLY_CHAIN,
                file_path="",
                start_line=0,
                confidence=0.3,
                engine="depguard",
                metadata={"package": "flask", "reachability": "unreachable"},
            ),
            Finding(
                rule_id="NS-DESER-001",
                message="no reachability info at all",
                severity=Severity.HIGH,
                category=Category.DESERIALIZATION,
                file_path="src/app.py",
                start_line=1,
                engine="neuroscan",
            ),
        ],
    )


class TestReachabilitySurfacedInReports:
    """SCAPass._apply_reachability computes finding.metadata["reachability"],
    but no reporter used to read it -- the signal was thrown away at report
    time. Every output format must now expose it."""

    def test_json_includes_reachability_fields(self, sca_result_with_reachability):
        data = json.loads(to_json(sca_result_with_reachability))
        reachable = next(f for f in data["findings"] if f["rule_id"] == "SCA-GHSA-test-reachable")
        unreachable = next(f for f in data["findings"] if f["rule_id"] == "SCA-GHSA-test-unreachable")
        no_info = next(f for f in data["findings"] if f["rule_id"] == "NS-DESER-001")

        assert reachable["reachability"] == "reachable"
        assert reachable["reachability_evidence"] == "requests.get"
        assert unreachable["reachability"] == "unreachable"
        assert unreachable["reachability_evidence"] is None
        assert no_info["reachability"] is None

    def test_sarif_includes_reachability_in_properties(self, sca_result_with_reachability):
        sarif = to_sarif(sca_result_with_reachability)
        results = sarif["runs"][0]["results"]
        reachable = next(r for r in results if r["ruleId"] == "SCA-GHSA-test-reachable")
        no_info = next(r for r in results if r["ruleId"] == "NS-DESER-001")

        assert reachable["properties"]["reachability"] == "reachable"
        assert reachable["properties"]["reachabilityEvidence"] == "requests.get"
        assert "reachability" not in no_info["properties"]

    def test_text_shows_reachability_line(self, sca_result_with_reachability):
        text = to_text(sca_result_with_reachability)
        assert "Reachability: reachable (requests.get)" in text
        assert "Reachability: unreachable" in text

    def test_html_shows_reachability_badge(self, sca_result_with_reachability):
        html = to_html(sca_result_with_reachability)
        assert "REACHABLE" in html
        assert "UNREACHABLE" in html
        assert "<th>Reachable</th>" in html


def test_json_report_has_schema_version_and_findings_match_schema():
    import json
    from pathlib import Path

    import jsonschema

    from rowan.core.findings import Category, Finding, ScanResult, Severity
    from rowan.reporters import REPORT_SCHEMA_VERSION, to_json

    result = ScanResult()
    result.add_finding(Finding(
        rule_id="NS-X", message="m", severity=Severity.HIGH, category=Category.INJECTION,
        file_path="a.py", start_line=3, engine="neuroscan",
        metadata={"evidence_tier": "pattern-only"},
    ))
    report = json.loads(to_json(result, "."))
    schema_path = Path(__file__).parent.parent / "docs" / "schema" / "finding.schema.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))

    assert report["schema_version"] == REPORT_SCHEMA_VERSION
    for finding in report["findings"]:
        jsonschema.validate(finding, schema)
