"""Reporters: format scan results as SARIF, JSON, text, VEX, and CycloneDX."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from rowan import __version__
from rowan.core.finding_clusters import FindingCluster, cluster_findings
from rowan.core.findings import Finding, ScanResult, Severity
from rowan.core.rule_class import rule_class

# OSV/scanner ecosystem name -> Package URL (purl) type, for building the
# `pkg:<type>/<name>@<version>` identifiers that VEX and CycloneDX use to name
# a component unambiguously across tools.
_ECOSYSTEM_TO_PURL_TYPE: dict[str, str] = {
    "PyPI": "pypi",
    "npm": "npm",
    "Go": "golang",
    "crates.io": "cargo",
    "Maven": "maven",
    "RubyGems": "gem",
    "Packagist": "composer",
}


def _purl(ecosystem: str, name: str, version: str) -> str | None:
    """Build a Package URL from ecosystem/name/version, or None if unsupported.

    Maven coordinates arrive as ``group:artifact`` and map onto purl's
    ``pkg:maven/<group>/<artifact>`` namespace/name split; every other
    supported ecosystem is a flat ``pkg:<type>/<name>``.
    """
    if not name or ecosystem not in _ECOSYSTEM_TO_PURL_TYPE:
        return None
    purl_type = _ECOSYSTEM_TO_PURL_TYPE[ecosystem]

    if purl_type == "maven" and ":" in name:
        group, _, artifact = name.partition(":")
        base = f"pkg:maven/{group}/{artifact}"
    else:
        base = f"pkg:{purl_type}/{name}"

    if version and version != "*":
        return f"{base}@{version}"
    return base


def _finding_to_purl(finding: Finding) -> str | None:
    """Build a Package URL for an SCA finding, or None if it isn't one."""
    return _purl(
        finding.metadata.get("ecosystem", ""),
        finding.metadata.get("package", ""),
        finding.metadata.get("version", ""),
    )


def _build_warnings(result: ScanResult) -> list[str]:
    return [f"{name}: {reason}" for name, reason in result.degraded_passes.items()]


def _severity_to_sarif_level(severity: Severity) -> str:
    return {
        Severity.CRITICAL: "error",
        Severity.HIGH: "error",
        Severity.MEDIUM: "warning",
        Severity.LOW: "note",
        Severity.INFO: "note",
    }.get(severity, "warning")


def _cluster_maps(
    result: ScanResult, source_root: str = ""
) -> tuple[list[FindingCluster], dict[int, tuple[FindingCluster, int]]]:
    effective_root = source_root or str(result.metadata.get("source_root") or "")
    clusters = cluster_findings(result.findings, effective_root)
    memberships = {
        finding_index: (cluster, variant_index)
        for cluster in clusters
        for variant_index, finding_index in enumerate(cluster.member_indexes)
    }
    return clusters, memberships


def _cluster_to_dict(cluster: FindingCluster, result: ScanResult) -> dict:
    members = [result.findings[index] for index in cluster.member_indexes]
    return {
        "id": cluster.cluster_id,
        "primary_finding_index": cluster.primary_index,
        "finding_indexes": list(cluster.member_indexes),
        "raw_count": len(cluster.member_indexes),
        "sink": {
            "file": cluster.sink_file,
            "line": cluster.sink_line,
            "rule_id": cluster.sink_rule,
            "symbol": cluster.sink_symbol,
        },
        "affected_callers": sorted(
            {
                str(finding.metadata.get("caller"))
                for finding in members
                if finding.metadata.get("caller")
            }
        ),
        "paths": [
            _taint_flow_to_dict(finding.taint_flow)
            for finding in members
            if finding.taint_flow is not None
        ],
    }


def to_sarif(result: ScanResult, source_root: str = "") -> dict:
    """Convert ScanResult to SARIF v2.1.0 JSON."""
    rules: dict[str, dict] = {}
    results_list: list[dict] = []
    clusters, memberships = _cluster_maps(result, source_root)

    for finding_index, f in enumerate(result.findings):
        rid = f.rule_id
        if rid not in rules:
            rules[rid] = {
                "id": rid,
                "name": f.metadata.get("rule_name", rid),
                "shortDescription": {"text": f.message[:200]},
                "help": {"text": f.message},
                "defaultConfiguration": {"level": _severity_to_sarif_level(f.severity)},
                "properties": {"severity": f.severity.value, "category": f.category.value},
            }

        physical_location = {"artifactLocation": {"uri": _sarif_uri(f.file_path, source_root)}}
        # Dependency and binary findings apply to an entire artifact and use
        # line 0 internally to represent that fact. SARIF requires a positive
        # startLine whenever a text region is present, so retain the artifact
        # location but omit the region instead of inventing line 1.
        if f.start_line > 0:
            physical_location["region"] = {"startLine": f.start_line}
        loc = {"physicalLocation": physical_location}
        if f.end_line and f.start_line > 0:
            loc["physicalLocation"]["region"]["endLine"] = f.end_line

        properties = {
            "confidence": f.confidence,
            "engine": f.engine,
        }
        cluster, variant_index = memberships[finding_index]
        properties.update({
            "rootCauseId": cluster.cluster_id,
            "rootCausePrimary": finding_index == cluster.primary_index,
            "rootCauseVariantIndex": variant_index,
            "rootCauseVariantCount": len(cluster.member_indexes),
        })
        reachability = f.metadata.get("reachability") if f.metadata else None
        if reachability:
            properties["reachability"] = reachability
            evidence = f.metadata.get("reachability_evidence")
            if evidence:
                properties["reachabilityEvidence"] = evidence

        if f.metadata and f.metadata.get("direct") is False:
            properties["direct"] = False
            chain = f.metadata.get("dependency_chain")
            if chain:
                properties["dependencyChain"] = chain
        if f.metadata and f.metadata.get("version_indeterminate"):
            properties["versionIndeterminate"] = True

        result_entry = {
            "ruleId": rid,
            "message": {"text": f.message},
            "locations": [loc],
            "level": _severity_to_sarif_level(f.severity),
            "properties": properties,
            "partialFingerprints": {
                "rowanRootCause/v1": cluster.cluster_id,
            },
        }
        code_flows = _taint_flow_to_code_flows(f.taint_flow, source_root)
        if code_flows:
            result_entry["codeFlows"] = code_flows
        results_list.append(result_entry)

    return {
        "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "Rowan",
                    "version": __version__,
                    "rules": list(rules.values()),
                }
            },
            "results": results_list,
            "properties": {
                "rowanDegraded": result.degraded,
                "rowanWarnings": _build_warnings(result),
                "rowanResolvedPolicy": result.metadata.get("resolved_policy"),
                "rowanPassOutcomes": result.metadata.get("pass_outcomes", []),
                "rowanSkippedPasses": result.metadata.get("skipped_passes", []),
                "rowanScopeSummary": result.metadata.get("scope_summary"),
                "rowanSourceSnapshot": result.metadata.get("source_snapshot"),
                "rowanFilterCounts": result.metadata.get("filter_counts", {}),
                "rowanCoverageSummary": result.metadata.get("coverage_summary"),
                "rowanReportView": result.metadata.get("view"),
                "rowanEntrypointPolicy": result.metadata.get("entrypoint_policy"),
                "rowanRawFindingCount": result.total_count,
                "rowanRootCauseCount": len(clusters),
                "rowanRootCauseClusters": [
                    _cluster_to_dict(cluster, result) for cluster in clusters
                ],
            },
        }],
    }


def to_json(result: ScanResult, source_root: str = "") -> str:
    """Convert ScanResult to JSON string."""
    findings_data = []
    clusters, memberships = _cluster_maps(result, source_root)
    for finding_index, f in enumerate(result.findings):
        cluster, variant_index = memberships[finding_index]
        findings_data.append({
            "rule_id": f.rule_id,
            "message": f.message,
            "severity": f.severity.value,
            "category": f.category.value,
            "file": f.file_path,
            "line": f.start_line,
            "end_line": f.end_line,
            "confidence": round(f.confidence, 2),
            "cwe": f.cwe_ids,
            "engine": f.engine,
            "evidence_tier": (f.metadata or {}).get("evidence_tier"),
            "rule_class": (
                "inventory"
                if f.engine == "mfv" and f.metadata.get("rule_class") == "presence"
                else rule_class(f.rule_id)
            ),
            "taint_flow": _taint_flow_to_dict(f.taint_flow) if f.taint_flow else None,
            "reachability": (f.metadata or {}).get("reachability"),
            "reachability_evidence": (f.metadata or {}).get("reachability_evidence"),
            "vuln_func_source": (f.metadata or {}).get("vuln_func_source"),
            "direct": (f.metadata or {}).get("direct"),
            "dependency_chain": (f.metadata or {}).get("dependency_chain"),
            "version_indeterminate": (f.metadata or {}).get("version_indeterminate", False),
            "fixed_version": (f.metadata or {}).get("fixed_version"),
            "epss": (f.metadata or {}).get("epss"),
            "epss_percentile": (f.metadata or {}).get("epss_percentile"),
            "phantom_dependency": (f.metadata or {}).get("phantom_dependency", False),
            "malicious": (f.metadata or {}).get("malicious", False),
            "root_cause_id": cluster.cluster_id,
            "root_cause_primary": finding_index == cluster.primary_index,
            "root_cause_variant_index": variant_index,
            "root_cause_variant_count": len(cluster.member_indexes),
        })

    return json.dumps({
        "scanner": "rowan",
        "version": __version__,
        "summary": {
            "total": result.total_count,
            "raw_total": result.total_count,
            "clustered_total": len(clusters),
            "critical": result.critical_count,
            "high": result.high_count,
            "medium": result.medium_count,
            "low": result.low_count,
            "code_findings": result.code_count,
            "sca_findings": result.sca_count,
            "files_scanned": result.files_scanned,
            "duration_seconds": round(result.duration_seconds, 1),
            "degraded": result.degraded,
            "warnings": _build_warnings(result),
        },
        "analysis_capability": result.metadata.get("analysis_capability"),
        "resolved_policy": result.metadata.get("resolved_policy"),
        "pass_outcomes": result.metadata.get("pass_outcomes", []),
        "skipped_passes": result.metadata.get("skipped_passes", []),
        "scope_summary": result.metadata.get("scope_summary"),
        "source_snapshot": result.metadata.get("source_snapshot"),
        "filter_counts": result.metadata.get("filter_counts", {}),
        "coverage_summary": result.metadata.get("coverage_summary"),
        "report_view": result.metadata.get("view"),
        "entrypoint_policy": result.metadata.get("entrypoint_policy"),
        "ignore_file_skipped": result.metadata.get("ignore_file_skipped"),
        "findings": findings_data,
        "clusters": [_cluster_to_dict(cluster, result) for cluster in clusters],
    }, indent=2)


def hunt_to_json(state) -> str:
    """Serialize a HuntState to JSON.

    Emits the same scan-compatible ``{summary, findings}`` shape as
    :func:`to_json` (derived from the recon scan stored on the state) plus a
    ``hunt`` block carrying the LLM triage output (hypotheses, confirmed
    chains, the generated report). This lets downstream consumers parse hunt
    output with the exact same code path as a plain ``scan``.
    """
    recon_result = getattr(state, "recon_result", None)
    base = json.loads(to_json(recon_result if recon_result is not None else ScanResult()))

    # Discovered findings (ADR-0004) are NOT in recon_result -- they are
    # produced after the scan, by the opt-in `discover` stage -- so without
    # this they would be dropped from the JSON entirely. They are appended to
    # `findings` so downstream consumers see them through the normal code
    # path, and every one carries engine="llm-discovery" so rule-corpus
    # precision stays computable with a single filter.
    discovered = list(getattr(state, "discovered", []))
    if discovered:
        base["findings"].extend(
            json.loads(to_json(ScanResult(findings=discovered)))["findings"]
        )

    chains = [dict(chain) for chain in state.chains]
    chain_states: dict[tuple[str, str], str] = {}
    for chain in chains:
        source_file = str(chain.get("source", "")).rpartition(":")[0]
        chain_states[(str(chain.get("type", "")), source_file)] = str(
            chain.get("evidence_state", "triaged")
        )

    hypotheses = []
    for original in state.hypotheses:
        hypothesis = dict(original)
        key = (str(hypothesis.get("rule_id", "")), str(hypothesis.get("file", "")))
        state_name = chain_states.get(key)
        if state_name is None:
            state_name = (
                "verifier_upheld"
                if hypothesis.get("verify_verdict") == "upheld"
                else "triaged"
            )
        hypothesis["evidence_state"] = state_name
        hypotheses.append(hypothesis)

    discovered_json = json.loads(to_json(ScanResult(findings=discovered)))["findings"]
    for finding in discovered_json:
        finding["evidence_state"] = "statically_validated"

    evidence_state_counts: dict[str, int] = {}
    for item in [*hypotheses, *chains, *discovered_json]:
        state_name = str(item.get("evidence_state", "triaged"))
        evidence_state_counts[state_name] = evidence_state_counts.get(state_name, 0) + 1

    base["mode"] = "hunt"
    base["summary"]["hypotheses"] = len(hypotheses)
    base["summary"]["chains"] = len(chains)
    base["summary"]["vulnerable"] = bool(state.vulnerable)
    base["summary"]["aiml_hypotheses"] = sum(1 for h in state.hypotheses if h.get("aiml"))
    base["summary"]["aiml_chains"] = sum(1 for c in state.chains if c.get("aiml"))
    base["summary"]["model_files_flagged"] = len(getattr(state, "model_findings", []))
    base["summary"]["discovered"] = len(discovered)
    base["summary"]["evidence_states"] = evidence_state_counts
    base["hunt"] = {
        "vulnerable": bool(state.vulnerable),
        "hypotheses": hypotheses,
        "chains": chains,
        "discovered_findings": discovered_json,
        "evidence_states": evidence_state_counts,
        "report": state.report,
        "errors": list(state.errors),
        "discovery_stats": dict(getattr(state, "discovery_stats", {})),
    }
    return json.dumps(base, indent=2)


def _sarif_uri(file_path: str, source_root: str = "") -> str:
    """Return a repository-relative SARIF URI when the finding is in scope."""
    if not source_root:
        return file_path
    try:
        return Path(file_path).resolve().relative_to(Path(source_root).resolve()).as_posix()
    except (OSError, ValueError):
        return file_path


def _taint_flow_node_to_sarif_location(node, source_root: str = "") -> dict:
    physical_location = {"artifactLocation": {"uri": _sarif_uri(node.file_path, source_root)}}
    if node.line > 0:
        physical_location["region"] = {"startLine": node.line}
    loc = {"physicalLocation": physical_location}
    if node.snippet:
        loc["message"] = {"text": node.snippet}
    return {"location": loc}


def _taint_flow_to_code_flows(flow, source_root: str = "") -> list[dict] | None:
    """Convert a `TaintFlow` into SARIF `codeFlows` (a single `threadFlows`
    entry walking source -> intermediate hops -> sink), so GitHub code
    scanning / IDE SARIF viewers can render the taint narrative instead of
    a bare location -- this matters most for cross-file findings, whose
    entire value is the multi-file hop story (issue #154 Defect 1)."""
    if flow is None:
        return None
    nodes = []
    if flow.source:
        nodes.append(flow.source)
    nodes.extend(flow.intermediate)
    if flow.sink:
        nodes.append(flow.sink)
    if not nodes:
        return None
    return [{
        "threadFlows": [{
            "locations": [_taint_flow_node_to_sarif_location(n, source_root) for n in nodes],
        }],
    }]


def _taint_flow_to_dict(flow) -> dict | None:
    if flow is None:
        return None
    return {
        "source": {
            "file": flow.source.file_path,
            "line": flow.source.line,
            "snippet": flow.source.snippet,
        } if flow.source else None,
        "sink": {
            "file": flow.sink.file_path,
            "line": flow.sink.line,
            "snippet": flow.sink.snippet,
        } if flow.sink else None,
        "intermediate": [
            {"file": n.file_path, "line": n.line, "snippet": n.snippet}
            for n in flow.intermediate
        ],
    }


def to_text(result: ScanResult) -> str:
    """Convert ScanResult to human-readable text."""
    lines: list[str] = []
    if result.degraded:
        warnings = _build_warnings(result)
        lines.append("!" * 72)
        for w in warnings:
            lines.append(f"WARNING: degraded scan ({w})")
        lines.append("Results below are INCOMPLETE and must not be treated as a clean scan.")
        lines.append("!" * 72)
        lines.append("")
    lines.append("=" * 72)
    lines.append("  Rowan Scan Report")
    lines.append("=" * 72)
    lines.append("")
    lines.append(f"  Files scanned:  {result.files_scanned}")
    lines.append(f"  Duration:       {result.duration_seconds:.1f}s")
    lines.append(f"  Total findings: {result.total_count}")
    clusters = cluster_findings(
        result.findings, str(result.metadata.get("source_root") or "")
    )
    lines.append(f"  Review clusters: {len(clusters)}")
    lines.append(f"    Critical: {result.critical_count}")
    lines.append(f"    High:     {result.high_count}")
    lines.append(f"    Medium:   {result.medium_count}")
    lines.append(f"    Low:      {result.low_count}")
    lines.append(f"  Code findings:  {result.code_count}")
    lines.append(f"  SCA findings:   {result.sca_count} (dependency CVEs -- see findings list for detail)")
    capability = result.metadata.get("analysis_capability") or {}
    patterns_only = capability.get("patterns_only_languages") or {}
    if patterns_only:
        langs = ", ".join(f"{lang} ({count} files)" for lang, count in patterns_only.items())
        lines.append("")
        lines.append(f"  ANALYSIS COVERAGE: patterns only (no dataflow engine) for: {langs}.")
        lines.append("  Findings in these languages are pattern matches, not verified flows;")
        lines.append("  absence of findings there is NOT evidence of absence.")
    unsupported = capability.get("unsupported_languages") or {}
    if unsupported:
        langs = ", ".join(f"{lang} ({count} files)" for lang, count in unsupported.items())
        lines.append("")
        lines.append(f"  ANALYSIS COVERAGE: not analysed (unsupported language) for: {langs}.")
        lines.append("  No engine ran on these files;")
        lines.append("  absence of findings there is NOT evidence of absence.")
    lines.append("")

    severity_order = {
        Severity.CRITICAL: 0,
        Severity.HIGH: 1,
        Severity.MEDIUM: 2,
        Severity.LOW: 3,
        Severity.INFO: 4,
    }
    sorted_clusters = sorted(
        clusters,
        key=lambda cluster: (
            severity_order.get(result.findings[cluster.primary_index].severity, 5),
            result.findings[cluster.primary_index].file_path,
            result.findings[cluster.primary_index].start_line,
        ),
    )

    for cluster in sorted_clusters:
        f = result.findings[cluster.primary_index]
        prefix = {
            Severity.CRITICAL: "🔴",
            Severity.HIGH: "🟠",
            Severity.MEDIUM: "🟡",
            Severity.LOW: "🔵",
            Severity.INFO: "⚪",
        }.get(f.severity, "  ")

        lines.append(f"  [{prefix} {f.severity.value.upper()}] {f.rule_id}")
        lines.append(f"  File: {f.file_path}:{f.start_line}")
        lines.append(f"  {f.message[:120]}")
        if f.taint_flow:
            lines.append(f"  Taint: {_taint_flow_short(f.taint_flow)}")
        if len(cluster.member_indexes) > 1:
            callers = sorted({
                str(result.findings[index].metadata.get("caller"))
                for index in cluster.member_indexes
                if result.findings[index].metadata.get("caller")
            })
            caller_text = f"; callers: {', '.join(callers)}" if callers else ""
            lines.append(
                f"  Root cause: {cluster.cluster_id} "
                f"({len(cluster.member_indexes)} raw flow variants{caller_text})"
            )
            for index in cluster.member_indexes:
                variant = result.findings[index]
                if variant.taint_flow:
                    lines.append(f"    Variant: {_taint_flow_short(variant.taint_flow)}")
        lines.append(f"  Confidence: {f.confidence:.0%} | Engine: {f.engine}")
        reachability = f.metadata.get("reachability") if f.metadata else None
        if reachability:
            evidence = f.metadata.get("reachability_evidence")
            suffix = f" ({evidence})" if evidence else ""
            lines.append(f"  Reachability: {reachability}{suffix}")
        if f.metadata and f.metadata.get("direct") is False:
            chain = f.metadata.get("dependency_chain")
            chain_str = " -> ".join(chain) if chain else "unknown path"
            lines.append(f"  Dependency: transitive (via {chain_str})")
        if f.metadata and f.metadata.get("version_indeterminate"):
            lines.append("  Version: range checked; exact installed version undetermined")
        remediation = f.metadata.get("remediation") if f.metadata else None
        if remediation:
            lines.append(f"  Fix: {remediation}")
        lines.append("")

    if not result.findings:
        if result.degraded:
            lines.append("  No findings, but the scan was INCOMPLETE (see warnings).")
        else:
            lines.append("  No vulnerabilities found.")
        lines.append("")

    if result.errors:
        lines.append("-" * 72)
        lines.append("  Errors:")
        for err in result.errors[:10]:
            lines.append(f"    {err[:100]}")
        lines.append("")

    return "\n".join(lines)


def _taint_flow_short(flow) -> str:
    parts = []
    if flow.source:
        parts.append(f"{flow.source.file_path}:{flow.source.line}")
    parts.append("->")
    for n in flow.intermediate[:3]:
        parts.append(f"{n.file_path}:{n.line} ->")
    if flow.sink:
        parts.append(f"{flow.sink.file_path}:{flow.sink.line}")
    return " ".join(parts)


def to_html(result: ScanResult) -> str:
    """Convert ScanResult to a self-contained HTML report."""
    from html import escape as esc

    sev_color = {
        "critical": "#c0392b", "high": "#e67e22",
        "medium": "#f1c40f", "low": "#3498db", "info": "#95a5a6",
    }

    reach_color = {"reachable": "#c0392b", "unreachable": "#7f8c8d"}

    rows = []
    for f in result.findings:
        sev = f.severity.value.lower()
        color = sev_color.get(sev, "#95a5a6")
        taint = _taint_flow_short(f.taint_flow) if f.taint_flow else ""
        remediation = (f.metadata or {}).get("remediation", "")
        cwe = ", ".join(f"CWE-{c}" for c in f.cwe_ids) if f.cwe_ids else ""
        reachability = (f.metadata or {}).get("reachability", "")
        reach_html = (
            f'<span class="badge" style="background:{reach_color.get(reachability, "#95a5a6")}">'
            f'{esc(reachability.upper())}</span>'
            if reachability else ""
        )
        dep_html = ""
        if (f.metadata or {}).get("direct") is False:
            chain = (f.metadata or {}).get("dependency_chain")
            chain_str = " → ".join(chain) if chain else "unknown path"
            dep_html = f'<span class="badge" style="background:#8e44ad">TRANSITIVE</span> {esc(chain_str)}'
        rows.append(f"""
<tr>
  <td><span class="badge" style="background:{color}">{esc(sev.upper())}</span></td>
  <td><code>{esc(f.rule_id)}</code></td>
  <td>{esc(f.file_path)}:{f.start_line}</td>
  <td>{esc(f.message[:200])}</td>
  <td>{esc(taint)}</td>
  <td>{esc(cwe)}</td>
  <td>{reach_html}</td>
  <td>{dep_html}</td>
  <td>{esc(remediation)}</td>
</tr>""")

    rows_html = "\n".join(rows) if rows else '<tr><td colspan="9">No findings.</td></tr>'
    degraded_banner = ""
    if result.degraded:
        degraded_banner = '<div class="warning">⚠ Scan was degraded: results may be incomplete.</div>'

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Rowan Scan Report</title>
<style>
  body{{font-family:system-ui,sans-serif;margin:2rem;color:#222}}
  h1{{color:#2c3e50}}
  .summary{{display:flex;gap:2rem;margin:1rem 0;flex-wrap:wrap}}
  .card{{background:#f8f9fa;border-radius:6px;padding:1rem 1.5rem;min-width:120px}}
  .card .num{{font-size:2rem;font-weight:700}}
  .card .lbl{{font-size:.85rem;color:#666}}
  .warning{{background:#fff3cd;border-left:4px solid #f1c40f;padding:.75rem 1rem;margin-bottom:1rem}}
  table{{width:100%;border-collapse:collapse;margin-top:1rem;font-size:.9rem}}
  th{{background:#2c3e50;color:#fff;padding:.6rem .8rem;text-align:left}}
  td{{padding:.55rem .8rem;border-bottom:1px solid #e0e0e0;vertical-align:top}}
  tr:hover td{{background:#f0f4f8}}
  .badge{{display:inline-block;padding:.2rem .55rem;border-radius:4px;color:#fff;font-size:.75rem;font-weight:700}}
  code{{background:#f4f4f4;padding:.1rem .3rem;border-radius:3px;font-size:.85rem}}
</style>
</head>
<body>
<h1>Rowan Scan Report</h1>
{degraded_banner}
<div class="summary">
  <div class="card"><div class="num">{result.total_count}</div><div class="lbl">Total</div></div>
  <div class="card"><div class="num" style="color:#c0392b">{result.critical_count}</div><div class="lbl">Critical</div></div>
  <div class="card"><div class="num" style="color:#e67e22">{result.high_count}</div><div class="lbl">High</div></div>
  <div class="card"><div class="num" style="color:#b7950b">{result.medium_count}</div><div class="lbl">Medium</div></div>
  <div class="card"><div class="num" style="color:#2980b9">{result.low_count}</div><div class="lbl">Low</div></div>
  <div class="card"><div class="num">{result.code_count}</div><div class="lbl">Code findings</div></div>
  <div class="card"><div class="num">{result.sca_count}</div><div class="lbl">SCA (dependency) findings</div></div>
  <div class="card"><div class="num">{result.files_scanned}</div><div class="lbl">Files scanned</div></div>
</div>
<table>
<thead>
<tr><th>Severity</th><th>Rule</th><th>Location</th><th>Message</th><th>Taint flow</th><th>CWE</th><th>Reachable</th><th>Dependency</th><th>Fix</th></tr>
</thead>
<tbody>
{rows_html}
</tbody>
</table>
</body>
</html>"""


def _sca_cve_findings(result: ScanResult) -> list[Finding]:
    """SCA dependency-CVE findings only (engine 'depguard', with a CVE id).

    Excludes phantom-dependency findings (`SCA-PHANTOM-001`) -- those name an
    undeclared component, not a vulnerability, so they have no VEX status.
    """
    return [
        f
        for f in result.findings
        if f.engine == "depguard" and f.metadata.get("cve_id")
    ]


def to_vex(result: ScanResult, timestamp: str | None = None) -> dict:
    """Emit an OpenVEX (v0.2.0) document from the scan's reachability signal.

    Each dependency CVE becomes a VEX statement whose status is driven by the
    call-graph reachability already computed in ``SCAPass``:

    * unreachable vulnerable function -> ``not_affected`` with justification
      ``vulnerable_code_not_in_execute_path`` (the machine-readable claim a
      downstream consumer needs to suppress the CVE with confidence);
    * reachable -> ``affected``, carrying an action statement to upgrade;
    * no reachability determination (package not in the vuln-function map, or
      a non-Python codebase) -> ``under_investigation`` rather than a guessed
      status.

    ``timestamp`` is injectable for reproducible output in tests; it defaults
    to the current UTC time.
    """
    ts = timestamp or datetime.now(timezone.utc).replace(microsecond=0).isoformat()

    statements: list[dict] = []
    for finding in _sca_cve_findings(result):
        purl = _finding_to_purl(finding)
        if purl is None:
            continue
        reachability = finding.metadata.get("reachability")
        statement: dict = {
            "vulnerability": {"name": finding.metadata["cve_id"]},
            "products": [{"@id": purl}],
        }
        if reachability == "unreachable":
            statement["status"] = "not_affected"
            statement["justification"] = "vulnerable_code_not_in_execute_path"
            evidence_note = (
                "Rowan call-graph analysis found no invocation of the "
                "vulnerable function in this codebase."
            )
            statement["impact_statement"] = evidence_note
        elif reachability == "reachable":
            statement["status"] = "affected"
            evidence = finding.metadata.get("reachability_evidence")
            fixed = finding.metadata.get("fixed_version")
            upgrade = f"Upgrade to >= {fixed}" if fixed else "Upgrade to a fixed version"
            statement["action_statement"] = (
                f"{upgrade}; the vulnerable function is invoked in this codebase"
                + (f" (evidence: {evidence})." if evidence else ".")
            )
        else:
            statement["status"] = "under_investigation"
        statements.append(statement)

    # A content-derived @id keeps re-runs on identical findings stable while
    # still being unique per distinct statement set (OpenVEX requires @id).
    digest = hashlib.sha256(
        json.dumps(statements, sort_keys=True).encode("utf-8")
    ).hexdigest()[:16]

    document = {
        "@context": "https://openvex.dev/ns/v0.2.0",
        "@id": f"https://openvex.dev/docs/rowan/vex-{digest}",
        "author": f"Rowan {__version__}",
        "timestamp": ts,
        "version": 1,
        "statements": statements,
    }
    degraded = result.degraded_passes.get("sca")
    if degraded:
        # Statements are incomplete; an empty list must not read as clean.
        document["rowan:degraded"] = degraded
    return document


def to_cyclonedx(result: ScanResult, timestamp: str | None = None) -> dict:
    """Emit a CycloneDX 1.5 SBOM from the scanned dependency inventory.

    Lists every declared component ``SCAPass`` parsed (recorded on
    ``result.metadata['dependencies']``), not just the vulnerable ones -- an
    SBOM is a complete bill of materials. Each component carries a purl and a
    ``bom-ref`` so a companion VEX document (see :func:`to_vex`) can reference
    it. Vulnerability analysis itself lives in the VEX artifact, keeping the
    two concerns cleanly separated as the standards intend.
    """
    ts = timestamp or datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    dependencies = result.metadata.get("dependencies", [])

    components: list[dict] = []
    seen_refs: set[str] = set()
    refs_by_component: dict[tuple[str, str, str], str] = {}
    for dep in dependencies:
        purl = _purl(dep.get("ecosystem", ""), dep.get("name", ""), dep.get("version", "*"))
        component: dict = {
            "type": "library",
            "name": dep.get("name", ""),
            "version": dep.get("version", "*"),
        }
        if purl:
            # bom-ref must be unique within the document; the purl is a good
            # natural key, but fall back to a suffix if two entries collide.
            ref = purl
            n = 1
            while ref in seen_refs:
                n += 1
                ref = f"{purl}#{n}"
            seen_refs.add(ref)
            component["purl"] = purl
            component["bom-ref"] = ref
            refs_by_component[(dep.get("ecosystem", ""), dep.get("name", ""), dep.get("version", "*"))] = ref
        source_files = dep.get("source_files", [])
        if source_files:
            component["properties"] = [
                {"name": "rowan:source-file", "value": str(source)}
                for source in source_files
            ]
        chain = dep.get("dependency_chain")
        if chain:
            component.setdefault("properties", []).append(
                {"name": "rowan:dependency-chain", "value": " -> ".join(map(str, chain))}
            )
        components.append(component)

    digest = hashlib.sha256(
        json.dumps(components, sort_keys=True).encode("utf-8")
    ).hexdigest()

    graph = []
    for dep in dependencies:
        ref = refs_by_component.get((dep.get("ecosystem", ""), dep.get("name", ""), dep.get("version", "*")))
        chain = dep.get("dependency_chain") or []
        if not ref or len(chain) < 2:
            continue
        # The parser records names only; resolve each edge to the matching
        # component in this inventory and omit unresolved edges safely.
        depends_on = []
        for name in chain[:-1]:
            for candidate in dependencies:
                if candidate.get("name") == name:
                    candidate_ref = refs_by_component.get((candidate.get("ecosystem", ""), candidate.get("name", ""), candidate.get("version", "*")))
                    if candidate_ref and candidate_ref != ref:
                        depends_on.append(candidate_ref)
                    break
        if depends_on:
            graph.append({"ref": ref, "dependsOn": sorted(set(depends_on))})

    document = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{digest[:8]}-{digest[8:12]}-{digest[12:16]}-{digest[16:20]}-{digest[20:32]}",
        "version": 1,
        "metadata": {
            "timestamp": ts,
            "tools": [
                {"vendor": "Hedgerow", "name": "Rowan", "version": __version__}
            ],
        },
        "components": components,
    }
    if graph:
        document["dependencies"] = graph
    degraded = result.degraded_passes.get("sca")
    if degraded:
        # The inventory is complete, the vulnerability data behind it is not.
        document["metadata"]["properties"] = [{"name": "rowan:degraded", "value": degraded}]
    return document


def write_report(result: ScanResult, output_path: Path, fmt: str, source_root: str = "") -> None:
    """Write scan results to a file in the specified format."""
    if fmt == "sarif":
        data = to_sarif(result, source_root)
        content = json.dumps(data, indent=2)
    elif fmt == "json":
        content = to_json(result, source_root)
    elif fmt == "html":
        content = to_html(result)
    else:
        content = to_text(result)

    output_path.write_text(content, encoding="utf-8")
