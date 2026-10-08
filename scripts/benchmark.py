#!/usr/bin/env python3
"""Precision/recall benchmark harness (issue #76).

Scores rowan against three ground-truth corpora under
benchmark/ground_truth/:

  vuln_cases/   -- standalone snippets with a documented vulnerability.
                   Scoring: recall (did we find the expected finding for
                   each file?). Scanned with taint OFF.
  ai_cases/     -- AI-surface snippets (LLM output, tool parameters) per
                   language, scanned with taint ON so `mode: taint` rules
                   can score. Scoring: recall by exact expected_rule_id.
  clean_models/ -- real, hash-pinned model files with no known threat.
                   Scoring: false-positive count (expect 0).
  clean_code/   -- real OSS repos with no vulnerabilities in scope.
                   Scoring: precision proxy (total findings and
                   HIGH/CRITICAL findings vs. a committed baseline;
                   regressions beyond tolerance fail the run).

Usage:
    uv run python scripts/benchmark.py [--update-baseline] [--corpus NAME]

Exits non-zero if vuln_cases recall < 1.0, clean_models has any
findings, or clean_code regresses beyond tolerance.
"""

from __future__ import annotations

import argparse
import ast
import functools
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).parent.parent))

from hayward import ModelFileScanner

from rowan.config import ScanConfig
from rowan.core.finding_clusters import cluster_findings
from rowan.pipeline import ScanPipeline

PROJECT_ROOT = Path(__file__).parent.parent
GROUND_TRUTH = PROJECT_ROOT / "benchmark" / "ground_truth"
BASELINE_PATH = Path(__file__).parent.parent / "benchmark" / "baseline.json"
CLEAN_CODE_CHECKPOINT = PROJECT_ROOT / ".cache" / "clean-code-benchmark.json"
_REPORT_VOLUME = {"scans": 0, "raw_findings": 0, "review_clusters": 0}


def _record_report_volume(result, target: Path) -> None:
    """Track presentation volume without changing a benchmark's score."""
    _REPORT_VOLUME["scans"] += 1
    _REPORT_VOLUME["raw_findings"] += len(result.findings)
    _REPORT_VOLUME["review_clusters"] += len(
        cluster_findings(result.findings, str(target))
    )

# A repo's total finding count is allowed to grow by this much (in absolute
# finding count) before a clean-code run is flagged as a regression. Catches
# "a rule went noisy" without failing on every single +/-1 finding from
# incidental repo drift (new commits landing upstream).
CLEAN_CODE_TOTAL_TOLERANCE = 5
# high/critical on a clean repo is a hard budget, not a tolerance: these are
# by definition false accusations at the severities the CI gate acts on, so
# ANY increase over the committed baseline fails, and reductions should be
# ratcheted in with --update-baseline. Asymmetric on purpose -- recall gates
# are hard, so precision gates must be too, or precision debt compounds into
# the baseline (which is how a "clean" repo baseline reached 205 h/c).
CLEAN_CODE_HIGH_CRITICAL_TOLERANCE = 0

# A vuln in the labeled vuln-app oracle counts as "detected" if a finding lands
# in its sink file within this many lines of the ground-truth sink line_hint
# (line hints are approximate; the symbol is the stable anchor, so a generous
# window is intentional). Env ROWAN_VULN_APP_PATH points at a local checkout of
# a ground-truth-labeled vulnerable app (e.g. ModelForge) whose
# benchmarks/ground_truth.yaml is the answer key -- not committed here.
VULN_APP_SINK_WINDOW = 15
# Semgrep rulesets used for the head-to-head comparison (both community/free).
SEMGREP_CONFIGS = ("p/security-audit", "p/owasp-top-ten")


@dataclass
class VulnCaseResult:
    file: str
    expected: str
    found: bool
    matched_rule_ids: list[str]
    # #106: which pool this case belongs to. Only "regression" gates CI; the
    # "holdout" pool is the honest generalization number (rule tuning may look
    # at regression, never at holdout).
    pool: str = "regression"
    # #107: how the case was credited -- "rule_id" | "category" | "cwe_class" |
    # "none". cwe_class means it matched by CWE-class consistency rather than an
    # exact rule id/category, which is what decouples recall from rule renames.
    match_mode: str = "none"


def _fmt_recall(bucket: dict) -> str:
    """Human-readable 'NN.N% (h/t)' for a _pool_recall bucket; 'n/a' if empty."""
    if bucket.get("recall") is None:
        return f"n/a (0/{bucket.get('total', 0)})"
    return f"{bucket['recall'] * 100:.1f}% ({bucket['hits']}/{bucket['total']})"


def _pool_recall(results: list[VulnCaseResult], pool: str) -> dict:
    """Recall over one pool. An empty pool reports recall None (not vacuously 1.0)."""
    subset = [r for r in results if r.pool == pool]
    hits = sum(1 for r in subset if r.found)
    total = len(subset)
    return {"recall": (hits / total if total else None), "hits": hits, "total": total}


def _class_consistent(case_findings: list, cwe_field) -> list:
    """#107: findings in a case file consistent with the declared CWE class.

    Rowan findings carry CWE metadata, which is stronger than wording in a
    composite message. Keyword matching remains a compatibility fallback for
    external or abbreviated findings that lack declared CWE metadata.
    """
    keywords = _cwe_keywords(str(cwe_field)) if cwe_field is not None else ()
    expected_cwe = _declared_cwe(cwe_field)
    if expected_cwe is None and not keywords:
        return []
    out = []
    for f in case_findings:
        ident = f"{f.category.value} {f.rule_id} {f.message}".lower()
        # Lightweight compatibility fixtures and external producers can lack
        # the field entirely. Rowan findings always carry it (possibly as an
        # empty list), and an empty Rowan declaration must not fall back to
        # wording in its message.
        cwe_ids = getattr(f, "cwe_ids", None)
        if cwe_ids is not None and expected_cwe is not None:
            if expected_cwe in cwe_ids:
                out.append(f)
        elif any(kw in ident for kw in keywords):
            out.append(f)
    return out


def _scan_dir(target: Path, **config_kwargs) -> list:
    findings, _ = _scan_dir_checked(target, **config_kwargs)
    return findings


def _scan_dir_checked(target: Path, **config_kwargs) -> tuple[list, dict[str, str]]:
    """Scan `target`, also returning the pipeline's degraded-pass report.

    A degraded scan (e.g. an opengrep batch that exited non-zero) produces
    FEWER findings, so recording it as a result is indistinguishable from a
    precision improvement -- it silently rewrites the baseline in the
    flattering direction. Callers that record numbers must check this;
    `_scan_dir` keeps the old shape for callers that only need the findings.
    """
    # Benchmarks grade the engine's full detection, not the CLI's presentation
    # view. The ScanConfig default report_view is "full", so these scans see
    # every finding; a caller can pass report_view="actionable" to grade the
    # view itself (as the FP-reduction recall checks do).
    config = ScanConfig(target=target, no_sca=True, **config_kwargs)
    result = ScanPipeline(config).run()
    _record_report_volume(result, target)
    return result.findings, dict(result.degraded_passes)


def _scan_dir_retrying(
    target: Path, attempts: int = 2, **config_kwargs
) -> tuple[list, dict[str, str]]:
    """`_scan_dir_checked` with a retry, since batch failures are intermittent.

    Returns the first non-degraded result. If every attempt degrades, returns
    the last one along with its (non-empty) degraded report so the caller can
    refuse to record it.
    """
    findings: list = []
    degraded: dict[str, str] = {}
    for attempt in range(1, attempts + 1):
        findings, degraded = _scan_dir_checked(target, **config_kwargs)
        if not degraded:
            return findings, {}
        if attempt < attempts:
            print(f"    scan degraded ({'; '.join(degraded.values())}) -- retrying {target.name}")
    return findings, degraded


def _score_vuln_cases(findings: list, manifest: dict) -> list[VulnCaseResult]:
    """Credit each manifest case against `findings` (see run_vuln_cases)."""
    findings_by_file: dict[str, list] = {}
    for f in findings:
        findings_by_file.setdefault(Path(f.file_path).name, []).append(f)

    results = []
    for case in manifest["cases"]:
        file_name = Path(case["file"]).name
        case_findings = findings_by_file.get(file_name, [])
        if "expected_rule_id" in case:
            matched = [f for f in case_findings if case["expected_rule_id"] in f.reported_rule_ids()]
            expected_desc = f"rule_id={case['expected_rule_id']}"
            match_mode = "rule_id" if matched else "none"
        elif "expected_category" in case:
            matched = [f for f in case_findings if f.category.value == case["expected_category"]]
            expected_desc = f"category={case['expected_category']}"
            match_mode = "category" if matched else "none"
        else:
            # CWE-only case: credited purely by the #107 class fallback below.
            # This is the right shape for a holdout entry -- naming an expected
            # rule id or category bakes our own taxonomy into the oracle, so a
            # rule rename or re-categorization would show up as a
            # generalization failure that never happened.
            matched = []
            expected_desc = f"cwe={case.get('cwe')}"
            match_mode = "none"

        # #107 fallback: an exact rule-id/category miss can still be a genuine
        # detection of the right class under a different rule. Credit it by CWE
        # class so recall doesn't drop the day a rule is renamed or re-categorized.
        if not matched:
            class_matched = _class_consistent(case_findings, case.get("cwe"))
            if class_matched:
                matched = class_matched
                match_mode = "cwe_class"

        results.append(
            VulnCaseResult(
                file=case["file"],
                expected=expected_desc,
                found=bool(matched),
                matched_rule_ids=sorted({f.rule_id for f in matched}),
                pool=case.get("pool", "regression"),
                match_mode=match_mode,
            )
        )

    return results


def _vuln_pool_scores(results: list[VulnCaseResult]) -> dict:
    return {
        "regression": _pool_recall(results, "regression"),
        "holdout": _pool_recall(results, "holdout"),
        "overall": {
            "recall": (sum(1 for r in results if r.found) / len(results)) if results else None,
            "hits": sum(1 for r in results if r.found),
            "total": len(results),
        },
    }


def run_vuln_cases() -> tuple[dict, list[VulnCaseResult]]:
    """Score the vuln_cases corpus. Returns (scores, results).

    scores is {"regression": {...}, "holdout": {...}, "overall": {...}}, each a
    ``_pool_recall``-style dict. Each case is credited (#107) by the first of:
    its ``expected_rule_id``, its ``expected_category``, or -- as a fallback that
    survives rule-id/category renames -- any finding in the file that is
    CWE-class-consistent with the case's declared ``cwe``.
    """
    manifest_path = GROUND_TRUTH / "vuln_cases" / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    corpus_dir = GROUND_TRUTH / "vuln_cases"

    # Scored twice (RT-04). The regex-only run is the historical, gated
    # number. With taint off no `mode: taint` rule can ever be credited, so
    # the corpus said nothing about the taint packs; the taint-on run is
    # reported as `*_taint` and not gated until it has some history.
    results = _score_vuln_cases(_scan_dir(corpus_dir, no_taint=True), manifest)
    taint_results = _score_vuln_cases(_scan_dir(corpus_dir), manifest)

    scores = _vuln_pool_scores(results)
    scores.update({f"{k}_taint": v for k, v in _vuln_pool_scores(taint_results).items()})
    return scores, results


# ---------------------------------------------------------------------------
# vuln_app: a real, ground-truth-labeled vulnerable application (ModelForge).
# Scores per-vuln recall against the app's own answer key AND, when semgrep is
# installed, runs Semgrep over the same app for a head-to-head comparison.
# ---------------------------------------------------------------------------


# Maps a ground-truth CWE to keywords that must appear in a finding's identity
# (our "category rule_id", or Semgrep's check_id) for that finding to count as
# *detecting that vuln class* -- not merely landing near the sink line. CWEs with
# no entry (639 IDOR is the sole deliberate holdout, see the AUTHZ-BOLA-* block
# below) are absence-of-check logic bugs with no reliable keyword signature;
# they stay honest MISSes rather than being credited by a coincidental nearby
# finding. Every entry below was checked against a real vuln_app scan
# (langfail) plus the rule corpus's own declared-CWE messages before being
# added, specifically to make sure the keyword doesn't also appear in some
# unrelated rule's message that happens to land in the same sink-file window.
_CWE_CLASS_KEYWORDS: dict[int, tuple[str, ...]] = {
    502: ("deser", "pickle", "yaml", "marshal", "joblib", "torch", "numpy", "allow_pickle"),
    22: ("path", "traversal", "zip", "tar", "extract", "slip"),
    73: ("path_traversal", "arbitrary file", "file write", "unsanitized path"),
    77: ("command", "cmdi", "injection", "subprocess", "shell"),
    78: ("command", "cmdi", "subprocess", "shell", "system"),
    79: ("xss", "autoescape", "escape", "html"),
    89: ("sqli", "sql", "injection"),
    94: ("eval", "exec", "code", "injection", "ssti", "template"),
    95: ("eval", "exec", "code", "injection"),
    98: ("path", "lfi", "include", "injection"),
    470: ("reflect", "import_module", "getattr", "dynamic import", "callable resolution"),
    611: ("xxe", "xml", "entity", "resolve_entities", "external entity"),
    918: ("ssrf", "request", "url", "fetch"),
    1321: ("proto", "prototype", "pollution", "xss"),
    # Bare "template" is too generic -- it matches any message that mentions
    # Jinja2 for whatever reason (e.g. an unrelated autoescape=False/XSS
    # finding on the exact same rendering function), not evidence of SSTI
    # specifically. "ssti" is what every genuine SSTI-categorized/worded
    # finding in this codebase actually carries.
    1336: ("ssti", "server-side template", "from_string"),
    # --- added: closes the gap on the 34 previously-unscoreable vuln_app
    # CWEs (ground-truth CWEs with no keyword entry scored as MISS
    # unconditionally) ---
    # CWE-15: config-as-taint (user-controlled config merge flips a security
    # toggle). No purpose-built rule exists yet; "config injection" mirrors
    # NS-AIML-013's own OmegaConf.merge() wording. Bare "config" was rejected
    # -- it appears in several unrelated rule messages (Flask debug config,
    # LangChain config routing, MCP config binding) that would coincidentally
    # co-locate with almost any config-handling sink.
    15: ("deep-merge", "deep merge", "config injection", "security toggle"),
    # CWE-20: MCP sampling-request poisoning (no human-in-the-loop gate).
    # Bare "sampling" was rejected -- NS-AIML-027's HF-dataset-streaming
    # message says "limit samples", an unrelated ML-ops concern that would
    # coincidentally co-locate with any dataset/model file.
    20: ("mcp sampling", "sampling request", "human-in-the-loop", "human gate"),
    # CWE-200: sensitive data exposure (model extraction / membership
    # inference / training-data regurgitation / markdown-image exfil). Bare
    # "extraction" was rejected -- it also matches the unrelated zip-slip
    # cross-file finding's "Archive extraction without path validation"
    # wording, and bare "data"/"leak" are far too generic per the file's
    # existing discipline.
    200: ("data exfiltration", "model extraction", "membership inference", "markdown-image"),
    # CWE-208: non-constant-time secret comparison; mirrors ns-infra-001's own
    # wording exactly.
    208: ("timing", "constant-time", "compare_digest"),
    # CWE-266: improper privilege assignment (self-assigned role at
    # registration). No rule currently targets this pattern in this corpus.
    # Bare "role" and "privilege" were rejected as too generic (role-based
    # access control shows up all over unrelated auth code).
    266: ("self-assigned role", "privilege assignment"),
    # CWE-306: missing authentication by default (insecure-bind-by-default
    # transport, e.g. V40's MCP-over-HTTP binding every interface with auth
    # off unless explicitly enabled). Deliberately does NOT include
    # NS-AIML-009's "without authentication check" wording: that rule flags
    # the MCP tool-call surface lacking an auth check, a different assertion
    # than "the transport binds every interface with insecure defaults,"
    # and crediting V40 through it would mask a real detection gap --
    # ns-aiml-126/ns-aiml-127 (the rules actually built for this bug) only
    # match FastMCP's high-level `.run(host=..., transport=...)` call shape
    # and are structurally blind to the low-level `Server` + Starlette +
    # `uvicorn.run(...)` deployment style this app (and the MCP SDK's own
    # published SSE examples) use -- a DEF-12-class engine defect. Keep this
    # entry narrow so V40 stays an honest MISS until that rule gap is fixed;
    # widening it back to "without authentication check" would make the fix
    # invisible to this exact benchmark. Once ns-aiml-126/127 (or a
    # replacement) can see the low-level deployment shape, re-widen this to
    # credit V40 -- that's the tripwire this comment exists to protect.
    306: ("binds every interface", "0.0.0.0", "all interfaces", "no auth by default"),  # noqa: S104 - scoring keyword, not a bind
    # CWE-327: broken/risky crypto algorithm. "md5" mirrors NS-CRYPTO-001's
    # own wording; "unsalted" is the ground truth's own term for the specific
    # digest-as-credential misuse (V47). Deliberately does NOT include "jwt"
    # or "algorithm" -- those would blur into the CWE-347 JWT-signature class
    # below, which is a separate vuln in this corpus even though both live in
    # core/security.py.
    327: ("md5", "unsalted"),
    # CWE-345: agent confirmation-spoof via an injected transcript marker (no
    # rule targets this presence-vs-absence-of-a-directive pattern yet).
    345: ("confirmation spoof", "transcript marker"),
    # CWE-347: JWT signature/algorithm confusion. "jwt" mirrors both ns-bb-001
    # ("JWT signed with a weak or hardcoded secret") and NS-AUTH-101 ("JWT
    # verification with algorithm=none..."), both of which fire on this
    # exact class and nowhere else in a 111-finding real scan.
    347: ("jwt",),
    # CWE-352: CSRF. Mirrors the several ns-fw-*/NS-AUTH-001 rule messages
    # ("CSRF protection...", "...CsrfViewMiddleware...").
    352: ("csrf", "cross-site request forgery", "anti-forgery"),
    # CWE-359: PII flows to a third-party LLM call with no redaction. No rule
    # currently fires on this in the corpus; "pii"/"redact" mirror
    # TNT-ML-014's own wording ("A PII-shaped field... reaches an LLM").
    359: ("pii", "redact"),
    # CWE-367: TOCTOU. "toctou"/"race condition" mirror ns-bb-009's own
    # wording. "rug pull" and "tool description" are ns-aiml-125's own
    # wording -- that rule explicitly cites the "Invariant Labs 2025
    # tool-poisoning / 'rug pull' disclosure" and is, by its own docstring,
    # "specifically about the description field as an injection channel",
    # which is exactly V59's TOCTOU-on-tool-descriptions mechanism (shared
    # sink function with the CWE-862 entry below).
    367: ("toctou", "race condition", "rug pull", "tool description"),
    # CWE-400: unbounded resource consumption / denial of wallet.
    # "iteration-cap" mirrors ns-aiml-120's own wording ("while True: loop
    # with no iteration-cap term"); that rule is real and fires in this app,
    # just not (yet) on the specific caller-parameterized loop this corpus's
    # V36 targets, so it correctly stays a MISS rather than being credited by
    # an unrelated while-loop elsewhere. Bare "timeout"/"unbounded" rejected
    # as too generic (would blur into the unrelated CS-CONFIG-001 HttpClient
    # class in a mixed-language scan).
    400: ("iteration-cap", "denial of wallet", "unbounded consumption"),
    # CWE-598: session/bearer token accepted via URL query string. No rule
    # targets this yet; kept as specific joined phrases so a coincidental
    # mention of "token" or "query" elsewhere (both very common words in this
    # corpus) can't credit it.
    598: ("bearer token", "query parameter"),
    # CWE-601: open redirect. Mirrors NS-REDIRECT-001/ns-fw-py-003/ns-fw-go-005
    # /ns-bb-007's own wording. Note TNT-HEADER-001 (CRLF header injection,
    # CWE-113) also mentions "open redirect" in passing ("...cache poisoning,
    # cookie injection, or open redirect attacks") -- harmless here because
    # the genuine open-redirect rules independently fire at the same sink
    # line in every case checked, but a future corpus without that
    # co-occurrence could see TNT-HEADER-001 alone false-credit a CWE-601 vuln.
    601: ("redirect",),
    # CWE-640: predictable/insufficiently-random password-reset token. No
    # rule targets this yet. Deliberately excludes bare "random" -- ns-bb-001
    # (JWT weak secret, CWE-347) says "Use a strong random key", which would
    # coincidentally co-locate in core/security.py where V46 also lives.
    640: ("predictable", "insufficient random", "weak random", "reset token", "recovery code"),
    # CWE-829: inclusion of functionality from an untrusted control sphere
    # (hub-style repo import executing hubconf.py, plugin/agent-installed
    # code, hallucinated-dependency slopsquatting). Mirrors NS-AIML-018/019's
    # own wording ("supply chain", "unpinned"). Deliberately excludes bare
    # "poisoning" -- TNT-HEADER-001's CRLF-injection message says "cache
    # poisoning", unrelated -- and bare "agency"/"excessive agency" -- an
    # unrelated cross-file finding about shell/subprocess tool access uses
    # that exact phrase and would coincidentally land in the same sink-file
    # window as the CWE-829 training-data-poisoning vuln in this corpus.
    829: (
        "supply chain",
        "hubconf",
        "exec_module",
        "torch.hub",
        "slopsquat",
        "hallucinated dependency",
        "dependency confusion",
        "unpinned",
    ),
    # CWE-862: missing authorization (MCP tool-description poisoning via
    # broken auth; confused-deputy agent tools). Deliberately does NOT
    # include "tool description" here even though ns-aiml-125 fires on the
    # same sink function V29 uses (shared with CWE-367 above, where it IS
    # earned): ns-aiml-125 asserts "this tool description is not a fixed
    # string literal," which says nothing about authorization. V29's actual
    # defect is that api/admin.py:set_tool_note performs no authorization
    # check on who may set a note -- a different claim from what
    # ns-aiml-125 detects. One finding crediting two ground-truth vulns
    # through two different CWE entries is exactly the kind of quiet recall
    # inflation this keyword gate exists to prevent; keep V29 an honest MISS
    # until a rule actually checks set_tool_note's authorization. Bare
    # "auth"/"access"/"authorization" also rejected per the file's existing
    # discipline.
    862: ("confused deputy", "broken authorization"),
    # CWE-915: mass assignment / unsafe setattr. Mirrors ns-bb-005/RB-AUTH-001
    # /ns-fw-java-005's own wording -- these rules are real (unlike CWE-639,
    # which has no keyword signature at all) but none currently fire on this
    # corpus's setattr-loop shape, so this stays an honest MISS rather than a
    # false credit; entry kept narrow so a future rule improvement can be
    # credited without also matching something coincidental.
    915: ("mass assignment", "setattr"),
    # CWE-1004: session cookie missing HttpOnly (JS-readable). No rule
    # targets this yet (the closest existing rule, ns-bb-003, is CWE-614 and
    # didn't fire in this corpus either).
    1004: ("httponly", "non-httponly", "js-readable"),
    # CWE-1021: clickjacking (missing X-Frame-Options/frame-ancestors). No
    # rule targets this yet.
    1021: ("clickjack", "x-frame-options", "frame-ancestors"),
    # CWE-1333: ReDoS. No rule targets this yet; keywords per the issue's own
    # suggestion.
    1333: ("redos", "catastrophic backtrack", "regex denial"),
}
# "injection" and "tool" alone are too generic -- Semgrep's *generic* SQLi/
# code-injection rule messages routinely say "may be a code injection
# vulnerability", which would falsely credit Semgrep for an LLM01 (prompt
# injection / agent tool abuse) vuln it has no purpose-built rule for at all.
# "prompt injection" as a joined phrase, plus "llm"/"agent", are specific
# enough that a generic rule's message won't coincidentally contain them.
_LLM_CLASS_KEYWORDS: tuple[str, ...] = ("prompt injection", "prompt-injection", "llm", "agent")


def _cwe_keywords(cwe_field: str) -> tuple[str, ...]:
    raw = str(cwe_field or "")
    if raw.upper().startswith("LLM"):
        return _LLM_CLASS_KEYWORDS
    digits = "".join(c for c in raw if c.isdigit())
    return _CWE_CLASS_KEYWORDS.get(int(digits), ()) if digits else ()


def _resolve_vuln_app() -> tuple[Path, dict] | None:
    """Resolve the local vuln-app checkout from ROWAN_VULN_APP_PATH and load its
    ground_truth.yaml. Returns (app_dir, ground_truth) or None if unavailable."""
    env_path = os.environ.get("ROWAN_VULN_APP_PATH")
    if not env_path:
        return None
    app_dir = Path(env_path).expanduser()
    gt_path = app_dir / "benchmarks" / "ground_truth.yaml"
    if not app_dir.is_dir() or not gt_path.exists():
        return None
    gt = yaml.safe_load(gt_path.read_text(encoding="utf-8"))
    return app_dir, gt


def _index_parts(
    entry: tuple[str, int, str] | tuple[str, int, str, tuple[int, ...] | None],
) -> tuple[str, int, str, tuple[int, ...] | None]:
    """Unpack an index row, retaining legacy three-field test fixtures.

    ``None`` means the producer has no trustworthy CWE metadata (currently
    Semgrep); an empty tuple means Rowan emitted a finding without a CWE and
    must not receive keyword-based class credit.
    """
    if len(entry) == 3:
        path, line, identity = entry
        return path, line, identity, None
    path, line, identity, cwe_ids = entry
    return path, line, identity, cwe_ids


def _class_match(
    identity: str,
    cwe_ids: tuple[int, ...] | None,
    expected_cwes: set[int],
    keywords: tuple[str, ...],
) -> bool:
    # Numeric CWE metadata is authoritative only when the oracle has a
    # numeric CWE to compare. AI classes such as LLM01 intentionally have no
    # standard CWE, so their deliberately narrow class keywords remain the
    # best available attribution signal even for Rowan findings.
    if cwe_ids is not None and expected_cwes:
        return bool(expected_cwes & set(cwe_ids))
    return bool(keywords) and any(keyword in identity for keyword in keywords)


def _hit(
    index: list[tuple[str, int, str] | tuple[str, int, str, tuple[int, ...] | None]],
    sink_file: str,
    line_hint: int | None,
    keywords: tuple[str, ...],
    expected_cwe: int | None = None,
) -> bool:
    """True if a finding in index lands in sink_file within the window AND its
    declared CWE matches the oracle. Keyword matching is reserved for sources
    with no trustworthy CWE metadata, such as Semgrep."""
    expected_cwes = {expected_cwe} if expected_cwe is not None else set()
    if not expected_cwes and not keywords:
        return False
    needle = "/" + sink_file.lstrip("/")
    for entry in index:
        path, line, ident, cwe_ids = _index_parts(entry)
        norm = path.replace("\\", "/")
        if not (norm.endswith(needle) or norm.endswith(sink_file)):
            continue
        if line_hint is not None and abs(line - line_hint) > VULN_APP_SINK_WINDOW:
            continue
        if _class_match(ident, cwe_ids, expected_cwes, keywords):
            return True
    return False


# ---------------------------------------------------------------------------
# AUTHZ-BOLA-* semantic grading (#175): CWE-639 (IDOR) is an absence-of-check
# logic bug with no reliable keyword signature to distinguish "the right BOLA
# model" from any other absence-of-check message, so _hit()'s keyword match
# (_CWE_CLASS_KEYWORDS has no entry for 639 by design) can never credit it.
# Ground-truth vulns/decoys tagged with an `authz_model` field (ownership /
# membership / hierarchical / status) are graded instead by file + declared
# model class, cross-referenced against AuthzPass's own
# metadata["missing_models"] -- a true positive is a finding that correctly
# names the SAME model as absent, not merely a nearby CWE-639 label.
# ---------------------------------------------------------------------------


def _authz_index(findings: list) -> list[tuple[str, int, list[str]]]:
    """(file, line, models) per AUTHZ-BOLA-* finding, where `models` is the
    union of metadata["missing_models"] (absent entirely -- High) and
    metadata["partial_models"] (guard present but not proven to dominate --
    Medium): a Medium finding is still evidence the tool caught the vuln at
    that model, just not proof the guard is sound, so it still counts as a
    recall hit for that model."""
    out = []
    for f in findings:
        if "AUTHZ-BOLA-001" not in f.reported_rule_ids():
            continue
        meta = f.metadata or {}
        models = list(meta.get("missing_models") or []) + list(meta.get("partial_models") or [])
        out.append((f.file_path, f.start_line, models))
    return out


def _authz_hit(
    index: list[tuple[str, int, list[str]]], sink_file: str, line_hint: int | None, authz_model: str
) -> bool:
    """True if an AUTHZ-BOLA-* finding lands in sink_file within the window AND
    names `authz_model` as one of the models it found missing or unproven."""
    needle = "/" + sink_file.lstrip("/")
    for path, line, models in index:
        norm = path.replace("\\", "/")
        if not (norm.endswith(needle) or norm.endswith(sink_file)):
            continue
        if line_hint is not None and abs(line - line_hint) > VULN_APP_SINK_WINDOW:
            continue
        if authz_model in models:
            return True
    return False


def _function_line_range(path: Path, symbol: str) -> tuple[int, int] | None:
    """(start, end) line range of `symbol`'s def in `path`, or None -- reuses
    the same AST-based resolution as benchmarks/check_ground_truth.py in the
    vuln-app repo, since a decoy's `location.symbol` is the stable anchor,
    not a line_hint the ground truth doesn't carry for decoys."""
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    except (OSError, SyntaxError):
        return None
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == symbol:
            return node.lineno, getattr(node, "end_lineno", node.lineno)
    return None


def _authz_false_positive(
    index: list[tuple[str, int, list[str]]], app_dir: Path, decoy_file: str, decoy_symbol: str
) -> bool:
    """True if an AUTHZ-BOLA-* finding lands inside decoy_symbol's own
    function body -- the decoy's whole point is that the authz_model it
    demonstrates is present and dominates, so a finding there (regardless of
    which model it claims is missing) is a false positive. Scoped to the
    symbol's line range, not merely "somewhere in decoy_file", since a decoy
    routinely shares a file with the vulnerability it's paired against (and
    with other decoys) -- a file-only check would blame every decoy in the
    file for a real finding in a neighboring function."""
    line_range = _function_line_range(app_dir / decoy_file, decoy_symbol)
    if line_range is None:
        return False
    start, end = line_range
    needle = "/" + decoy_file.lstrip("/")
    for path, line, _missing in index:
        norm = path.replace("\\", "/")
        if not (norm.endswith(needle) or norm.endswith(decoy_file)):
            continue
        if start <= line <= end:
            return True
    return False


def _decoy_class_keywords(decoy: dict, cwe_by_vuln_id: dict[str, str]) -> tuple[str, ...]:
    """Class keywords a finding must carry to count as *this decoy's* false
    positive, derived from the ground truth's own data rather than parsed out
    of the decoy's prose.

    Every decoy names the vulnerabilities it imitates in `resembles`
    ("V03/V24 (path traversal)"), so the decoy's class is the union of those
    vulns' declared CWEs. Class-matching matters because a decoy is a narrow
    claim -- D01 asserts `download_artifact` is *not* path traversal, not that
    nothing whatsoever may be reported in that function. An unrelated
    finding there (a logging or crypto issue) is not evidence the decoy was
    fooled, and blaming it would make the precision figure react to changes in
    completely unrelated rules.
    """
    keywords: set[str] = set()
    for vuln_id in re.findall(r"\bV\d+\b", decoy.get("resembles", "") or ""):
        cwe = cwe_by_vuln_id.get(vuln_id)
        if cwe:
            keywords.update(_cwe_keywords(str(cwe)))
    return tuple(sorted(keywords))


def _decoy_class_cwes(decoy: dict, cwe_by_vuln_id: dict[str, str]) -> set[int]:
    """Declared CWE classes of the vulnerabilities a decoy imitates."""
    return {
        cwe
        for vuln_id in re.findall(r"\bV\d+\b", decoy.get("resembles", "") or "")
        if (cwe := _declared_cwe(cwe_by_vuln_id.get(vuln_id, ""))) is not None
    }


def _symbol_class_hit(
    index: list[tuple[str, int, str] | tuple[str, int, str, tuple[int, ...] | None]],
    app_dir: Path,
    file: str,
    symbol: str | None,
    keywords: tuple[str, ...] | None,
    expected_cwes: set[int] | None = None,
) -> bool:
    """True if a class-consistent finding lands inside `symbol`'s function body
    (or anywhere in `file` when the ground truth gives no symbol).

    Symbol-scoped rather than file-scoped for the reason `_authz_false_positive`
    documents: a decoy routinely shares a file with the very vulnerability it
    is paired against, so a file-only test would blame the decoy for the real
    finding next door.

    `keywords=None` matches any finding at the location regardless of class.
    That is only used for `known_unlabeled` reporting, which is informational
    and never affects the score -- all three of the oracle's known_unlabeled
    CWEs (459, 798, 209) are outside `_CWE_CLASS_KEYWORDS`, so requiring a
    class here would make that reporting dead code. An empty *tuple* still
    means "no usable class, never a match", which is what decoy scoring needs.
    """
    if keywords is not None and not keywords:
        return False
    if not file:
        return False
    line_range = _function_line_range(app_dir / file, symbol) if symbol else None
    needle = "/" + file.lstrip("/")
    for entry in index:
        path, line, ident, cwe_ids = _index_parts(entry)
        norm = path.replace("\\", "/")
        if not (norm.endswith(needle) or norm.endswith(file)):
            continue
        if line_range is not None and not (line_range[0] <= line <= line_range[1]):
            continue
        if keywords is None or _class_match(ident, cwe_ids, expected_cwes or set(), keywords):
            return True
    return False


def _score_decoys(
    gt: dict,
    our_index: list[tuple[str, int, str] | tuple[str, int, str, tuple[int, ...] | None]],
    app_dir: Path,
) -> dict:
    """False positives against the ground truth's full decoy set.

    The oracle ships 50 decoys -- safe code deliberately shaped like the
    vulnerability it sits next to (a parameterized query beside the SQLi, a
    realpath-checked download beside the traversal). Only the 10 carrying an
    `authz_model` were scored, by `_score_authz_bola`; the other 40 were
    unused, which left the headline a recall figure with no paired precision
    figure and therefore trivially gameable by broadening rules.

    `known_unlabeled` entries are counted and reported but never penalized:
    they are real issues the oracle deliberately leaves out of the labeled set
    (a temp-file leak, documented demo seed credentials), so flagging one is
    correct behaviour, not a false positive.
    """
    decoys = gt.get("decoys", []) or []
    cwe_by_vuln_id = {
        v["id"]: v.get("cwe", "") for v in gt.get("vulnerabilities", []) if v.get("id")
    }

    fp_ids: list[str] = []
    authz_graded: list[str] = []
    unscored: list[str] = []
    for d in decoys:
        keywords = _decoy_class_keywords(d, cwe_by_vuln_id)
        if not keywords:
            # CWE-639 has no _CWE_CLASS_KEYWORDS entry by design (IDOR has no
            # reliable keyword signature), so its decoys can't be scored here.
            # An `authz_model`-tagged one is graded by _score_authz_bola
            # instead and is fully covered; one without that tag is scored by
            # nothing at all, which is a gap in the ground truth rather than in
            # this scorer -- surfaced separately so it can be fixed there.
            (authz_graded if d.get("authz_model") else unscored).append(d.get("id", "?"))
            continue
        loc = d.get("location", {}) or {}
        if _symbol_class_hit(
            our_index,
            app_dir,
            loc.get("file", ""),
            loc.get("symbol"),
            keywords,
            _decoy_class_cwes(d, cwe_by_vuln_id),
        ):
            fp_ids.append(d.get("id", "?"))

    ku_hits: list[str] = []
    for ku in gt.get("known_unlabeled", []) or []:
        loc = ku.get("location", {}) or {}
        # Location-only (keywords=None): informational, never scored. An entry
        # whose location gives no `symbol` is skipped rather than matched
        # file-wide, which would attribute any finding in that file to it.
        if not loc.get("symbol"):
            continue
        if _symbol_class_hit(our_index, app_dir, loc.get("file", ""), loc["symbol"], None):
            ku_hits.append(ku.get("id", "?"))

    return {
        "total": len(decoys),
        "scored": len(decoys) - len(authz_graded) - len(unscored),
        "authz_graded_ids": authz_graded,
        "unscored_ids": unscored,
        "false_positive_ids": fp_ids,
        "false_positives": len(fp_ids),
        "known_unlabeled_hit_ids": ku_hits,
    }


# Conservative category expectations for ground-truth CWEs whose Rowan
# category has one unambiguous home.  CWEs without such a mapping are omitted:
# reporting no category assessment is more useful than inventing a mismatch.
_CWE_EXPECTED_CATEGORIES: dict[int, set[str]] = {
    22: {"path_traversal"},
    73: {"path_traversal"},
    78: {"command_injection", "injection"},
    79: {"xss"},
    89: {"injection"},
    94: {"injection"},
    98: {"path_traversal"},
    200: {"general", "ai_ml"},
    287: {"auth"},
    306: {"auth"},
    311: {"crypto", "config"},
    319: {"crypto", "config"},
    327: {"crypto"},
    347: {"crypto", "auth"},
    352: {"auth"},
    502: {"deserialization"},
    601: {"xss", "general"},
    611: {"injection"},
    798: {"secrets"},
    862: {"auth"},
    863: {"auth"},
    918: {"ssrf"},
}


def _declared_cwe(value: object) -> int | None:
    raw = str(value).strip()
    if not (raw.upper().startswith("CWE-") or raw.isdigit()):
        return None
    match = re.search(r"(\d+)", raw)
    return int(match.group(1)) if match else None


def _finding_record(finding) -> dict:
    category = getattr(finding.category, "value", str(finding.category))
    return {
        "file": finding.file_path,
        "line": finding.start_line,
        "rule_id": finding.rule_id,
        "engine": finding.engine or "unknown",
        "category": category,
        "cwe_ids": list(finding.cwe_ids),
    }


def _same_file(path: str, expected: str) -> bool:
    norm = path.replace("\\", "/")
    return norm.endswith("/" + expected.lstrip("/")) or norm.endswith(expected)


def _finding_identity(finding) -> str:
    category = getattr(finding.category, "value", str(finding.category))
    return f"{category} {finding.rule_id} {finding.message}".lower()


def _score_distinct_findings(
    gt: dict,
    findings: list,
    app_dir: Path,
    eligible_vulnerability_ids: set[str] | None = None,
) -> dict:
    """Attribute each raw finding to at most one labeled root cause.

    This is diagnostic accounting alongside the established recall oracle. It
    makes duplicate rules and classification errors visible without allowing a
    single broad finding to receive credit for several vulnerabilities.
    """
    vulns = gt.get("vulnerabilities", []) or []
    assignments: dict[str, list] = {v["id"]: [] for v in vulns if v.get("id")}
    assigned: set[int] = set()
    category_mismatches: list[dict] = []
    cwe_mismatches: list[dict] = []

    # Reserve class-consistent findings inside explicitly labeled safe decoys
    # before applying the deliberately generous sink-line window. Nearby safe
    # and unsafe functions are common in this corpus; location order must not
    # turn a decoy alert into a TP or duplicate.
    cwe_by_vuln_id = {v["id"]: v.get("cwe", "") for v in vulns if v.get("id")}
    decoy_hits: dict[str, list] = {}
    for decoy in gt.get("decoys", []) or []:
        loc = decoy.get("location", {}) or {}
        keywords = _decoy_class_keywords(decoy, cwe_by_vuln_id)
        expected_cwes = _decoy_class_cwes(decoy, cwe_by_vuln_id)
        if not keywords or not loc.get("file"):
            continue
        line_range = (
            _function_line_range(app_dir / loc["file"], loc.get("symbol"))
            if loc.get("symbol")
            else None
        )
        hits = []
        for index, finding in enumerate(findings):
            if not _same_file(finding.file_path, loc["file"]):
                continue
            if line_range and not (line_range[0] <= finding.start_line <= line_range[1]):
                continue
            if finding.cwe_ids:
                class_match = bool(expected_cwes & set(finding.cwe_ids))
            else:
                class_match = any(keyword in _finding_identity(finding) for keyword in keywords)
            if class_match:
                hits.append(finding)
                assigned.add(index)
        if hits:
            decoy_hits[decoy.get("id", "?")] = hits

    candidates_by_finding: dict[int, list[tuple[int, int, str]]] = {}
    positional_by_finding: dict[int, list[tuple[int, str, int | None]]] = {}
    for index, finding in enumerate(findings):
        if index in assigned:
            continue
        identity = _finding_identity(finding)
        candidates: list[tuple[int, int, str]] = []
        positional: list[tuple[int, str, int | None]] = []
        for vuln in vulns:
            vuln_id = vuln.get("id")
            if not vuln_id:
                continue
            raw_sink = vuln.get("sink", {})
            sinks = raw_sink if isinstance(raw_sink, list) else [raw_sink]
            distances = [
                abs(finding.start_line - sink["line_hint"])
                for sink in sinks
                if sink.get("file")
                and isinstance(sink.get("line_hint"), int)
                and _same_file(finding.file_path, sink["file"])
                and abs(finding.start_line - sink["line_hint"]) <= VULN_APP_SINK_WINDOW
            ]
            sink_distance = min(distances) if distances else None
            expected_cwe = _declared_cwe(vuln.get("cwe"))
            if sink_distance is not None:
                positional.append((sink_distance, vuln_id, expected_cwe))
            if eligible_vulnerability_ids is not None and vuln_id not in eligible_vulnerability_ids:
                continue

            keywords = _cwe_keywords(vuln.get("cwe", ""))
            cwe_exact = expected_cwe is not None and expected_cwe in finding.cwe_ids
            # Declared CWE metadata is stronger than words in a composite
            # cross-file message, which can mention a prompt-injection source
            # while ending at an SSRF sink. Fall back to identity keywords only
            # when either side has no numeric CWE to compare.
            if expected_cwe is not None and finding.cwe_ids:
                class_match = cwe_exact
            else:
                class_match = bool(keywords) and any(k in identity for k in keywords)
            metadata = finding.metadata or {}
            finding_authz_models = set(metadata.get("missing_models") or []) | set(
                metadata.get("partial_models") or []
            )
            authz_match = (
                bool(vuln.get("authz_model"))
                and "AUTHZ-BOLA-001" in finding.reported_rule_ids()
                and vuln["authz_model"] in finding_authz_models
            )
            ai_match = (
                bool(vuln.get("ai_native_rule"))
                and str(vuln["ai_native_rule"]).lower() in {r.lower() for r in finding.reported_rule_ids()}
            )
            if not (class_match or authz_match or ai_match):
                continue
            if sink_distance is not None:
                rank = 0 if (authz_match or ai_match) else (1 if cwe_exact else 2)
                candidates.append((rank, sink_distance, vuln_id))
                continue
            path_files = _taint_path_files(vuln.get("taint_path", []))
            if any(_same_file(finding.file_path, path_file) for path_file in path_files):
                # A generic CF-* finding in a busy API file must identify this
                # vulnerability's declared caller/callee hops. File+CWE alone
                # can otherwise assign an unrelated cross-file path to a new
                # root merely because several vulnerabilities share a module.
                path_symbols = _taint_path_symbols(vuln.get("taint_path", []))
                cf = _cf_caller_callee(identity)
                if cf is not None and path_symbols and not all(
                    symbol in path_symbols for symbol in cf
                ):
                    continue
                # Same bar as the recall oracle: off the sink window, only a
                # finding inside a declared hop function counts (RT-11).
                if not _in_declared_hop(
                    finding.file_path, finding.start_line,
                    _taint_path_hops(vuln.get("taint_path", [])),
                ):
                    continue
                candidates.append((0 if cwe_exact else 1, VULN_APP_SINK_WINDOW + 1, vuln_id))

        if candidates:
            candidates_by_finding[index] = sorted(candidates)
        elif positional:
            positional_by_finding[index] = positional

    # Maximum bipartite matching gives every independently detected root cause
    # one representative before surplus alerts are counted as duplicates. A
    # greedy per-finding owner loses TPs when one broad cross-file alert can fit
    # several paths and consumes the only alert for a neighboring root cause.
    representative: dict[str, int] = {}

    def claim(index: int, seen: set[str]) -> bool:
        for _rank, _distance, vuln_id in candidates_by_finding.get(index, []):
            if vuln_id in seen:
                continue
            seen.add(vuln_id)
            previous = representative.get(vuln_id)
            if previous is None or claim(previous, seen):
                representative[vuln_id] = index
                return True
        return False

    for index in sorted(candidates_by_finding, key=lambda i: candidates_by_finding[i][0]):
        claim(index, set())

    owner_by_finding = {index: vuln_id for vuln_id, index in representative.items()}
    ordered_candidates = sorted(
        candidates_by_finding.items(), key=lambda item: (item[0] not in owner_by_finding, item[0])
    )
    for index, candidates in ordered_candidates:
        owner = owner_by_finding.get(index, candidates[0][2])
        finding = findings[index]
        assignments[owner].append(finding)
        assigned.add(index)
        owner_vuln = next(v for v in vulns if v.get("id") == owner)
        expected_cwe = _declared_cwe(owner_vuln.get("cwe"))
        expected_categories = _CWE_EXPECTED_CATEGORIES.get(expected_cwe or -1)
        actual_category = getattr(finding.category, "value", str(finding.category))
        if expected_categories and actual_category not in expected_categories:
            category_mismatches.append(
                {
                    **_finding_record(finding),
                    "vulnerability_id": owner,
                    "expected_categories": sorted(expected_categories),
                }
            )
        if expected_cwe is not None and expected_cwe not in finding.cwe_ids:
            cwe_mismatches.append(
                {
                    **_finding_record(finding),
                    "vulnerability_id": owner,
                    "expected_cwe": expected_cwe,
                    "kind": "missing" if not finding.cwe_ids else "wrong",
                }
            )

    for index, positional in positional_by_finding.items():
        finding = findings[index]
        if positional:
            # A finding at a labeled sink with an explicit, incompatible CWE is
            # useful evidence of classification drift, but receives no TP credit.
            distance, vuln_id, expected_cwe = min(positional)
            vuln = next(v for v in vulns if v.get("id") == vuln_id)
            keywords = _cwe_keywords(vuln.get("cwe", ""))
            class_hint = bool(keywords) and any(
                keyword in _finding_identity(finding) for keyword in keywords
            )
            if (
                class_hint
                and expected_cwe is not None
                and finding.cwe_ids
                and expected_cwe not in finding.cwe_ids
            ):
                cwe_mismatches.append(
                    {**_finding_record(finding), "vulnerability_id": vuln_id,
                     "expected_cwe": expected_cwe, "sink_distance": distance}
                )

    duplicates_by_vulnerability = {
        vuln_id: [_finding_record(f) for f in owned[1:]]
        for vuln_id, owned in assignments.items()
        if len(owned) > 1
    }
    per_engine: dict[str, dict[str, int]] = {}
    per_rule: dict[str, dict[str, int]] = {}

    def bump(bucket: dict, key: str, metric: str, amount: int = 1) -> None:
        row = bucket.setdefault(key, {"findings": 0, "distinct_tp": 0, "duplicates": 0, "decoy_fp": 0})
        row[metric] += amount

    for finding in findings:
        bump(per_engine, finding.engine or "unknown", "findings")
        bump(per_rule, finding.rule_id, "findings")
    for owned in assignments.values():
        if not owned:
            continue
        bump(per_engine, owned[0].engine or "unknown", "distinct_tp")
        bump(per_rule, owned[0].rule_id, "distinct_tp")
        for finding in owned[1:]:
            bump(per_engine, finding.engine or "unknown", "duplicates")
            bump(per_rule, finding.rule_id, "duplicates")
    for hits in decoy_hits.values():
        for finding in hits:
            bump(per_engine, finding.engine or "unknown", "decoy_fp")
            bump(per_rule, finding.rule_id, "decoy_fp")

    return {
        "true_positive_vulnerability_ids": sorted(k for k, v in assignments.items() if v),
        "distinct_true_positives": sum(bool(v) for v in assignments.values()),
        "false_positive_decoy_ids": sorted(decoy_hits),
        "false_positive_decoys": len(decoy_hits),
        "duplicate_findings": sum(max(0, len(v) - 1) for v in assignments.values()),
        "duplicates_by_vulnerability": duplicates_by_vulnerability,
        "unmatched_findings": [_finding_record(f) for i, f in enumerate(findings) if i not in assigned],
        "category_mismatches": category_mismatches,
        "cwe_mismatches": cwe_mismatches,
        "per_engine": dict(sorted(per_engine.items())),
        "per_rule": dict(sorted(per_rule.items())),
    }


def _taint_path_files(taint_path: list) -> set[str]:
    """Extract file paths from ground-truth taint_path entries, e.g.
    'dvml/api/models.py:create_model (note)' -> 'dvml/api/models.py'."""
    files = set()
    for entry in taint_path or []:
        text = entry if isinstance(entry, str) else str(entry)
        file_part = text.split(":", 1)[0].strip()
        if file_part:
            files.add(file_part)
    return files


def _taint_path_symbols(taint_path: list) -> set[str]:
    """Extract declared symbol names from the structured 'file:symbol[ ->
    symbol2][ / symbol3][ OR symbol4]' prefix of each taint_path entry,
    ignoring free-form descriptive text in parens/quotes and entries with no
    ':' at all (pure prose asides, e.g. "unlike fetch()" inside a note --
    that's not a declared hop of the exploit chain, just a comparison)."""
    symbols: set[str] = set()
    for entry in taint_path or []:
        text = entry if isinstance(entry, str) else str(entry)
        if ":" not in text:
            continue
        after_colon = text.split(":", 1)[1]
        stripped = re.sub(r"\([^)]*\)", "", after_colon)
        stripped = re.sub(r'"[^"]*"', "", stripped)
        for part in re.split(r"->|/|,| OR ", stripped):
            name = part.strip()
            if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
                symbols.add(name)
    # The structured parser also recovers names this split loses to nested
    # parens (RT-11); a dotted Class.method hop contributes its method name.
    for _file, name in _taint_path_hops(taint_path):
        symbols.add(name.rsplit(".", 1)[-1])
    return symbols


_HOP_FILE_RE = re.compile(r"([\w./-]+\.py):")
_HOP_NAME_RE = re.compile(r"[A-Za-z_][\w.]*")


def _taint_path_hops(taint_path: list) -> set[tuple[str, str]]:
    """(file, function) pairs the oracle declares on a vulnerability's path.

    Each ``file.py:name`` starts a hop; ``-> name``, ``/ name``, ``, name`` or
    ``OR name`` right after it adds more functions in the same file. The note
    that follows is prose, often with nested parens or quotes
    (``legacy_access_key (unsalted md5(password) ...)``), so parens and quotes
    are removed before splitting, the first part keeps only its leading name,
    and a later part counts only if it is a bare name (so "OR sync POST on
    archive import" adds nothing). RT-11.
    """
    hops: set[tuple[str, str]] = set()
    for entry in taint_path or []:
        if isinstance(entry, dict):
            text = " ".join(f"{key} {value}" for key, value in entry.items())
        else:
            text = str(entry)
        marks = list(_HOP_FILE_RE.finditer(text))
        for index, mark in enumerate(marks):
            end = marks[index + 1].start() if index + 1 < len(marks) else len(text)
            rest = re.sub(r'"[^"]*"', "", text[mark.end():end])
            while True:
                stripped = re.sub(r"\([^()]*\)", "", rest)
                if stripped == rest:
                    break
                rest = stripped
            rest = rest.split("(", 1)[0]
            for position, part in enumerate(re.split(r"->|/|,|\bOR\b", rest)):
                part = part.strip()
                name = _HOP_NAME_RE.match(part) if position == 0 else _HOP_NAME_RE.fullmatch(part)
                if name:
                    hops.add((mark.group(1), name.group(0)))
    return hops


@functools.lru_cache(maxsize=4096)
def _function_ranges(path: str, name: str) -> tuple[tuple[int, int], ...]:
    """Line ranges of every def called ``name`` in ``path`` (a dotted
    ``Class.method`` hop matches the method)."""
    try:
        tree = ast.parse(Path(path).read_text(encoding="utf-8"))
    except (OSError, SyntaxError, UnicodeDecodeError, ValueError):
        return ()
    short = name.rsplit(".", 1)[-1]
    return tuple(
        (node.lineno, getattr(node, "end_lineno", node.lineno))
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == short
    )


def _in_declared_hop(file_path: str, line: int, hops: set[tuple[str, str]]) -> bool:
    """True when (file_path, line) lies inside a function the oracle names on
    this vulnerability's path. A same-class finding elsewhere in a path file
    (another function, module level) is not a detection of it (RT-11)."""
    for hop_file, name in hops:
        if not _same_file(file_path, hop_file):
            continue
        if any(start <= line <= end for start, end in _function_ranges(file_path, name)):
            return True
    return False


def _cf_caller_callee(ident: str) -> tuple[str, str] | None:
    """Extract (caller, callee) function names from one of our own CF-SINK-001
    /CF-RETURN-001 cross-file findings' identity string (category+rule_id+
    message, e.g. '...cf-sink-001...chat() in agent.py reaches a sink via
    run_agent() from core.py...'). Returns None for anything that doesn't
    look like this exact shape (a different engine's finding, or an
    abbreviated fixture) -- callers should treat that as "can't verify," not
    "reject."

    Before issue #154's rule-id rename, the callee name was embedded in the
    rule id itself (`CF-<callee>`), so a bare `cf-(\\w+)` grabbed it directly.
    Now that cross-file findings use a small fixed rule-id family, both the
    caller and callee names are only available in the message text -- pulled
    from the same "<caller>() in <file> reaches a sink via <callee>()" /
    "captures tainted return from <callee>()" phrase `_emit_cross_file_finding`
    always emits.
    """
    if "cf-sink-001" not in ident and "cf-return-001" not in ident:
        return None
    m = re.search(
        r"(\w+)\(\)\s+in\s+\S+\s+(?:reaches a sink via|captures tainted return from)\s+(\w+)\(\)",
        ident,
    )
    if not m:
        return None
    return m.group(1), m.group(2)


def _hit_anywhere_on_path(
    index: list[tuple[str, int, str] | tuple[str, int, str, tuple[int, ...] | None]],
    taint_path_files: set[str],
    keywords: tuple[str, ...],
    taint_path_symbols: set[str] | None = None,
    expected_cwe: int | None = None,
    hops: set[tuple[str, str]] | None = None,
) -> bool:
    """Fallback for multi-hop findings (e.g. cross-file taint) that are
    correctly anchored at a call site along the taint path rather than the
    ground truth's final sink line -- a real detection, just not at the exact
    sink location the tight sink+line-hint check in _hit() expects. Requires
    the SAME class-consistency bar, just without the line-hint proximity
    requirement (multi-hop findings are pinned to a call site, not the sink
    line itself).

    File-membership + class-keyword alone is too loose once a taint_path's
    files overlap another vuln's (a common file can host several distinct
    bugs, or two vulns can legitimately share a hop): when `taint_path_symbols`
    is given and the candidate identifies as one of our own CF-* findings
    (caller/callee both parseable), also require BOTH the caller and the
    callee it names to be declared hops of THIS vuln's taint path -- not
    just class-consistent findings anywhere on files it happens to touch.
    Findings we can't parse a caller/callee out of (a different engine, or
    an abbreviated test fixture) skip this extra check rather than being
    rejected outright -- symbol-correlation is a tightening for the case we
    can verify, not a new universal requirement."""
    expected_cwes = {expected_cwe} if expected_cwe is not None else set()
    if (not expected_cwes and not keywords) or not taint_path_files or not hops:
        return False
    pairs = [("/" + f.lstrip("/"), f) for f in taint_path_files]
    for entry in index:
        path, line, ident, cwe_ids = _index_parts(entry)
        norm = path.replace("\\", "/")
        if not any(norm.endswith(needle) or norm.endswith(f) for needle, f in pairs):
            continue
        # Off the sink window, the finding must sit inside a declared hop
        # function, not merely somewhere in a file the path touches (RT-11).
        if not _in_declared_hop(path, line, hops):
            continue
        if not _class_match(ident, cwe_ids, expected_cwes, keywords):
            continue
        if taint_path_symbols:
            cf = _cf_caller_callee(ident)
            if cf is not None:
                caller, callee = cf
                if caller not in taint_path_symbols or callee not in taint_path_symbols:
                    continue
        return True
    return False


def _semgrep_index(
    app_dir: Path,
) -> list[tuple[str, int, str, tuple[int, ...] | None]] | None:
    """Run Semgrep over app_dir; return rows with untrusted CWE metadata.

    Semgrep's ``extra.metadata.cwe`` is not consistently populated, so the
    final field is deliberately ``None`` and class matching falls back to its
    rule/message identity.
    """
    semgrep_bin = shutil.which("semgrep")
    if semgrep_bin is None:
        return None
    configs: list[str] = []
    for c in SEMGREP_CONFIGS:
        configs += ["--config", c]
    try:
        proc = subprocess.run(  # noqa: S603
            [semgrep_bin, "scan", *configs, "--json", "--quiet", str(app_dir)],
            capture_output=True,
            text=True,
            timeout=600,
            encoding="utf-8",
            errors="replace",
        )
        data = json.loads(proc.stdout or "{}")
    except (subprocess.SubprocessError, json.JSONDecodeError, OSError):
        return None
    return [
        (
            r.get("path", ""),
            r.get("start", {}).get("line", -1),
            f"{r.get('check_id', '')} {r.get('extra', {}).get('message', '')}".lower(),
            None,
        )
        for r in data.get("results", [])
    ]


def run_vuln_app(with_semgrep: bool = True) -> dict | None:
    """Score per-vuln recall on the labeled vuln app; compare against Semgrep."""
    resolved = _resolve_vuln_app()
    if resolved is None:
        return None
    app_dir, gt = resolved
    source_dir = app_dir / (gt.get("meta", {}).get("source_dir") or ".")

    # enable_authz=True so AUTHZ-BOLA-* semantic grading (below) has AuthzPass
    # findings to score against; enable_multiagent=True so AGENT-HANDOFF-001
    # (one of the ai_native_rule categories, #197) fires -- both opt-in passes
    # only add findings, never suppress another engine's.
    ours = _scan_dir(source_dir, enable_authz=True, enable_multiagent=True)
    # Rowan CWE metadata is authoritative for its own findings. Semgrep's
    # metadata is not consistent enough to trust, so its index remains on the
    # explicit keyword-compatibility path below.
    our_index = [
        (
            f.file_path,
            f.start_line,
            f"{f.category.value} {f.rule_id} {f.message}".lower(),
            tuple(f.cwe_ids),
        )
        for f in ours
    ]
    authz_index = _authz_index(ours)
    ai_native_index = _ai_native_index(ours)

    semgrep_index = _semgrep_index(app_dir) if with_semgrep else None

    vulns = gt.get("vulnerabilities", [])
    rows = []
    for v in vulns:
        raw_sink = v.get("sink", {})
        # A vuln can be reachable via more than one sink (e.g. a sync path and
        # a worker/async path) -- ground truth then declares `sink` as a list
        # rather than a single dict; a hit on ANY of them counts.
        sinks = raw_sink if isinstance(raw_sink, list) else [raw_sink]
        keywords = _cwe_keywords(v.get("cwe", ""))
        expected_cwe = _declared_cwe(v.get("cwe"))
        path_files = _taint_path_files(v.get("taint_path", []))
        path_symbols = _taint_path_symbols(v.get("taint_path", []))
        path_hops = _taint_path_hops(v.get("taint_path", []))
        authz_model = v.get("authz_model")
        ai_native_rule = v.get("ai_native_rule")

        ours_hit = any(
            _hit(our_index, s.get("file", ""), s.get("line_hint"), keywords, expected_cwe)
            for s in sinks
            if s.get("file")
        ) or _hit_anywhere_on_path(
            our_index, path_files, keywords, path_symbols, expected_cwe, path_hops
        )
        if authz_model:
            ours_hit = ours_hit or any(
                _authz_hit(authz_index, s.get("file", ""), s.get("line_hint"), authz_model)
                for s in sinks
                if s.get("file")
            )
        if ai_native_rule:
            # CWEs like 863 (authz) and 269 (privilege mgmt) have no reliable
            # keyword signature in _CWE_CLASS_KEYWORDS -- same reasoning as
            # authz_model above -- so an exact rule_id hit is scored directly
            # rather than falling through to a permanent MISS.
            ours_hit = ours_hit or any(
                _ai_native_hit(ai_native_index, s.get("file", ""), s.get("line_hint"), ai_native_rule)
                for s in sinks if s.get("file")
            )
        semgrep_hit = None
        if semgrep_index is not None:
            semgrep_hit = any(
                _hit(semgrep_index, s.get("file", ""), s.get("line_hint"), keywords, expected_cwe)
                for s in sinks
                if s.get("file")
            ) or _hit_anywhere_on_path(
                semgrep_index, path_files, keywords, path_symbols, expected_cwe, path_hops
            )
        rows.append(
            {
                "id": v.get("id"),
                "tier": v.get("tier"),
                "title": v.get("title", ""),
                "ours": ours_hit,
                "semgrep": semgrep_hit,
                "authz_model": authz_model,
            }
        )

    n = len(rows)
    our_recall = sum(1 for r in rows if r["ours"]) / n if n else 0.0
    semgrep_recall = (
        sum(1 for r in rows if r["semgrep"]) / n if (semgrep_index is not None and n) else None
    )
    detected = sum(1 for r in rows if r["ours"])
    decoys = _score_decoys(gt, our_index, app_dir)
    # Precision over the oracle's own labeled set, counting each entry once:
    # a detected vulnerability is a true positive, a decoy we flagged in-class
    # is a false positive. This is NOT precision over every finding the scan
    # produced -- the oracle does not label the whole app (see its
    # `known_unlabeled` section), so that number cannot be computed from it.
    # Reported alongside recall so recall can never be raised by broadening
    # rules without the cost showing up here.
    fp = decoys["false_positives"]
    decoys["precision"] = detected / (detected + fp) if (detected + fp) else None
    distinct = _score_distinct_findings(
        gt,
        ours,
        app_dir,
        {row["id"] for row in rows if row["ours"]},
    )

    return {
        "rows": rows,
        "n": n,
        "our_recall": our_recall,
        "semgrep_recall": semgrep_recall,
        "semgrep_available": semgrep_index is not None,
        "authz_bola": _score_authz_bola(gt, authz_index, app_dir),
        "decoys": decoys,
        "distinct_findings": distinct,
        "ai_native": _score_ai_native(gt, ai_native_index, app_dir),
    }


def _score_authz_bola(
    gt: dict, authz_index: list[tuple[str, int, list[str]]], app_dir: Path
) -> dict | None:
    """Per-model recall/precision for AUTHZ-BOLA-* findings (#175): recall
    against `authz_model`-tagged vulnerabilities, precision against
    `authz_model`-tagged decoys (a finding inside the decoy's own function is
    a false positive by definition -- the decoy's whole point is that its
    model is present and dominates). Returns None if the ground truth has no
    authz_model-tagged entries at all (an older vuln-app checkout)."""
    vulns = [v for v in gt.get("vulnerabilities", []) if v.get("authz_model")]
    decoys = [d for d in gt.get("decoys", []) if d.get("authz_model")]
    if not vulns and not decoys:
        return None

    per_model: dict[str, dict[str, int]] = {}
    for v in vulns:
        model = v["authz_model"]
        raw_sink = v.get("sink", {})
        sinks = raw_sink if isinstance(raw_sink, list) else [raw_sink]
        hit = any(
            _authz_hit(authz_index, s.get("file", ""), s.get("line_hint"), model)
            for s in sinks
            if s.get("file")
        )
        bucket = per_model.setdefault(model, {"tp": 0, "fn": 0, "fp": 0, "decoys": 0})
        bucket["tp" if hit else "fn"] += 1

    fp_ids: list[str] = []
    for d in decoys:
        model = d["authz_model"]
        loc = d.get("location", {})
        bucket = per_model.setdefault(model, {"tp": 0, "fn": 0, "fp": 0, "decoys": 0})
        bucket["decoys"] += 1
        if (
            loc.get("file")
            and loc.get("symbol")
            and _authz_false_positive(authz_index, app_dir, loc["file"], loc["symbol"])
        ):
            bucket["fp"] += 1
            fp_ids.append(d.get("id", "?"))

    for bucket in per_model.values():
        tp, fn, fp = bucket["tp"], bucket["fn"], bucket["fp"]
        bucket["recall"] = tp / (tp + fn) if (tp + fn) else None
        bucket["precision"] = tp / (tp + fp) if (tp + fp) else None

    total_tp = sum(b["tp"] for b in per_model.values())
    total_fn = sum(b["fn"] for b in per_model.values())
    total_fp = sum(b["fp"] for b in per_model.values())
    return {
        "per_model": per_model,
        "overall_recall": total_tp / (total_tp + total_fn) if (total_tp + total_fn) else None,
        "overall_precision": total_tp / (total_tp + total_fp) if (total_tp + total_fp) else None,
        "false_positive_decoy_ids": fp_ids,
    }


# ---------------------------------------------------------------------------
# AI-native detection categories (epic #183, seed tier for #197): unlike
# AUTHZ-BOLA-001, each category here is its own distinct rule_id (a YAML rule
# or an AST pass emitting a fixed rule_id like AGENT-HANDOFF-001), not one
# rule covering a family of semantic models. Ground-truth vulns/decoys tagged
# with `ai_native_rule` are graded by EXACT rule_id match, not by a
# missing-model classification.
# ---------------------------------------------------------------------------


def _ai_native_index(findings: list) -> list[tuple[str, int, str]]:
    """(file, line, rule_id) for every finding, the raw material for exact
    rule_id lookups below."""
    return [(f.file_path, f.start_line, r) for f in findings for r in sorted(f.reported_rule_ids())]


def _ai_native_hit(
    index: list[tuple[str, int, str]], sink_file: str, line_hint: int | None, rule_id: str
) -> bool:
    """True if a finding with EXACTLY `rule_id` lands in sink_file within the window."""
    needle = "/" + sink_file.lstrip("/")
    for path, line, fid in index:
        if fid != rule_id:
            continue
        norm = path.replace("\\", "/")
        if not (norm.endswith(needle) or norm.endswith(sink_file)):
            continue
        if line_hint is not None and abs(line - line_hint) > VULN_APP_SINK_WINDOW:
            continue
        return True
    return False


def _ai_native_false_positive(
    index: list[tuple[str, int, str]], app_dir: Path, decoy_file: str, decoy_symbol: str, rule_id: str
) -> bool:
    """True if a finding with EXACTLY `rule_id` lands inside decoy_symbol's own
    function body -- reuses _function_line_range, the same AST-based anchor
    _authz_false_positive relies on."""
    line_range = _function_line_range(app_dir / decoy_file, decoy_symbol)
    if line_range is None:
        return False
    start, end = line_range
    needle = "/" + decoy_file.lstrip("/")
    for path, line, fid in index:
        if fid != rule_id:
            continue
        norm = path.replace("\\", "/")
        if not (norm.endswith(needle) or norm.endswith(decoy_file)):
            continue
        if start <= line <= end:
            return True
    return False


def _score_ai_native(
    gt: dict, ai_native_index: list[tuple[str, int, str]], app_dir: Path
) -> dict | None:
    """Per-rule recall/precision for `ai_native_rule`-tagged ground truth
    (#183/#197): each shipped AI-native category gets its own rule_id-scoped
    recall (against its one tagged vuln) and precision (against its one
    tagged decoy). Deliberately thin -- one vuln + one decoy per rule, a seed
    measurement rather than a mature multi-decoy tier like BOLA's (#175).
    Returns None if the ground truth has no ai_native_rule-tagged entries at
    all (an older vuln-app checkout, or langfail's own upstream state before
    this tier landed)."""
    vulns = [v for v in gt.get("vulnerabilities", []) if v.get("ai_native_rule")]
    decoys = [d for d in gt.get("decoys", []) if d.get("ai_native_rule")]
    if not vulns and not decoys:
        return None

    per_rule: dict[str, dict[str, int]] = {}
    for v in vulns:
        rule_id = v["ai_native_rule"]
        raw_sink = v.get("sink", {})
        sinks = raw_sink if isinstance(raw_sink, list) else [raw_sink]
        hit = any(
            _ai_native_hit(ai_native_index, s.get("file", ""), s.get("line_hint"), rule_id)
            for s in sinks if s.get("file")
        )
        bucket = per_rule.setdefault(rule_id, {"tp": 0, "fn": 0, "fp": 0, "decoys": 0})
        bucket["tp" if hit else "fn"] += 1

    fp_ids: list[str] = []
    for d in decoys:
        rule_id = d["ai_native_rule"]
        loc = d.get("location", {})
        bucket = per_rule.setdefault(rule_id, {"tp": 0, "fn": 0, "fp": 0, "decoys": 0})
        bucket["decoys"] += 1
        if loc.get("file") and loc.get("symbol") and _ai_native_false_positive(
            ai_native_index, app_dir, loc["file"], loc["symbol"], rule_id
        ):
            bucket["fp"] += 1
            fp_ids.append(d.get("id", "?"))

    for bucket in per_rule.values():
        tp, fn, fp = bucket["tp"], bucket["fn"], bucket["fp"]
        bucket["recall"] = tp / (tp + fn) if (tp + fn) else None
        bucket["precision"] = tp / (tp + fp) if (tp + fp) else None

    total_tp = sum(b["tp"] for b in per_rule.values())
    total_fn = sum(b["fn"] for b in per_rule.values())
    total_fp = sum(b["fp"] for b in per_rule.values())
    return {
        "per_rule": per_rule,
        "overall_recall": total_tp / (total_tp + total_fn) if (total_tp + total_fn) else None,
        "overall_precision": total_tp / (total_tp + total_fp) if (total_tp + total_fp) else None,
        "false_positive_decoy_ids": fp_ids,
    }


def _finding_hops(f) -> int | None:
    """True source->sink hop distance of a taint finding (0 = direct), or None
    if the finding isn't a hop-scored taint finding at all."""
    if getattr(f, "engine", None) == "crossfile":
        hd = (f.metadata or {}).get("hop_depth")
        return (hd - 1) if isinstance(hd, int) and hd >= 1 else 0
    tf = getattr(f, "taint_flow", None)
    if tf is not None and getattr(f, "engine", None) == "opengrep":
        return len(tf.intermediate)
    return None


def collect_calibration_observations() -> list[tuple[int, bool]]:
    """Run the labeled vuln_app scan and label each hop-scored taint finding
    as a true or false positive (#123). A finding is a TP if it lands within
    the sink window of some ground-truth vulnerability with a matching CWE
    class; otherwise a FP. Returns [] when the corpus is unavailable."""
    resolved = _resolve_vuln_app()
    if resolved is None:
        return []
    app_dir, gt = resolved
    source_dir = app_dir / (gt.get("meta", {}).get("source_dir") or ".")
    findings = _scan_dir(source_dir)

    gt_sinks: list[tuple[str, int | None, tuple[str, ...], int | None]] = []
    for v in gt.get("vulnerabilities", []):
        raw = v.get("sink", {})
        for s in raw if isinstance(raw, list) else [raw]:
            if s.get("file"):
                gt_sinks.append(
                    (
                        s["file"],
                        s.get("line_hint"),
                        _cwe_keywords(v.get("cwe", "")),
                        _declared_cwe(v.get("cwe")),
                    )
                )

    observations: list[tuple[int, bool]] = []
    for f in findings:
        hops = _finding_hops(f)
        if hops is None:
            continue
        ident = f"{f.category.value} {f.rule_id} {f.message}".lower()
        index = [(f.file_path, f.start_line, ident, tuple(f.cwe_ids))]
        is_tp = any(_hit(index, sf, sl, kw, expected_cwe) for sf, sl, kw, expected_cwe in gt_sinks)
        observations.append((hops, is_tp))
    return observations


def run_calibrate() -> int:
    """Report how well the shipped confidence constants separate true from
    false positives on the labeled corpus, and the best grid alternative."""
    from rowan.core.confidence import (
        OPENGREP_TAINT,
        calibrate_hop_model,
        discriminative_separation,
    )

    obs = collect_calibration_observations()
    if not obs:
        print(
            "  SKIP: calibration needs the labeled vuln_app corpus. Set "
            "ROWAN_VULN_APP_PATH to a ModelForge checkout (see "
            "benchmark/ground_truth/vuln_app/README.md)."
        )
        return 0
    tps = sum(1 for _h, tp in obs if tp)
    print(f"  observations: {len(obs)} taint findings ({tps} TP / {len(obs) - tps} FP)")
    shipped = discriminative_separation(obs, OPENGREP_TAINT)
    best_model, best_score = calibrate_hop_model(obs)
    print(f"  shipped OPENGREP_TAINT separation: {shipped:+.4f}")
    print(
        f"  best grid model: base={best_model.base} decay={best_model.decay} "
        f"separation={best_score:+.4f}"
    )
    if best_score > shipped + 1e-6:
        print(
            "  -> the grid found better-separating constants; consider updating "
            "rowan/core/confidence.py (re-verify recall/precision first)."
        )
    else:
        print("  -> shipped constants are at/near the grid optimum on this corpus.")
    return 0


def run_clean_models() -> tuple[int, list[str], int]:
    """Returns (total_findings, detail_messages, num_models_scanned)."""
    models_dir = GROUND_TRUTH / "clean_models"
    manifest_path = models_dir / "manifest.json"
    if not manifest_path.exists():
        return 0, [], 0
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    cache_dir = models_dir / "cache"

    scanner = ModelFileScanner()
    total_findings = 0
    scanned = 0
    details = []
    for entry in manifest["models"]:
        local_path = cache_dir / entry["cache_filename"]
        if not local_path.exists():
            details.append(f"{entry['name']}: NOT CACHED (run scripts/fetch_clean_models.py first)")
            continue
        scanned += 1
        findings = scanner.scan_file(local_path)
        if findings:
            total_findings += len(findings)
            details.append(f"{entry['name']}: {len(findings)} findings (expected 0)")
    return total_findings, details, scanned


def _git_revision(path: Path) -> str:
    git = shutil.which("git")
    if git is None:
        return "unknown"
    result = subprocess.run(  # noqa: S603 -- fixed git argv; path is never interpreted by a shell
        [git, "-C", str(path), "rev-parse", "HEAD"], capture_output=True, text=True
    )
    return result.stdout.strip() if result.returncode == 0 else "unknown"


def _scanner_fingerprint() -> str:
    """Fingerprint committed and working-tree scanner/rule changes."""
    digest = hashlib.sha256(_git_revision(PROJECT_ROOT).encode())
    git = shutil.which("git")
    if git is None:
        return digest.hexdigest()
    result = subprocess.run(  # noqa: S603 -- fixed git argv; no shell involved
        [git, "-C", str(PROJECT_ROOT), "diff", "--", "rowan", "rules"],
        capture_output=True,
    )
    digest.update(result.stdout)
    return digest.hexdigest()


def _write_checkpoint(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)


def run_clean_code(
    update_baseline: bool,
    repo_names: set[str] | None = None,
    resume: bool = False,
    checkpoint_path: Path = CLEAN_CODE_CHECKPOINT,
    taint_jobs: int | None = None,
) -> tuple[bool, dict]:
    manifest_path = GROUND_TRUTH / "clean_code" / "manifest.json"
    if not manifest_path.exists():
        return True, {}
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    baseline = {}
    if BASELINE_PATH.exists():
        baseline = json.loads(BASELINE_PATH.read_text(encoding="utf-8")).get("clean_code", {})

    selected = [e for e in manifest["repos"] if not repo_names or e["name"] in repo_names]
    known_names = {e["name"] for e in manifest["repos"]}
    unknown = sorted((repo_names or set()) - known_names)
    if unknown:
        raise ValueError(f"unknown clean-code repo(s): {', '.join(unknown)}")

    fingerprint = _scanner_fingerprint()
    checkpoint: dict = {"scanner": fingerprint, "repos": {}}
    if resume and checkpoint_path.exists():
        loaded = json.loads(checkpoint_path.read_text(encoding="utf-8"))
        if loaded.get("scanner") == fingerprint and loaded.get("taint_jobs") == taint_jobs:
            checkpoint = loaded
    checkpoint["taint_jobs"] = taint_jobs

    current = {}
    regressed = False
    degraded_repos: list[str] = []
    for entry in selected:
        repo_path = PROJECT_ROOT / entry["local_path"]
        if not repo_path.exists():
            print(f"  SKIP {entry['name']}: not cloned locally at {repo_path}")
            continue
        revision = _git_revision(repo_path)
        cached = checkpoint["repos"].get(entry["name"])
        resumed = bool(resume and cached and cached.get("revision") == revision)
        if resumed:
            print(f"  {entry['name']}: resumed completed result", flush=True)
            total = cached["result"]["total"]
            high_critical = cached["result"]["high_critical"]
        else:
            print(f"  {entry['name']}: scanning {revision[:12]}...", flush=True)
            findings, degraded = _scan_dir_retrying(repo_path, taint_jobs=taint_jobs)
            if not degraded:
                total = len(findings)
                high_critical = sum(
                    1 for f in findings if f.severity.value in ("high", "critical")
                )
        if not resumed:
            if degraded:
                # Never record a partial scan: it yields fewer findings, so it
                # reads as a precision improvement and would silently ratchet the
                # baseline down to a number the scanner cannot actually reproduce.
                # The repo keeps its previous baseline entry and the run fails.
                reason = "; ".join(degraded.values())
                print(f"  {entry['name']}: DEGRADED after retry ({reason}) -- not recorded")
                degraded_repos.append(entry["name"])
                if entry["name"] in baseline:
                    current[entry["name"]] = dict(baseline[entry["name"]])
                continue
        current[entry["name"]] = {"total": total, "high_critical": high_critical}
        checkpoint["repos"][entry["name"]] = {
            "revision": revision,
            "result": current[entry["name"]],
        }
        _write_checkpoint(checkpoint_path, checkpoint)

        prior = baseline.get(entry["name"])
        if prior and not update_baseline:
            total_delta = total - prior["total"]
            hc_delta = high_critical - prior["high_critical"]
            flag = ""
            if (
                total_delta > CLEAN_CODE_TOTAL_TOLERANCE
                or hc_delta > CLEAN_CODE_HIGH_CRITICAL_TOLERANCE
            ):
                regressed = True
                flag = "  <-- REGRESSION"
            print(
                f"  {entry['name']}: total {prior['total']} -> {total} ({total_delta:+d}), "
                f"high/critical {prior['high_critical']} -> {high_critical} ({hc_delta:+d}){flag}"
            )
        else:
            print(
                f"  {entry['name']}: total={total} high_critical={high_critical} (no prior baseline)"
            )

    if degraded_repos:
        print(
            f"\n  {len(degraded_repos)} repo(s) scanned incompletely and were not measured: "
            f"{', '.join(degraded_repos)}.\n"
            "  A degraded scan reports fewer findings, so recording it would read as a\n"
            "  precision improvement. Re-run once the underlying scan failure is resolved."
        )
    return (not regressed and not degraded_repos), current


# ---------------------------------------------------------------------------
# cve_cases: real-CVE recall corpus (issue #105). Commit-pinned PRE-FIX repo
# checkouts, each labeled with the sink file/line and CWE of the real
# vulnerability. Fetched on demand (scripts/fetch_cve_cases.py) into
# cve_cases/cache/<id>/ and NOT committed -- unfetched cases are skipped, exactly
# like clean_models. Scored through the same file+line+CWE-class grader as
# vuln_app, so recall here means "we detect the real bug, by the right class."
# ---------------------------------------------------------------------------


@dataclass
class CveCaseResult:
    id: str
    cwe: str
    pool: str
    fetched: bool
    found: bool


def run_cve_cases() -> tuple[dict, list[CveCaseResult], int]:
    """Returns (scores, results, num_fetched). Recall is over FETCHED cases only."""
    manifest_path = GROUND_TRUTH / "cve_cases" / "manifest.json"
    if not manifest_path.exists():
        return {}, [], 0
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    cache_dir = GROUND_TRUTH / "cve_cases" / "cache"

    results: list[CveCaseResult] = []
    fetched = 0
    for case in manifest.get("cases", []):
        cid = case["id"]
        pool = case.get("pool", "regression")
        checkout = cache_dir / cid
        if not checkout.is_dir():
            results.append(
                CveCaseResult(cid, str(case.get("cwe", "")), pool, fetched=False, found=False)
            )
            continue
        fetched += 1
        scan_root = checkout / case["subdir"] if case.get("subdir") else checkout
        findings = _scan_dir(scan_root)
        index = [
            (
                f.file_path,
                f.start_line,
                f"{f.category.value} {f.rule_id} {f.message}".lower(),
                tuple(f.cwe_ids),
            )
            for f in findings
        ]
        keywords = _cwe_keywords(str(case.get("cwe", "")))
        hit = _hit(
            index,
            case["sink_file"],
            case.get("sink_line"),
            keywords,
            _declared_cwe(case.get("cwe")),
        )
        results.append(CveCaseResult(cid, str(case.get("cwe", "")), pool, fetched=True, found=hit))

    fetched_results = [
        # reuse _pool_recall by presenting fetched CVE cases as vuln-case-shaped rows
        VulnCaseResult(file=r.id, expected=r.cwe, found=r.found, matched_rule_ids=[], pool=r.pool)
        for r in results
        if r.fetched
    ]
    scores = {
        "regression": _pool_recall(fetched_results, "regression"),
        "holdout": _pool_recall(fetched_results, "holdout"),
        "overall": {
            "recall": (sum(1 for r in fetched_results if r.found) / len(fetched_results))
            if fetched_results
            else None,
            "hits": sum(1 for r in fetched_results if r.found),
            "total": len(fetched_results),
        },
    }
    return scores, results, fetched


def run_js_authz_cases() -> dict | None:
    """Small self-contained JS BOLA/IDOR tier for JSAuthzPass. Recall over
    `kind: vuln` fixtures, precision over `kind: decoy` fixtures. Returns None
    when the optional tree-sitter stack is unavailable."""
    from rowan.passes.js_cross_file import TREE_SITTER_AVAILABLE

    if not TREE_SITTER_AVAILABLE:
        return None
    corpus_dir = GROUND_TRUTH / "js_authz"
    manifest_path = corpus_dir / "manifest.json"
    if not manifest_path.exists():
        return None
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    findings = [
        f
        for f in _scan_dir(
            corpus_dir,
            enable_authz=True,
            no_taint=True,
            legacy_neuroscan=True,
            no_cross_file=True,
        )
        if "AUTHZ-BOLA-001" in f.reported_rule_ids()
    ]
    files = {Path(f.file_path).name for f in findings}
    rows: list[tuple[str, str, bool]] = []
    hits = vulns = decoy_fps = 0
    for case in manifest.get("cases", []):
        kind = case.get("kind", "vuln")
        found = case["file"] in files
        if kind == "vuln":
            vulns += 1
            hits += int(found)
        else:
            decoy_fps += int(found)
        rows.append((case["file"], kind, found))
    recall = hits / vulns if vulns else None
    precision = hits / (hits + decoy_fps) if (hits + decoy_fps) else None
    return {
        "recall": recall,
        "precision": precision,
        "hits": hits,
        "vulns": vulns,
        "decoy_fps": decoy_fps,
        "rows": rows,
        "ok": recall == 1.0 and decoy_fps == 0,
    }


#: Cross-file rule ids. A second-order flow is credited only by one of these:
#: they are the only findings that assert "the reader is handling untrusted
#: data that arrived from somewhere else". Single-file hits on the sink helper
#: (NS-CMDI-002 and friends) say nothing about the writer/reader pairing.
_SECOND_ORDER_RULE_IDS: frozenset[str] = frozenset({"CF-SINK-001", "CF-RETURN-001"})


def run_authz_cases() -> dict | None:
    """Score the fixture-driven Python/JS authorization recognizer corpus."""
    corpus_dir = GROUND_TRUTH / "authz"
    manifest_path = corpus_dir / "manifest.json"
    if not manifest_path.exists():
        return None
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    rows: list[dict] = []
    for case in manifest.get("cases", []):
        case_dir = corpus_dir / case["dir"]
        if not case_dir.is_dir():
            continue
        findings, degraded = _scan_dir_retrying(
            case_dir, enable_authz=True, enable_multiagent=True
        )
        if degraded:
            return {"degraded": degraded, "rows": []}

        indexed = [
            (
                Path(f.file_path).resolve().relative_to(case_dir.resolve()).as_posix(),
                f.start_line,
                f.rule_id,
            )
            for f in findings
        ]
        if case["expected"] == "detect":
            expected_items = [tuple(item) for item in case.get("expect", [])]
            matched = [
                item
                for item in expected_items
                if any(
                    path == item[0] and line == item[1] and item[2] in rule_id
                    for path, line, rule_id in indexed
                )
            ]
            found = len(matched) == len(expected_items)
            detail = {"expected_items": expected_items, "matched": matched}
        else:
            prohibited = set(case.get("rules", []))
            firing = sorted(
                (path, line, rule_id)
                for path, line, rule_id in indexed
                if rule_id in prohibited
            )
            found = bool(firing)
            detail = {"firing": firing}
        rows.append(
            {
                "dir": case["dir"],
                "expected": case["expected"],
                "item": case.get("item", ""),
                "found": found,
                **detail,
            }
        )

    detect = [row for row in rows if row["expected"] == "detect"]
    clean = [row for row in rows if row["expected"] == "clean"]
    hits = sum(1 for row in detect if row["found"])
    fps = sum(1 for row in clean if row["found"])
    return {
        "degraded": {},
        "rows": rows,
        "recall": hits / len(detect) if detect else None,
        "hits": hits,
        "vulns": len(detect),
        "false_positives": fps,
        "ok": (not detect or hits == len(detect)) and fps == 0,
    }


def run_second_order_cases() -> dict | None:
    """Score the second_order corpus: taint written to a persistence layer in
    one file and read back in another, with no call edge joining them.

    Each case directory is scanned as its OWN project root. The vector-store
    channel prefers stable resource identity and falls back to receiver scope;
    the ORM channel falls back to bare class names when a class can't be
    resolved. Per-case scans preserve both channel identity and benchmark
    isolation instead of allowing one case to arm or contaminate another.

    `expected: detect` and `expected: clean` gate. `known_gap` and `known_fp`
    are recorded and printed but never gate: they are the documented roadmap,
    and a run that starts disagreeing with them is reported as an improvement,
    not a failure.
    """
    corpus_dir = GROUND_TRUTH / "second_order"
    manifest_path = corpus_dir / "manifest.json"
    if not manifest_path.exists():
        return None
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    rows: list[dict] = []
    for case in manifest.get("cases", []):
        case_dir = corpus_dir / case["dir"]
        if not case_dir.is_dir():
            continue
        findings, degraded = _scan_dir_retrying(case_dir)
        if degraded:
            # A degraded scan produces FEWER findings, so recording it would
            # read as "the gaps got wider" (or as a negative passing) for a
            # reason that has nothing to do with the analysis.
            return {"degraded": degraded, "rows": []}

        reader_file = case["reader_file"]
        hit_lines = sorted(
            f.start_line
            for f in findings
            if f.reported_rule_ids() & _SECOND_ORDER_RULE_IDS
            and Path(f.file_path).resolve().relative_to(case_dir.resolve()).as_posix()
            == reader_file
        )
        rows.append(
            {
                "dir": case["dir"],
                "channel": case["channel"],
                "expected": case["expected"],
                "detection": case.get("detection", "channel"),
                "found": bool(hit_lines),
                "lines": hit_lines,
            }
        )

    def _bucket(expected: str) -> list[dict]:
        return [r for r in rows if r["expected"] == expected]

    detect, clean = _bucket("detect"), _bucket("clean")
    gaps, known_fps = _bucket("known_gap"), _bucket("known_fp")
    hits = sum(1 for r in detect if r["found"])
    fps = sum(1 for r in clean if r["found"])
    paired = [r for r in detect if r["detection"] == "channel"]

    return {
        "degraded": {},
        "rows": rows,
        "recall": (hits / len(detect)) if detect else None,
        "hits": hits,
        "vulns": len(detect),
        "paired_hits": sum(1 for r in paired if r["found"]),
        "paired_total": len(paired),
        "false_positives": fps,
        "gaps_closed": [r["dir"] for r in gaps if r["found"]],
        "gaps_open": [r["dir"] for r in gaps if not r["found"]],
        "known_gaps_total": len(gaps),
        "known_fps_firing": [r["dir"] for r in known_fps if r["found"]],
        "known_fps_fixed": [r["dir"] for r in known_fps if not r["found"]],
        "known_fps_total": len(known_fps),
        "ok": (not detect or hits == len(detect)) and fps == 0,
    }


# ---------------------------------------------------------------------------
# cross_file: ordinary call-edge chains between files (RT-19). Until this
# corpus existed no gated number exercised CrossFilePass at all.
# ---------------------------------------------------------------------------

_CROSS_FILE_RULE_IDS = frozenset({"CF-SINK-001", "CF-RETURN-001"})


def run_cross_file_cases() -> dict | None:
    """Score the cross_file corpus. Each case directory is its own project
    root. A `detect` case is a hit when every line in its `lines` carries a
    CF-SINK-001 (or the case's `rule_id`, e.g. CF-RETURN-001) anchored in
    `caller_file`; a `clean` case must produce no
    CF-* finding anywhere. Both gate. JavaScript cases are skipped when
    tree-sitter is not installed."""
    corpus_dir = GROUND_TRUTH / "cross_file"
    manifest_path = corpus_dir / "manifest.json"
    if not manifest_path.exists():
        return None
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    from rowan.passes.js_cross_file import TREE_SITTER_AVAILABLE

    rows: list[dict] = []
    skipped: list[str] = []
    for case in manifest.get("cases", []):
        case_dir = corpus_dir / case["dir"]
        if not case_dir.is_dir():
            continue
        if case.get("language") == "javascript" and not TREE_SITTER_AVAILABLE:
            skipped.append(case["dir"])
            continue
        findings, degraded = _scan_dir_retrying(case_dir)
        if degraded:
            return {"degraded": degraded, "rows": [], "skipped": skipped}
        cf = [f for f in findings if f.reported_rule_ids() & _CROSS_FILE_RULE_IDS]
        caller_lines = sorted(
            f.start_line
            for f in cf
            if case.get("rule_id", "CF-SINK-001") in f.reported_rule_ids()
            and Path(f.file_path).resolve().relative_to(case_dir.resolve()).as_posix()
            == case["caller_file"]
        )
        if case["expected"] == "detect":
            found = all(line in caller_lines for line in case["lines"])
        else:
            found = bool(cf)
        rows.append(
            {
                "dir": case["dir"],
                "expected": case["expected"],
                "defect": case.get("defect", ""),
                "found": found,
                "lines": caller_lines,
                "any_cf": len(cf),
            }
        )

    detect = [r for r in rows if r["expected"] == "detect"]
    clean = [r for r in rows if r["expected"] == "clean"]
    hits = sum(1 for r in detect if r["found"])
    fps = sum(1 for r in clean if r["found"])
    return {
        "degraded": {},
        "rows": rows,
        "skipped": skipped,
        "recall": (hits / len(detect)) if detect else None,
        "hits": hits,
        "vulns": len(detect),
        "false_positives": fps,
        "ok": (not detect or hits == len(detect)) and fps == 0,
    }


# ---------------------------------------------------------------------------
# framework_cases: paired framework vulnerability contracts. Each case has a
# vulnerable application call path and a fixed control. Scoring is exact-rule
# by basename, so both recall and same-rule false positives gate the corpus.
# ---------------------------------------------------------------------------

FRAMEWORK_CASES_DIR = GROUND_TRUTH / "framework_cases"
FRAMEWORK_SOURCE_CASES_DIR = GROUND_TRUTH / "framework_source_cases"


def _run_framework_pair_cases(
    corpus_dir: Path, corpus_name: str, subdir: str = "python"
) -> dict | None:
    """Score exact-rule vulnerable/fixed pairs in one corpus language directory."""
    manifest_path = corpus_dir / "manifest.json"
    if not manifest_path.exists():
        return None
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    cases = manifest.get("cases", [])
    seen: set[str] = set()
    for case in cases:
        for key in ("id", "expected_rule_id", "vulnerable", "fixed"):
            if key not in case:
                raise ValueError(f"{corpus_name}: {case.get('id', '?')} is missing {key!r}")
        for fixture_key in ("vulnerable", "fixed"):
            fixture = corpus_dir / case[fixture_key]
            if not fixture.is_file():
                raise ValueError(f"{corpus_name}: fixture does not exist: {fixture}")
            if fixture.name in seen:
                raise ValueError(f"{corpus_name}: duplicate basename {fixture.name!r}")
            seen.add(fixture.name)

    findings, degraded = _scan_dir_retrying(corpus_dir / subdir)
    if degraded:
        return {"degraded": degraded, "rows": [], "ok": False}
    by_file: dict[str, set[str]] = {}
    for finding in findings:
        by_file.setdefault(Path(finding.file_path).name, set()).update(
            r.lower() for r in finding.reported_rule_ids()
        )

    rows = []
    for case in cases:
        expected = case["expected_rule_id"]
        expected_lower = expected.lower()
        vulnerable_ids = by_file.get(Path(case["vulnerable"]).name, set())
        fixed_ids = by_file.get(Path(case["fixed"]).name, set())
        rows.append(
            {
                "id": case["id"],
                "class": case.get("class", ""),
                "expected_rule_id": expected,
                "vulnerable_hit": expected_lower in vulnerable_ids,
                "fixed_false_positive": expected_lower in fixed_ids,
            }
        )

    hits = sum(1 for row in rows if row["vulnerable_hit"])
    false_positives = sum(1 for row in rows if row["fixed_false_positive"])
    total = len(rows)
    return {
        "degraded": {},
        "rows": rows,
        "hits": hits,
        "total": total,
        "recall": hits / total if total else None,
        "false_positives": false_positives,
        "ok": hits == total and false_positives == 0,
    }


def run_framework_cases(corpus_dir: Path = FRAMEWORK_CASES_DIR) -> dict | None:
    """Run paired application call-path fixtures with taint enabled."""
    return _run_framework_pair_cases(corpus_dir, "framework_cases")


def run_framework_source_cases(corpus_dir: Path = FRAMEWORK_SOURCE_CASES_DIR) -> dict | None:
    """Run paired, version-pinned framework implementation fixtures."""
    return _run_framework_pair_cases(corpus_dir, "framework_source_cases")


TS_AGENT_CASES_DIR = GROUND_TRUTH / "ts_agent_cases"


def run_ts_agent_cases(corpus_dir: Path = TS_AGENT_CASES_DIR) -> dict | None:
    """Run paired TypeScript MCP/agent-tool/LLM-output fixtures with taint enabled."""
    return _run_framework_pair_cases(corpus_dir, "ts_agent_cases", subdir="typescript")


PY_AGENT_CASES_DIR = GROUND_TRUTH / "py_agent_cases"


def run_py_agent_cases(corpus_dir: Path = PY_AGENT_CASES_DIR) -> dict | None:
    """Run paired Python MCP tool fixtures with taint enabled."""
    return _run_framework_pair_cases(corpus_dir, "py_agent_cases")


def _print_degraded_fail(degraded: dict, name: str | None = None) -> None:
    """A degraded scan is code that was not analysed. No number is recorded
    from it, and the gate fails rather than reading it as a pass, the same as
    clean_code already does."""
    label = f" {name}" if name else ""
    print(
        f"  FAIL{label}: scan degraded ({'; '.join(degraded.values())}) -- no number "
        "recorded; a partial scan cannot pass the gate."
    )


def _report_pair_cases(name: str, heading: str, report: dict | None, baseline_out: dict) -> bool:
    """Print one paired corpus result; return False when it fails its gate."""
    print(f"\n=== {name} ({heading}) ===")
    if report is None:
        print(f"  SKIP: no benchmark/ground_truth/{name}/manifest.json.")
        return True
    if report["degraded"]:
        _print_degraded_fail(report["degraded"])
        return False
    for row in report["rows"]:
        vulnerable_status = "OK" if row["vulnerable_hit"] else "MISS"
        fixed_status = "FP" if row["fixed_false_positive"] else "CLEAN"
        print(
            f"  [{vulnerable_status}/{fixed_status}] {row['id']} "
            f"({row['class']}; {row['expected_rule_id']})"
        )
    print(
        f"  vulnerable recall: {report['hits']}/{report['total']} "
        f"({report['recall']:.1%})   <- gates CI"
    )
    print(f"  fixed-pair false positives: {report['false_positives']}   <- gates CI")
    baseline_out[f"{name}_recall"] = report["recall"]
    baseline_out[f"{name}_fixed_fps"] = report["false_positives"]
    return report["ok"]


# ---------------------------------------------------------------------------
# ai_cases: AI-surface snippets scored with taint ON. vuln_cases is scored
# with no_taint=True (converted regex rules only), so a `mode: taint` rule can
# never register there; this corpus is where the LLM-output / tool-parameter
# taint rules for Python, Java and Go get a recall number.
# ---------------------------------------------------------------------------

AI_CASES_DIR = GROUND_TRUTH / "ai_cases"


def load_ai_cases_manifest(corpus_dir: Path) -> list[dict]:
    """Load and validate ai_cases/manifest.json.

    Every case needs `file`, `language` and `expected_rule_id`, the file must
    exist, and basenames must be unique per language directory: one scan runs
    per language directory and findings are attributed by basename, so a
    duplicate would let one case's finding credit another.
    """
    manifest = json.loads((corpus_dir / "manifest.json").read_text(encoding="utf-8"))
    cases = manifest["cases"]
    seen: set[tuple[str, str]] = set()
    for case in cases:
        for key in ("file", "language", "expected_rule_id"):
            if key not in case:
                raise ValueError(f"ai_cases manifest: {case.get('file', '?')} is missing {key!r}")
        if not (corpus_dir / case["file"]).is_file():
            raise ValueError(f"ai_cases manifest: {case['file']} does not exist")
        ident = (case["language"], Path(case["file"]).name)
        if ident in seen:
            raise ValueError(
                f"ai_cases manifest: duplicate basename {ident[1]!r} in language {ident[0]!r}"
            )
        seen.add(ident)
    return cases


def run_ai_cases(corpus_dir: Path = AI_CASES_DIR) -> dict | None:
    """Score the ai_cases corpus with taint on (cross-file on, SCA off).

    One scan per language subdirectory. A case is a hit only when a finding
    with exactly its `expected_rule_id` lands in its file; an expected rule
    that does not exist yet is simply a MISS, which is how placeholder cases
    for rules still being written are tracked. Pools work as in vuln_cases.
    Returns None when the manifest is absent, or {"degraded": ...} when a
    language scan degraded on every attempt.
    """
    if not (corpus_dir / "manifest.json").exists():
        return None
    cases = load_ai_cases_manifest(corpus_dir)
    by_language: dict[str, list[dict]] = {}
    for case in cases:
        by_language.setdefault(case["language"], []).append(case)

    results: list[VulnCaseResult] = []
    for language, lang_cases in sorted(by_language.items()):
        findings, degraded = _scan_dir_retrying(corpus_dir / language)
        if degraded:
            return {"degraded": degraded, "results": [], "scores": {}}
        by_file: dict[str, list] = {}
        for f in findings:
            by_file.setdefault(Path(f.file_path).name, []).append(f)
        for case in lang_cases:
            expected = case["expected_rule_id"]
            case_findings = by_file.get(Path(case["file"]).name, [])
            matched = [
                f for f in case_findings
                if expected.lower() in {r.lower() for r in f.reported_rule_ids()}
            ]
            results.append(
                VulnCaseResult(
                    file=case["file"],
                    expected=f"rule_id={expected}",
                    found=bool(matched),
                    matched_rule_ids=sorted({f.rule_id for f in matched}),
                    pool=case.get("pool", "regression"),
                    match_mode="rule_id" if matched else "none",
                )
            )

    hits = sum(1 for r in results if r.found)
    scores = {
        "regression": _pool_recall(results, "regression"),
        "holdout": _pool_recall(results, "holdout"),
        "overall": {
            "recall": (hits / len(results)) if results else None,
            "hits": hits,
            "total": len(results),
        },
    }
    return {"degraded": {}, "results": results, "scores": scores}


# ---------------------------------------------------------------------------
# ai_apps (JG-11, PY-02): three small deliberately vulnerable oracle apps
# (Java Spring AI, Go mcp-go, Python FastAPI over the current agent SDKs)
# under benchmark/ground_truth/ai_apps/*/, each with a Langfail-shaped
# ground_truth.yaml. Unlike ai_cases (isolated snippets),
# these apps carry the multi-file controller -> service -> tool/agent shapes
# the JG-09/JG-11 surveys found in real repos, so this is where the JG-13
# cross-file decision gets its numbers. Scored by expected_rule_ids (exact
# rule_id match, as run_ai_cases does), not by CWE keywords -- the apps are
# new and the rule ids are the oracle's own vocabulary, not a legacy taxonomy
# that might get renamed.
# ---------------------------------------------------------------------------

AI_APPS_DIR = GROUND_TRUTH / "ai_apps"
AI_APPS_SINK_WINDOW = 5


def _brace_scope_line_range(path: Path, symbol: str) -> tuple[int, int] | None:
    """(start, end) 1-based line range of a Java method or Go func/method
    named `symbol`, found by locating its declaration line and counting
    braces to the matching close. Language-agnostic (Java and Go are both
    brace-delimited), unlike `_function_line_range`'s Python-AST approach --
    Java/Go findings carry no AST-derived symbol range (BACKLOG.md JG-02:
    "the source-origin tracer is Python-AST only"), so decoy scoring here
    needs its own resolver rather than reusing that one.

    Returns None if the symbol's declaration line can't be found or its
    braces never balance (best-effort; callers fall back to file-level
    matching, same as `_symbol_class_hit` does for a missing Python symbol).
    """
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return None
    # Match the DECLARATION line, not a call site -- `go startDebugServer(s)`
    # or `shellTool.run(command)` also contain `symbol(` and would otherwise
    # be picked up by a bare `\bsymbol\s*\(` search, anchoring the brace scan
    # to the wrong statement.
    if path.suffix == ".go":
        decl_re = re.compile(r"^\s*func\s+(?:\([^)]*\)\s*)?" + re.escape(symbol) + r"\s*\(")
    else:
        decl_re = re.compile(
            r"^\s*(?:@\w+(?:\([^)]*\))?\s*)*"
            r"(?:public|private|protected|static|final|synchronized|abstract)\b.*\b"
            + re.escape(symbol) + r"\s*\("
        )
    start_idx = next((i for i, line in enumerate(lines) if decl_re.search(line)), None)
    if start_idx is None:
        return None
    depth = 0
    seen_open = False
    for i in range(start_idx, len(lines)):
        for ch in lines[i]:
            if ch == "{":
                depth += 1
                seen_open = True
            elif ch == "}":
                depth -= 1
        if seen_open and depth <= 0:
            return start_idx + 1, i + 1
    return None


def _ai_app_hit(
    index: list[tuple[str, int, str]], sink_file: str, line_hint: int | None, expected_rule_ids: list[str]
) -> bool:
    """True if a finding with one of `expected_rule_ids` lands in sink_file
    within AI_APPS_SINK_WINDOW lines of line_hint."""
    ids = {r.lower() for r in expected_rule_ids}
    if not ids or not sink_file:
        return False
    needle = "/" + sink_file.lstrip("/")
    for path, line, rule_id in index:
        norm = path.replace("\\", "/")
        if not (norm.endswith(needle) or norm.endswith(sink_file)):
            continue
        if line_hint is not None and abs(line - line_hint) > AI_APPS_SINK_WINDOW:
            continue
        if rule_id.lower() in ids:
            return True
    return False


def _ai_app_decoy_fp(
    index: list[tuple[str, int, str]],
    app_dir: Path,
    decoy_file: str,
    decoy_symbol: str | None,
    expected_rule_ids: list[str],
) -> bool:
    """True if a finding with one of `expected_rule_ids` lands inside the
    decoy's own symbol body (or anywhere in decoy_file when the symbol can't
    be resolved). Symbol-scoped for the same reason `_authz_false_positive`
    is: several ai_apps decoys deliberately share a file with the real
    vulnerability they are paired against (e.g. Go's ReadFileSafe sits next
    to the vulnerable ReadFile in internal/tools/file.go), so a file-only
    check would blame the decoy for a real finding next door. Python decoys
    (PY-02) resolve through the AST-based `_function_line_range`; Java and
    Go through the brace counter."""
    ids = {r.lower() for r in expected_rule_ids}
    if not ids or not decoy_file:
        return False
    decoy_path = app_dir / decoy_file
    if not decoy_symbol:
        line_range = None
    elif decoy_path.suffix == ".py":
        line_range = _function_line_range(decoy_path, decoy_symbol)
    else:
        line_range = _brace_scope_line_range(decoy_path, decoy_symbol)
    needle = "/" + decoy_file.lstrip("/")
    for path, line, rule_id in index:
        norm = path.replace("\\", "/")
        if not (norm.endswith(needle) or norm.endswith(decoy_file)):
            continue
        if line_range is not None and not (line_range[0] <= line <= line_range[1]):
            continue
        if rule_id.lower() in ids:
            return True
    return False


def run_ai_apps() -> dict | None:
    """Score the ai_apps corpus: one taint-on, cross-file-on, SCA-off,
    report_view=full scan per app directory under
    benchmark/ground_truth/ai_apps/*/ (the `_scan_dir_retrying` defaults
    already are exactly this -- see `_scan_dir_checked`). A vulnerability is
    a HIT when a finding with one of its `expected_rule_ids` lands in its
    sink file within `AI_APPS_SINK_WINDOW` lines of `line_hint`. A decoy is
    a false positive when a finding with one of its `expected_rule_ids`
    lands inside its own symbol body. Returns None when no app directory has
    a ground_truth.yaml, or records {"degraded": ...} per app whose scan
    degraded on every attempt."""
    if not AI_APPS_DIR.is_dir():
        return None
    app_dirs = sorted(p for p in AI_APPS_DIR.iterdir() if p.is_dir() and (p / "ground_truth.yaml").exists())
    if not app_dirs:
        return None

    apps: dict[str, dict] = {}
    for app_dir in app_dirs:
        gt = yaml.safe_load((app_dir / "ground_truth.yaml").read_text(encoding="utf-8"))
        # Keyed by the directory name (e.g. "java", "go") rather than the
        # ground truth's own `meta.app` so callers have a stable, predictable
        # key for baseline field names; the display name is carried alongside
        # for printing.
        app_key = app_dir.name
        display_name = gt.get("meta", {}).get("app", app_key)
        findings, degraded = _scan_dir_retrying(app_dir)
        if degraded:
            apps[app_key] = {"degraded": degraded, "display_name": display_name}
            continue

        index = [(f.file_path, f.start_line, r) for f in findings for r in sorted(f.reported_rule_ids())]

        rows = []
        for v in gt.get("vulnerabilities", []):
            sink = v.get("sink", {})
            expected = v.get("expected_rule_ids", []) or []
            hit = _ai_app_hit(index, sink.get("file", ""), sink.get("line_hint"), expected)
            rows.append(
                {
                    "id": v.get("id"),
                    "tier": v.get("tier"),
                    "title": v.get("title", ""),
                    "hit": hit,
                    "expected": expected,
                }
            )

        decoy_fp_ids = []
        for d in gt.get("decoys", []):
            loc = d.get("location", {})
            expected = d.get("expected_rule_ids", []) or []
            if _ai_app_decoy_fp(index, app_dir, loc.get("file", ""), loc.get("symbol"), expected):
                decoy_fp_ids.append(d.get("id", "?"))

        by_tier: dict[object, dict] = {}
        for r in rows:
            bucket = by_tier.setdefault(r["tier"], {"hits": 0, "total": 0})
            bucket["total"] += 1
            bucket["hits"] += 1 if r["hit"] else 0

        hits = sum(1 for r in rows if r["hit"])
        apps[app_key] = {
            "degraded": {},
            "display_name": display_name,
            "rows": rows,
            "by_tier": by_tier,
            "hits": hits,
            "total": len(rows),
            "recall": (hits / len(rows)) if rows else None,
            "decoy_total": len(gt.get("decoys", []) or []),
            "decoy_fp_ids": decoy_fp_ids,
        }

    return {"apps": apps}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--corpus",
        choices=[
            "vuln_cases",
            "cve_cases",
            "clean_models",
            "clean_code",
            "vuln_app",
            "authz",
            "js_authz",
            "second_order",
            "cross_file",
            "framework_cases",
            "framework_source_cases",
            "ts_agent_cases",
            "py_agent_cases",
            "ai_cases",
            "ai_apps",
            "all",
        ],
        default="all",
    )
    parser.add_argument(
        "--update-baseline", action="store_true", help="write current results as the new baseline"
    )
    parser.add_argument(
        "--clean-code-repo", action="append", default=[], metavar="NAME",
        help="scan only this clean-code repository (repeatable)",
    )
    parser.add_argument(
        "--resume", action="store_true", help="reuse completed clean-code repository scans"
    )
    parser.add_argument(
        "--taint-jobs", type=int, default=None,
        help="maximum Opengrep CPU workers per batch (use 2 for a quieter benchmark)",
    )
    parser.add_argument(
        "--no-semgrep",
        action="store_true",
        help="skip the Semgrep head-to-head in the vuln_app corpus",
    )
    parser.add_argument(
        "--calibrate",
        action="store_true",
        help="calibrate confidence constants (#123) against the labeled vuln_app "
        "corpus and report the best-separating (base, decay); requires "
        "ROWAN_VULN_APP_PATH",
    )
    args = parser.parse_args()
    if args.taint_jobs is not None and args.taint_jobs < 1:
        parser.error("--taint-jobs must be at least 1")

    if args.calibrate:
        print("=== confidence calibration (#123) ===")
        return run_calibrate()

    _REPORT_VOLUME.update(scans=0, raw_findings=0, review_clusters=0)
    ok = True
    baseline_out: dict = {}
    if BASELINE_PATH.exists():
        baseline_out = json.loads(BASELINE_PATH.read_text(encoding="utf-8"))
    baseline_reference = dict(baseline_out)

    if args.corpus in ("vuln_cases", "all"):
        print("=== vuln_cases (recall) ===")
        scores, results = run_vuln_cases()
        for r in results:
            status = "OK  " if r.found else "MISS"
            pool_tag = "" if r.pool == "regression" else f" [{r.pool}]"
            mode = f" via {r.match_mode}" if r.found else ""
            print(
                f"  [{status}]{pool_tag} {r.file} (expected {r.expected}){mode} matched={r.matched_rule_ids}"
            )
        reg, hold, overall = scores["regression"], scores["holdout"], scores["overall"]
        print(f"  regression recall: {_fmt_recall(reg)}   <- gates CI")
        print(f"  holdout recall:    {_fmt_recall(hold)}   <- generalization signal (not gated)")
        print(f"  overall recall:    {_fmt_recall(overall)}")
        print(
            f"  taint-on recall:   regression {_fmt_recall(scores['regression_taint'])}, "
            f"holdout {_fmt_recall(scores['holdout_taint'])}   <- reported, not gated"
        )
        # #106: only the regression pool gates. A missing/empty regression pool
        # (recall None) is a pass, not a failure.
        if reg["recall"] is not None and reg["recall"] < 1.0:
            ok = False
        baseline_out["vuln_cases_recall"] = overall["recall"]
        baseline_out["vuln_cases_recall_regression"] = reg["recall"]
        baseline_out["vuln_cases_recall_holdout"] = hold["recall"]
        baseline_out["vuln_cases_recall_regression_taint"] = scores["regression_taint"]["recall"]
        baseline_out["vuln_cases_recall_holdout_taint"] = scores["holdout_taint"]["recall"]

    if args.corpus in ("cve_cases", "all"):
        print("\n=== cve_cases (real-CVE recall) ===")
        cve_scores, cve_results, fetched = run_cve_cases()
        if not cve_results:
            print("  SKIP: no benchmark/ground_truth/cve_cases/manifest.json entries.")
        elif fetched == 0:
            print(
                f"  SKIP: none of {len(cve_results)} CVE case(s) fetched "
                "(run scripts/fetch_cve_cases.py)."
            )
        else:
            for r in cve_results:
                if not r.fetched:
                    print(f"  [SKIP] {r.id} (not fetched)")
                    continue
                status = "OK  " if r.found else "MISS"
                pool_tag = "" if r.pool == "regression" else f" [{r.pool}]"
                print(f"  [{status}]{pool_tag} {r.id} (CWE-{r.cwe})")
            reg = cve_scores["regression"]
            print(
                f"  regression recall: {_fmt_recall(reg)}   <- gates CI  "
                f"({fetched}/{len(cve_results)} fetched)"
            )
            print(f"  holdout recall:    {_fmt_recall(cve_scores['holdout'])}")
            if reg["recall"] is not None and reg["recall"] < 1.0:
                ok = False
            baseline_out["cve_cases_recall"] = cve_scores["overall"]["recall"]

    if args.corpus in ("js_authz", "all"):
        print("\n=== js_authz (JS BOLA/IDOR tier) ===")
        report = run_js_authz_cases()
        if report is None:
            print("  SKIP: tree-sitter not installed or js_authz manifest missing.")
        else:
            for file, kind, found in report["rows"]:
                expected = kind == "vuln"
                status = "OK  " if found == expected else ("MISS" if expected else "FP  ")
                print(f"  [{status}] {file} ({kind})")
            print(
                f"  recall: {_fmt_recall({'recall': report['recall'], 'hits': report['hits'], 'total': report['vulns']})}"
            )
            print(f"  decoy false positives: {report['decoy_fps']} (expected 0)")
            if not report["ok"]:
                ok = False
            baseline_out["js_authz_recall"] = report["recall"]
            baseline_out["js_authz_decoy_fps"] = report["decoy_fps"]

    if args.corpus in ("authz", "all"):
        print("\n=== authz (fixture-driven recognizer sweep) ===")
        report = run_authz_cases()
        if report is None:
            print("  SKIP: no benchmark/ground_truth/authz/manifest.json.")
        elif report["degraded"]:
            _print_degraded_fail(report["degraded"])
            ok = False
        else:
            for row in report["rows"]:
                expected_hit = row["expected"] == "detect"
                status = "OK  " if row["found"] == expected_hit else (
                    "MISS" if expected_hit else "FP  "
                )
                print(f"  [{status}] {row['dir']} ({row['item']})")
            print(
                "  recall: "
                f"{_fmt_recall({'recall': report['recall'], 'hits': report['hits'], 'total': report['vulns']})}"
            )
            print(f"  negative false positives: {report['false_positives']} (expected 0)")
            if not report["ok"]:
                ok = False
            baseline_out["authz_recall"] = report["recall"]
            baseline_out["authz_negative_fps"] = report["false_positives"]

    if args.corpus in ("second_order", "all"):
        print("\n=== second_order (persistence-channel taint, no call edge) ===")
        report = run_second_order_cases()
        if report is None:
            print("  SKIP: no benchmark/ground_truth/second_order/manifest.json.")
        elif report["degraded"]:
            _print_degraded_fail(report["degraded"])
            ok = False
        else:
            status_for = {
                ("detect", True): "OK  ",
                ("detect", False): "MISS",
                ("clean", False): "OK  ",
                ("clean", True): "FP  ",
                ("known_gap", False): "GAP ",
                ("known_gap", True): "GAP CLOSED",
                ("known_fp", True): "FP* ",
                ("known_fp", False): "FP FIXED",
            }
            for r in sorted(report["rows"], key=lambda x: (x["expected"], x["dir"])):
                status = status_for[(r["expected"], r["found"])]
                tag = "" if r["detection"] == "channel" else f" [{r['detection']}]"
                print(f"  [{status}] {r['dir']} ({r['channel']}){tag} lines={r['lines']}")
            print(
                f"  recall on expected-detect: "
                f"{_fmt_recall({'recall': report['recall'], 'hits': report['hits'], 'total': report['vulns']})}"
                f"   <- gates CI"
            )
            print(
                f"  of which writer/reader-paired: {report['paired_hits']}/{report['paired_total']}"
            )
            print(f"  negative false positives: {report['false_positives']} (expected 0)")
            print(
                f"  known gaps still open:    {len(report['gaps_open'])}/"
                f"{report['known_gaps_total']} {report['gaps_open']}"
            )
            if report["gaps_closed"]:
                print(f"  GAPS CLOSED (promote to expected=detect): {report['gaps_closed']}")
            print(
                "  known false positives still firing: "
                f"{len(report['known_fps_firing'])}/{report['known_fps_total']} "
                f"{report['known_fps_firing']}"
            )
            if report["known_fps_fixed"]:
                print(f"  FPs FIXED (promote to expected=clean): {report['known_fps_fixed']}")
            if not report["ok"]:
                ok = False
            baseline_out["second_order_recall"] = report["recall"]
            baseline_out["second_order_paired_hits"] = report["paired_hits"]
            baseline_out["second_order_negative_fps"] = report["false_positives"]
            baseline_out["second_order_gaps_open"] = len(report["gaps_open"])

    if args.corpus in ("cross_file", "all"):
        print("\n=== cross_file (call-edge chains across files) ===")
        report = run_cross_file_cases()
        if report is None:
            print("  SKIP: no benchmark/ground_truth/cross_file/manifest.json.")
        elif report["degraded"]:
            _print_degraded_fail(report["degraded"])
            ok = False
        else:
            status_for = {
                ("detect", True): "OK  ",
                ("detect", False): "MISS",
                ("clean", False): "OK  ",
                ("clean", True): "FP  ",
            }
            for r in sorted(report["rows"], key=lambda x: (x["expected"], x["dir"])):
                status = status_for[(r["expected"], r["found"])]
                print(f"  [{status}] {r['dir']} ({r['defect']}) lines={r['lines']} cf={r['any_cf']}")
            for d in report["skipped"]:
                print(f"  [SKIP] {d} (tree-sitter not installed)")
            print(
                f"  recall on expected-detect: "
                f"{_fmt_recall({'recall': report['recall'], 'hits': report['hits'], 'total': report['vulns']})}"
                f"   <- gates CI"
            )
            print(f"  negative false positives: {report['false_positives']} (expected 0)   <- gates CI")
            if not report["ok"]:
                ok = False
            baseline_out["cross_file_recall"] = report["recall"]
            baseline_out["cross_file_negative_fps"] = report["false_positives"]

    for name, heading, runner in (
        ("framework_cases", "paired framework vulnerability contracts", run_framework_cases),
        ("framework_source_cases", "version-pinned implementation pairs", run_framework_source_cases),
        ("ts_agent_cases", "paired TypeScript agent-boundary contracts", run_ts_agent_cases),
        ("py_agent_cases", "paired Python MCP tool contracts", run_py_agent_cases),
    ):
        if args.corpus in (name, "all") and not _report_pair_cases(
            name, heading, runner(), baseline_out
        ):
            ok = False

    if args.corpus in ("ai_cases", "all"):
        print("\n=== ai_cases (AI-surface recall, taint ON) ===")
        report = run_ai_cases(AI_CASES_DIR)
        if report is None:
            print("  SKIP: no benchmark/ground_truth/ai_cases/manifest.json.")
        elif report["degraded"]:
            _print_degraded_fail(report["degraded"])
            ok = False
        else:
            for r in report["results"]:
                status = "OK  " if r.found else "MISS"
                pool_tag = "" if r.pool == "regression" else f" [{r.pool}]"
                print(f"  [{status}]{pool_tag} {r.file} (expected {r.expected}) matched={r.matched_rule_ids}")
            scores = report["scores"]
            reg, hold, overall = scores["regression"], scores["holdout"], scores["overall"]
            print(f"  regression recall: {_fmt_recall(reg)}   <- gates CI")
            print(f"  holdout recall:    {_fmt_recall(hold)}   <- may only rise without --update-baseline")
            print(f"  overall recall:    {_fmt_recall(overall)}")
            if reg["recall"] is not None and reg["recall"] < 1.0:
                ok = False
            current = {
                "ai_cases_recall": overall["recall"],
                "ai_cases_holdout": hold["recall"],
                "ai_cases_regression": reg["recall"],
            }
            # Ratchet: every ai_cases number may rise freely but a drop below
            # the committed baseline fails, the same way vuln_app_distinct_tp
            # does. --update-baseline is the deliberate way to accept a drop.
            for key, value in current.items():
                previous = baseline_reference.get(key)
                if (
                    not args.update_baseline
                    and previous is not None
                    and value is not None
                    and value < previous
                ):
                    print(f"  REGRESSION: {key}={value:.4f} fell below baseline {previous:.4f}")
                    ok = False
                baseline_out[key] = value

    if args.corpus in ("ai_apps", "all"):
        print("\n=== ai_apps (JG-11/PY-02 oracle apps: Java/Go/Python recall + decoy FPs) ===")
        report = run_ai_apps()
        if report is None:
            print("  SKIP: no benchmark/ground_truth/ai_apps/*/ground_truth.yaml.")
        else:
            total_decoy_fps = 0
            for app_key in sorted(report["apps"]):
                app = report["apps"][app_key]
                name = app.get("display_name", app_key)
                if app.get("degraded"):
                    _print_degraded_fail(app["degraded"], name)
                    ok = False
                    continue
                print(f"  --- {name} ---")
                for r in sorted(app["rows"], key=lambda x: (x["tier"], x["id"])):
                    status = "OK  " if r["hit"] else "MISS"
                    print(f"    [{status}] tier {r['tier']} {r['id']} {r['title'][:56]} expected={r['expected']}")
                for tier in sorted(app["by_tier"]):
                    b = app["by_tier"][tier]
                    print(f"    tier {tier} recall: {b['hits']}/{b['total']}")
                print(f"    overall recall: {_fmt_recall({'recall': app['recall'], 'hits': app['hits'], 'total': app['total']})}")
                print(f"    decoy false positives: {len(app['decoy_fp_ids'])}/{app['decoy_total']} (expected 0)")
                if app["decoy_fp_ids"]:
                    print(f"      {app['decoy_fp_ids']}")
                total_decoy_fps += len(app["decoy_fp_ids"])
                baseline_out[f"ai_apps_{app_key}_recall"] = app["recall"]

            # Ratchet, same shape as ai_cases: recall may only rise, decoy
            # false positives may only fall, without --update-baseline. The
            # rules this corpus scores (JG-04..06, JG-10) are being written
            # concurrently, so today's numbers are expected to be mostly
            # MISS -- the ratchet is what stops that baseline from silently
            # sliding backwards once rules start landing.
            for app_key in sorted(report["apps"]):
                key = f"ai_apps_{app_key}_recall"
                value = baseline_out.get(key)
                previous = baseline_reference.get(key)
                if (
                    not args.update_baseline
                    and previous is not None
                    and value is not None
                    and value < previous
                ):
                    print(f"  REGRESSION: {key}={value:.4f} fell below baseline {previous:.4f}")
                    ok = False

            previous_fps = baseline_reference.get("ai_apps_decoy_fps")
            if (
                not args.update_baseline
                and previous_fps is not None
                and total_decoy_fps > previous_fps
            ):
                print(
                    f"  REGRESSION: ai_apps_decoy_fps={total_decoy_fps} exceeded "
                    f"baseline {previous_fps}"
                )
                ok = False
            baseline_out["ai_apps_decoy_fps"] = total_decoy_fps

    if args.corpus in ("clean_models", "all"):
        print("\n=== clean_models (false positives) ===")
        total_fp, details, scanned = run_clean_models()
        for d in details:
            print(f"  {d}")
        print(
            f"  total findings on clean models: {total_fp} (expected 0, {scanned} models scanned)"
        )
        if total_fp > 0:
            ok = False
        baseline_out["clean_models_findings"] = total_fp

    if args.corpus in ("clean_code", "all"):
        print("\n=== clean_code (precision baseline) ===")
        clean_ok, current = run_clean_code(
            args.update_baseline,
            repo_names=set(args.clean_code_repo),
            resume=args.resume,
            taint_jobs=args.taint_jobs,
        )
        if not clean_ok:
            ok = False
        if current:
            baseline_out["clean_code"] = {
                **baseline_out.get("clean_code", {}),
                **current,
            }

    if args.corpus in ("vuln_app", "all"):
        print("\n=== vuln_app (labeled ground-truth recall + Semgrep head-to-head) ===")
        report = run_vuln_app(with_semgrep=not args.no_semgrep)
        if report is None:
            print(
                "  SKIP: set ROWAN_VULN_APP_PATH to a local vuln-app checkout "
                "(with benchmarks/ground_truth.yaml) to enable this corpus."
            )
        else:
            sg_avail = report["semgrep_available"]
            hdr = f"  {'VULN':4} {'TIER':4} {'OURS':5}"
            if sg_avail:
                hdr += f" {'SEMGREP':7}"
            print(hdr + "  TITLE")
            for r in sorted(report["rows"], key=lambda x: (x["tier"], x["id"])):
                ours = "hit " if r["ours"] else "MISS"
                line = f"  {r['id']:4} {r['tier']!s:4} {ours:5}"
                if sg_avail:
                    sg = "hit " if r["semgrep"] else "miss"
                    line += f" {sg:7}"
                line += f"  {r['title'][:52]}"
                print(line)
            n = report["n"]
            print(
                f"\n  rowan recall: {report['our_recall'] * 100:.1f}% "
                f"({sum(1 for r in report['rows'] if r['ours'])}/{n})"
            )
            if report["semgrep_recall"] is not None:
                sg_hits = sum(1 for r in report["rows"] if r["semgrep"])
                print(f"  semgrep recall:    {report['semgrep_recall'] * 100:.1f}% ({sg_hits}/{n})")
                only_us = [r["id"] for r in report["rows"] if r["ours"] and not r["semgrep"]]
                only_sg = [r["id"] for r in report["rows"] if r["semgrep"] and not r["ours"]]
                print(f"  caught by us only:      {only_us}")
                print(f"  caught by semgrep only: {only_sg}")
            else:
                print("  (semgrep not installed -- comparison skipped)")
            baseline_out["vuln_app_recall"] = report["our_recall"]

            decoys = report.get("decoys")
            if decoys and decoys["total"]:
                detected = sum(1 for r in report["rows"] if r["ours"])
                print(
                    f"\n  --- decoy precision ({decoys['scored']}/{decoys['total']} decoys scored) ---"
                )
                if decoys["precision"] is not None:
                    print(
                        f"  precision: {decoys['precision'] * 100:.1f}% "
                        f"({detected} detected vulns / {detected} + "
                        f"{decoys['false_positives']} flagged decoys)"
                    )
                print(f"  decoys wrongly flagged: {decoys['false_positives']}")
                if decoys["false_positive_ids"]:
                    print(f"    {decoys['false_positive_ids']}")
                if decoys["authz_graded_ids"]:
                    print(
                        f"  graded by the authz path instead (CWE-639): "
                        f"{len(decoys['authz_graded_ids'])}"
                    )
                if decoys["unscored_ids"]:
                    print(
                        f"  NOT SCORED BY ANYTHING -- needs an authz_model in "
                        f"the ground truth: {decoys['unscored_ids']}"
                    )
                if decoys["known_unlabeled_hit_ids"]:
                    print(
                        f"  known_unlabeled flagged (correct, not penalized): "
                        f"{decoys['known_unlabeled_hit_ids']}"
                    )
                baseline_out["vuln_app_precision"] = decoys["precision"]
                baseline_out["vuln_app_decoy_fps"] = decoys["false_positives"]

            distinct = report.get("distinct_findings")
            if distinct:
                print("\n  --- finding-level attribution ---")
                print(f"  distinct root causes: {distinct['distinct_true_positives']}")
                print(f"  duplicate findings:   {distinct['duplicate_findings']}")
                print(f"  unmatched findings:   {len(distinct['unmatched_findings'])}")
                print(f"  category mismatches:  {len(distinct['category_mismatches'])}")
                print(f"  CWE mismatches:       {len(distinct['cwe_mismatches'])}")
                print("  per engine:")
                for engine, bucket in distinct["per_engine"].items():
                    print(
                        f"    {engine:14} findings={bucket['findings']:3} "
                        f"tp={bucket['distinct_tp']:2} duplicates={bucket['duplicates']:2} "
                        f"decoy_fp={bucket['decoy_fp']:2}"
                    )
                noisy_rules = [
                    (rule_id, bucket)
                    for rule_id, bucket in distinct["per_rule"].items()
                    if bucket["duplicates"] or bucket["decoy_fp"]
                ]
                if noisy_rules:
                    print("  rules with duplicates or decoy FPs:")
                    for rule_id, bucket in sorted(
                        noisy_rules,
                        key=lambda item: (-item[1]["decoy_fp"], -item[1]["duplicates"], item[0]),
                    ):
                        print(
                            f"    {rule_id:24} duplicates={bucket['duplicates']:2} "
                            f"decoy_fp={bucket['decoy_fp']:2}"
                        )

                regression_metrics = {
                    "vuln_app_distinct_tp": distinct["distinct_true_positives"],
                    "vuln_app_distinct_decoy_fps": distinct["false_positive_decoys"],
                    "vuln_app_raw_duplicates": distinct["duplicate_findings"],
                    "vuln_app_category_mismatches": len(distinct["category_mismatches"]),
                    "vuln_app_cwe_mismatches": len(distinct["cwe_mismatches"]),
                }
                for key, current in regression_metrics.items():
                    previous = baseline_reference.get(key)
                    regressed = (
                        current < previous
                        if key == "vuln_app_distinct_tp" and previous is not None
                        else previous is not None and current > previous
                    )
                    if regressed:
                        direction = "fell below" if key == "vuln_app_distinct_tp" else "exceeded"
                        print(f"  REGRESSION: {key}={current} {direction} baseline {previous}")
                        ok = False
                baseline_out["vuln_app_distinct_tp"] = distinct["distinct_true_positives"]
                baseline_out["vuln_app_distinct_decoy_fps"] = distinct[
                    "false_positive_decoys"
                ]
                baseline_out["vuln_app_raw_duplicates"] = distinct["duplicate_findings"]
                baseline_out["vuln_app_unmatched_findings"] = len(distinct["unmatched_findings"])
                baseline_out["vuln_app_category_mismatches"] = len(
                    distinct["category_mismatches"]
                )
                baseline_out["vuln_app_cwe_mismatches"] = len(distinct["cwe_mismatches"])

            authz = report.get("authz_bola")
            if authz is not None:
                print("\n  --- AUTHZ-BOLA-* per-model recall/precision (#175) ---")
                for model in sorted(authz["per_model"]):
                    b = authz["per_model"][model]
                    recall_s = (
                        f"{b['recall'] * 100:.0f}% ({b['tp']}/{b['tp'] + b['fn']})"
                        if b["recall"] is not None
                        else "n/a"
                    )
                    precision_s = (
                        f"{b['precision'] * 100:.0f}% ({b['tp']}/{b['tp'] + b['fp']})"
                        if b["precision"] is not None
                        else "n/a"
                    )
                    print(
                        f"    {model:12} recall={recall_s:16} precision={precision_s:16} decoys={b['decoys']}"
                    )
                if authz["overall_recall"] is not None:
                    print(f"  overall authz recall:    {authz['overall_recall'] * 100:.1f}%")
                if authz["overall_precision"] is not None:
                    print(f"  overall authz precision: {authz['overall_precision'] * 100:.1f}%")
                if authz["false_positive_decoy_ids"]:
                    print(f"  FALSE POSITIVES on decoys: {authz['false_positive_decoy_ids']}")
                baseline_out["authz_bola_recall"] = authz["overall_recall"]
                baseline_out["authz_bola_precision"] = authz["overall_precision"]

            ai_native = report.get("ai_native")
            if ai_native is not None:
                print("\n  --- AI-native categories per-rule recall/precision (#183/#197) ---")
                for rule_id in sorted(ai_native["per_rule"]):
                    b = ai_native["per_rule"][rule_id]
                    recall_s = f"{b['recall'] * 100:.0f}% ({b['tp']}/{b['tp'] + b['fn']})" if b["recall"] is not None else "n/a"
                    precision_s = f"{b['precision'] * 100:.0f}% ({b['tp']}/{b['tp'] + b['fp']})" if b["precision"] is not None else "n/a"
                    print(f"    {rule_id:18} recall={recall_s:16} precision={precision_s:16} decoys={b['decoys']}")
                if ai_native["overall_recall"] is not None:
                    print(f"  overall ai_native recall:    {ai_native['overall_recall'] * 100:.1f}%")
                if ai_native["overall_precision"] is not None:
                    print(f"  overall ai_native precision: {ai_native['overall_precision'] * 100:.1f}%")
                if ai_native["false_positive_decoy_ids"]:
                    print(f"  FALSE POSITIVES on decoys: {ai_native['false_positive_decoy_ids']}")
                baseline_out["ai_native_recall"] = ai_native["overall_recall"]
                baseline_out["ai_native_precision"] = ai_native["overall_precision"]

    if args.update_baseline:
        BASELINE_PATH.write_text(
            json.dumps(baseline_out, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        print(f"\nBaseline written to {BASELINE_PATH}")

    print(
        "\nReport volume (non-gating): "
        f"{_REPORT_VOLUME['raw_findings']} raw findings / "
        f"{_REPORT_VOLUME['review_clusters']} review clusters "
        f"across {_REPORT_VOLUME['scans']} scan(s)"
    )
    print(f"\n{'PASS' if ok else 'FAIL'}")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
