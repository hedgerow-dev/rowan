"""Regression coverage for `_is_sink_rule`'s category-driven sink classification.

`rowan/passes/cross_file.py::_is_sink_rule` used to classify a regex
(NeuroScan-family) finding as a cross-file taint "sink" by hand-enumerating
rule-ID prefixes (`_SINK_RULE_PREFIXES`). That list rotted: it stopped at
`ns-aiml-077` (the corpus has since grown to `ns-aiml-128`), had internal
gaps, and never recognized the uppercase `NS-AIML-` family at all -- so
dozens of genuine sink rules (keras/torch/pickle-family code execution and
deserialization, command injection, mass assignment, open redirect, etc.)
were invisible to cross-file taint propagation.

The fix derives sink status from each rule's declared `metadata.category`
(sourced from `rules/converted/_manifest.json` via
`context.metadata["conversion_manifest"]["rule_map"]`), falling back to the
legacy prefix list only when no manifest is available (manifest load
failure, or `--legacy-neuroscan` mode).

This file locks in that contract and, most importantly, guards against the
same kind of corpus drift happening again: `test_manifest_sink_categories_all_wired_for_python`
walks the *actual* converted-rule manifest and fails the moment a new rule
in a sink category is added without being classified as a sink.
"""

from __future__ import annotations

import glob
import json
from pathlib import Path

import pytest
import yaml

from rowan.config import ScanConfig
from rowan.core.findings import Category, Finding, ScanResult, Severity
from rowan.passes.base import ScanContext
from rowan.passes.cross_file import _SINK_CATEGORIES, CrossFilePass, _is_sink_rule

REPO_ROOT = Path(__file__).resolve().parent.parent
MANIFEST_PATH = REPO_ROOT / "rules" / "converted" / "_manifest.json"
CONVERTED_RULES_DIR = REPO_ROOT / "rules" / "converted"


# ---------------------------------------------------------------------------
# Fixtures: load the real, on-disk rule corpus. No network, no scan of the
# rowan repo itself -- these just parse the rule manifest/YAML that
# ship with the package, the same files `Pipeline._load_conversion_manifest`
# and the rule loader read at scan time.
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def manifest_rule_map() -> dict[str, dict]:
    """id -> manifest entry dict, exactly as `Pipeline._load_conversion_manifest`
    builds `context.metadata["conversion_manifest"]["rule_map"]`."""
    data = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    return {rule["id"]: rule for rule in data["rules"]}


@pytest.fixture(scope="module")
def rule_languages_by_id() -> dict[str, list[str]]:
    """id -> `languages` list, read from the converted YAML rule files (the
    manifest itself doesn't carry `languages`, only category/cwe/etc.)."""
    languages: dict[str, list[str]] = {}
    for yaml_path in sorted(glob.glob(str(CONVERTED_RULES_DIR / "*.yaml"))):
        doc = yaml.safe_load(Path(yaml_path).read_text(encoding="utf-8"))
        if not doc or "rules" not in doc:
            continue
        for rule in doc["rules"]:
            rid = rule.get("id")
            if rid:
                languages[rid] = rule.get("languages", [])
    return languages


# ---------------------------------------------------------------------------
# 1. Corpus-drift guard (most important test in this file).
# ---------------------------------------------------------------------------


def test_manifest_sink_categories_all_wired_for_python(manifest_rule_map, rule_languages_by_id):
    """Every Python-targeting rule in `rules/converted/_manifest.json` whose
    declared category is in `_SINK_CATEGORIES` must be classified as a sink
    by `_is_sink_rule`.

    This is the guard that fails the next time someone adds a rule in a sink
    category (command_injection, deserialization, injection, path_traversal,
    ssrf, ssti, xss, nosql_injection, prototype_pollution, supply_chain)
    and forgets to wire it up -- there is nothing left to
    "forget" here since classification is derived from the manifest itself,
    but this test also protects against `_SINK_CATEGORIES` silently losing a
    category it used to cover.
    """
    missing: list[str] = []
    for rule_id, entry in manifest_rule_map.items():
        category = entry.get("category")
        if category not in _SINK_CATEGORIES:
            continue
        languages = rule_languages_by_id.get(rule_id, [])
        if "python" not in languages:
            continue
        if not _is_sink_rule(rule_id, manifest_rule_map):
            missing.append(f"{rule_id} (category={category!r})")

    assert not missing, (
        "these Python rules declare a sink category in the manifest but are "
        "not classified as sinks by _is_sink_rule -- cross-file taint "
        f"propagation will silently miss them: {missing}"
    )


# ---------------------------------------------------------------------------
# 2. Named-regression tests for representative rules from the 34 that were
#    previously missed by the hand-enumerated prefix list.
# ---------------------------------------------------------------------------

# (rule_id, category, what it detects) -- each of these previously fell
# through the gaps in `_SINK_RULE_PREFIXES`: either past the ns-aiml-077
# cutoff, inside one of its internal gaps, or in the uppercase NS-AIML-
# family the old list never matched at all.
NAMED_REGRESSION_RULES = [
    (
        "NS-AIML-029", "ssti",
        "unsandboxed Jinja2 Template() rendering of a model-provided "
        "chat_template -- SSTI/RCE (CVE-2026-5760); uppercase NS-AIML- "
        "family, never matched by the old prefix list at all",
    ),
    (
        "ns-aiml-114", "deserialization",
        "keras.models.load_model()/tf.keras.models.load_model() executes "
        "arbitrary code via a Lambda layer (CVE-2024-3660); past the old "
        "list's ns-aiml-077 cutoff",
    ),
    (
        "ns-aiml-115", "deserialization",
        "keras.models.load_model(..., safe_mode=False) explicitly disables "
        "the Lambda-layer safety check; past the old list's ns-aiml-077 cutoff",
    ),
    (
        "ns-bb-008", "deserialization",
        "yaml.load() with FullLoader/UnsafeLoader allows arbitrary object "
        "instantiation",
    ),
    (
        "ns-grd-005", "command_injection",
        "Gradio handler executes shell commands built from user input",
    ),
    (
        "ns-stl-001", "command_injection",
        "Streamlit user input passed straight to a shell command",
    ),
    (
        "NS-GIT-001", "command_injection",
        "unsafe git operations -- user-controlled URL passed to git clone",
    ),
    (
        "NS-MASS-001", "injection",
        "mass assignment -- request data passed directly to a model "
        "create/update call",
    ),
    (
        "ns-fw-py-003", "injection",
        "open redirect -- redirect target taken straight from user input",
    ),
]


@pytest.mark.parametrize(
    "rule_id,category,description",
    NAMED_REGRESSION_RULES,
    ids=[r[0] for r in NAMED_REGRESSION_RULES],
)
def test_named_regression_rule_is_sink(rule_id, category, description, manifest_rule_map):
    entry = manifest_rule_map.get(rule_id)
    assert entry is not None, f"{rule_id} not found in rules/converted/_manifest.json"
    assert entry.get("category") == category, (
        f"{rule_id}'s manifest category changed to {entry.get('category')!r} "
        f"(expected {category!r}) -- update this test's expectation, this is "
        "not necessarily a bug"
    )
    assert _is_sink_rule(rule_id, manifest_rule_map) is True, (
        f"{rule_id} ({description}) must be classified as a sink"
    )


# ---------------------------------------------------------------------------
# 3. Non-sink categories stay non-sinks (precision guard).
# ---------------------------------------------------------------------------

NON_SINK_RULES = [
    ("ns-aiml-100", "config"),
    ("NS-AIML-007", "auth"),
    ("ns-cloud-003", "crypto"),
    ("ns-sec-001", "secrets"),
]


@pytest.mark.parametrize(
    "rule_id,category", NON_SINK_RULES, ids=[r[0] for r in NON_SINK_RULES]
)
def test_non_sink_category_rule_is_not_a_sink(rule_id, category, manifest_rule_map):
    entry = manifest_rule_map.get(rule_id)
    assert entry is not None, f"{rule_id} not found in rules/converted/_manifest.json"
    assert entry.get("category") == category, (
        f"{rule_id}'s manifest category changed to {entry.get('category')!r} "
        f"(expected {category!r}) -- update this test's expectation, this is "
        "not necessarily a bug"
    )
    assert category not in _SINK_CATEGORIES, (
        f"test fixture assumption broken: {category!r} was added to "
        "_SINK_CATEGORIES -- pick a different non-sink category/rule id"
    )
    assert _is_sink_rule(rule_id, manifest_rule_map) is False, (
        f"{rule_id} is a {category} rule and must NOT be classified as a sink"
    )


# ---------------------------------------------------------------------------
# 4. Fallback behaviour: no manifest available (load failure, or
#    --legacy-neuroscan mode, which never populates the manifest at all).
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("rule_map", [None, {}], ids=["rule_map=None", "rule_map={}"])
@pytest.mark.parametrize(
    "rule_id", ["NS-DESER-006", "NS-INJECT-001"], ids=["NS-DESER-006", "NS-INJECT-001"]
)
def test_fallback_prefix_list_used_when_no_manifest(rule_id, rule_map):
    """Without a usable rule_map, `_is_sink_rule` must fall back to the
    legacy `_SINK_RULE_PREFIXES` startswith check rather than returning
    False for everything -- this is the path exercised when the conversion
    manifest fails to load, and always in --legacy-neuroscan mode."""
    assert _is_sink_rule(rule_id, rule_map) is True


def test_fallback_prefix_list_still_used_with_default_argument():
    """`_is_sink_rule` callable with just a rule_id (rule_map omitted
    entirely), matching the legacy single-argument call sites."""
    assert _is_sink_rule("NS-DESER-006") is True


# ---------------------------------------------------------------------------
# 5. End-to-end: a cross-file finding is actually produced for one of the
#    rules that used to be invisible (ns-aiml-114, keras.models.load_model).
# ---------------------------------------------------------------------------


def test_cross_file_pass_detects_previously_missed_keras_sink(tmp_path):
    """The exact real-world shape: a Flask endpoint passes a request
    parameter into a helper module's `keras.models.load_model()` call.
    ns-aiml-114 (code_execution) is one of the 34 rules the old
    `_SINK_RULE_PREFIXES` list never matched (past its ns-aiml-077 cutoff),
    so before the fix `load()` never became a sink function at all and no
    cross-file finding was produced for this chain."""
    root = tmp_path / "app"
    root.mkdir()

    h_keras = root / "h_keras.py"
    h_keras.write_text(
        "import keras\n"
        "def load(p):\n"
        "    return keras.models.load_model(p)\n",
        encoding="utf-8",
    )
    entry = root / "entry.py"
    entry.write_text(
        "from flask import request, Flask\n"
        "import h_keras\n"
        "app = Flask(__name__)\n"
        "\n"
        "@app.route(\"/k\")\n"
        "def r_keras():\n"
        "    return h_keras.load(request.args.get(\"p\"))\n",
        encoding="utf-8",
    )

    h_keras_resolved = str(h_keras.resolve())

    seed_findings = [
        Finding(
            rule_id="ns-aiml-114",
            message=(
                "keras.models.load_model()/keras.saving.load_model() executes "
                "arbitrary code if the loaded archive contains a Lambda layer"
            ),
            severity=Severity.MEDIUM,
            category=Category.AI_ML,
            file_path=h_keras_resolved,
            start_line=3,
            engine="opengrep",
        ),
    ]

    manifest_data = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    rule_map = {rule["id"]: rule for rule in manifest_data["rules"]}
    assert rule_map["ns-aiml-114"]["category"] == "deserialization"

    config = ScanConfig(target=root)
    ctx = ScanContext(
        target_path=root,
        config=config,
        result=ScanResult(findings=seed_findings),
        metadata={"conversion_manifest": {"rule_map": rule_map}},
    )
    pass_result = CrossFilePass().run(ctx)

    cross_file_hits = [f for f in pass_result.findings if f.rule_id.startswith("CF-")]
    assert cross_file_hits, (
        "expected a cross-file finding linking entry.py's request.args "
        "source, through the h_keras import, to h_keras.py's "
        "keras.models.load_model() sink (ns-aiml-114) -- this chain was "
        "invisible before ns-aiml-114 was wired up as a sink category"
    )


def test_vulnerability_rule_wins_sink_message_over_presence_rule():
    """XF-15: an agent-safety presence rule on the same line must not
    replace the command-injection rule's message and CWE."""
    from rowan.core.findings import Category, Finding, Severity
    from rowan.passes.cross_file import _FunctionSig, _match_findings_to_functions

    def finding(rule_id, message, severity, category, cwe):
        return Finding(rule_id=rule_id, message=message, severity=severity, category=category,
                       file_path="c.py", start_line=5, cwe_ids=cwe)

    presence = finding("ns-aiml-076", "LLM agent with shell/subprocess access has excessive agency.",
                       Severity.MEDIUM, Category.AI_ML, [94])
    cmdi = finding("NS-CMDI-002", "subprocess with shell=True.", Severity.HIGH,
                   Category.COMMAND_INJECTION, [78])
    for order in ([presence, cmdi], [cmdi, presence]):
        sig = _FunctionSig(name="run_it", file="c.py", line=3, params=["cmd"], calls=[], end_line=6)
        _match_findings_to_functions(order, [sig], rule_map=None)
        assert sig.sink_detail.startswith("subprocess with shell=True"), order[0].rule_id
        assert sig.sink_cwe == [78]
