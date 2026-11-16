"""Tests for project config (.rowan.yml) and managed ignore file."""

from __future__ import annotations

import re

import pytest

from rowan.config import ScanConfig
from rowan.core.findings import Category, Finding, ScanResult, Severity
from rowan.ignore import apply_ignore, find_ignore_file, load_ignore_file
from rowan.project_config import (
    PROJECT_CONFIG_SCHEMA_VERSION,
    ProjectConfig,
    ProjectConfigError,
    apply_project_config,
    find_project_config,
    load_project_config,
)


def _invoke_scan_config(tmp_path, monkeypatch, *args):
    from click.testing import CliRunner

    from rowan import cli
    captured = {}
    class FakePipeline:
        def __init__(self, config): captured["config"] = config
        def run(self): return ScanResult()
    monkeypatch.setattr(cli, "ScanPipeline", FakePipeline)
    result = CliRunner().invoke(cli.main, ["scan", str(tmp_path), *args])
    assert result.exit_code == 0, result.output
    return captured["config"]

# ── Project config (#7) ──────────────────────────────────────────────────────


def _default_config(tmp_path):
    return ScanConfig(target=tmp_path)


def test_find_project_config_in_target(tmp_path):
    cfg = tmp_path / ".rowan.yml"
    cfg.write_text("exclude: []\n")
    assert find_project_config(tmp_path) == cfg


def test_find_project_config_walks_up(tmp_path):
    # Up to the repository root (the directory holding .git), PL-11.
    (tmp_path / ".git").mkdir()
    cfg = tmp_path / ".rowan.yml"
    cfg.write_text("exclude: []\n")
    subdir = tmp_path / "src" / "deep"
    subdir.mkdir(parents=True)
    assert find_project_config(subdir) == cfg


def test_find_project_config_none_when_absent(tmp_path):
    assert find_project_config(tmp_path) is None


def test_apply_extra_excludes(tmp_path):
    cfg = tmp_path / ".rowan.yml"
    cfg.write_text("exclude:\n  - vendor\n  - '*.min.js'\n")
    config = _default_config(tmp_path)
    apply_project_config(load_project_config(cfg), cfg, config)
    assert "vendor" in config.extra_excludes


def test_cli_flag_overrides_config(tmp_path):
    cfg = tmp_path / ".rowan.yml"
    cfg.write_text("no_sca: true\n")
    config = _default_config(tmp_path)
    config.no_sca = False  # CLI explicitly set False (same as default; still wins via _is_default)
    # Since False is the dataclass default, the config file IS allowed to set it.
    apply_project_config(load_project_config(cfg), cfg, config)
    assert config.no_sca is True

    # But an explicitly non-default CLI value must not be clobbered.
    config2 = _default_config(tmp_path)
    config2.profile = "server"  # non-default, simulates explicit --profile server
    cfg2 = tmp_path / ".rowan2.yml"
    cfg2.write_text("profile: library\n")
    apply_project_config(load_project_config(cfg2), cfg2, config2)
    assert config2.profile == "server"  # CLI wins


def test_apply_enable_authz_from_project_config(tmp_path):
    cfg = tmp_path / ".rowan.yml"
    cfg.write_text("enable_authz: true\n")
    config = _default_config(tmp_path)
    apply_project_config(load_project_config(cfg), cfg, config)
    assert config.enable_authz is True


def test_explicit_fields_protects_negatable_flag_at_its_default(tmp_path):
    """--no-legacy-neuroscan sets legacy_neuroscan=False -- identical to the
    dataclass default, so the plain _is_default heuristic can't tell that
    apart from the flag never having been passed. explicit_fields closes
    that gap."""
    cfg = tmp_path / ".rowan.yml"
    cfg.write_text("legacy_neuroscan: true\n")
    config = _default_config(tmp_path)
    config.legacy_neuroscan = False  # simulates explicit --no-legacy-neuroscan
    apply_project_config(
        load_project_config(cfg), cfg, config, explicit_fields={"legacy_neuroscan"}
    )
    assert config.legacy_neuroscan is False


def test_explicit_fields_protects_choice_option_at_its_default(tmp_path):
    """--profile auto is identical to the ScanConfig default ("auto"), same
    ambiguity class as the boolean case above."""
    cfg = tmp_path / ".rowan.yml"
    cfg.write_text("profile: server\n")
    config = _default_config(tmp_path)
    config.profile = "auto"  # simulates explicit --profile auto
    apply_project_config(load_project_config(cfg), cfg, config, explicit_fields={"profile"})
    assert config.profile == "auto"


def test_explicit_fields_omitted_field_still_uses_default_heuristic(tmp_path):
    """A field not named in explicit_fields keeps the old default-comparison
    behavior -- explicit_fields only narrows, never widens, what gets applied."""
    cfg = tmp_path / ".rowan.yml"
    cfg.write_text("legacy_neuroscan: true\nprofile: server\n")
    config = _default_config(tmp_path)
    config.legacy_neuroscan = False
    config.profile = "auto"
    apply_project_config(load_project_config(cfg), cfg, config, explicit_fields={"legacy_neuroscan"})
    assert config.legacy_neuroscan is False  # protected
    assert config.profile == "server"  # not protected -- config file applies


def test_hunt_style_no_taint_protected_from_project_config(tmp_path):
    """hunt() hardcodes no_taint=False (not a CLI flag) because its recon
    stage always needs taint analysis; a project config's no_taint must
    never silently disable that."""
    cfg = tmp_path / ".rowan.yml"
    cfg.write_text("no_taint: true\n")
    config = ScanConfig(target=tmp_path, no_taint=False)
    apply_project_config(load_project_config(cfg), cfg, config, explicit_fields={"no_taint"})
    assert config.no_taint is False


def test_hunt_style_other_fields_still_apply_from_project_config(tmp_path):
    """Fields hunt doesn't hardcode (e.g. exclude) must still flow from the
    project config, same as scan()."""
    cfg = tmp_path / ".rowan.yml"
    cfg.write_text("exclude:\n  - vendor\nno_taint: true\n")
    config = ScanConfig(target=tmp_path, no_taint=False)
    apply_project_config(load_project_config(cfg), cfg, config, explicit_fields={"no_taint"})
    assert "vendor" in config.extra_excludes
    assert config.no_taint is False

def test_ci_ignores_target_owned_project_config_by_default(tmp_path, monkeypatch):
    (tmp_path / ".rowan.yml").write_text("no_sca: true\nno_taint: true\nno_cross_file: true\nexclude: ['*.py']\n")
    config = _invoke_scan_config(tmp_path, monkeypatch, "--ci")
    assert not config.no_sca and not config.no_taint and not config.no_cross_file
    assert config.extra_excludes == []

def test_ci_can_explicitly_trust_project_config(tmp_path, monkeypatch):
    (tmp_path / ".rowan.yml").write_text("no_sca: true\n")
    assert _invoke_scan_config(tmp_path, monkeypatch, "--ci", "--project-config").no_sca


def test_action_final_no_project_config_wins_over_extra_args(tmp_path, monkeypatch):
    (tmp_path / ".rowan.yml").write_text("no_sca: true\n")
    config = _invoke_scan_config(
        tmp_path, monkeypatch, "--ci", "--project-config", "--no-project-config"
    )
    assert not config.no_sca

def test_local_scan_keeps_project_config_default(tmp_path, monkeypatch):
    (tmp_path / ".rowan.yml").write_text("no_sca: true\n")
    assert _invoke_scan_config(tmp_path, monkeypatch).no_sca


def test_load_returns_typed_versioned_config(tmp_path):
    cfg = tmp_path / ".rowan.yml"
    cfg.write_text("version: 1\nseverity: HIGH\nlanguages: [Python]\n")
    loaded = load_project_config(cfg)
    assert isinstance(loaded, ProjectConfig)
    assert loaded.version == PROJECT_CONFIG_SCHEMA_VERSION
    assert loaded.severity is Severity.HIGH
    assert loaded.languages == ("python",)


def test_unversioned_config_is_schema_v1_for_compatibility(tmp_path):
    cfg = tmp_path / ".rowan.yml"
    cfg.write_text("no_sca: true\n")
    assert load_project_config(cfg).version == 1


@pytest.mark.parametrize(
    ("content", "expected"),
    [
        ("unknown_option: true\n", "key 'unknown_option': unknown key"),
        ('no_sca: "false"\n', "key 'no_sca': expected an unquoted YAML boolean"),
        ("no_taint: 0\n", "key 'no_taint': expected an unquoted YAML boolean"),
        ("severity: urgent\n", "key 'severity': unknown value 'urgent'"),
        ("severity: 3\n", "key 'severity': expected one of"),
        ("profile: batch\n", "key 'profile': unknown value 'batch'"),
        ("max_file_bytes: '1000'\n", "key 'max_file_bytes': expected an integer"),
        ("max_file_bytes: true\n", "key 'max_file_bytes': expected an integer"),
        ("exclude: vendor\n", "key 'exclude': expected a YAML list"),
        ("exclude: [vendor, 4]\n", "key 'exclude': item 1 must be a non-empty string"),
        ("languages: [python, 4]\n", "key 'languages': item 1 must be a non-empty string"),
        ("languages: [python, '']\n", "key 'languages': Unsupported language(s): <empty>"),
        ("languages: [python, brainfuck]\n", "key 'languages': Unsupported language(s)"),
        ("baseline: 7\n", "key 'baseline': expected a non-empty path string"),
        ('baseline: ""\n', "key 'baseline': expected a non-empty path string"),
        ("version: 2\n", "key 'version': unsupported schema version 2"),
        ('version: "1"\n', "key 'version': expected integer 1"),
    ],
)
def test_invalid_project_config_values_fail_with_key_path(tmp_path, content, expected):
    cfg = tmp_path / ".rowan.yml"
    cfg.write_text(content)
    with pytest.raises(ProjectConfigError, match=re.escape(expected)):
        load_project_config(cfg)


@pytest.mark.parametrize("content", ["- no_sca\n", "just text\n", "42\n"])
def test_project_config_requires_top_level_mapping(tmp_path, content):
    cfg = tmp_path / ".rowan.yml"
    cfg.write_text(content)
    with pytest.raises(ProjectConfigError, match="expected a top-level YAML mapping"):
        load_project_config(cfg)


def test_malformed_yaml_has_actionable_file_error(tmp_path):
    cfg = tmp_path / ".rowan.yml"
    cfg.write_text("no_sca: [\n")
    with pytest.raises(ProjectConfigError) as raised:
        load_project_config(cfg)
    assert str(cfg) in str(raised.value)
    assert "could not parse YAML at line 2, column 1" in str(raised.value)


def test_mapping_callers_are_validated_before_application(tmp_path):
    config = _default_config(tmp_path)
    with pytest.raises(ProjectConfigError, match="key 'no_sca'"):
        apply_project_config({"no_sca": "false"}, tmp_path / "config.yml", config)
    assert config.no_sca is False


def test_all_supported_values_apply_without_changing_precedence(tmp_path):
    baseline = tmp_path / "baseline.json"
    baseline.write_text("{}")
    cfg = tmp_path / ".rowan.yml"
    cfg.write_text(
        """\
version: 1
exclude: [vendor]
languages: [Python, JavaScript]
severity: medium
no_sca: true
no_taint: true
no_cross_file: true
enable_authz: true
legacy_neuroscan: true
scan_vendored: true
max_file_bytes: 0
profile: server
baseline: baseline.json
"""
    )
    config = _default_config(tmp_path)
    apply_project_config(load_project_config(cfg), cfg, config)
    assert config.extra_excludes == ["vendor"]
    assert config.languages == ["python", "javascript"]
    assert config.severity is Severity.MEDIUM
    assert config.no_sca and config.no_taint and config.no_cross_file
    assert config.enable_authz and config.legacy_neuroscan and config.scan_vendored
    assert config.max_file_bytes == 0
    assert config.profile == "server"
    assert config.baseline_path == baseline


# ── Managed ignore file (#14) ─────────────────────────────────────────────────


def _finding(file_path, rule_id="NS-TEST", cat=Category.INJECTION):
    return Finding(
        rule_id=rule_id, message="test", severity=Severity.HIGH,
        category=cat, file_path=str(file_path), start_line=1,
    )


def test_find_ignore_file(tmp_path):
    ig = tmp_path / ".rowan-ignore.yml"
    ig.write_text("ignore: []\n")
    assert find_ignore_file(tmp_path) == ig


def test_ignore_by_fingerprint(tmp_path):
    from rowan import baseline
    f = tmp_path / "a.py"
    f.write_text("os.system(x)\n")
    finding = _finding(f)
    baseline._line_cache.clear()
    fp = baseline.fingerprint(finding, tmp_path)

    ig = tmp_path / ".rowan-ignore.yml"
    ig.write_text(f"ignore:\n  - fingerprint: {fp}\n    reason: accepted\n")
    entries = load_ignore_file(ig)
    fps = {id(finding): fp}
    kept, suppressed = apply_ignore([finding], entries, fps, tmp_path)
    assert suppressed == 1
    assert kept == []


def test_ignore_by_rule_and_path(tmp_path):
    f = tmp_path / "server.py"
    f.write_text("send_file(path)\n")
    finding = _finding(f, rule_id="NS-PATH-003")

    ig = tmp_path / ".rowan-ignore.yml"
    ig.write_text("ignore:\n  - rule_id: NS-PATH-003\n    path: 'server.py'\n    reason: auth middleware handles it\n")
    entries = load_ignore_file(ig)
    _, suppressed = apply_ignore([finding], entries, {}, tmp_path)
    assert suppressed == 1


def test_ignore_expired_entry_is_skipped(tmp_path):
    f = tmp_path / "a.py"
    finding = _finding(f)
    ig = tmp_path / ".rowan-ignore.yml"
    ig.write_text("ignore:\n  - rule_id: NS-TEST\n    expires: '2000-01-01'\n    reason: expired\n")
    entries = load_ignore_file(ig)
    kept, suppressed = apply_ignore([finding], entries, {}, tmp_path)
    assert suppressed == 0
    assert len(kept) == 1


@pytest.mark.parametrize("content", ["ignore:\n", "ignore: []\n"])
def test_empty_ignore_list_loads_as_no_entries(tmp_path, content):
    ig = tmp_path / ".rowan-ignore.yml"
    ig.write_text(content)
    assert load_ignore_file(ig) == []


# ── HTML report (#12) ────────────────────────────────────────────────────────


def test_to_html_produces_valid_html(tmp_path):
    from rowan.reporters import to_html, write_report
    result = ScanResult()
    result.files_scanned = 3
    result.add_finding(Finding(
        rule_id="NS-DESER-001", message="pickle.loads() detected",
        severity=Severity.HIGH, category=Category.DESERIALIZATION,
        file_path="src/loader.py", start_line=42,
        cwe_ids=[502], metadata={"remediation": "Use safetensors instead."},
    ))
    html = to_html(result)
    assert "<!DOCTYPE html>" in html
    assert "NS-DESER-001" in html
    assert "CWE-502" in html
    assert "Use safetensors instead." in html

    out = tmp_path / "report.html"
    write_report(result, out, "html")
    assert out.exists()
    assert "NS-DESER-001" in out.read_text()


# ── Remediation / fix field (#10) ─────────────────────────────────────────────


def test_fix_field_loaded_into_remediation(tmp_path):
    from rowan.core.rules import load_neuroscan_rules
    rule_yaml = tmp_path / "rule.yaml"
    rule_yaml.write_text(
        "rules:\n"
        "  - id: NS-TEST-FIX\n"
        "    name: test\n"
        "    severity: high\n"
        "    category: injection\n"
        "    cwe: [94]\n"
        "    languages: [python]\n"
        "    patterns: ['eval\\\\s*\\\\(']\n"
        "    message: eval detected\n"
        "    fix: 'Use ast.literal_eval() for safe evaluation.'\n"
    )
    rules = load_neuroscan_rules(rule_yaml)
    assert rules
    assert rules[0].metadata.remediation == "Use ast.literal_eval() for safe evaluation."


def test_remediation_appears_in_findings(tmp_path):
    """Remediation text flows from rule fix: field into finding.metadata."""
    from rowan.core.rules import load_neuroscan_rules
    rule_yaml = tmp_path / "rule.yaml"
    # Use a simple literal-match pattern that doesn't need regex escapes
    rule_yaml.write_text(
        "rules:\n"
        "  - id: NS-TEST-FIX\n"
        "    name: test\n"
        "    severity: high\n"
        "    category: injection\n"
        "    cwe: [94]\n"
        "    languages: [python]\n"
        "    patterns:\n"
        "      - DANGEROUS_CALL\n"
        "    message: eval detected\n"
        "    fix: Use ast.literal_eval().\n"
    )
    rules = load_neuroscan_rules(rule_yaml)
    assert rules and rules[0].metadata.remediation == "Use ast.literal_eval()."
    src = tmp_path / "app.py"
    src.write_text("DANGEROUS_CALL(user_input)\n")
    findings = rules[0].check(src)
    assert findings
    assert findings[0].metadata.get("remediation") == "Use ast.literal_eval()."


def test_no_sca_false_does_not_override_policy(tmp_path):
    """PL-10: writing the documented default must not force a pass on."""
    from rowan.scan_plan import build_scan_plan

    config = ScanConfig(target=tmp_path)
    apply_project_config({"policy": "fast", "no_sca": False}, tmp_path / ".rowan.yml", config)
    assert build_scan_plan(config).effective_policy["sca"] is False


def test_banner_reflects_project_config(tmp_path, monkeypatch):
    """PL-13: the banner shows the effective severity and languages."""
    from click.testing import CliRunner

    from rowan import cli

    (tmp_path / ".rowan.yml").write_text("severity: high\nlanguages: [python]\n")

    class FakePipeline:
        def __init__(self, config): pass
        def run(self): return ScanResult()

    monkeypatch.setattr(cli, "ScanPipeline", FakePipeline)
    out = CliRunner().invoke(cli.main, ["scan", str(tmp_path)]).output
    assert "Severity filter: high" in out
    assert "Languages: python" in out
    assert "Project config:" in out


def test_config_outside_git_root_is_ignored(tmp_path):
    """PL-11: a config above the repository must not apply to scans in it."""
    from rowan.ignore import find_ignore_file
    from rowan.project_config import find_project_config

    outer = tmp_path / "outer"
    repo = outer / "repo"
    (repo / ".git").mkdir(parents=True)
    (repo / "src").mkdir()
    (outer / ".rowan.yml").write_text("severity: critical\n")
    (outer / ".rowan-ignore.yml").write_text("ignore: []\n")

    assert find_project_config(repo / "src") is None
    assert find_ignore_file(repo / "src") is None

    (repo / ".rowan.yml").write_text("severity: high\n")
    assert find_project_config(repo / "src") == (repo / ".rowan.yml").resolve()


def test_config_lookup_without_git_checks_only_the_target(tmp_path):
    from rowan.project_config import find_project_config

    (tmp_path / ".rowan.yml").write_text("severity: critical\n")
    (tmp_path / "scan").mkdir()
    assert find_project_config(tmp_path / "scan") is None
    assert find_project_config(tmp_path) == (tmp_path / ".rowan.yml").resolve()
