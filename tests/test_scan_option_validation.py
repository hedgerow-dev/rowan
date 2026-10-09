"""CLI validation for contradictory and invalid scan options."""

from __future__ import annotations

import click
import pytest
from click.testing import CliRunner

import rowan.agents
from rowan import cli


def _invoke(tmp_path, monkeypatch, *args: str):
    class UnexpectedPipeline:
        def __init__(self, config):
            pytest.fail("invalid scan options must be rejected before pipeline construction")

    monkeypatch.setattr(cli, "ScanPipeline", UnexpectedPipeline)
    return CliRunner().invoke(cli.main, ["scan", str(tmp_path), *args])


def test_audit_and_confirmed_are_mutually_exclusive(tmp_path, monkeypatch):
    result = _invoke(tmp_path, monkeypatch, "--audit", "--confirmed")

    assert result.exit_code == 2
    assert "--audit and --confirmed cannot be used together" in result.output


def test_help_separates_report_views_from_analysis_policy():
    result = CliRunner().invoke(cli.main, ["scan", "--help"])

    assert result.exit_code == 0
    assert "--audit" in result.output
    assert "--confirmed" in result.output
    assert "--policy [default|fast|deep]" in result.output
    assert "Scan policy; primitive flags override its" in result.output
    assert "capabilities" in result.output


@pytest.mark.parametrize(("language", "shown"), [("pythn", "pythn"), ("python,", "<empty>")])
def test_unsupported_language_fails_before_pipeline(tmp_path, monkeypatch, language, shown):
    result = _invoke(tmp_path, monkeypatch, "--lang", language)

    assert result.exit_code == 2
    assert f"Unsupported language(s): {shown}" in result.output


@pytest.mark.parametrize("artifact_option", ["--vex", "--sbom"])
def test_no_sca_rejects_supply_chain_artifacts(tmp_path, monkeypatch, artifact_option):
    result = _invoke(
        tmp_path,
        monkeypatch,
        "--no-sca",
        artifact_option,
        str(tmp_path / "artifact.json"),
    )

    assert result.exit_code == 2
    assert f"--no-sca cannot be used with {artifact_option}" in result.output
    assert "dependency scanning is required" in result.output


def test_no_sca_reports_both_conflicting_artifacts(tmp_path, monkeypatch):
    result = _invoke(
        tmp_path,
        monkeypatch,
        "--no-sca",
        "--vex",
        str(tmp_path / "vex.json"),
        "--sbom",
        str(tmp_path / "sbom.json"),
    )

    assert result.exit_code == 2
    assert "--no-sca cannot be used with --vex and --sbom" in result.output


@pytest.mark.parametrize("artifact_option", ["--vex", "--sbom"])
def test_policy_with_sca_off_rejects_supply_chain_artifacts(tmp_path, monkeypatch, artifact_option):
    """The fast policy leaves SCA off; an SBOM/VEX from it would be empty."""
    result = _invoke(
        tmp_path,
        monkeypatch,
        "--policy",
        "fast",
        artifact_option,
        str(tmp_path / "artifact.json"),
    )

    assert result.exit_code == 2
    assert f"{artifact_option} requires dependency scanning" in result.output
    assert "add --sca" in result.output


def test_policy_with_sca_off_accepts_artifacts_when_sca_forced(tmp_path, monkeypatch):
    class ConstructedError(Exception):
        pass

    class Pipeline:
        def __init__(self, config):
            raise ConstructedError

    monkeypatch.setattr(cli, "ScanPipeline", Pipeline)
    result = CliRunner().invoke(
        cli.main,
        ["scan", str(tmp_path), "--policy", "fast", "--sca", "--sbom", str(tmp_path / "s.json")],
    )
    assert isinstance(result.exception, ConstructedError)


def test_project_config_no_sca_rejects_cli_artifact(tmp_path, monkeypatch):
    (tmp_path / ".rowan.yml").write_text("no_sca: true\n", encoding="utf-8")

    result = _invoke(
        tmp_path,
        monkeypatch,
        "--vex",
        str(tmp_path / "vex.json"),
    )

    assert result.exit_code == 2
    assert "--no-sca cannot be used with --vex" in result.output


@pytest.mark.parametrize("languages", [["pythn"], ["python", ""]])
def test_project_config_language_scope_fails_closed(tmp_path, monkeypatch, languages):
    rendered = ", ".join(f"'{language}'" for language in languages)
    (tmp_path / ".rowan.yml").write_text(f"languages: [{rendered}]\n", encoding="utf-8")

    result = _invoke(tmp_path, monkeypatch)

    assert result.exit_code == 2
    assert "Unsupported language(s):" in result.output


@pytest.mark.parametrize("command", ["hunt", "estimate"])
def test_all_language_cli_entry_points_use_canonical_validation(tmp_path, command):
    result = CliRunner().invoke(cli.main, [command, str(tmp_path), "--lang", "pythn"])

    assert result.exit_code == 2
    assert "Unsupported language(s): pythn" in result.output


def _invoke_invalid_hunt(tmp_path, monkeypatch, *args: str):
    class UnexpectedLLM:
        def __init__(self, *args, **kwargs):
            pytest.fail("invalid Hunt options must fail before LLM construction")

    monkeypatch.setattr(rowan.agents, "LLMBackend", UnexpectedLLM)
    return CliRunner().invoke(cli.main, ["hunt", str(tmp_path), *args])


def test_hunt_discovery_requires_verification(tmp_path, monkeypatch):
    result = _invoke_invalid_hunt(tmp_path, monkeypatch, "--discover", "--no-verify")

    assert result.exit_code == 2
    assert "--discover cannot be used with --no-verify" in result.output
    assert "require adversarial verification" in result.output


def test_hunt_file_target_is_a_usage_error(tmp_path, monkeypatch):
    """A file target must surface as a Click usage error, not a raw ValueError."""

    class StubLLM:
        backend = "auto"
        is_configured = False

        def __init__(self, *args, **kwargs):
            pass

        @classmethod
        def from_env(cls, *args, **kwargs):
            return cls()

    monkeypatch.setattr(rowan.agents, "LLMBackend", StubLLM)
    target = tmp_path / "app.py"
    target.write_text("print('hi')\n", encoding="utf-8")

    result = CliRunner().invoke(cli.main, ["hunt", str(target)])

    assert result.exit_code == 2
    assert "target must be a directory" in result.output


def test_hunt_exploit_requires_base_url(tmp_path, monkeypatch):
    result = _invoke_invalid_hunt(tmp_path, monkeypatch, "--exploit")

    assert result.exit_code == 2
    assert "--exploit requires --base-url" in result.output


def test_hunt_base_url_requires_exploit_mode(tmp_path, monkeypatch):
    result = _invoke_invalid_hunt(tmp_path, monkeypatch, "--base-url", "https://app.example")

    assert result.exit_code == 2
    assert "--base-url requires --exploit" in result.output


@pytest.mark.parametrize(
    ("base_url", "reason"),
    [
        ("app.example", "absolute HTTP(S) URL"),
        ("ftp://app.example", "absolute HTTP(S) URL"),
        ("http:///only-a-path", "absolute HTTP(S) URL"),
        ("https://user:secret@app.example", "embedded credentials"),
        ("https://app.example/path?mode=test", "query strings"),
        ("https://app.example/path?", "query strings"),
        ("https://app.example/path#section", "fragments"),
        ("https://app.example/path#", "fragments"),
        (" https://app.example", "whitespace"),
        ("https://app.example:invalid", "Port could not be cast"),
    ],
)
def test_hunt_rejects_unsafe_or_malformed_exploit_base_url(tmp_path, monkeypatch, base_url, reason):
    result = _invoke_invalid_hunt(tmp_path, monkeypatch, "--exploit", "--base-url", base_url)

    assert result.exit_code == 2
    assert "Invalid --base-url:" in result.output
    assert reason in result.output


def _resolve_to(monkeypatch, address):
    """Stub DNS so no test performs a real lookup."""
    import socket

    def fake(host, *args, **kwargs):
        if address is None:
            raise socket.gaierror("not found")
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, 0))]

    monkeypatch.setattr(socket, "getaddrinfo", fake)


@pytest.mark.parametrize(
    "base_url",
    [
        "http://localhost:5000",
        "http://127.0.0.1:8000/app",
        "http://[::1]:8080",
        "http://10.0.0.5",
        "http://192.168.1.10:3000",
    ],
)
def test_hunt_accepts_local_and_private_targets_by_default(base_url):
    assert (
        cli._validate_hunt_options(
            discover=False,
            no_verify=False,
            exploit=True,
            base_url=base_url,
        )
        == base_url
    )


def test_hunt_accepts_hostname_resolving_to_private_address(monkeypatch):
    _resolve_to(monkeypatch, "172.18.0.4")
    url = "http://webapp:8080"
    assert cli._validate_hunt_options(
        discover=False, no_verify=False, exploit=True, base_url=url
    ) == url


@pytest.mark.parametrize(
    ("base_url", "resolved"),
    [
        ("http://8.8.8.8", None),
        ("https://app.example/service/root", "93.184.216.34"),
        ("https://does-not-resolve.invalid", None),
        # IPv4-mapped IPv6: older Python 3.10/3.11 patch releases call the whole
        # ::ffff:0:0/96 range private (CVE-2024-4032).
        ("http://[::ffff:8.8.8.8]", None),
        # Link-local holds the cloud metadata service; probing it is never a
        # local test of the scanned app.
        ("http://169.254.169.254/latest/meta-data", None),
        ("http://[fe80::1]:8080", None),
    ],
)
def test_hunt_refuses_remote_targets_without_opt_in(monkeypatch, base_url, resolved):
    _resolve_to(monkeypatch, resolved)
    with pytest.raises(click.UsageError, match="--allow-remote-target"):
        cli._validate_hunt_options(
            discover=False, no_verify=False, exploit=True, base_url=base_url
        )


def test_hunt_accepts_metadata_address_only_with_opt_in():
    url = "http://169.254.169.254"
    assert cli._validate_hunt_options(
        discover=False, no_verify=False, exploit=True, base_url=url, allow_remote_target=True
    ) == url


def test_hunt_accepts_remote_target_with_opt_in(monkeypatch):
    _resolve_to(monkeypatch, "93.184.216.34")
    url = "https://app.example/service/root"
    assert cli._validate_hunt_options(
        discover=False, no_verify=False, exploit=True, base_url=url, allow_remote_target=True
    ) == url


@pytest.mark.parametrize("option", ["--taint-timeout", "--taint-workers", "--taint-jobs"])
@pytest.mark.parametrize("value", ["0", "-1"])
def test_taint_numeric_options_must_be_positive(tmp_path, monkeypatch, option, value):
    result = _invoke(tmp_path, monkeypatch, option, value)

    assert result.exit_code == 2
    assert f"Invalid value for '{option}'" in result.output
    assert "1<=x<=" in result.output


@pytest.mark.parametrize(
    ("option", "value", "maximum"),
    [
        ("--taint-timeout", "86401", "86400"),
        ("--taint-workers", "65", "64"),
        ("--taint-jobs", "65", "64"),
        ("--network-concurrency", "65", "64"),
    ],
)
def test_resource_options_enforce_shared_upper_bounds(
    tmp_path, monkeypatch, option, value, maximum
):
    result = _invoke(tmp_path, monkeypatch, option, value)

    assert result.exit_code == 2
    assert f"Invalid value for '{option}'" in result.output
    assert f"x<={maximum}" in result.output


def test_exclude_option_skips_a_known_bad_file_in_ci(tmp_path):
    """PL-09: CI needs a trusted, command-line way to skip a path; the repo's
    own ignore file and project-config excludes are not trusted there."""
    from click.testing import CliRunner

    from rowan.cli import main

    (tmp_path / "good.py").write_text("x = 1\n")
    (tmp_path / "legacy.py").write_text('print "legacy python 2"\n')
    common = [str(tmp_path), "--ci", "--no-sca", "-f", "json", "-o", str(tmp_path / "out.json")]

    assert CliRunner().invoke(main, ["scan", *common]).exit_code == 2  # parse failure degrades
    result = CliRunner().invoke(main, ["scan", *common, "--exclude", "legacy.py"])
    assert result.exit_code == 0, result.output
