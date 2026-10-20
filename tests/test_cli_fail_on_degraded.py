"""--fail-on-degraded exits 2 on an incomplete scan, with or without --ci."""

from __future__ import annotations

import pytest
from click.testing import CliRunner

from rowan import cli
from rowan.core.findings import ScanResult


def _invoke(tmp_path, monkeypatch, args, degraded):
    class FakePipeline:
        def __init__(self, config):
            pass

        def run(self):
            result = ScanResult()
            if degraded:
                result.degraded_passes["taint"] = "engine missing"
            return result

    monkeypatch.setattr(cli, "ScanPipeline", FakePipeline)
    return CliRunner().invoke(cli.main, ["scan", str(tmp_path), *args])


@pytest.mark.parametrize(
    ("args", "degraded", "code"),
    [
        ([], True, 0),
        (["--fail-on-degraded"], True, 2),
        (["--fail-on-degraded"], False, 0),
        (["--ci"], True, 2),
    ],
)
def test_degraded_exit_codes(tmp_path, monkeypatch, args, degraded, code):
    assert _invoke(tmp_path, monkeypatch, args, degraded).exit_code == code


def test_file_target_is_a_usage_error_not_findings(tmp_path):
    """Exit 1 means 'findings present' to a CI gate; a bad target is a usage error."""
    target = tmp_path / "app.py"
    target.write_text("x = 1\n", encoding="utf-8")
    result = CliRunner().invoke(cli.main, ["scan", str(target), "--ci"])
    assert result.exit_code == 2
    assert "Target must be a directory" in result.output


def test_unresolvable_target_is_a_usage_error(tmp_path, monkeypatch):
    def _raise(self, strict=False):
        raise OSError("loop")

    monkeypatch.setattr(cli.Path, "resolve", _raise)
    result = CliRunner().invoke(cli.main, ["scan", str(tmp_path), "--ci"])
    assert result.exit_code == 2
    assert "Cannot resolve path" in result.output
