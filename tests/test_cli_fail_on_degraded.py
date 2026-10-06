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
