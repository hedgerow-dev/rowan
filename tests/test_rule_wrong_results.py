"""Regex rules that reported the wrong thing (detection review, #47).

- DK-CONFIG-009 flagged `chmod 644` and missed setuid/setgid modes.
- ns-aiml-170 reported a model name assigned to `openAiModel` as a CRITICAL
  hardcoded key because the key-name suffix was optional.
- RB-INJECT-002's backtick pattern looked for `${`, shell syntax that Ruby
  never uses; Ruby interpolates with `#{`.

Runs the full pipeline so converter output and enrichment are covered.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from rowan.config import ScanConfig
from rowan.pipeline import ScanPipeline
from rowan.taint.opengrep_adapter import OpengrepAdapter

pytestmark = pytest.mark.skipif(
    not OpengrepAdapter().is_installed(), reason="Opengrep binary not installed"
)


def _lines(tmp_path: Path, name: str, text: str, rule_id: str) -> set[int]:
    (tmp_path / name).write_text(text, encoding="utf-8")
    findings = ScanPipeline(ScanConfig(target=tmp_path, no_sca=True, report_view="full")).run().findings
    return {f.start_line for f in findings if rule_id in f.reported_rule_ids()}


def test_dockerfile_setuid_is_flagged_and_plain_modes_are_not(tmp_path):
    # Reports of one pattern rule within a few lines fold into one finding,
    # so each case sits on its own far-apart line.
    pad = "#\n" * 11
    dockerfile = (
        "FROM debian:12\n"
        "RUN chmod 644 /etc/app.conf\n" + pad
        + "RUN chmod 600 /root/key\n" + pad
        + "RUN chmod 4755 /usr/local/bin/helper\n" + pad
        + "RUN chmod u+s /usr/local/bin/other\n" + pad
        + "RUN chmod 2755 /srv/shared\n"
        "USER app\n"
    )
    assert _lines(tmp_path, "Dockerfile", dockerfile, "DK-CONFIG-009") == {26, 38, 50}


def test_java_model_name_is_not_a_secret(tmp_path):
    java = (
        "class Cfg {\n"
        '  String openAiModel = "text-embedding-3-small";\n'
        '  String openaiApiKey = "sk-9Xq2vB7mLp4RtY8wZc3nHd6k";\n'
        "}\n"
    )
    assert _lines(tmp_path, "Cfg.java", java, "ns-aiml-170") == {3}


def test_ruby_backtick_interpolation_is_shell_injection(tmp_path):
    ruby = (
        "def h\n"
        "  out = `ls #{params[:d]}`\n" + "  #\n" * 11
        + '  system "ls #{params[:d]}"\n'
        "end\n"
    )
    assert _lines(tmp_path, "a.rb", ruby, "RB-INJECT-002") == {2, 14}
