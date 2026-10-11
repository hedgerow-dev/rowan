"""LLM-output sinks are the dangerous argument, not the whole call (#72).

Without focus-metavariable these sinks fire when model text reaches any
argument: piped to a fixed shell command's stdin (TNT-LLMOUT-002), passed as
a pandas local variable (TNT-LLMOUT-003), written into a fixed file path or
copied FROM a model-chosen path (TNT-LLMOUT-005), or bound as a Jinja
context variable (TNT-LLMOUT-006). Requires the Opengrep binary.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from rowan.taint.opengrep_adapter import OpengrepAdapter

RULES_DIR = Path(__file__).parent.parent / "rules"

pytestmark = pytest.mark.skipif(
    not OpengrepAdapter().is_installed(),
    reason="Opengrep binary not installed; these tests need a live scan.",
)

HEADER = (
    "import openai\n\n"
    "def run(prompt):\n"
    "    resp = openai_client.chat.completions.create(model='m', messages=prompt)\n"
    "    out = resp.choices[0].message.content\n"
)


def _fires(tmp_path, rule_id, line):
    (tmp_path / "app.py").write_text(HEADER + "    " + line + "\n", encoding="utf-8")
    findings = OpengrepAdapter().scan_with_rules(
        tmp_path, [RULES_DIR / "llm_output_taint.yaml"], languages=["python"]
    )
    return any(f.rule_id == rule_id for f in findings)


DANGEROUS = [
    ("TNT-LLMOUT-002", "subprocess.run(out, shell=True)"),
    ("TNT-LLMOUT-003", "exec(out, {})"),
    ("TNT-LLMOUT-005", "Path(out).write_text('x')"),
    ("TNT-LLMOUT-005", "shutil.copy('a.txt', out)"),
    ("TNT-LLMOUT-006", "render_template_string(out)"),
]

HARMLESS = [
    ("TNT-LLMOUT-002", "subprocess.run('wc -l', shell=True, input=out)"),
    ("TNT-LLMOUT-003", "pd.eval('a + 1', local_dict={'a': out})"),
    ("TNT-LLMOUT-005", "Path('report.md').write_text(out)"),
    ("TNT-LLMOUT-005", "shutil.copy(out, 'backup/')"),
    ("TNT-LLMOUT-006", "render_template_string('<p>{{ t }}</p>', t=out)"),
]


@pytest.mark.parametrize("rule_id,line", DANGEROUS)
def test_dangerous_argument_fires(tmp_path, rule_id, line):
    assert _fires(tmp_path, rule_id, line), line


@pytest.mark.parametrize("rule_id,line", HARMLESS)
def test_harmless_argument_does_not_fire(tmp_path, rule_id, line):
    assert not _fires(tmp_path, rule_id, line), line
