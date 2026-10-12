"""Go command and path sinks focus the argument that carries the risk (#56).

Shared registry sink fragments `exec_go` and `file_path_go` feed the
command and path rules in go_taint.yaml and go_ai_taint.yaml. Requires the
Opengrep binary.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from rowan.taint.opengrep_adapter import OpengrepAdapter

RULES = Path(__file__).parent.parent / "rules"

pytestmark = pytest.mark.skipif(
    not OpengrepAdapter().is_installed(),
    reason="Opengrep binary not installed; these tests need a live scan.",
)

HEADER = (
    "package main\n\n"
    "func h(ctx context.Context, w http.ResponseWriter, r *http.Request, c *gin.Context) {\n"
    '\tv := r.FormValue("v")\n'
)


def _ids(tmp_path, body, rule_file="go_taint.yaml"):
    (tmp_path / "main.go").write_text(HEADER + body + "}\n", encoding="utf-8")
    return {f.rule_id for f in OpengrepAdapter().scan_with_rules(tmp_path, [RULES / rule_file], languages=["go"])}


CMDI = "tnt-go-cmdi-001"
ARGI = "tnt-go-argi-001"
PATH = "tnt-go-path-001"


@pytest.mark.parametrize(
    "body",
    [
        "\texec.Command(v).Run()\n",
        '\texec.Command("sh", "-c", v).Run()\n',
        '\texec.CommandContext(ctx, "bash", "-c", "echo " + v).Run()\n',
        '\texec.Command("cmd", "/c", v).Run()\n',
        # filepath.Base does not neutralize a shell string.
        '\texec.Command("sh", "-c", filepath.Base(v)).Run()\n',
    ],
)
def test_command_injection_fires(tmp_path, body):
    assert CMDI in _ids(tmp_path, body), body


def test_extra_argument_to_fixed_program_is_argument_injection(tmp_path):
    ids = _ids(tmp_path, '\texec.Command("git", "clone", v).Run()\n')
    assert ARGI in ids
    assert CMDI not in ids


def test_shell_string_is_not_also_argument_injection(tmp_path):
    assert ARGI not in _ids(tmp_path, '\texec.Command("sh", "-c", v).Run()\n')


@pytest.mark.parametrize(
    "body",
    [
        "\tos.Open(v)\n",
        "\tos.OpenFile(v, os.O_RDWR, 0o600)\n",
        '\tos.WriteFile(v, []byte("x"), 0o600)\n',
        "\tos.RemoveAll(v)\n",
        '\tos.Rename("a", v)\n',
        '\tos.Open(filepath.Join("/srv/data", v))\n',
        "\tc.File(v)\n",
        '\tc.FileAttachment(v, "report.pdf")\n',
        # An early-return guard is not modelled; the strings.Contains
        # "sanitizer" only cleared the bool it returned.
        '\tif strings.Contains(v, "..") {\n\t\treturn\n\t}\n\tos.Open(v)\n',
    ],
)
def test_path_traversal_fires(tmp_path, body):
    assert PATH in _ids(tmp_path, body), body


@pytest.mark.parametrize(
    "body",
    [
        # Building a path is not using it.
        '\tp := filepath.Join("/srv/data", v)\n\t_ = p\n',
        '\tos.WriteFile("/srv/fixed.txt", []byte(v), 0o600)\n',
        '\tp, _ := securejoin.SecureJoin("/srv/data", v)\n\tos.Open(p)\n',
        "\tos.Open(filepath.Base(v))\n",
    ],
)
def test_path_quiet(tmp_path, body):
    assert PATH not in _ids(tmp_path, body), body


def test_go_cmd_and_path_rules_share_the_registry_sinks():
    text = "".join((RULES / f).read_text(encoding="utf-8") for f in ("go_taint.yaml", "go_ai_taint.yaml"))
    assert text.count("rowan-registry:begin sink=exec_go") == 4
    assert text.count("rowan-registry:begin sink=file_path_go") == 4
