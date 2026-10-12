"""Go header, log and deserialization rules claim only what applies (#56).

net/http replaces CR/LF in header values when writing, slog and logrus
escape newlines, and gob/yaml decode into declared types. Requires the
Opengrep binary.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from rowan.taint.opengrep_adapter import OpengrepAdapter

RULES = Path(__file__).parent.parent / "rules" / "go_taint.yaml"

HEADER = (
    "package main\n\n"
    'import (\n\t"log"\n\t"log/slog"\n\t"net/http"\n)\n\n'
    "func h(w http.ResponseWriter, r *http.Request) {\n"
    '\tv := r.FormValue("v")\n'
)


def _ids(tmp_path, body):
    (tmp_path / "main.go").write_text(HEADER + body + "}\n", encoding="utf-8")
    return {f.rule_id for f in OpengrepAdapter().scan_with_rules(tmp_path, [RULES], languages=["go"])}


def _rule(rule_id):
    return next(r for r in yaml.safe_load(RULES.read_text(encoding="utf-8"))["rules"] if r["id"] == rule_id)


def test_severities_and_messages_match_what_is_computed():
    assert _rule("tnt-go-header-001")["severity"] == "WARNING"
    assert "enabling header injection or response splitting" not in _rule("tnt-go-header-001")["message"]
    assert _rule("tnt-go-deser-001")["severity"] == "WARNING"
    assert "potentially enabling code execution" not in _rule("tnt-go-deser-001")["message"]


needs_opengrep = pytest.mark.skipif(
    not OpengrepAdapter().is_installed(),
    reason="Opengrep binary not installed; these tests need a live scan.",
)


@needs_opengrep
@pytest.mark.parametrize(
    "rule_id,body",
    [
        ("tnt-go-header-001", '\tw.Header().Set("Content-Disposition", "attachment; filename=" + v)\n'),
        ("tnt-go-header-001", '\tw.Header().Add("Set-Cookie", "pref=" + v)\n'),
        ("tnt-go-redirect-001", '\tw.Header().Set("Location", v)\n'),
        ("tnt-go-log-001", '\tlog.Printf("user %s logged in", v)\n'),
        ("tnt-go-log-001", "\tlog.Println(v)\n"),
    ],
)
def test_fires(tmp_path, rule_id, body):
    assert rule_id in _ids(tmp_path, body), body


@needs_opengrep
@pytest.mark.parametrize(
    "rule_id,body",
    [
        ("tnt-go-header-001", '\tw.Header().Set("X-Request-Id", v)\n'),
        ("tnt-go-log-001", '\tslog.Info("login", "user", v)\n'),
        ("tnt-go-log-001", '\tlog.Printf("user %q logged in", v)\n'),
    ],
)
def test_quiet(tmp_path, rule_id, body):
    assert rule_id not in _ids(tmp_path, body), body
