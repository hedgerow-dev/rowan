"""Header injection (CWE-113) taint rule for Python, TNT-HEADER-001.

`set_cookie` is not a sink: Werkzeug's `dump_cookie` and the stdlib
`SimpleCookie` used by Django and Starlette quote or reject CR/LF in cookie
values, and reject bad names. Raw header writes stay, since Starlette passes
header values through without checking them.

Requires the Opengrep binary.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from rowan.taint.opengrep_adapter import OpengrepAdapter

RULES_DIR = Path(__file__).parent.parent / "rules"
RULE = "TNT-HEADER-001"

pytestmark = pytest.mark.skipif(
    not OpengrepAdapter().is_installed(),
    reason="Opengrep binary not installed; these tests need a live scan.",
)


def _scan(tmp_path, body):
    src = "from flask import request\n" + body
    (tmp_path / "app.py").write_text(src, encoding="utf-8")
    findings = OpengrepAdapter().scan_with_rules(
        tmp_path, [RULES_DIR / "python_taint.yaml"], languages=["python"]
    )
    return [f for f in findings if f.rule_id == RULE]


def test_set_cookie_with_user_value_is_not_flagged(tmp_path):
    body = (
        "def view(response):\n"
        "    response.set_cookie('lang', request.args.get('lang'))\n"
        "    response.set_cookie(key='theme', value=request.cookies.get('theme'))\n"
    )
    assert not _scan(tmp_path, body)


def test_raw_header_write_with_user_value_is_flagged(tmp_path):
    body = (
        "def view(response):\n"
        "    value = request.args.get('value')\n"
        "    response.headers['X-Custom'] = value\n"
    )
    assert _scan(tmp_path, body)


def test_raw_header_write_with_constant_is_not_flagged(tmp_path):
    body = (
        "def view(response):\n"
        "    response.headers['X-Custom'] = 'fixed'\n"
    )
    assert not _scan(tmp_path, body)
