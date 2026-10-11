"""Cookie flag rules as structural Opengrep rules (#71, #53).

ns-websec-1004-001 (no HttpOnly) and ns-websec-614-001 (no Secure) were
regex rules with a "sanitizer window" to see flags on later lines of a
wrapped call. They also fired on the client-side cookie jar
(`jar.set_cookie(cookie)`), which sets nothing on a response, and 614
missed Flask's `app.config["SESSION_COOKIE_SECURE"] = False`.
Requires the Opengrep binary.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from rowan.taint.opengrep_adapter import OpengrepAdapter

RULES = Path(__file__).parent.parent / "rules" / "python_web_surface_opengrep.yaml"

pytestmark = pytest.mark.skipif(
    not OpengrepAdapter().is_installed(),
    reason="Opengrep binary not installed; these tests need a live scan.",
)


def _lines(tmp_path, rule_id, src):
    (tmp_path / "views.py").write_text(src, encoding="utf-8")
    findings = OpengrepAdapter().scan_with_rules(tmp_path, [RULES], languages=["python"])
    return {f.start_line for f in findings if f.rule_id == rule_id}


def _call(*args):
    return "def h(resp, sid):\n    resp.set_cookie(\n" + "".join(f"        {a},\n" for a in args) + "    )\n"


HTTPONLY = "ns-websec-1004-001"
SECURE = "ns-websec-614-001"


@pytest.mark.parametrize(
    "rule_id,src",
    [
        (HTTPONLY, "def h(resp, sid):\n    resp.set_cookie('session', sid)\n"),
        (HTTPONLY, _call("'session'", "sid", "secure=True")),
        (HTTPONLY, "def h(r, v):\n    r.set_cookie(key='session', value=v)\n"),
        (HTTPONLY, "def h(r, v):\n    r.set_signed_cookie('session', v)\n"),
        (SECURE, "def h(resp, sid):\n    resp.set_cookie('session', sid)\n"),
        (SECURE, _call("'session'", "sid", "httponly=True")),
        (SECURE, _call("'session'", "sid", "httponly=True", "secure=False")),
        (SECURE, "SESSION_COOKIE_SECURE = False\n"),
        (SECURE, "CSRF_COOKIE_SECURE = False\n"),
        (SECURE, "app.config['SESSION_COOKIE_SECURE'] = False\n"),
        (SECURE, "app.config.update(SESSION_COOKIE_SECURE=False)\n"),
    ],
)
def test_missing_flag_fires(tmp_path, rule_id, src):
    assert _lines(tmp_path, rule_id, src), src


@pytest.mark.parametrize(
    "rule_id,src",
    [
        (HTTPONLY, _call("'session'", "sid", "httponly=True", "secure=True")),
        # A config value still passes the flag (9 FPs in langflow when the
        # literal True was required).
        (HTTPONLY, _call("'session'", "sid", "httponly=auth_settings.ACCESS_HTTPONLY")),
        (SECURE, _call("'session'", "sid", "secure=True", "httponly=True")),
        (SECURE, _call("'session'", "sid", "secure=settings.SECURE_COOKIES")),
        (SECURE, "SESSION_COOKIE_SECURE = True\n"),
        # Client-side cookie jar: one positional Cookie, no response involved.
        (HTTPONLY, "def h(session, c):\n    session.cookies.set_cookie(c)\n"),
        (SECURE, "def h(jar, c):\n    jar.set_cookie(c)\n"),
        # Flags hidden in a helper's kwargs.
        (HTTPONLY, "def h(resp):\n    resp.set_cookie('s', 'v', **cookie_kwargs())\n"),
        (SECURE, "def h(resp):\n    resp.set_cookie('s', 'v', **cookie_kwargs())\n"),
    ],
)
def test_flag_present_or_not_a_response_cookie_is_quiet(tmp_path, rule_id, src):
    assert not _lines(tmp_path, rule_id, src), src


def test_finding_is_on_the_call_line(tmp_path):
    src = "def login(user):\n    resp = make_response(redirect('/'))\n    resp.set_cookie('session', issue_token(user.id))\n    return resp\n"
    assert _lines(tmp_path, HTTPONLY, src) == {3}
