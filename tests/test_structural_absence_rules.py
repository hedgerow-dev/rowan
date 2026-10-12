""""X without Y" framework rules as structural Opengrep rules (#71, #53).

As regex rules these fired on the `MIDDLEWARE = [` / `express()` line itself,
because `pattern-not` only sees that one line and Y is always on another.
Requires the Opengrep binary.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from rowan.taint.opengrep_adapter import OpengrepAdapter

RULES = Path(__file__).parent.parent / "rules" / "framework_opengrep.yaml"

pytestmark = pytest.mark.skipif(
    not OpengrepAdapter().is_installed(),
    reason="Opengrep binary not installed; these tests need a live scan.",
)


def _fires(tmp_path, filename, language, rule_id, src):
    (tmp_path / filename).write_text(src, encoding="utf-8")
    findings = OpengrepAdapter().scan_with_rules(tmp_path, [RULES], languages=[language])
    return any(f.rule_id == rule_id for f in findings)


DJANGO_WITH_CSRF = """MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
]
"""
DJANGO_WITHOUT_CSRF = """MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
]
"""


def test_django_middleware_without_csrf_fires(tmp_path):
    assert _fires(tmp_path, "settings.py", "python", "ns-fw-py-004", DJANGO_WITHOUT_CSRF)


def test_django_middleware_with_csrf_on_another_line_is_quiet(tmp_path):
    assert not _fires(tmp_path, "settings.py", "python", "ns-fw-py-004", DJANGO_WITH_CSRF)


EXPRESS_WITH_HELMET = """const express = require('express');
const helmet = require('helmet');
const app = express();
app.use(helmet());
app.listen(3000);
"""
EXPRESS_WITHOUT_HELMET = """const express = require('express');
const app = express();
app.get('/', (req, res) => res.send('ok'));
app.listen(3000);
"""
PLAIN_SERVER = """const http = require('http');
const server = http.createServer(handler);
server.listen(3000);
"""


def test_express_without_helmet_fires(tmp_path):
    assert _fires(tmp_path, "app.js", "javascript", "ns-fw-js-001", EXPRESS_WITHOUT_HELMET)


def test_express_with_helmet_on_another_line_is_quiet(tmp_path):
    assert not _fires(tmp_path, "app.js", "javascript", "ns-fw-js-001", EXPRESS_WITH_HELMET)


def test_non_express_listen_is_quiet(tmp_path):
    assert not _fires(tmp_path, "server.js", "javascript", "ns-fw-js-001", PLAIN_SERVER)


AIOHTTP_LOGIN = """from aiohttp_session import get_session

async def index(request):
    session = await get_session(request)
    user = await authorize(request)
    session['user_id'] = user.id
    return redirect('/')
"""
AIOHTTP_LOGIN_ROTATED = """from aiohttp_session import new_session

async def index(request):
    user = await authorize(request)
    session = await new_session(request)
    session['user_id'] = user.id
    return redirect('/')
"""
FLASK_LOGIN_CLEARED = """from flask import session

def login():
    user = check_password()
    session.clear()
    session['user_id'] = user.id
"""
SESSION_READ_AND_CART = """from flask import session

def view():
    uid = session['user_id']
    session['cart'] = []
    return uid
"""


def test_login_without_session_rotation_fires(tmp_path):
    assert _fires(tmp_path, "views.py", "python", "ns-fw-sess-001", AIOHTTP_LOGIN)


@pytest.mark.parametrize("src", [AIOHTTP_LOGIN_ROTATED, FLASK_LOGIN_CLEARED, SESSION_READ_AND_CART])
def test_rotated_session_or_non_login_key_is_quiet(tmp_path, src):
    assert not _fires(tmp_path, "views.py", "python", "ns-fw-sess-001", src)
