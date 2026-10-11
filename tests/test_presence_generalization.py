"""Generalization fixtures for the three presence (regex) rules that were
rebuilt from single-idiom benchmark-fitting into idiom-complete detections:

  * ns-bb-014        weak PRNG for a security value (CWE-330/338)
  * ns-websec-614-001 cookie set without Secure (CWE-614)
  * NS-CONFIG-101     debug/development mode enabled (CWE-215)

Unlike the taint rules (TNT-UPLOAD-001, TNT-LOG-002), these are line-oriented
regex rules: they generalize across framework *idioms* but cannot follow
dataflow or see a sanitizer in another statement. The weak-PRNG multi-line
function-body case below is a documented limitation, not a bug -- a value drawn
from a non-crypto PRNG in a def whose body spans lines is out of a line regex's
reach and is only caught when the binding itself is security-named.

Scans through the CONVERTED opengrep rules (rules/converted/*.yaml), which is
what the real scanner loads. Skipped if Opengrep is not installed.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from rowan.taint.opengrep_adapter import OpengrepAdapter

PROJECT = Path(__file__).parent.parent

_adapter = OpengrepAdapter()
pytestmark = pytest.mark.skipif(
    not _adapter.is_installed(),
    reason="Opengrep binary not installed; these tests need a live scan.",
)


def _fires(tmp_path, filename, source, rule_file, rule_id):
    """Run the FULL scan pipeline (not raw opengrep): the sanitizer-window
    suppression that ns-websec-614-001 relies on (secure=True near the
    set_cookie) is applied by a post-scan pass, not by opengrep itself, so a
    raw scan_with_rules would spuriously fire on the secured variant.
    rule_file is unused now (kept for readability of the call sites)."""
    (tmp_path / filename).write_text(source, encoding="utf-8")
    out = tmp_path / "_out.json"
    subprocess.run(
        [sys.executable, "-m", "rowan", "scan", str(tmp_path),
         "--no-sca", "--audit", "--format", "json", "--output", str(out)],
        cwd=PROJECT, capture_output=True, text=True,
    )
    if not out.exists():
        return False
    data = json.loads(out.read_text())
    # A rule merged into another rule's finding on the same line still fired.
    return any(
        rule_id == f.get("rule_id") or rule_id in (f.get("duplicate_rule_ids") or [])
        for f in data.get("findings", [])
    )


# --- weak PRNG for a security value: ns-bb-014 --------------------------------

@pytest.mark.parametrize("name,src", [
    ("named_token_binding", "import random\ntoken = random.randint(1000, 9999)\n"),
    ("apikey_from_random", "import random\napi_key = str(random.random())\n"),
    ("otp_choice_join", "import random\notp = ''.join(random.choice('0123456789') for _ in range(6))\n"),
])
def test_weak_prng_fires(tmp_path, name, src):
    assert _fires(tmp_path, f"{name}.py", src, "misc_rules.yaml", "ns-bb-014")


@pytest.mark.parametrize("name,src", [
    ("csprng_secrets", "import secrets\ntoken = secrets.token_hex(16)\n"),
    ("systemrandom", "import random\nrng = random.SystemRandom()\nsecret = rng.randint(0, 9)\n"),
    ("nonsecurity_jitter", "import random\njitter = random.uniform(0, 0.5)\n"),
])
def test_weak_prng_safe(tmp_path, name, src):
    assert not _fires(tmp_path, f"{name}.py", src, "misc_rules.yaml", "ns-bb-014")


@pytest.mark.xfail(reason="line-regex ceiling: a multi-line function body is out of reach")
def test_weak_prng_multiline_body_is_a_known_gap(tmp_path):
    src = "import random\ndef make_session_id():\n    return ''.join(random.choice('abc123') for _ in range(16))\n"
    assert _fires(tmp_path, "ml.py", src, "misc_rules.yaml", "ns-bb-014")


# --- cookie set without Secure: ns-websec-614-001 -----------------------------

@pytest.mark.parametrize("name,src", [
    ("multiline_no_secure", "def h(response, sid):\n    response.set_cookie(\n        'session',\n        sid,\n        httponly=True,\n    )\n"),
    ("oneline_no_secure", "def h(resp, t):\n    resp.set_cookie('auth_token', t)\n"),
])
def test_cookie_missing_secure_fires(tmp_path, name, src):
    assert _fires(tmp_path, f"{name}.py", src, "python_web_surface.yaml", "ns-websec-614-001")


def test_cookie_with_secure_true_safe(tmp_path):
    src = "def h(response, sid):\n    response.set_cookie(\n        'session',\n        sid,\n        secure=True,\n        httponly=True,\n    )\n"
    assert not _fires(tmp_path, "safe.py", src, "python_web_surface.yaml", "ns-websec-614-001")


# --- debug mode enabled: NS-CONFIG-101 ----------------------------------------

@pytest.mark.parametrize("name,src", [
    ("django_literal", "DEBUG = True\n"),
    ("flask_run", "from flask import Flask\napp = Flask(__name__)\napp.run(debug=True)\n"),
    ("env_truthy_default", "import os\nDEBUG = os.getenv('DJANGO_DEBUG', 'True') == 'True'\n"),
    ("fastapi_ctor", "from fastapi import FastAPI\napp = FastAPI(debug=True)\n"),
])
def test_debug_enabled_fires(tmp_path, name, src):
    assert _fires(tmp_path, f"{name}.py", src, "security_surface.yaml", "NS-CONFIG-101")


@pytest.mark.parametrize("name,src", [
    ("debug_false", "DEBUG = False\n"),
    ("env_falsy_default", "import os\nDEBUG = os.getenv('DJANGO_DEBUG', 'False') == 'True'\n"),
])
def test_debug_disabled_safe(tmp_path, name, src):
    assert not _fires(tmp_path, f"{name}.py", src, "security_surface.yaml", "NS-CONFIG-101")
