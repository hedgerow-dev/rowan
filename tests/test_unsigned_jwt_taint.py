"""TNT-AUTH-JWT-001 (rules/python_taint.yaml): a request-supplied JWT split on
"." whose payload is base64-decoded and json-parsed by hand, trusted without a
signature check. Requires the Opengrep binary (skipped if not installed).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from rowan.taint.opengrep_adapter import OpengrepAdapter

RULES_DIR = Path(__file__).parent.parent / "rules"

_adapter = OpengrepAdapter()
pytestmark = pytest.mark.skipif(
    not _adapter.is_installed(),
    reason="Opengrep binary not installed; these tests need a live scan.",
)

HEADER = "import base64, json, jwt\nfrom flask import request\n"


def _flagged(tmp_path, body):
    (tmp_path / "app.py").write_text(HEADER + body, encoding="utf-8")
    findings = OpengrepAdapter().scan_with_rules(
        tmp_path, [RULES_DIR / "python_taint.yaml"], languages=["python"]
    )
    return [f for f in findings if f.rule_id == "TNT-AUTH-JWT-001"]


def test_hand_rolled_payload_decode_is_flagged(tmp_path):
    assert _flagged(
        tmp_path,
        "def exchange():\n"
        '    seg = request.json["token"].split(".")[1]\n'
        '    claims = json.loads(base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4)))\n'
        '    return claims["sub"]\n',
    )


def test_header_token_variant_is_flagged(tmp_path):
    assert _flagged(
        tmp_path,
        "def whoami():\n"
        '    token = request.headers.get("Authorization").split(" ")[1]\n'
        '    payload = token.split(".")[1]\n'
        "    return json.loads(base64.b64decode(payload))\n",
    )


def test_verified_decode_is_not_flagged(tmp_path):
    assert not _flagged(
        tmp_path,
        "def exchange():\n"
        '    claims = jwt.decode(request.json["token"], KEY, algorithms=["HS256"])\n'
        '    return claims["sub"]\n',
    )


def test_signature_verified_before_manual_decode_is_not_flagged(tmp_path):
    assert not _flagged(
        tmp_path,
        "def exchange():\n"
        '    token = request.json["token"]\n'
        '    jwt.decode(token, KEY, algorithms=["HS256"])\n'
        '    seg = token.split(".")[1]\n'
        '    return json.loads(base64.urlsafe_b64decode(seg + "=="))\n',
    )


def test_base64_json_body_without_dot_split_is_not_flagged(tmp_path):
    assert not _flagged(
        tmp_path,
        "def upload():\n"
        '    raw = request.json["blob"]\n'
        "    return json.loads(base64.b64decode(raw))\n",
    )
