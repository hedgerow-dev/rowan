from __future__ import annotations

from pathlib import Path

from rowan.config import ScanConfig
from rowan.core.findings import ScanResult
from rowan.passes.base import ScanContext
from rowan.passes.web_security import WebSecurityPass
from rowan.pipeline import ScanPipeline


def _scan(root: Path):
    context = ScanContext(root, ScanConfig(root), ScanResult())
    return WebSecurityPass().run(context).findings


def test_lf2_general_web_security_shapes(tmp_path: Path) -> None:
    (tmp_path / "views.py").write_text(
        """
from flask import request, Response
import jsonpickle
from jsonpickle import loads as restore_typed_json

def apply_updates(obj, updates):
    for key, value in updates.items():
        setattr(obj, key, value)

def import_document():
    data = request.get_json() or {}
    return jsonpickle.decode(data.get("payload", ""))

def import_aliased_document():
    data = request.get_json() or {}
    return restore_typed_json(data.get("payload", ""))

def update_model(model):
    updates = request.get_json() or {}
    apply_updates(model, updates)

def register():
    data = request.get_json() or {}
    return User(name=data.get("name"), role=data.get("role", "user"))

def upload_svg():
    data = request.get_json() or {}
    svg = data.get("svg", "")
    Path("avatar.svg").write_text(svg)

def get_svg():
    return Response(load_avatar(), mimetype="image/svg+xml",
                    headers={"Content-Disposition": "inline"})

def check_http_auth(headers):
    presented = headers.get("Authorization")
    return presented == Config.HTTP_TOKEN

@app.route("/settings", methods=["GET", "POST"])
@login_required
def settings():
    if request.method == "POST":
        store.update(theme=request.form.get("theme"))
    return render_template("settings.html")

@app.after_request
def security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response
""",
        encoding="utf-8",
    )
    (tmp_path / "auth.py").write_text(
        "from flask import request\ndef user():\n    return request.cookies.get('session_token')\n",
        encoding="utf-8",
    )

    findings = _scan(tmp_path)
    by_rule = {finding.rule_id: finding for finding in findings}
    assert sum(f.rule_id == "WEB-DESER-JSONPICKLE-001" for f in findings) == 2
    expected = {
        "WEB-DESER-JSONPICKLE-001": 502,
        "WEB-INLINE-ACTIVE-CONTENT-001": 79,
        "WEB-AUTH-TIMING-001": 208,
        "WEB-MASS-ASSIGN-001": 915,
        "WEB-PRIVILEGE-ASSIGN-001": 266,
        "WEB-CSRF-COOKIE-001": 352,
        "WEB-CLICKJACKING-001": 1021,
    }
    assert set(by_rule) == set(expected)
    for rule_id, cwe in expected.items():
        assert by_rule[rule_id].cwe_ids == [cwe]
        assert by_rule[rule_id].metadata["evidence_tier"] == "engine"
        assert ScanPipeline(ScanConfig(tmp_path))._in_confirmed_view(by_rule[rule_id])
        assert ScanPipeline(ScanConfig(tmp_path))._in_actionable_view(by_rule[rule_id])


def test_lf2_safe_controls_are_not_reported(tmp_path: Path) -> None:
    (tmp_path / "safe.py").write_text(
        """
from flask import request, Response
from flask_wtf.csrf import CSRFProtect
import hmac, json

csrf = CSRFProtect(app)

def apply_updates(obj, updates):
    ALLOWED_FIELDS = {"name", "description"}
    for key, value in updates.items():
        if key not in ALLOWED_FIELDS:
            continue
        setattr(obj, key, value)

def import_document():
    data = request.get_json() or {}
    return json.loads(data.get("payload", ""))

def update_model(model):
    updates = request.get_json() or {}
    apply_updates(model, updates)

def register():
    data = request.get_json() or {}
    role = data.get("role", "user")
    if role not in {"user", "viewer"}:
        return {"error": "invalid role"}, 400
    return User(role=role)

def upload_svg():
    data = request.get_json() or {}
    Path("avatar.svg").write_text(data.get("svg", ""))

def download_svg():
    return Response(load_avatar(), mimetype="image/svg+xml",
                    headers={"Content-Disposition": "attachment"})

def check_http_auth(headers):
    return hmac.compare_digest(headers.get("Authorization", ""), Config.HTTP_TOKEN)

@app.after_request
def security_headers(response):
    response.headers["Content-Security-Policy"] = "frame-ancestors 'none'"
    return response
""",
        encoding="utf-8",
    )
    (tmp_path / "auth.py").write_text(
        "from flask import request\ndef user():\n    return request.cookies.get('session_token')\n",
        encoding="utf-8",
    )

    assert _scan(tmp_path) == []


def test_public_identity_hash_used_as_recovery_code_is_predictable(tmp_path: Path) -> None:
    (tmp_path / "security.py").write_text(
        """
import hashlib

def derive_password_recovery_code(username: str, email: str) -> str:
    return hashlib.sha256(f"{username}:{email}".encode()).hexdigest()[:12]
""",
        encoding="utf-8",
    )
    findings = [
        finding for finding in _scan(tmp_path)
        if finding.rule_id == "WEB-PREDICTABLE-RECOVERY-001"
    ]
    assert len(findings) == 1
    assert findings[0].cwe_ids == [640]


def test_random_single_use_recovery_code_is_not_predictable(tmp_path: Path) -> None:
    (tmp_path / "security.py").write_text(
        """
import hashlib
import secrets

def new_password_recovery_code(username: str) -> tuple[str, str]:
    code = secrets.token_urlsafe(24)
    return code, hashlib.sha256(code.encode()).hexdigest()
""",
        encoding="utf-8",
    )
    assert not any(
        finding.rule_id == "WEB-PREDICTABLE-RECOVERY-001"
        for finding in _scan(tmp_path)
    )


def test_keyed_recovery_derivation_is_not_reported_as_publicly_predictable(
    tmp_path: Path,
) -> None:
    (tmp_path / "security.py").write_text(
        """
import hashlib
import hmac

def derive_password_recovery_code(username: str, secret_key: bytes) -> str:
    return hmac.new(secret_key, username.encode(), hashlib.sha256).hexdigest()
""",
        encoding="utf-8",
    )
    assert not any(
        finding.rule_id == "WEB-PREDICTABLE-RECOVERY-001"
        for finding in _scan(tmp_path)
    )


def test_content_hash_outside_account_recovery_is_not_reported(tmp_path: Path) -> None:
    (tmp_path / "cache.py").write_text(
        """
import hashlib

def derive_cache_key(username: str, email: str) -> str:
    return hashlib.sha256(f"{username}:{email}".encode()).hexdigest()
""",
        encoding="utf-8",
    )
    assert not any(
        finding.rule_id == "WEB-PREDICTABLE-RECOVERY-001"
        for finding in _scan(tmp_path)
    )


def test_annotation_only_assignment_does_not_crash_scan(tmp_path: Path) -> None:
    (tmp_path / "models.py").write_text(
        "def configure():\n    handler: object\n    return None\n",
        encoding="utf-8",
    )
    assert _scan(tmp_path) == []


_SIGNUP = """
from flask import Flask, request, jsonify, g, abort
app = Flask(__name__)

def admin_only(fn):
    def wrapper(*a, **k):
        if g.{field} != "admin":
            abort(403)
        return fn(*a, **k)
    return wrapper

@app.post("/signup")
def signup():
    data = request.get_json()
    u = User(name=data["name"], {field}=data.get("{field}", "member"))
    db.session.add(u)
    return jsonify(id=u.id)
"""


def _privilege_findings(root: Path):
    return [f for f in _scan(root) if f.rule_id == "WEB-PRIVILEGE-ASSIGN-001"]


def test_privilege_field_with_unlisted_name_is_found_via_admin_guard(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(_SIGNUP.format(field="tier"), encoding="utf-8")
    assert _privilege_findings(tmp_path)


def test_field_never_compared_to_admin_is_not_a_privilege_field(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        _SIGNUP.format(field="tier").replace('g.tier != "admin"', 'g.is_admin_ok'),
        encoding="utf-8",
    )
    assert not _privilege_findings(tmp_path)


def test_reserved_name_check_does_not_make_username_a_privilege_field(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "from flask import request\n"
        "def signup():\n"
        "    data = request.get_json()\n"
        "    if data['username'] == 'admin':\n"
        "        return 'reserved'\n"
        "    return User(username=data['username'])\n"
        "def check(user):\n"
        "    return user.username == 'admin'\n",
        encoding="utf-8",
    )
    assert not _privilege_findings(tmp_path)


def test_privilege_discovery_getattr_arbitrary_field(tmp_path: Path) -> None:
    code = _SIGNUP.format(field="clearance").replace('g.clearance != "admin"', 'getattr(g, "clearance", "member") != "admin"')
    (tmp_path / "app.py").write_text(code)
    assert _privilege_findings(tmp_path)
