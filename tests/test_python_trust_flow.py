"""Independent regression cases for shared parameter/return trust analysis."""

import ast

from rowan.analysis.python_functions import FunctionIndex
from rowan.analysis.trust_flow import TrustFlow


def scan(tmp_path, files):
    trees = {}
    for name, code in files.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(code)
        trees[path] = ast.parse(code)
    return TrustFlow(FunctionIndex(trees)).run()


def test_aliased_two_hop_unpickler_stream(tmp_path):
    findings = scan(
        tmp_path,
        {
            "pkg/routes.py": "from flask import request\nfrom . import service as svc\ndef upload():\n    return svc.unpack(request.stream.read())\n",
            "pkg/service.py": "from .codec import restore as parse\ndef unpack(raw):\n    return parse(content=raw)\n",
            "pkg/codec.py": "import pickle as p\nfrom io import BytesIO as Buffer\ndef restore(content):\n    reader = p.Unpickler(Buffer(content))\n    return reader.load()\n",
        },
    )
    assert len(findings) == 1
    assert findings[0].rule_id == "PY-DESER-FLOW-001"
    assert findings[0].file_path.endswith("codec.py")
    assert findings[0].taint_flow.source.file_path.endswith("routes.py")


def test_unused_constructor_local_file_and_restricted_class_are_clean(tmp_path):
    assert not scan(
        tmp_path,
        {
            "app.py": """
import pickle, io
from flask import request
def unused():
    return pickle.Unpickler(io.BytesIO(request.data))
def local():
    return pickle.Unpickler(open('trusted.bin', 'rb')).load()
class Restricted(pickle.Unpickler):
    def find_class(self, module, name):
        raise ValueError()
def safe():
    return Restricted(io.BytesIO(request.data)).load()
"""
        },
    )


def test_split_unpack_claims_return_to_credential_mint(tmp_path):
    findings = scan(
        tmp_path,
        {
            "api.py": """
from flask import request
from tokens import parse as decode, issue
@app.post('/session')
def exchange():
    data = request.get_json()
    claims = decode(data['credential'])
    return issue(claims['sub'], claims.get('role'))
""",
            "tokens.py": """
import base64 as b, json, jwt
def parse(raw):
    header, payload, *_ = raw.split('.')
    return json.loads(b.urlsafe_b64decode(payload + '=='))
def issue(identity, access):
    return jwt.encode({'sub': identity, 'role': access}, KEY, algorithm='HS256')
""",
        },
    )
    assert len(findings) == 1
    assert findings[0].rule_id == "PY-JWT-TRUST-001"


def test_verified_tokens_and_unrelated_json_are_clean(tmp_path):
    assert not scan(
        tmp_path,
        {
            "api.py": """
from flask import request
import jwt, base64, json
@app.post('/verified')
def verified():
    claims = jwt.decode(request.get_json()['token'], KEY, algorithms=['HS256'])
    return claims['sub']
@app.post('/document')
def document():
    data = json.loads(base64.b64decode(request.data))
    return data['sub']
"""
        },
    )


def test_displaying_unsigned_payload_without_trusting_identity_is_clean(tmp_path):
    assert not scan(
        tmp_path,
        {
            "api.py": """
from flask import request
import base64, json
@app.post('/inspect')
def inspect():
    segment = request.data.split('.')[1]
    claims = json.loads(base64.b64decode(segment))
    return claims.get('description')
"""
        },
    )


def test_cycles_stop_and_do_not_invent_sinks(tmp_path):
    assert not scan(
        tmp_path,
        {
            "api.py": """
from flask import request
def one(value):
    return two(value)
def two(value):
    return one(value)
def upload():
    return one(request.data)
"""
        },
    )


def test_reassignment_clears_taint(tmp_path):
    assert not scan(
        tmp_path,
        {
            "api.py": """
from flask import request
import pickle, io
def upload():
    raw = request.data
    raw = b'fixed'
    return pickle.Unpickler(io.BytesIO(raw)).load()
"""
        },
    )


def test_verification_must_protect_same_token_on_all_paths(tmp_path):
    template = """
from flask import request
import jwt, base64, json
@app.post('/exchange')
def exchange():
    raw = request.get_json()['token']
    {verify}
    claims = json.loads(base64.b64decode(raw.split('.')[1]))
    return claims['sub']
"""
    assert not scan(
        tmp_path, {"app.py": template.format(verify="jwt.decode(raw, KEY, algorithms=['HS256'])")}
    )
    assert scan(
        tmp_path,
        {"app.py": template.format(verify="jwt.decode('other', KEY, algorithms=['HS256'])")},
    )
    assert scan(
        tmp_path,
        {
            "app.py": template.format(
                verify="jwt.decode(raw, KEY, algorithms=['HS256'], options={'verify_signature': False})"
            )
        },
    )
    assert scan(
        tmp_path,
        {
            "app.py": template.format(
                verify="if request.args.get('verify'):\n        jwt.decode(raw, KEY, algorithms=['HS256'])"
            )
        },
    )


def test_verification_exception_must_fail_closed(tmp_path):
    template = """
from flask import request
import jwt, base64, json
@app.post('/exchange')
def exchange():
    raw = request.get_json()['token']
    try:
        jwt.decode(raw, KEY, algorithms=['HS256'])
    except Exception:
        {failure}
    claims = json.loads(base64.b64decode(raw.split('.')[1]))
    return claims['sub']
"""
    assert not scan(tmp_path, {"app.py": template.format(failure="return None")})
    assert scan(tmp_path, {"app.py": template.format(failure="pass")})


def test_separate_operations_remain_distinct(tmp_path):
    findings = scan(
        tmp_path,
        {
            "app.py": """
from flask import request
import pickle, io
def upload():
    a = pickle.Unpickler(io.BytesIO(request.data)).load()
    b = pickle.Unpickler(io.BytesIO(request.data)).load()
    return a, b
"""
        },
    )
    assert len(findings) == 2


def test_fastapi_body_parameter_and_dependency_boundary(tmp_path):
    template = """
from fastapi import Body, Depends
import pickle, io
@router.post('/restore')
def restore(content: bytes = {default}):
    return pickle.Unpickler(io.BytesIO(content)).load()
"""
    assert scan(tmp_path, {"api.py": template.format(default="Body(...)")})
    assert not scan(tmp_path, {"api.py": template.format(default="Depends(trusted_content)")})


def test_django_request_body_to_imported_decoder(tmp_path):
    assert scan(
        tmp_path,
        {
            "views.py": "from codec import decode\ndef restore(request):\n    return decode(request.body)\n",
            "codec.py": "import pickle, io\ndef decode(value):\n    return pickle.Unpickler(io.BytesIO(value)).load()\n",
        },
    )


def test_two_sinks_on_same_line_are_distinct(tmp_path):
    findings = scan(
        tmp_path,
        {
            "app.py": """
from flask import request
import pickle, io
def upload():
    return pickle.Unpickler(io.BytesIO(request.data)).load(), pickle.Unpickler(io.BytesIO(request.data)).load()
"""
        },
    )
    assert len(findings) == 2
    assert findings[0].start_column != findings[1].start_column


def test_import_resolution_reexports_and_ambiguous_modules(tmp_path):
    assert scan(
        tmp_path,
        {
            "api.py": "from package import restore\nfrom flask import request\ndef upload():\n    return restore(request.data)\n",
            "package/__init__.py": "from .codec import decode as restore\n",
            "package/codec.py": "import io, pickle\ndef decode(raw):\n    return pickle.Unpickler(io.BytesIO(raw)).load()\n",
        },
    )
    assert not scan(
        tmp_path,
        {
            "api.py": "from codec import restore\nfrom flask import request\ndef upload():\n    return restore(request.data)\n",
            "one/codec.py": "import io, pickle\ndef restore(raw):\n    return pickle.Unpickler(io.BytesIO(raw)).load()\n",
            "two/codec.py": "def restore(raw):\n    return raw\n",
        },
    )


def test_shadowed_import_is_not_resolved_as_repository_helper(tmp_path):
    assert not scan(
        tmp_path,
        {
            "api.py": "from codec import restore\nfrom flask import request\ndef upload(restore):\n    return restore(request.data)\n",
            "codec.py": "import io, pickle\ndef restore(raw):\n    return pickle.Unpickler(io.BytesIO(raw)).load()\n",
        },
    )


def test_client_chosen_verification_key_is_not_a_trust_boundary(tmp_path):
    assert scan(
        tmp_path,
        {
            "api.py": """
from flask import request
import jwt, base64, json
@app.post('/exchange')
def exchange():
    data = request.get_json()
    raw = data['token']
    jwt.decode(raw, data['key'], algorithms=['HS256'])
    claims = json.loads(base64.b64decode(raw.split('.')[1]))
    return claims['sub']
"""
        },
    )


def test_calling_imported_module_does_not_crash_resolution(tmp_path):
    assert not scan(tmp_path, {'api.py': '''
import external
from flask import request
def upload():
    return external(request.data)
'''})
