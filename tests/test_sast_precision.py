"""Paired safe/vulnerable cases through the production scan pipeline."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from rowan.analysis.safe_sink_context import (
    resolved_regex_search,
    safe_flask_response,
    safe_flask_template_render,
    safe_pickle_roundtrip,
)
from rowan.config import ScanConfig
from rowan.core.findings import Category, Finding, Severity, TaintFlow, TaintNode
from rowan.passes.enrichment import EnrichmentPass
from rowan.pipeline import ScanPipeline
from rowan.taint.opengrep_adapter import OpengrepAdapter


@pytest.fixture(scope="module")
def precision_scan(tmp_path_factory):
    if not OpengrepAdapter().is_installed():
        pytest.skip("Production-pipeline regression requires Opengrep")
    root = tmp_path_factory.mktemp("rowan_precision")
    cases = {
        "version_notice_helper.py": '''async def notify(release):
    await logger.awarning(f"Please update your release {release}")
''',
        "version_notice_route.py": '''from flask import request
from version_notice_helper import notify
async def handle():
    release = request.args.get("release")
    await notify(release)
''',
        "query_helper.py": '''def fetch(key):
    return logger.info(connection.execute(f"SELECT * FROM docs WHERE key = '{key}'"))
''',
        "query_route.py": '''from flask import request
from query_helper import fetch
def handle():
    key = request.args.get("key")
    return fetch(key)
''',
        "regex_safe.py": '''from flask import request
import re as regex
def check():
    text = request.args.get("text")
    return regex.search("hello", text)
''',
        "vector_query_unsafe.py": '''from flask import request
def retrieve(store):
    text = request.args.get("text")
    return store.search(text)
''',
        "template_safe.py": '''from flask import request, render_template
def index():
    name = request.args.get("name")
    return render_template("index.html", name=name)
''',
        "plain_safe.py": '''from flask import request, make_response
def index():
    name = request.args.get("name")
    response = make_response(name)
    response.mimetype = "text/plain"
    return response
''',
        "html_unsafe.py": '''from flask import request, make_response
def index():
    name = request.args.get("name")
    return make_response(name)
''',
        "markup_unsafe.py": '''from flask import request, render_template
from markupsafe import Markup
def index():
    name = request.args.get("name")
    return render_template("index.html", name=Markup(name))
''',
        "header_unsafe.py": '''from flask import request
def index(response):
    value = request.args.get("value")
    response.headers["X-Custom"] = value
    return response
''',
        "make_response_header_unsafe.py": '''from flask import request, make_response
def index():
    value = request.args.get("value")
    return make_response("ok", 200, {"X-Custom": value})
''',
        "template_autoescape_disabled.py": '''from flask import Flask, request, render_template
app = Flask(__name__)
app.jinja_env.autoescape = False
def index():
    name = request.args.get("name")
    return render_template("index.html", name=name)
''',
        "template_non_html_unsafe.py": '''from flask import request, render_template
def index():
    name = request.args.get("name")
    return render_template("email.txt", name=name)
''',
        "template_safe_filter_unsafe.py": '''from flask import request, render_template
def index():
    name = request.args.get("name")
    return render_template("unsafe.html", name=name)
''',
        "pickle_safe.py": '''from flask import request
import pickle
def health():
    return request.args.get("status", "ok")
def local_roundtrip():
    blob = pickle.dumps({"count": 1})
    return pickle.loads(blob)
''',
        "pickle_unsafe.py": '''from flask import request
import pickle
def load():
    data = request.data
    return pickle.loads(data)
''',
        "json_safe.py": '''from flask import request
import json
import sqlite3
def health():
    return request.args.get("status", "ok")
def seed():
    row = json.loads('{"query":"SELECT 1"}')
    conn = sqlite3.connect(":memory:")
    return conn.execute(row["query"]).fetchall()
''',
        "json_unsafe.py": '''from flask import request
import json
def run(conn):
    row = json.loads(request.args.get("query"))
    return conn.execute(row["query"])
''',
        "kwargs_safe.py": '''def run(conn, **kwargs):
    return conn.execute(kwargs.get("query", "SELECT 1"))
def seed(conn):
    return run(conn, query="SELECT 1")
''',
        "kwargs_unsafe.py": '''from flask import request
def run(conn):
    kwargs = {"query": request.args.get("query")}
    return conn.execute(kwargs.get("query"))
''',
    }
    for name, code in cases.items():
        (root / name).write_text(code)
    (root / "templates").mkdir()
    (root / "templates" / "index.html").write_text("<p>Hello {{ name }}</p>")
    (root / "templates" / "email.txt").write_text("Hello {{ name }}")
    (root / "templates" / "unsafe.html").write_text("<p>{{ name|safe }}</p>")
    config = ScanConfig(target=root, no_sca=True)
    result = ScanPipeline(config).run()
    return config, result


@pytest.mark.parametrize("filename", [
    "template_safe.py", "plain_safe.py", "pickle_safe.py", "json_safe.py", "kwargs_safe.py",
    "regex_safe.py",
])
def test_safe_cases_have_no_vulnerability_findings(precision_scan, filename):
    _, result = precision_scan
    findings = [f for f in result.findings if Path(f.file_path).name == filename]
    assert not findings, [(f.rule_id, f.severity.value, f.metadata) for f in findings]


@pytest.mark.parametrize(("filename", "rule_id"), [
    ("html_unsafe.py", "TNT-XSS-001"),
    ("markup_unsafe.py", "TNT-XSS-001"),
    ("header_unsafe.py", "TNT-HEADER-001"),
    ("make_response_header_unsafe.py", "TNT-HEADER-001"),
    ("template_autoescape_disabled.py", "TNT-XSS-001"),
    ("template_non_html_unsafe.py", "TNT-XSS-001"),
    ("template_safe_filter_unsafe.py", "TNT-XSS-001"),
    ("pickle_unsafe.py", "TNT-DESER-001"),
    ("json_unsafe.py", "TNT-SQLI-002"),
    ("kwargs_unsafe.py", "TNT-SQLI-002"),
])
def test_vulnerable_pairs_survive_confirmed_view(precision_scan, filename, rule_id):
    config, result = precision_scan
    pipe = ScanPipeline(config)
    findings = [f for f in result.findings
                if Path(f.file_path).name == filename and f.rule_id == rule_id]
    assert findings, [(Path(f.file_path).name, f.rule_id) for f in result.findings]
    assert all(f.taint_flow is not None and pipe._in_confirmed_view(f) for f in findings)
    if rule_id in {"TNT-DESER-001", "TNT-SQLI-002"}:
        assert all(f.severity in {Severity.HIGH, Severity.CRITICAL} for f in findings)


@pytest.mark.parametrize("rule_id", ["TNT-ML-004", "TNT-LDAP-001"])
def test_unknown_search_receiver_keeps_claim(precision_scan, rule_id):
    _, result = precision_scan
    assert any(Path(f.file_path).name == "vector_query_unsafe.py"
               and f.rule_id == rule_id for f in result.findings)


def test_cross_file_log_message_is_not_sql_but_query_is(precision_scan):
    _, result = precision_scan
    notice_claims = [f for f in result.findings
                     if Path(f.file_path).name in {"version_notice_helper.py", "version_notice_route.py"}
                     and (f.rule_id == "NS-SQLI-005" or 89 in f.cwe_ids)]
    assert not notice_claims
    assert any(Path(f.file_path).name == "query_route.py"
               and f.rule_id == "CF-SINK-001" and 89 in f.cwe_ids for f in result.findings)


@pytest.mark.parametrize("source", [
    'import re\nre.search("prefix", text)',
    'import re as rx\nrx.search("prefix", text)',
    'from re import search as match\nmatch("prefix", text)',
])
def test_resolved_regex_search_is_not_vector_query(source):
    assert resolved_regex_search(ast.parse(source), 2)


@pytest.mark.parametrize("source, line", [
    ('import re\nre = store\nre.search(text)', 3),
    ('import re\ndef check(re):\n    return re.search(text)', 3),
    ('import re\nre.search = other\nre.search(text)', 3),
    ('import re\nfrom other import re\nre.search(text)', 3),
    ('import re\nfrom other import *\nre.search(text)', 3),
    ('import re, other as re\nre.search(text)', 2),
    ('import re\nre.search("x", text); store.search(text)', 2),
    ('import re\nre.search("x", text); directory.search_s(text)', 2),
    ('store.search(text)', 1),
    ('index.query(text)', 1),
    ('re.search("x", text)', 1),
])
def test_ambiguous_or_vector_search_is_retained(source, line):
    assert not resolved_regex_search(ast.parse(source), line)


@pytest.mark.parametrize("body", [
    'blob = pickle.dumps({"n": 1})\nreturn pickle.loads(blob)',
    'return pickle.loads(pickle.dumps([1, "hello"]))',
])
def test_literal_pickle_proof(body):
    code = "import pickle\ndef load():\n" + "\n".join("    " + s for s in body.splitlines())
    assert safe_pickle_roundtrip(ast.parse(code), len(code.splitlines()))


@pytest.mark.parametrize("body", [
    'blob = pickle.dumps(custom_object)\nreturn pickle.loads(blob)',
    'blob = pickle.dumps({"n": 1})\nblob = request.data\nreturn pickle.loads(blob)',
    'blob = request.data\nif flag:\n    blob = pickle.dumps({"n": 1})\nreturn pickle.loads(blob)',
    'return pickle.loads(b"cos\\nsystem\\n(S\\"whoami\\"\\ntR.")',
    'blob = pickle.dumps({"n": 1})\nmutate()\nreturn pickle.loads(blob)',
    'blob = pickle.dumps({"n": 1})\nreturn (pickle.loads(blob), pickle.loads(request.data))',
    'blob = pickle.dumps({"n": 1})\nreturn (pickle.loads(blob), dill.loads(request.data))',
])
def test_unsafe_or_unknown_pickle_is_not_suppressed(body):
    code = "import pickle\ndef load():\n" + "\n".join("    " + s for s in body.splitlines())
    assert not safe_pickle_roundtrip(ast.parse(code), len(code.splitlines()))


@pytest.mark.parametrize("body", [
    'response.mimetype = "text/plain"\nreturn response',
    'response.content_type = "application/json; charset=utf-8"\nreturn response',
])
def test_non_html_response_proof(body):
    code = "from flask import make_response\ndef view():\n    response = make_response(value)\n"
    code += "\n".join("    " + s for s in body.splitlines())
    assert safe_flask_response(ast.parse(code), 3)


def test_flask_template_safety_requires_default_autoescaped_literal():
    code = '''from flask import render_template
def view():
    return render_template("index.html", name=value)
'''
    tree = ast.parse(code)
    assert safe_flask_template_render(tree, 3, autoescape_disabled=False)
    assert not safe_flask_template_render(tree, 3, autoescape_disabled=True)
    assert not safe_flask_template_render(
        ast.parse(code.replace("index.html", "email.txt")),
        3,
        autoescape_disabled=False,
    )


@pytest.mark.parametrize("body", [
    'if flag:\n    response.mimetype = "text/plain"\nreturn response',
    'return response\nresponse.mimetype = "text/plain"',
    'response.mimetype = "text/plain"\nresponse.mimetype = "text/html"\nreturn response',
    'response.mimetype = "text/html"\nreturn response',
    'other.mimetype = "text/plain"\nreturn response',
    'response.mimetype = "text/plain"\nchange(response)\nreturn response',
])
def test_response_safety_requires_unconditional_final_type(body):
    code = "from flask import make_response\ndef view():\n    response = make_response(value)\n"
    code += "\n".join("    " + s for s in body.splitlines())
    assert not safe_flask_response(ast.parse(code), 3)


@pytest.mark.parametrize("proof,code", [
    (safe_pickle_roundtrip, 'import pickle\ndef load(pickle):\n    return pickle.loads(pickle.dumps(1))'),
    (safe_flask_response, 'from flask import make_response\ndef view(make_response):\n    response = make_response(value)\n    response.mimetype = "text/plain"\n    return response'),
])
def test_shadowed_imports_are_not_safety_proofs(proof, code):
    assert not proof(ast.parse(code), 3)


def test_file_context_cannot_promote_or_confirm_a_pattern(tmp_path):
    source = tmp_path / "app.py"
    source.write_text('from flask import request\n@app.get("/")\ndef index():\n    return request.data\n')
    finding = Finding(rule_id="NS-DESER-001", message="pickle", severity=Severity.HIGH,
                      category=Category.DESERIALIZATION, file_path=str(source), start_line=4)
    enrichment = EnrichmentPass()
    enrichment._cap_unverified_severity([finding])
    enrichment._apply_sink_severity_floor([finding])
    assert finding.severity == Severity.MEDIUM
    assert finding.metadata["evidence_tier"] == "pattern-only"
    pipe = ScanPipeline(ScanConfig(target=tmp_path))
    assert not pipe._in_confirmed_view(finding)
    finding.severity = Severity.CRITICAL
    assert not pipe._in_confirmed_view(finding)


def test_downgraded_taint_cannot_be_promoted_or_confirmed(tmp_path):
    finding = Finding(rule_id="TNT-DESER-001", message="pickle", severity=Severity.INFO,
                      category=Category.DESERIALIZATION, file_path=str(tmp_path / "app.py"), start_line=1,
                      taint_flow=TaintFlow(source=TaintNode(file_path="app.py", line=1),
                                           sink=TaintNode(file_path="app.py", line=2)),
                      metadata={"taint_unconfirmed": True, "evidence_tier": "taint-flow"})
    EnrichmentPass()._apply_sink_severity_floor([finding])
    assert finding.severity == Severity.INFO
    finding.severity = Severity.HIGH
    assert not ScanPipeline(ScanConfig(target=tmp_path))._in_confirmed_view(finding)
