"""Regression fixtures from the 2026-09-21 LangFlow/PyTorch scan validation.

These are deliberately small copies of real repository shapes.  Each negative
has a paired positive so lowering a rule's severity or deleting it cannot make
the precision gate pass by hiding recall loss.
"""

from __future__ import annotations

from pathlib import Path

from rowan.config import ScanConfig
from rowan.core.findings import Category, Finding, Severity
from rowan.passes.enrichment import EnrichmentPass
from rowan.pipeline import ScanPipeline


def _scan(
    root: Path,
    *,
    cross_file: bool = False,
    languages: list[str] | None = None,
):
    return ScanPipeline(
        ScanConfig(
            target=root,
            no_sca=True,
            no_cross_file=not cross_file,
            report_view="full",
            languages=languages or ["python"],
        )
    ).run()


def _hits(result, rule_id: str, filename: str | None = None):
    return [
        finding
        for finding in result.findings
        if rule_id in finding.reported_rule_ids()
        and (filename is None or Path(finding.file_path).name == filename)
    ]


def test_upload_file_response_is_not_a_file_response_sink(tmp_path):
    (tmp_path / "files.py").write_text(
        "class UploadFileResponse:\n"
        "    def __init__(self, **kwargs): pass\n"
        "def metadata(user_file):\n"
        "    return UploadFileResponse(path=user_file.path)\n",
        encoding="utf-8",
    )
    (tmp_path / "download.py").write_text(
        "from fastapi.responses import FileResponse\n"
        "def download(user_file):\n"
        "    return FileResponse(user_file.path)\n",
        encoding="utf-8",
    )

    result = _scan(tmp_path)

    assert not _hits(result, "NS-PATH-003", "files.py")
    assert _hits(result, "NS-PATH-003", "download.py")


def test_upload_file_response_does_not_seed_cross_file_callers(tmp_path):
    (tmp_path / "files.py").write_text(
        "class UploadFileResponse:\n"
        "    def __init__(self, **kwargs): pass\n"
        "def metadata(user_file):\n"
        "    return UploadFileResponse(path=user_file.path)\n",
        encoding="utf-8",
    )
    (tmp_path / "routes.py").write_text(
        "from flask import request\n"
        "from files import metadata\n"
        "def route():\n"
        "    return metadata(request.args.get('file'))\n",
        encoding="utf-8",
    )

    result = _scan(tmp_path, cross_file=True)

    assert not _hits(result, "NS-PATH-003")
    assert not _hits(result, "CF-SINK-001")


def test_local_file_read_is_not_a_network_pickle_source(tmp_path):
    (tmp_path / "local_cache.py").write_text(
        "import pickle\n"
        "def load(path):\n"
        "    with open(path, 'rb') as reader:\n"
        "        return pickle.loads(reader.read())\n",
        encoding="utf-8",
    )
    (tmp_path / "network.py").write_text(
        "import pickle\n"
        "def load(sock):\n"
        "    payload = sock.recv(4096)\n"
        "    return pickle.loads(payload)\n",
        encoding="utf-8",
    )
    (tmp_path / "archive.py").write_text(
        "import pickle\n"
        "def load(zf, member):\n"
        "    with zf.open(member) as reader:\n"
        "        return pickle.loads(reader.read())\n",
        encoding="utf-8",
    )
    (tmp_path / "async_network.py").write_text(
        "import asyncio\n"
        "import pickle\n"
        "async def load(host, port):\n"
        "    reader, writer = await asyncio.open_connection(host, port)\n"
        "    payload = await reader.read(4096)\n"
        "    return pickle.loads(payload)\n",
        encoding="utf-8",
    )
    (tmp_path / "zmq_network.py").write_text(
        "import pickle\n"
        "def load(sock):\n"
        "    payload = sock.recv_multipart()\n"
        "    return pickle.loads(payload)\n",
        encoding="utf-8",
    )

    result = _scan(tmp_path)

    assert not _hits(result, "TNT-DESER-004", "local_cache.py")
    assert not _hits(result, "TNT-DESER-004", "archive.py")
    assert _hits(result, "TNT-DESER-004", "network.py")
    assert _hits(result, "TNT-DESER-004", "async_network.py")
    assert _hits(result, "TNT-DESER-004", "zmq_network.py")


def test_operator_environment_pickle_is_not_high_but_request_pickle_is(tmp_path):
    (tmp_path / "env_cache.py").write_text(
        "import ast\n"
        "import pickle\n"
        "from os import getenv\n"
        "def load():\n"
        "    raw = ast.literal_eval(getenv('CACHE_BYTES'))\n"
        "    return pickle.loads(raw)\n",
        encoding="utf-8",
    )
    (tmp_path / "request_payload.py").write_text(
        "import pickle\n"
        "from flask import request\n"
        "def load():\n"
        "    return pickle.loads(request.data)\n",
        encoding="utf-8",
    )

    result = _scan(tmp_path)
    env_hits = _hits(result, "TNT-DESER-001", "env_cache.py")
    request_hits = _hits(result, "TNT-DESER-001", "request_payload.py")

    assert env_hits
    assert all(hit.severity not in {Severity.CRITICAL, Severity.HIGH} for hit in env_hits)
    assert request_hits
    assert any(hit.severity in {Severity.CRITICAL, Severity.HIGH} for hit in request_hits)


def test_jwt_weak_key_rule_requires_weak_or_hardcoded_signing_key(tmp_path):
    (tmp_path / "configured.py").write_text(
        "import jwt\n"
        "def sign(payload, settings):\n"
        "    key = settings.SECRET_KEY.get_secret_value()\n"
        "    return jwt.encode(payload, key, algorithm='HS256')\n",
        encoding="utf-8",
    )
    (tmp_path / "literal.py").write_text(
        "import jwt\n"
        "def sign(payload):\n"
        "    return jwt.encode(payload, 'changeme', algorithm='HS256')\n",
        encoding="utf-8",
    )
    (tmp_path / "constant.py").write_text(
        "import jwt\n"
        "JWT_SECRET = 'test-secret'\n"
        "def sign(payload):\n"
        "    return jwt.encode(payload, JWT_SECRET, algorithm='HS256')\n",
        encoding="utf-8",
    )

    result = _scan(tmp_path)

    assert not _hits(result, "ns-bb-001", "configured.py")
    assert _hits(result, "ns-bb-001", "literal.py")
    assert _hits(result, "ns-bb-001", "constant.py")


def test_jwt_weak_key_residual_requires_literal_evidence_in_non_python_source(tmp_path):
    configured_path = tmp_path / "configured.js"
    literal_path = tmp_path / "literal.js"
    configured_path.write_text(
        "return jwt.sign(payload, settings.secret);\n", encoding="utf-8"
    )
    literal_path.write_text("return jwt.sign(payload, 'changeme');\n", encoding="utf-8")

    def finding(path: Path) -> Finding:
        return Finding(
            rule_id="ns-bb-001",
            message="JWT signed with a weak or hardcoded secret",
            severity=Severity.HIGH,
            category=Category.CRYPTO,
            file_path=str(path),
            start_line=1,
        )

    configured_finding = finding(configured_path)
    literal_finding = finding(literal_path)
    filtered = EnrichmentPass._suppress_contextual_false_positives(
        [configured_finding, literal_finding]
    )

    assert configured_finding not in filtered
    assert literal_finding in filtered

    constant = [
        "const JWT_SECRET = 'test-secret';",
        "return jwt.sign(payload, JWT_SECRET);",
    ]
    assert EnrichmentPass._jwt_text_call_has_hardcoded_key(constant, 2)


def test_cookie_header_taint_focuses_value_and_accepts_re_encoding(tmp_path):
    (tmp_path / "direct.py").write_text(
        "from flask import request\n"
        "def direct(response):\n"
        "    response.set_cookie('x', request.cookies.get('x'))\n",
        encoding="utf-8",
    )
    (tmp_path / "name.py").write_text(
        "from flask import request\n"
        "def tainted_name(response):\n"
        "    response.set_cookie(request.args.get('name'), 'constant')\n",
        encoding="utf-8",
    )
    (tmp_path / "encoded.py").write_text(
        "import jwt\n"
        "from flask import request\n"
        "def reencoded(response, secret):\n"
        "    original = request.cookies.get('refresh')\n"
        "    token = jwt.encode({'sub': original}, secret, algorithm='HS256')\n"
        "    response.set_cookie('access', token)\n",
        encoding="utf-8",
    )
    (tmp_path / "raw.py").write_text(
        "from flask import request\n"
        "def raw_header(response):\n"
        "    original = request.cookies.get('refresh')\n"
        "    response.headers['X-Token'] = 'Bearer ' + original\n",
        encoding="utf-8",
    )

    result = _scan(tmp_path)

    assert _hits(result, "TNT-HEADER-001", "direct.py")
    assert not _hits(result, "TNT-HEADER-001", "name.py")
    assert not _hits(result, "TNT-HEADER-001", "encoded.py")
    assert _hits(result, "TNT-HEADER-001", "raw.py")


def test_opaque_cookie_reissue_is_unverified_without_hiding_direct_reflection(tmp_path):
    (tmp_path / "login.py").write_text(
        "from fastapi import Request, Response\n"
        "from auth_plugin import get_auth_service\n"
        "async def refresh_token(request: Request, response: Response, db):\n"
        "    token = request.cookies.get('refresh_token_lf')\n"
        "    if token:\n"
        "        auth = get_auth_service()\n"
        "        tokens = await auth.create_refresh_token(token, db)\n"
        "        response.set_cookie(\n"
        "            'refresh_token_lf',\n"
        "            tokens['refresh_token'],\n"
        "            httponly=True,\n"
        "        )\n"
        "        return tokens\n",
        encoding="utf-8",
    )
    (tmp_path / "raw.py").write_text(
        "from fastapi import Request, Response\n"
        "def reflect(request: Request, response: Response):\n"
        "    token = request.cookies.get('refresh_token_lf')\n"
        "    response.set_cookie('refresh_token_lf', token)\n",
        encoding="utf-8",
    )

    result = _scan(tmp_path)
    hits = _hits(result, "TNT-HEADER-001", "login.py")

    assert any(
        hit.start_line == 10
        and hit.severity == Severity.MEDIUM
        and hit.metadata.get("evidence_tier") == "taint-flow-unresolved"
        and "may reach" in hit.message
        for hit in hits
    ), [
        (hit.start_line, hit.severity, hit.message) for hit in hits
    ]
    assert any(hit.severity == Severity.HIGH for hit in _hits(result, "TNT-HEADER-001", "raw.py"))


def test_tool_argument_presence_is_discovery_not_high_severity(tmp_path):
    (tmp_path / "voice.py").write_text(
        "def handle(tool):\n"
        "    arguments = tool.function.arguments\n"
        "    return parse(arguments)\n",
        encoding="utf-8",
    )

    hits = _hits(_scan(tmp_path), "ns-aiml-054", "voice.py")

    assert hits
    assert all(hit.severity in {Severity.INFO, Severity.LOW} for hit in hits)


def test_path_chain_requires_a_matching_tainted_write_and_read(tmp_path):
    (tmp_path / "debugger.py").write_text(
        "def repl():\n"
        "    command = input('command: ')\n"
        "    return eval(command)\n",
        encoding="utf-8",
    )
    (tmp_path / "helper.py").write_text("VALUE = 1\n", encoding="utf-8")

    hits = _hits(_scan(tmp_path, cross_file=True), "TNT-PATH-003")

    assert hits == []


def test_path_chain_matches_same_file_channel_across_handlers(tmp_path):
    (tmp_path / "service.py").write_text(
        "from pathlib import Path\n"
        "import pickle\n"
        "from flask import request\n"
        "def upload():\n"
        "    name = request.args.get('name')\n"
        "    path = Path('/tmp/uploads') / name\n"
        "    payload = request.data\n"
        "    path.write_bytes(payload)\n"
        "def load():\n"
        "    name = request.args.get('name')\n"
        "    path = Path('/tmp/uploads') / name\n"
        "    payload = path.read_bytes()\n"
        "    return pickle.loads(payload)\n",
        encoding="utf-8",
    )

    hits = _hits(_scan(tmp_path, cross_file=True), "TNT-PATH-003", "service.py")

    assert len(hits) == 1
    assert hits[0].severity == Severity.HIGH
    assert hits[0].metadata["persistent_channel"] == "file"


def test_path_chain_matches_file_fed_command_execution(tmp_path):
    (tmp_path / "jobs.py").write_text(
        "from pathlib import Path\n"
        "import subprocess\n"
        "from flask import request\n"
        "def save_job():\n"
        "    path = Path('/tmp/jobs') / request.args.get('name')\n"
        "    path.write_text(request.data.decode())\n"
        "def run_job():\n"
        "    path = Path('/tmp/jobs') / request.args.get('name')\n"
        "    subprocess.run(path.read_text(), shell=True)\n",
        encoding="utf-8",
    )

    hits = _hits(_scan(tmp_path, cross_file=True), "TNT-PATH-003", "jobs.py")

    assert len(hits) == 1
    assert hits[0].severity == Severity.HIGH


def test_path_chain_rejects_wrong_channel_and_operator_cli(tmp_path):
    (tmp_path / "web_writer.py").write_text(
        "from pathlib import Path\n"
        "from flask import request\n"
        "def upload():\n"
        "    path = Path('/tmp/uploads') / request.args.get('write_name')\n"
        "    path.write_bytes(request.data)\n",
        encoding="utf-8",
    )
    (tmp_path / "web_reader.py").write_text(
        "from pathlib import Path\n"
        "import pickle\n"
        "from flask import request\n"
        "def load():\n"
        "    path = Path('/tmp/uploads') / request.args.get('read_name')\n"
        "    return pickle.loads(path.read_bytes())\n",
        encoding="utf-8",
    )
    (tmp_path / "cli.py").write_text(
        "from pathlib import Path\n"
        "import pickle, sys\n"
        "def save():\n"
        "    Path(sys.argv[1]).write_bytes(input().encode())\n"
        "def load():\n"
        "    return pickle.loads(Path(sys.argv[1]).read_bytes())\n",
        encoding="utf-8",
    )

    assert _hits(_scan(tmp_path, cross_file=True), "TNT-PATH-003") == []


def test_path_chain_uses_bindings_that_precede_each_operation(tmp_path):
    (tmp_path / "writer.py").write_text(
        "from pathlib import Path\n"
        "from flask import request\n"
        "def upload():\n"
        "    path = Path('/tmp/uploads') / request.args.get('name')\n"
        "    path.write_bytes(request.data)\n"
        "    path = Path('/tmp/constant')\n",
        encoding="utf-8",
    )
    (tmp_path / "reader.py").write_text(
        "from pathlib import Path\n"
        "import pickle\n"
        "from flask import request\n"
        "def load():\n"
        "    path = Path('/tmp/uploads') / request.args.get('name')\n"
        "    payload = path.read_bytes()\n"
        "    path = Path('/tmp/other')\n"
        "    return pickle.loads(payload)\n",
        encoding="utf-8",
    )

    assert len(_hits(_scan(tmp_path, cross_file=True), "TNT-PATH-003")) == 1
