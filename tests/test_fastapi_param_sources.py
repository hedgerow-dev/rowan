"""FastAPI route parameters are taint sources.

FastAPI passes request data to a handler as typed parameters (`name: str`,
`q: str = Query()`, a Pydantic body), so the handler never reads a request
object. Those parameters must reach the Python taint rules as user input.
Numeric parameters (validated by FastAPI), `Depends()` results and
undecorated functions are not sources. Requires the Opengrep binary.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from rowan.taint.opengrep_adapter import OpengrepAdapter

RULES_DIR = Path(__file__).parent.parent / "rules"
TAINT_RULES = sorted(p for p in RULES_DIR.glob("*_taint*.yaml"))

pytestmark = pytest.mark.skipif(
    not OpengrepAdapter().is_installed(),
    reason="Opengrep binary not installed; these tests need a live scan.",
)

HEADER = """\
import csv, io, os, subprocess, sqlite3, pickle, requests
from fastapi import FastAPI, APIRouter, Query, Path, Body, Header, Cookie, Form, UploadFile, Depends
from fastapi.responses import RedirectResponse, HTMLResponse, FileResponse
from pydantic import BaseModel
app = FastAPI()
router = APIRouter()
db = sqlite3.connect("x.db")
class Item(BaseModel):
    url: str
"""


def _taint_findings(tmp_path, body):
    (tmp_path / "app.py").write_text(HEADER + body, encoding="utf-8")
    findings = OpengrepAdapter().scan_with_rules(tmp_path, TAINT_RULES, languages=["python"])
    return [f for f in findings if f.rule_id.startswith("TNT-")]


def _taint_lines(tmp_path, body):
    """Taint rule ids reported on the body's last line (the sink)."""
    sink_line = len(HEADER.splitlines()) + body.strip("\n").count("\n") + 1
    return {f.rule_id for f in _taint_findings(tmp_path, body) if f.start_line == sink_line}


VULNERABLE = {
    "plain_str_to_shell": '@app.get("/a")\ndef a(host: str):\n    subprocess.run("ping " + host, shell=True)\n',
    "query_to_sql": '@app.get("/a")\ndef a(q: str = Query(...)):\n    db.execute(f"SELECT * FROM t WHERE n = \'{q}\'")\n',
    "path_param_to_open": '@app.get("/a/{name}")\ndef a(name: str = Path(...)):\n    open(os.path.join("/data", name))\n',
    "pydantic_body_to_ssrf": '@app.post("/a")\ndef a(item: Item):\n    requests.get(item.url)\n',
    "header_to_shell": '@app.get("/a")\ndef a(x_cmd: str = Header(None)):\n    os.system(x_cmd)\n',
    "form_to_pickle": '@app.post("/a")\ndef a(data: str = Form(...)):\n    pickle.loads(data.encode())\n',
    "cookie_to_sql": '@app.get("/a")\ndef a(session: str = Cookie(None)):\n    db.execute("SELECT * FROM s WHERE id = " + session)\n',
    "upload_to_pickle": '@app.post("/a")\nasync def a(f: UploadFile):\n    data = await f.read()\n    pickle.loads(data)\n',
    "optional_str_async": '@app.get("/a")\nasync def a(cmd: str | None = None):\n    os.system(cmd)\n',
    "router_route": '@router.get("/a")\ndef a(cmd: str):\n    subprocess.call(cmd, shell=True)\n',
    # A prefixed APIRouter often mounts its root route at "".
    "router_empty_path": '@router.post("", status_code=201)\ndef a(cmd: str):\n    os.system(cmd)\n',
    "open_redirect": '@app.get("/a")\ndef a(next: str):\n    return RedirectResponse(next)\n',
    "reflected_xss": '@app.get("/a")\ndef a(name: str):\n    return HTMLResponse(f"<h1>{name}</h1>")\n',
    "file_response": '@app.get("/a")\ndef a(path: str):\n    return FileResponse(path)\n',
}


@pytest.mark.parametrize("case", sorted(VULNERABLE))
def test_route_parameter_reaches_sink(tmp_path, case):
    assert _taint_lines(tmp_path, VULNERABLE[case])


SAFE = {
    "int_param": '@app.get("/a")\ndef a(n: int):\n    db.execute(f"SELECT * FROM t LIMIT {n}")\n',
    "depends_value": (
        "def get_cmd():\n    return 'ls'\n"
        '@app.get("/a")\ndef a(cmd: str = Depends(get_cmd)):\n    os.system(cmd)\n'
    ),
    "undecorated": "def a(cmd: str):\n    os.system(cmd)\n",
    # The ORM binds `email` as a parameter. Passing user data to db.add()
    # taints the handle; that alone must not make db.query() a SQL sink.
    "orm_filter_after_add": (
        '@app.post("/a")\nasync def a(file: UploadFile, db: Session = Depends(get_db)):\n'
        "    for row in csv.DictReader(io.StringIO((await file.read()).decode())):\n"
        "        email = row.get('email')\n"
        "        if not db.query(User).filter(User.email == email).first():\n"
        "            db.add(User(email=email))\n"
        "    db.commit()\n"
    ),
    "non_route_decorator": "@lru_cache(maxsize=1)\ndef a(cmd: str):\n    os.system(cmd)\n",
    # `patch` is also a route method; a mock target is not a route path.
    "mock_patch_decorator": '@mock.patch("pkg.run")\ndef a(cmd: str):\n    os.system(cmd)\n',
}


@pytest.mark.parametrize("case", sorted(SAFE))
def test_non_input_parameter_is_not_a_source(tmp_path, case):
    assert not _taint_findings(tmp_path, SAFE[case])


def test_fastapi_source_only_in_python_only_rules():
    """The source is Python syntax; in a rule that also runs on JavaScript
    it fails to parse and silently disables the whole rule."""
    import yaml

    for path in sorted(RULES_DIR.glob("*.yaml")):
        for rule in (yaml.safe_load(path.read_text(encoding="utf-8")) or {}).get("rules", []):
            if '$M("$ROUTE"' in str(rule.get("pattern-sources")):
                assert rule["languages"] == ["python"], f"{path.name}: {rule['id']}"
