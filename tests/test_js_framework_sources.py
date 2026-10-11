"""Request sources for Next.js, NestJS, Hono and non-destructured Express/Koa.

Before this, those frameworks produced no finding from any JavaScript web
taint rule: their request values never matched `req.query` / `req.body`
(detection review, #54). Requires the Opengrep binary.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from rowan.taint.opengrep_adapter import OpengrepAdapter

RULES = [Path(__file__).parent.parent / "rules" / "javascript_taint.yaml"]

pytestmark = pytest.mark.skipif(
    not OpengrepAdapter().is_installed(),
    reason="Opengrep binary not installed; these tests need a live scan.",
)


def _cmdi_lines(tmp_path, name, src):
    (tmp_path / name).write_text(src, encoding="utf-8")
    lang = "typescript" if name.endswith(".ts") else "javascript"
    findings = OpengrepAdapter().scan_with_rules(tmp_path, RULES, languages=[lang])
    return {f.start_line for f in findings if f.rule_id == "tnt-js-cmdi-001"}


CASES = {
    "next_route_search_params": (
        "route.ts",
        "import { exec } from 'child_process'\n"
        "import { NextRequest } from 'next/server'\n"
        "export async function GET(req: NextRequest) {\n"
        "  const d = req.nextUrl.searchParams.get('d')\n"
        "  exec('ls ' + d)\n"
        "}\n",
        5,
    ),
    "next_route_json_body": (
        "route.ts",
        "import { exec } from 'child_process'\n"
        "export async function POST(request: Request) {\n"
        "  const body = await request.json()\n"
        "  exec('ls ' + body.dir)\n"
        "}\n",
        4,
    ),
    "server_action_form_data": (
        "actions.ts",
        "'use server'\n"
        "import { exec } from 'child_process'\n"
        "export async function run(formData: FormData) {\n"
        "  exec('ls ' + formData.get('dir'))\n"
        "}\n",
        4,
    ),
    "hono_query": (
        "app.ts",
        "import { exec } from 'child_process'\n"
        "app.get('/x', (c) => {\n"
        "  exec('ls ' + c.req.query('d'))\n"
        "})\n",
        3,
    ),
    "nest_query_decorator": (
        "ctrl.ts",
        "import { exec } from 'child_process'\n"
        "class Ctrl {\n"
        "  run(@Query('d') d: string) {\n"
        "    exec('ls ' + d)\n"
        "  }\n"
        "}\n",
        4,
    ),
    "express_req_get_header": (
        "app.js",
        "const { exec } = require('child_process')\n"
        "app.get('/x', function (req, res) {\n"
        "  exec('ls ' + req.get('X-Dir'))\n"
        "})\n",
        3,
    ),
}


@pytest.mark.parametrize("case", sorted(CASES))
def test_framework_request_value_is_a_source(tmp_path, case):
    name, src, line = CASES[case]
    assert line in _cmdi_lines(tmp_path, name, src), case


def test_fetch_response_json_outside_a_route_handler_is_not_a_source(tmp_path):
    src = (
        "import { exec } from 'child_process'\n"
        "export async function sync() {\n"
        "  const r = await fetch('https://api.example.com/x')\n"
        "  const data = await r.json()\n"
        "  exec('ls ' + data.dir)\n"
        "}\n"
    )
    assert not _cmdi_lines(tmp_path, "sync.ts", src)


def test_hono_request_accessor_is_not_a_sql_sink(tmp_path):
    # `c.req.query('name')` reads the request; it matched the SQL sink
    # `$DB.query($SQL, ...)` once Hono request values became sources.
    src = (
        "app.use(async (c, next) => {\n"
        "  const name = c.req.query('name')\n"
        "  await next()\n"
        "})\n"
    )
    (tmp_path / "app.ts").write_text(src, encoding="utf-8")
    findings = OpengrepAdapter().scan_with_rules(tmp_path, RULES, languages=["typescript"])
    assert not [f for f in findings if f.rule_id == "tnt-js-sqli-001"]
