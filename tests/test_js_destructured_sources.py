"""JS taint rules see request fields destructured in a handler's parameters.

Handlers written `({ query }: Request, res) => ...` (Juice Shop's redirect
route) never mention `req.query`, so the explicit sources missed them. The
shared `web_request_js_destructured` fragment adds the destructured name when
the parameter is typed as a request or a second parameter is named like a
response. Requires the Opengrep binary.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from rowan.taint.opengrep_adapter import OpengrepAdapter

RULES = Path(__file__).parent.parent / "rules" / "javascript_taint.yaml"

pytestmark = pytest.mark.skipif(
    not OpengrepAdapter().is_installed(),
    reason="Opengrep binary not installed; these tests need a live scan.",
)


def _hits(tmp_path, source, rule_id, filename="app.ts", language="typescript"):
    (tmp_path / filename).write_text(source, encoding="utf-8")
    findings = OpengrepAdapter().scan_with_rules(tmp_path, [RULES], languages=[language])
    return [f for f in findings if f.rule_id == rule_id]


def test_typed_destructured_query_reaches_redirect(tmp_path):
    # Juice Shop routes/redirect.ts
    src = (
        "import { type Request, type Response } from 'express'\n"
        "export function performRedirect () {\n"
        "  return ({ query }: Request, res: Response) => {\n"
        "    const toUrl: string = query.to as string\n"
        "    res.redirect(toUrl)\n"
        "  }\n"
        "}\n"
    )
    assert _hits(tmp_path, src, "tnt-js-redirect-001")


def test_untyped_destructured_body_reaches_sql(tmp_path):
    src = (
        "app.post('/search', ({ body }, res) => {\n"
        "  db.query('SELECT * FROM items WHERE name = \\'' + body.name + '\\'')\n"
        "  res.end()\n"
        "})\n"
    )
    assert _hits(tmp_path, src, "tnt-js-sqli-001", filename="app.js", language="javascript")


def test_named_function_with_typed_params(tmp_path):
    src = (
        "import { Request, Response } from 'express'\n"
        "export function go ({ params }: Request, res: Response) { res.redirect(params.u) }\n"
    )
    assert _hits(tmp_path, src, "tnt-js-redirect-001")


def test_destructured_param_that_is_not_a_request_is_ignored(tmp_path):
    src = (
        "type Message = { body: string }\n"
        "export function render ({ body }: Message, res: Response) { res.redirect(body) }\n"
        "export const fmt = ({ query }) => res.redirect(query)\n"
    )
    assert not _hits(tmp_path, src, "tnt-js-redirect-001")


def test_constant_redirect_stays_quiet(tmp_path):
    src = "export const h = ({ query }: Request, res: Response) => { res.redirect('/home') }\n"
    assert not _hits(tmp_path, src, "tnt-js-redirect-001")
