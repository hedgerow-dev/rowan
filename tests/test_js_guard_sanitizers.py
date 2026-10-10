"""Guards that clear taint in the JavaScript path traversal rule.

OWASP Juice Shop serves files with `if (!file.includes('/')) { res.sendFile(
path.resolve('dir/', file)) }`. A name with no slash cannot leave the
directory, so the guarded branch should not be flagged. The same code
without the guard must still be flagged. Requires the Opengrep binary.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from rowan.taint.opengrep_adapter import OpengrepAdapter

RULES_DIR = Path(__file__).parent.parent / "rules"
RULE = "tnt-js-path-001"

pytestmark = pytest.mark.skipif(
    not OpengrepAdapter().is_installed(),
    reason="Opengrep binary not installed; these tests need a live scan.",
)


def _scan(tmp_path, body, filename="app.js", language="javascript", rule_id=RULE):
    src = f"const path = require('path');\nconst fs = require('fs');\n{body}\n"
    (tmp_path / filename).write_text(src, encoding="utf-8")
    findings = OpengrepAdapter().scan_with_rules(
        tmp_path, [RULES_DIR / "javascript_taint.yaml"], languages=[language]
    )
    return [f for f in findings if f.rule_id == rule_id]


def test_no_slash_guard_clears_send_file(tmp_path):
    body = """
app.get('/keys/:file', (req, res, next) => {
  const file = req.params.file
  if (!file.includes('/')) {
    res.sendFile(path.resolve('encryptionkeys/', file))
  } else {
    res.status(403)
  }
})
"""
    assert not _scan(tmp_path, body)


def test_no_slash_guard_clears_destructured_typescript(tmp_path):
    body = """
import { type Request, type Response } from 'express'
export function serve () {
  return ({ params }: Request, res: Response) => {
    const file = params.file
    if (!file.includes('/')) {
      res.sendFile(path.resolve('logs/', file))
    } else {
      res.status(403)
    }
  }
}
"""
    assert not _scan(tmp_path, body, filename="app.ts", language="typescript")


def test_no_slash_guard_clears_path_join_sink(tmp_path):
    body = """
app.get('/f', (req, res) => {
  const file = req.query.file
  if (!file.includes('/')) {
    fs.readFileSync(path.join('/data', file))
  }
})
"""
    assert not _scan(tmp_path, body)


def test_else_branch_of_no_slash_guard_is_flagged(tmp_path):
    body = """
app.get('/f', (req, res) => {
  const file = req.query.file
  if (!file.includes('/')) {
    res.status(200)
  } else {
    res.sendFile(path.resolve('dir/', file))
  }
})
"""
    assert _scan(tmp_path, body)


def test_guard_on_other_variable_does_not_clear(tmp_path):
    body = """
app.get('/f', (req, res) => {
  const file = req.query.file
  const name = req.query.name
  if (!name.includes('/')) {
    res.sendFile(path.resolve('dir/', file))
  }
})
"""
    assert _scan(tmp_path, body)


def test_basename_clears_send_file(tmp_path):
    body = """
app.get('/f', (req, res) => {
  res.sendFile(path.resolve('dir/', path.basename(req.query.file)))
})
"""
    assert not _scan(tmp_path, body)


def test_unguarded_send_file_is_flagged(tmp_path):
    body = """
app.get('/f', (req, res) => {
  const file = req.params.file
  res.sendFile(path.resolve('encryptionkeys/', file))
})
"""
    assert _scan(tmp_path, body)


def test_unguarded_path_join_is_flagged(tmp_path):
    body = """
app.get('/f', (req, res) => {
  const file = req.query.file
  fs.readFileSync(path.join('/data', file))
})
"""
    assert _scan(tmp_path, body)


# The same guard written as an early exit: reject a name with a slash, then
# use it. Only code after the exit is cleared.
@pytest.mark.parametrize(
    "guard",
    [
        "if (file.includes('/')) {\n    return res.status(403).end()\n  }",
        "if (file.includes('/')) return res.status(403).end()",
        "if (file.includes('/')) {\n    res.status(403)\n    return\n  }",
        "if (file.includes('/')) throw new Error('bad name')",
    ],
)
def test_early_exit_slash_guard_clears(tmp_path, guard):
    body = f"""
app.get('/f', (req, res) => {{
  const file = req.query.file
  {guard}
  res.sendFile(path.resolve('dir/', file))
}})
"""
    assert not _scan(tmp_path, body)


def test_slash_check_without_exit_is_flagged(tmp_path):
    body = """
app.get('/f', (req, res) => {
  const file = req.query.file
  if (file.includes('/')) {
    console.log('slash in name')
  }
  res.sendFile(path.resolve('dir/', file))
})
"""
    assert _scan(tmp_path, body)


def test_early_exit_on_other_variable_does_not_clear(tmp_path):
    body = """
app.get('/f', (req, res) => {
  const file = req.query.file
  const name = req.query.name
  if (name.includes('/')) return res.status(403).end()
  res.sendFile(path.resolve('dir/', file))
})
"""
    assert _scan(tmp_path, body)


def test_sink_before_early_exit_is_flagged(tmp_path):
    body = """
app.get('/f', (req, res) => {
  const file = req.query.file
  fs.readFileSync(path.join('/data', file))
  if (file.includes('/')) return res.status(403).end()
})
"""
    assert _scan(tmp_path, body)


# Sequelize takes an options object (`where`, `include`) and binds values as
# SQL parameters; string operators from a query string are off by default.
# That shape is not a MongoDB filter, so the NoSQL rule should skip it.
NOSQL = "tnt-js-nosql-001"


def test_sequelize_where_is_not_nosql(tmp_path):
    body = """
app.get('/u', async (req, res) => {
  const user = await UserModel.findOne({ where: { email: req.query.email } })
  res.json(user)
})
"""
    assert not _scan(tmp_path, body, rule_id=NOSQL)


def test_sequelize_include_is_not_nosql(tmp_path):
    body = """
app.get('/u', async (req, res) => {
  const a = await AnswerModel.findOne({ include: [{ model: UserModel, where: { email: req.query.email } }] })
  res.json(a)
})
"""
    assert not _scan(tmp_path, body, rule_id=NOSQL)


def test_mongo_filter_is_nosql(tmp_path):
    body = """
app.post('/login', async (req, res) => {
  const user = await db.collection('users').findOne({ email: req.body.email })
  res.json(user)
})
"""
    assert _scan(tmp_path, body, rule_id=NOSQL)


def test_mongo_dollar_where_is_nosql(tmp_path):
    body = """
app.get('/r', async (req, res) => {
  const r = await reviews.find({ $where: 'this.product == ' + req.query.id })
  res.json(r)
})
"""
    assert _scan(tmp_path, body, rule_id=NOSQL)
