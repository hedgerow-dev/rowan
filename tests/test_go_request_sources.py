"""Go request sources the review found missing (#56).

`c.ShouldBindJSON(&req)` returns an error; the request lands in `req`, so the
source is the bound variable, by side effect. Requires the Opengrep binary.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from rowan.rules_registry import render_pattern_either_block
from rowan.taint.opengrep_adapter import OpengrepAdapter

RULES = Path(__file__).parent.parent / "rules" / "go_taint.yaml"


def test_bind_fragment_renders_as_a_top_level_source_item():
    block = render_pattern_either_block("source", "web_request_go_bind", 6)
    assert block.startswith("      - patterns:\n")
    assert "\n        by-side-effect: true" in block


needs_opengrep = pytest.mark.skipif(
    not OpengrepAdapter().is_installed(),
    reason="Opengrep binary not installed; these tests need a live scan.",
)

SQL = '\tdb.Query("SELECT * FROM t WHERE n = \'" + v + "\'")\n'


def _sqli(tmp_path, body):
    src = (
        "package main\n\nfunc h(w http.ResponseWriter, r *http.Request, c *gin.Context, e echo.Context, f *fiber.Ctx, db *sql.DB) {\n"
        + body + SQL + "}\n"
    )
    (tmp_path / "main.go").write_text(src, encoding="utf-8")
    findings = OpengrepAdapter().scan_with_rules(tmp_path, [RULES], languages=["go"])
    return [x for x in findings if x.rule_id == "tnt-go-sqli-001"]


@needs_opengrep
@pytest.mark.parametrize(
    "body",
    [
        "\tvar req Req\n\tc.ShouldBindJSON(&req)\n\tv := req.Name\n",
        "\tvar req Req\n\tjson.NewDecoder(r.Body).Decode(&req)\n\tv := req.Name\n",
        "\tvar req Req\n\tf.BodyParser(&req)\n\tv := req.Name\n",
        '\tv := chi.URLParam(r, "id")\n',
        '\tv := mux.Vars(r)["id"]\n',
        "\tv := r.URL.Path\n",
        '\tv := r.PostFormValue("id")\n',
        '\tv := r.Header.Get("X-User")\n',
        '\tv := e.QueryParam("id")\n',
        '\tv := c.PostForm("id")\n',
        '\tv := c.DefaultQuery("id", "1")\n',
        '\tv := f.Params("id")\n',
    ],
)
def test_request_input_reaches_sql(tmp_path, body):
    assert _sqli(tmp_path, body), body


@needs_opengrep
def test_decoding_a_config_file_is_not_request_input(tmp_path):
    body = '\tfh, _ := os.Open("config.json")\n\tvar cfg Cfg\n\tjson.NewDecoder(fh).Decode(&cfg)\n\tv := cfg.Table\n'
    assert _sqli(tmp_path, body) == []
