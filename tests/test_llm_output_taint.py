"""Positive/negative fixtures for the TNT-LLMOUT-* rule family
(rules/llm_output_taint.yaml, issue #133: insecure LLM output handling).

Requires the Opengrep binary (skipped entirely if not installed, matching
the project's convention -- CI does not install it, see .github/workflows/ci.yml).

Each rule gets:
  - a positive fixture (non-streaming completion source -> sink), which
    must fire;
  - a streaming-accumulation positive fixture (`full += chunk.choices[0]
    .delta.content` into a variable that then reaches the sink), which
    must also fire -- issue #133's FP-considerations explicitly calls out
    that streaming accumulation must propagate taint or the family misses
    most modern code;
  - a negative fixture where the completion is validated through a
    Pydantic structured-output model before reaching the sink (except for
    TNT-LLMOUT-006, where the issue explicitly says a structured-output
    validator must NOT suppress the HTML sink).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from rowan.taint.opengrep_adapter import OpengrepAdapter

RULES_DIR = Path(__file__).parent.parent / "rules"
RULE_FILE = "llm_output_taint.yaml"

_adapter = OpengrepAdapter()
pytestmark = pytest.mark.skipif(
    not _adapter.is_installed(),
    reason="Opengrep binary not installed; these tests need a live scan.",
)


def _scan(tmp_path, filename, source, rule_id):
    fp = tmp_path / filename
    fp.write_text(source, encoding="utf-8")
    adapter = OpengrepAdapter()
    findings = adapter.scan_with_rules(
        tmp_path, [RULES_DIR / RULE_FILE], languages=["python"]
    )
    return [f for f in findings if f.rule_id == rule_id]


class TestLLMOutputSQL:
    """TNT-LLMOUT-001."""

    def test_completion_content_into_cursor_execute_flagged(self, tmp_path):
        src = (
            "import openai\n\n"
            "def run(prompt):\n"
            "    resp = openai_client.chat.completions.create(model='gpt-4o', messages=prompt)\n"
            "    sql = resp.choices[0].message.content\n"
            "    cursor.execute(sql)\n"
        )
        findings = _scan(tmp_path, "sql_agent.py", src, "TNT-LLMOUT-001")
        assert findings, "LLM completion text into cursor.execute() must be flagged"

    def test_streaming_accumulation_into_cursor_execute_flagged(self, tmp_path):
        src = (
            "def run(prompt):\n"
            "    full = ''\n"
            "    for chunk in llm_client.chat.completions.create(model='gpt-4o', messages=prompt, stream=True):\n"
            "        full += chunk.choices[0].delta.content\n"
            "    cursor.execute(full)\n"
        )
        findings = _scan(tmp_path, "sql_stream_agent.py", src, "TNT-LLMOUT-001")
        assert findings, (
            "streaming delta accumulated into a variable that reaches "
            "cursor.execute() must be flagged"
        )

    def test_pydantic_validated_sql_is_still_flagged(self, tmp_path):
        src = (
            "from pydantic import BaseModel\n\n"
            "class SafeQuery(BaseModel):\n"
            "    sql: str\n\n"
            "def run(prompt):\n"
            "    resp = openai_client.chat.completions.create(model='gpt-4o', messages=prompt)\n"
            "    raw = resp.choices[0].message.content\n"
            "    validated = SafeQuery.model_validate_json(raw)\n"
            "    cursor.execute(validated)\n"
        )
        findings = _scan(tmp_path, "sql_agent_validated.py", src, "TNT-LLMOUT-001")
        # #74: schema validation constrains shape, not value; a schema-valid
        # string field is still model-chosen. Bound parameters do not make
        # a model-written statement safe.
        assert findings

    def test_model_written_sql_with_bound_params_is_flagged(self, tmp_path):
        src = (
            "def run(prompt):\n"
            "    resp = openai_client.chat.completions.create(model='gpt-4o', messages=prompt)\n"
            "    sql = resp.choices[0].message.content\n"
            "    cursor.execute(sql, params)\n"
        )
        findings = _scan(tmp_path, "sql_agent_param.py", src, "TNT-LLMOUT-001")
        # #74: schema validation constrains shape, not value; a schema-valid
        # string field is still model-chosen. Bound parameters do not make
        # a model-written statement safe.
        assert findings

    def test_asyncio_run_not_flagged_as_sql_sink(self, tmp_path):
        """Regression guard: found scanning scan-targets/autogen -- a bare
        `$DB.run($SQL)` sink pattern with no receiver constraint matched
        ANY object with a one-arg `.run()` method, including
        `asyncio.run(...)`, on code with no SQL anywhere nearby. Fixed by
        requiring $DB/$CONN/$SESSION to look like a db/conn/session/sql/
        cursor/engine-shaped receiver, matching the existing $LLM/$CHAIN/
        $MODEL/$PIPE convention in this same file."""
        src = (
            "import asyncio\n\n"
            "def main():\n"
            "    resp = st.session_state['agent'].chat(prompt)\n"
            "    asyncio.run(resp)\n"
        )
        findings = _scan(tmp_path, "not_a_db_call.py", src, "TNT-LLMOUT-001")
        assert not findings, (
            f"asyncio.run() must not be treated as a SQL execute sink, got: {findings}"
        )


class TestLLMOutputShell:
    """TNT-LLMOUT-002."""

    def test_completion_content_into_shell_flagged(self, tmp_path):
        src = (
            "import subprocess\n\n"
            "def run(task):\n"
            "    cmd = llm.invoke(f'suggest a shell command to {task}').content\n"
            "    subprocess.run(cmd, shell=True)\n"
        )
        findings = _scan(tmp_path, "shell_agent.py", src, "TNT-LLMOUT-002")
        assert findings, "LLM completion text into subprocess.run(shell=True) must be flagged"

    def test_streaming_accumulation_into_shell_flagged(self, tmp_path):
        src = (
            "import subprocess\n\n"
            "def run(task):\n"
            "    full = ''\n"
            "    for chunk in llm_client.chat.completions.create(model='gpt-4o', messages=task, stream=True):\n"
            "        full += chunk.choices[0].delta.content\n"
            "    subprocess.run(full, shell=True)\n"
        )
        findings = _scan(tmp_path, "shell_stream_agent.py", src, "TNT-LLMOUT-002")
        assert findings, "streaming delta accumulated into a shell sink must be flagged"

    def test_pydantic_validated_command_is_still_flagged(self, tmp_path):
        src = (
            "from pydantic import BaseModel\n"
            "import subprocess\n\n"
            "class SafeCommand(BaseModel):\n"
            "    cmd: str\n\n"
            "def run(task):\n"
            "    raw = llm.invoke(f'suggest a shell command to {task}').content\n"
            "    validated = SafeCommand.model_validate_json(raw)\n"
            "    subprocess.run(validated, shell=True)\n"
        )
        findings = _scan(tmp_path, "shell_agent_validated.py", src, "TNT-LLMOUT-002")
        # #74: schema validation constrains shape, not value; a schema-valid
        # string field is still model-chosen. Bound parameters do not make
        # a model-written statement safe.
        assert findings

    def test_list_arg_subprocess_not_flagged(self, tmp_path):
        src = (
            "import subprocess\n\n"
            "def run(task):\n"
            "    cmd = llm.invoke(f'suggest a shell command to {task}').content\n"
            "    subprocess.run([cmd, '--safe'])\n"
        )
        findings = _scan(tmp_path, "shell_agent_list.py", src, "TNT-LLMOUT-002")
        assert not findings, "list-argument subprocess.run() (no shell=True) must not be flagged"


class TestLLMOutputEvalFamily:
    """TNT-LLMOUT-003."""

    def test_completion_content_into_pd_eval_flagged(self, tmp_path):
        src = (
            "import pandas as pd\n\n"
            "def run(query, df):\n"
            "    expr = llm.invoke(query).content\n"
            "    pd.eval(expr)\n"
        )
        findings = _scan(tmp_path, "pandas_agent.py", src, "TNT-LLMOUT-003")
        assert findings, "LLM completion text into pd.eval() must be flagged"

    def test_completion_content_into_df_query_python_engine_flagged(self, tmp_path):
        src = (
            "def run(query, df):\n"
            "    expr = llm.invoke(query).content\n"
            "    df.query(expr, engine='python')\n"
        )
        findings = _scan(tmp_path, "pandas_query_agent.py", src, "TNT-LLMOUT-003")
        assert findings, "LLM completion text into df.query(engine='python') must be flagged"

    def test_streaming_accumulation_into_eval_flagged(self, tmp_path):
        src = (
            "def run(query):\n"
            "    full = ''\n"
            "    for chunk in llm_client.chat.completions.create(model='gpt-4o', messages=query, stream=True):\n"
            "        full += chunk.choices[0].delta.content\n"
            "    eval(full)\n"
        )
        findings = _scan(tmp_path, "eval_stream_agent.py", src, "TNT-LLMOUT-003")
        assert findings, "streaming delta accumulated into eval() must be flagged"

    def test_pydantic_validated_expr_is_still_flagged(self, tmp_path):
        src = (
            "from pydantic import BaseModel\n\n"
            "class SafeExpr(BaseModel):\n"
            "    expr: str\n\n"
            "def run(query, df):\n"
            "    raw = llm.invoke(query).content\n"
            "    validated = SafeExpr.model_validate_json(raw)\n"
            "    df.query(validated, engine='python')\n"
        )
        findings = _scan(tmp_path, "pandas_agent_validated.py", src, "TNT-LLMOUT-003")
        # #74: schema validation constrains shape, not value; a schema-valid
        # string field is still model-chosen. Bound parameters do not make
        # a model-written statement safe.
        assert findings

    def test_default_engine_df_query_not_flagged(self, tmp_path):
        """DataFrame.query()'s default engine (numexpr) evaluates a
        restricted expression grammar, not arbitrary Python -- consistent
        with TNT-ML-011's existing, evidence-based precision decision."""
        src = (
            "def run(query, df):\n"
            "    expr = llm.invoke(query).content\n"
            "    df.query(expr)\n"
        )
        findings = _scan(tmp_path, "pandas_query_default_engine.py", src, "TNT-LLMOUT-003")
        assert not findings, "df.query() without engine='python' must not be flagged"


class TestLLMOutputSSRF:
    """TNT-LLMOUT-004."""

    def test_completion_content_into_requests_get_flagged(self, tmp_path):
        src = (
            "import requests\n\n"
            "def run(prompt):\n"
            "    url = llm.invoke(prompt).content\n"
            "    requests.get(url)\n"
        )
        findings = _scan(tmp_path, "ssrf_agent.py", src, "TNT-LLMOUT-004")
        assert findings, "LLM completion text into requests.get() must be flagged"

    def test_streaming_accumulation_into_httpx_flagged(self, tmp_path):
        src = (
            "import httpx\n\n"
            "def run(prompt):\n"
            "    full = ''\n"
            "    for chunk in llm_client.chat.completions.create(model='gpt-4o', messages=prompt, stream=True):\n"
            "        full += chunk.choices[0].delta.content\n"
            "    httpx.get(full)\n"
        )
        findings = _scan(tmp_path, "ssrf_stream_agent.py", src, "TNT-LLMOUT-004")
        assert findings, "streaming delta accumulated into httpx.get() must be flagged"

    def test_allowlisted_url_not_flagged(self, tmp_path):
        """A bare guard-clause check (`if not is_allowed_url(url): raise`)
        does NOT suppress taint in this engine version (documented
        limitation, see agent_taint.yaml's TNT-ML-012 engine note); the
        sanitizer must reassign/wrap the value, e.g. `url =
        validate_url(url)`."""
        src = (
            "import requests\n\n"
            "def run(prompt):\n"
            "    url = llm.invoke(prompt).content\n"
            "    url = validate_url(url)\n"
            "    requests.get(url)\n"
        )
        findings = _scan(tmp_path, "ssrf_agent_allowlisted.py", src, "TNT-LLMOUT-004")
        assert not findings, "validate_url()-reassigned URL must not be flagged"


class TestLLMOutputFilesystemPath:
    """TNT-LLMOUT-005."""

    def test_completion_content_as_write_path_flagged(self, tmp_path):
        src = (
            "def run(prompt):\n"
            "    path = llm.invoke(prompt).content\n"
            "    with open(path, 'w') as f:\n"
            "        f.write('data')\n"
        )
        findings = _scan(tmp_path, "path_agent.py", src, "TNT-LLMOUT-005")
        assert findings, "LLM completion text used as a write path must be flagged"

    def test_streaming_accumulation_as_write_path_flagged(self, tmp_path):
        src = (
            "def run(prompt):\n"
            "    full = ''\n"
            "    for chunk in llm_client.chat.completions.create(model='gpt-4o', messages=prompt, stream=True):\n"
            "        full += chunk.choices[0].delta.content\n"
            "    with open(full, 'w') as f:\n"
            "        f.write('data')\n"
        )
        findings = _scan(tmp_path, "path_stream_agent.py", src, "TNT-LLMOUT-005")
        assert findings, "streaming delta accumulated into a write-path sink must be flagged"

    def test_basename_sanitized_path_not_flagged(self, tmp_path):
        src = (
            "import os\n\n"
            "def run(prompt):\n"
            "    raw = llm.invoke(prompt).content\n"
            "    path = os.path.basename(raw)\n"
            "    with open(path, 'w') as f:\n"
            "        f.write('data')\n"
        )
        findings = _scan(tmp_path, "path_agent_sanitized.py", src, "TNT-LLMOUT-005")
        assert not findings, "os.path.basename()-sanitized path must not be flagged"


class TestLLMOutputHTML:
    """TNT-LLMOUT-006."""

    def test_completion_content_into_markdown_render_flagged(self, tmp_path):
        src = (
            "import markdown\n\n"
            "def run(prompt):\n"
            "    text = llm.invoke(prompt).content\n"
            "    html = markdown.markdown(text)\n"
        )
        findings = _scan(tmp_path, "markdown_agent.py", src, "TNT-LLMOUT-006")
        assert findings, "LLM completion text into markdown.markdown() must be flagged"

    def test_completion_content_into_streamlit_unsafe_html_flagged(self, tmp_path):
        src = (
            "import streamlit as st\n\n"
            "def run(prompt):\n"
            "    text = llm.invoke(prompt).content\n"
            "    st.markdown(text, unsafe_allow_html=True)\n"
        )
        findings = _scan(tmp_path, "streamlit_agent.py", src, "TNT-LLMOUT-006")
        assert findings, "LLM completion text into st.markdown(unsafe_allow_html=True) must be flagged"

    def test_streaming_accumulation_into_markdown_render_flagged(self, tmp_path):
        src = (
            "import markdown\n\n"
            "def run(prompt):\n"
            "    full = ''\n"
            "    for chunk in llm_client.chat.completions.create(model='gpt-4o', messages=prompt, stream=True):\n"
            "        full += chunk.choices[0].delta.content\n"
            "    html = markdown.markdown(full)\n"
        )
        findings = _scan(tmp_path, "markdown_stream_agent.py", src, "TNT-LLMOUT-006")
        assert findings, "streaming delta accumulated into a markdown-render sink must be flagged"

    def test_pydantic_validated_text_still_flagged(self, tmp_path):
        """Per issue #133: a structured-output validator must NOT suppress
        the HTML sink -- a schema-valid string is still unescaped HTML."""
        src = (
            "from pydantic import BaseModel\n"
            "import markdown\n\n"
            "class SafeText(BaseModel):\n"
            "    text: str\n\n"
            "def run(prompt):\n"
            "    raw = llm.invoke(prompt).content\n"
            "    validated = SafeText.model_validate_json(raw)\n"
            "    html = markdown.markdown(validated.text)\n"
        )
        findings = _scan(tmp_path, "markdown_agent_validated.py", src, "TNT-LLMOUT-006")
        assert findings, (
            "Pydantic-validated completion text must still be flagged at the "
            "HTML sink -- structured-output validation is not HTML escaping"
        )

    def test_bleach_cleaned_text_not_flagged(self, tmp_path):
        src = (
            "import bleach\n"
            "import markdown\n\n"
            "def run(prompt):\n"
            "    raw = llm.invoke(prompt).content\n"
            "    clean = bleach.clean(raw)\n"
            "    html = markdown.markdown(clean)\n"
        )
        findings = _scan(tmp_path, "markdown_agent_bleached.py", src, "TNT-LLMOUT-006")
        assert not findings, "bleach.clean()-sanitized text must not be flagged"
