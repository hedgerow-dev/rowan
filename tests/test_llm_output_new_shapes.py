"""BACKLOG PY-01: the `llm_output` fragment knows the 2025-era agent SDKs.

Each shape below is verified live against `rules/llm_output_taint.yaml`
(TNT-LLMOUT-001, the SQL sink): a fixture using the SDK's return shape must
fire, and a control where the same attribute or key comes from a non-LLM
object must stay quiet. Only the *call* is a source in the fragment; the
attribute read (`.final_output`, `.output`, `.content`, `.answer`), the dict
lookup and the `async for` loop variable are covered by Opengrep's own taint
propagation, which is what these tests pin.

Requires the Opengrep binary (skipped entirely if not installed, matching
the project's convention -- CI does not install it, see .github/workflows/ci.yml).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from rowan.taint.opengrep_adapter import OpengrepAdapter

RULES_DIR = Path(__file__).parent.parent / "rules"
RULE_FILE = "llm_output_taint.yaml"
SQL = "TNT-LLMOUT-001"
HTML = "TNT-LLMOUT-006"

_adapter = OpengrepAdapter()
pytestmark = pytest.mark.skipif(
    not _adapter.is_installed(),
    reason="Opengrep binary not installed; these tests need a live scan.",
)


def _scan(tmp_path, filename, source, rule_id):
    fp = tmp_path / filename
    fp.write_text(source, encoding="utf-8")
    adapter = OpengrepAdapter()
    findings = adapter.scan_with_rules(tmp_path, [RULES_DIR / RULE_FILE], languages=["python"])
    return [f for f in findings if f.rule_id == rule_id]


def _lines(findings) -> set[int]:
    return {f.start_line for f in findings}


class TestOpenAIAgentsSDK:
    def test_runner_result_final_output_flagged(self, tmp_path):
        src = (
            "from agents import Agent, Runner\n\n"
            "async def ask(agent, q):\n"
            "    result = await Runner.run(agent, q)\n"
            "    cursor.execute(result.final_output)\n"
            "def ask_sync(agent, q):\n"
            "    res = Runner.run_sync(agent, q)\n"
            "    cursor.execute(res.final_output)\n"
            "def ask_streamed(agent, q):\n"
            "    cursor.execute(Runner.run_streamed(agent, q).final_output)\n"
        )
        assert _lines(_scan(tmp_path, "oa.py", src, SQL)) == {5, 8, 10}

    def test_local_dataclass_final_output_is_not_a_source(self, tmp_path):
        src = (
            "from dataclasses import dataclass\n\n"
            "@dataclass\n"
            "class Local:\n"
            "    final_output: str\n\n"
            "def build():\n"
            "    result = Local(final_output='select 1')\n"
            "    cursor.execute(result.final_output)\n"
        )
        assert _scan(tmp_path, "local.py", src, SQL) == []

    def test_foreign_runner_class_is_not_a_source(self, tmp_path):
        """`agents.Runner.run` relies on import resolution: a `Runner` from
        somewhere else, or with no import at all, must not bind."""
        src = (
            "from mytasks import Runner\n\n"
            "def go(job):\n"
            "    result = Runner.run(job)\n"
            "    cursor.execute(result.final_output)\n"
            "def go2(job):\n"
            "    cursor.execute(OtherRunner.run_sync(job).final_output)\n"
        )
        assert _scan(tmp_path, "tasks.py", src, SQL) == []


class TestPydanticAI:
    def test_agent_run_output_and_data_flagged(self, tmp_path):
        src = (
            "from pydantic_ai import Agent\n\n"
            "async def ask(agent, q):\n"
            "    result = await agent.run(q)\n"
            "    cursor.execute(result.output)\n"
            "    cursor.execute(result.data)\n"
            "def ask_sync(agent, q):\n"
            "    r = agent.run_sync(q)\n"
            "    cursor.execute(r.output)\n"
            "async def ask_stream(agent, q):\n"
            "    async with agent.run_stream(q) as r:\n"
            "        cursor.execute(await r.get_output())\n"
        )
        assert _lines(_scan(tmp_path, "pai.py", src, SQL)) == {5, 6, 9, 12}

    def test_subprocess_result_and_unnamed_receiver_are_not_sources(self, tmp_path):
        src = (
            "import subprocess\n\n"
            "def go(worker, q):\n"
            "    result = subprocess.run(['ls'], capture_output=True)\n"
            "    cursor.execute(result.stdout)\n"
            "    cursor.execute(result.output)\n"
            "    job = worker.run_sync(q)\n"
            "    cursor.execute(job.output)\n"
        )
        assert _scan(tmp_path, "proc.py", src, SQL) == []


class TestGoogleADK:
    def test_run_async_event_parts_text_flagged(self, tmp_path):
        src = (
            "from google.adk.runners import Runner\n\n"
            "async def ask(runner, msg):\n"
            "    async for event in runner.run_async(user_id='u', session_id='s', new_message=msg):\n"
            "        cursor.execute(event.content.parts[0].text)\n"
            "        for part in event.content.parts:\n"
            "            cursor.execute(part.text)\n"
            "def ask_sync(runner, msg):\n"
            "    for event in runner.run(user_id='u', session_id='s', new_message=msg):\n"
            "        cursor.execute(event.content.parts[0].text)\n"
        )
        assert _lines(_scan(tmp_path, "adk.py", src, SQL)) == {5, 7, 10}

    def test_parts_text_from_a_plain_list_is_not_a_source(self, tmp_path):
        src = (
            "def render(rows, doc):\n"
            "    for event in rows:\n"
            "        cursor.execute(event.content.parts[0].text)\n"
            "    for part in doc.parts:\n"
            "        cursor.execute(part.text)\n"
        )
        assert _scan(tmp_path, "rows.py", src, SQL) == []


class TestHaystack:
    def test_pipeline_run_replies_flagged(self, tmp_path):
        src = (
            "from haystack import Pipeline\n\n"
            "def ask(pipeline, pipe, q):\n"
            "    res = pipeline.run({'prompt_builder': {'question': q}})\n"
            "    cursor.execute(res['llm']['replies'][0])\n"
            "    out = pipe.run({'q': q})\n"
            "    cursor.execute(out['generator']['replies'][0])\n"
            "def render(result):\n"
            "    cursor.execute(result['llm']['replies'][0])\n"
        )
        assert _lines(_scan(tmp_path, "hs.py", src, SQL)) == {5, 7, 9}

    def test_other_run_result_and_bare_replies_key_are_not_sources(self, tmp_path):
        src = (
            "def go(migrator, thread):\n"
            "    res = migrator.run({'q': 1})\n"
            "    cursor.execute(res['rows'][0])\n"
            "    cursor.execute(thread['replies'][0])\n"
        )
        assert _scan(tmp_path, "mig.py", src, SQL) == []


class TestSemanticKernel:
    def test_get_response_and_invoke_prompt_flagged(self, tmp_path):
        src = (
            "from semantic_kernel import Kernel\n\n"
            "async def ask(kernel, agent, fn, q):\n"
            "    resp = await agent.get_response(messages=q)\n"
            "    cursor.execute(resp.content)\n"
            "    r2 = await kernel.invoke_prompt(q)\n"
            "    cursor.execute(str(r2))\n"
            "    r3 = await kernel.invoke(fn, q)\n"
            "    cursor.execute(str(r3))\n"
        )
        assert _lines(_scan(tmp_path, "sk.py", src, SQL)) == {5, 7, 9}

    def test_invoke_on_an_unnamed_receiver_is_not_a_source(self, tmp_path):
        src = (
            "def go(worker, q):\n"
            "    r = worker.invoke(q)\n"
            "    cursor.execute(str(r))\n"
            "    resp = worker.get_response(q)\n"
            "    cursor.execute(resp.content)\n"
        )
        assert _scan(tmp_path, "worker.py", src, SQL) == []


class TestDSPy:
    def test_predict_and_chain_of_thought_answer_flagged(self, tmp_path):
        src = (
            "import dspy\n\n"
            "def ask(q):\n"
            "    out = dspy.Predict('question -> answer')(question=q)\n"
            "    cursor.execute(out.answer)\n"
            "    cot = dspy.ChainOfThought(Sig)\n"
            "    cursor.execute(cot(question=q).answer)\n"
            "    predictor = dspy.Predict(Sig)\n"
            "    cursor.execute(predictor(question=q).answer)\n"
            "class Mod:\n"
            "    def forward(self, q):\n"
            "        cursor.execute(self.predict(question=q).answer)\n"
        )
        assert _lines(_scan(tmp_path, "dspy_app.py", src, SQL)) == {5, 7, 9, 12}

    def test_estimator_predict_via_predictor_gate_is_not_a_source(self, tmp_path):
        """The `$PREDICTOR(...)` gate is anchored to the whole callable name;
        `clf.predict(x)` must not bind through it (the receiver gate on
        `$LLM.predict` is a separate, pre-existing judgement call)."""
        src = (
            "def go(clf, x, answer):\n"
            "    y = clf.predict(x)\n"
            "    cursor.execute(y)\n"
            "    cursor.execute(answer.answer)\n"
        )
        assert _scan(tmp_path, "sk_est.py", src, SQL) == []


class TestClaudeAgentSDK:
    def test_query_result_message_flagged(self, tmp_path):
        src = (
            "from claude_agent_sdk import query, ResultMessage\n\n"
            "async def ask(q):\n"
            "    async for message in query(prompt=q):\n"
            "        if isinstance(message, ResultMessage):\n"
            "            cursor.execute(message.result)\n"
        )
        assert _lines(_scan(tmp_path, "cl.py", src, SQL)) == {6}

    def test_database_query_result_is_not_a_source(self, tmp_path):
        src = (
            "from db import query\n\n"
            "async def go(q):\n"
            "    async for message in query(q):\n"
            "        cursor.execute(message.result)\n"
            "def go2(q):\n"
            "    for message in query(q):\n"
            "        cursor.execute(message.result)\n"
        )
        assert _scan(tmp_path, "dbq.py", src, SQL) == []


class TestLiteLLMAndInstructor:
    def test_acompletion_flagged(self, tmp_path):
        src = (
            "import litellm\n\n"
            "async def ask(q):\n"
            "    r = await litellm.acompletion(model='m', messages=q)\n"
            "    cursor.execute(r.choices[0].message.content)\n"
        )
        assert _lines(_scan(tmp_path, "ll.py", src, SQL)) == {5}

    def test_instructor_response_model_is_a_source_and_not_a_sanitizer(self, tmp_path):
        """Nothing was added for Instructor: the patched client keeps the
        `$CLIENT.chat.completions.create(...)` shape, which is already a
        source. `response_model=` is not a sanitizer (#74): a schema-valid
        `name: str` field is still model-chosen text."""
        src = (
            "import instructor\n"
            "from openai import OpenAI\n\n"
            "client = instructor.from_openai(OpenAI())\n"
            "def ask(q):\n"
            "    user = client.chat.completions.create(model='m', messages=q, response_model=User)\n"
            "    cursor.execute(user.name)\n"
            "    st.markdown(user.name, unsafe_allow_html=True)\n"
        )
        assert _lines(_scan(tmp_path, "ins.py", src, SQL)) == {7}
        assert _lines(_scan(tmp_path, "ins.py", src, HTML)) == {8}
