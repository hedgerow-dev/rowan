"""Guardrail enforcement rules ns-aiml-156/131/132 (issue #186, epic #183).

These cover the inverse of the usual taint question: a guardrail *was* called,
but is its verdict acted on? That is a control-flow property, which is why it
cannot live in `TNT-AIML-004`'s sanitizer list -- see DEF-43 in BACKLOG.md and
`tests/test_taint_sanitizer_soundness.py::TestGuardrailIdentifierSanitizerFix`
for the dataflow half of this issue.

Requires the Opengrep binary (skipped entirely if not installed, matching the
project's convention for tests that need a live scan).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from rowan.taint.opengrep_adapter import OpengrepAdapter

RULES_DIR = Path(__file__).parent.parent / "rules"
RULE_FILE = "guardrail_opengrep.yaml"

_adapter = OpengrepAdapter()
pytestmark = pytest.mark.skipif(
    not _adapter.is_installed(),
    reason="Opengrep binary not installed; these tests need a live scan.",
)


def _scan(tmp_path: Path, source: str, rule_id: str | None = None) -> list:
    (tmp_path / "target.py").write_text(source, encoding="utf-8")
    adapter = OpengrepAdapter()
    findings = adapter.scan_with_rules(
        tmp_path, [RULES_DIR / RULE_FILE], languages=["python"]
    )
    if rule_id is None:
        return findings
    return [f for f in findings if f.rule_id == rule_id]


_PREAMBLE = (
    "import logging\n"
    "import openai\n"
    "client = openai.OpenAI()\n"
    "agent = object()\n"
    "metrics = object()\n"
    "\n"
)


class TestNsAiml130ResultDiscarded:
    """A guardrail invoked as a bare expression statement."""

    def test_discarded_result_flagged(self, tmp_path):
        src = _PREAMBLE + (
            "def handler(q):\n"
            "    client.moderations.create(input=q)\n"
            "    agent.run(q)\n"
        )
        assert _scan(tmp_path, src, "ns-aiml-156"), (
            "a moderation verdict that is never bound must be flagged"
        )

    def test_result_consumed_inline_not_flagged(self, tmp_path):
        src = _PREAMBLE + (
            "def handler(q):\n"
            "    if client.moderations.create(input=q).results[0].flagged:\n"
            "        raise ValueError('blocked')\n"
            "    agent.run(q)\n"
        )
        assert not _scan(tmp_path, src, "ns-aiml-156")

    def test_result_returned_not_flagged(self, tmp_path):
        src = _PREAMBLE + (
            "def handler(q):\n"
            "    return client.moderations.create(input=q)\n"
        )
        assert not _scan(tmp_path, src, "ns-aiml-156")

    def test_result_bound_not_flagged(self, tmp_path):
        src = _PREAMBLE + (
            "def handler(q):\n"
            "    result = client.moderations.create(input=q)\n"
            "    if result.results[0].flagged:\n"
            "        raise ValueError('blocked')\n"
            "    agent.run(q)\n"
        )
        assert not _scan(tmp_path, src, "ns-aiml-156")

    def test_unrelated_discarded_call_not_flagged(self, tmp_path):
        """The vocabulary regex must not turn every discarded call into a
        finding."""
        src = _PREAMBLE + (
            "def handler(q):\n"
            "    compute_total(q)\n"
            "    agent.run(q)\n"
            "\n"
            "def compute_total(x):\n"
            "    return x\n"
        )
        assert not _scan(tmp_path, src, "ns-aiml-156")


class TestNsAiml131FailOpen:
    """A guardrail whose exception handler falls through to the model call."""

    def test_except_pass_flagged(self, tmp_path):
        src = _PREAMBLE + (
            "def handler(q):\n"
            "    try:\n"
            "        client.moderations.create(input=q)\n"
            "    except Exception:\n"
            "        pass\n"
            "    agent.run(q)\n"
        )
        assert _scan(tmp_path, src, "ns-aiml-157"), (
            "`except Exception: pass` around a guardrail is fail-open"
        )

    def test_bare_except_pass_flagged(self, tmp_path):
        src = _PREAMBLE + (
            "def handler(q):\n"
            "    try:\n"
            "        client.moderations.create(input=q)\n"
            "    except:\n"
            "        pass\n"
            "    agent.run(q)\n"
        )
        assert _scan(tmp_path, src, "ns-aiml-157")

    def test_log_only_handler_flagged(self, tmp_path):
        src = _PREAMBLE + (
            "def handler(q):\n"
            "    try:\n"
            "        client.moderations.create(input=q)\n"
            "    except Exception as exc:\n"
            "        logging.warning('guard failed: %s', exc)\n"
            "    agent.run(q)\n"
        )
        assert _scan(tmp_path, src, "ns-aiml-157"), (
            "logging an error and continuing is still fail-open"
        )

    def test_bare_reraise_not_flagged(self, tmp_path):
        """A bare `raise` has no argument, so it is a distinct pattern from
        `raise ...` and needs its own exclusion."""
        src = _PREAMBLE + (
            "def handler(q):\n"
            "    try:\n"
            "        client.moderations.create(input=q)\n"
            "    except Exception:\n"
            "        raise\n"
            "    agent.run(q)\n"
        )
        assert not _scan(tmp_path, src, "ns-aiml-157")

    def test_raise_with_argument_not_flagged(self, tmp_path):
        src = _PREAMBLE + (
            "def handler(q):\n"
            "    try:\n"
            "        client.moderations.create(input=q)\n"
            "    except Exception:\n"
            "        raise RuntimeError('safety check unavailable')\n"
            "    agent.run(q)\n"
        )
        assert not _scan(tmp_path, src, "ns-aiml-157")

    def test_return_handler_not_flagged(self, tmp_path):
        src = _PREAMBLE + (
            "def handler(q):\n"
            "    try:\n"
            "        client.moderations.create(input=q)\n"
            "    except Exception:\n"
            "        return 'blocked'\n"
            "    agent.run(q)\n"
        )
        assert not _scan(tmp_path, src, "ns-aiml-157")

    def test_unrelated_try_except_pass_not_flagged(self, tmp_path):
        """No guardrail call in the try body: `except: pass` on its own is not
        this rule's concern."""
        src = (
            "import json\n"
            "\n"
            "def handler(s):\n"
            "    try:\n"
            "        return json.loads(s)\n"
            "    except Exception:\n"
            "        pass\n"
            "    return None\n"
        )
        assert not _scan(tmp_path, src, "ns-aiml-157")


class TestNsAiml132VerdictNotEnforced:
    """A guardrail verdict that is checked but never acted on."""

    def test_log_only_branch_flagged(self, tmp_path):
        src = _PREAMBLE + (
            "def handler(q):\n"
            "    result = client.moderations.create(input=q)\n"
            "    if result.results[0].flagged:\n"
            "        logging.warning('flagged')\n"
            "    agent.run(q)\n"
        )
        assert _scan(tmp_path, src, "ns-aiml-158"), (
            "logging a flagged verdict and continuing is not enforcement"
        )

    def test_metric_only_branch_flagged(self, tmp_path):
        src = _PREAMBLE + (
            "def handler(q):\n"
            "    verdict = client.moderations.create(input=q)\n"
            "    if verdict.results[0].flagged:\n"
            "        metrics.increment('flagged')\n"
            "    agent.run(q)\n"
        )
        assert _scan(tmp_path, src, "ns-aiml-158")

    def test_guardrails_ai_validate_flagged(self, tmp_path):
        """Framework coverage: Guardrails AI's `guard.validate(...)`."""
        src = (
            "from guardrails import Guard\n"
            "agent = object()\n"
            "guard = Guard()\n"
            "\n"
            "def handler(q):\n"
            "    outcome = guard.validate(q)\n"
            "    if not outcome.validation_passed:\n"
            "        print('bad')\n"
            "    agent.run(q)\n"
        )
        assert _scan(tmp_path, src, "ns-aiml-158")

    def test_raise_branch_not_flagged(self, tmp_path):
        src = _PREAMBLE + (
            "def handler(q):\n"
            "    result = client.moderations.create(input=q)\n"
            "    if result.results[0].flagged:\n"
            "        raise ValueError('blocked')\n"
            "    agent.run(q)\n"
        )
        assert not _scan(tmp_path, src, "ns-aiml-158")

    def test_return_branch_not_flagged(self, tmp_path):
        src = _PREAMBLE + (
            "def handler(q):\n"
            "    result = client.moderations.create(input=q)\n"
            "    if result.results[0].flagged:\n"
            "        return 'blocked'\n"
            "    agent.run(q)\n"
        )
        assert not _scan(tmp_path, src, "ns-aiml-158")

    def test_abort_branch_not_flagged(self, tmp_path):
        src = _PREAMBLE + (
            "from flask import abort\n"
            "\n"
            "def handler(q):\n"
            "    result = client.moderations.create(input=q)\n"
            "    if result.results[0].flagged:\n"
            "        abort(400)\n"
            "    agent.run(q)\n"
        )
        assert not _scan(tmp_path, src, "ns-aiml-158")

    def test_never_checked_is_not_this_rule(self, tmp_path):
        """A bound-but-unchecked verdict is not ns-aiml-158's finding (there is
        no conditional to evaluate)."""
        src = _PREAMBLE + (
            "def handler(q):\n"
            "    result = client.moderations.create(input=q)\n"
            "    agent.run(q)\n"
        )
        assert not _scan(tmp_path, src, "ns-aiml-158")


class TestNoDoubleReporting:
    """DEF-10's lesson: overlapping rules must not each report the same line."""

    def test_fail_open_reports_only_131(self, tmp_path):
        """The guard call inside a fail-open try/except is also 'discarded',
        so ns-aiml-156 must stand down in favour of the more specific finding."""
        src = _PREAMBLE + (
            "def handler(q):\n"
            "    try:\n"
            "        client.moderations.create(input=q)\n"
            "    except Exception:\n"
            "        pass\n"
            "    agent.run(q)\n"
        )
        ids = sorted({f.rule_id for f in _scan(tmp_path, src)})
        assert ids == ["ns-aiml-157"], f"expected only ns-aiml-157, got {ids}"

    def test_correctly_guarded_code_is_silent(self, tmp_path):
        """The shape we are telling people to write must produce nothing from
        any of the three rules."""
        src = _PREAMBLE + (
            "def handler(q):\n"
            "    try:\n"
            "        result = client.moderations.create(input=q)\n"
            "    except Exception:\n"
            "        raise RuntimeError('safety check unavailable')\n"
            "    if result.results[0].flagged:\n"
            "        raise ValueError('blocked')\n"
            "    agent.run(q)\n"
        )
        findings = _scan(tmp_path, src)
        assert not findings, f"correctly guarded code must be silent, got {findings}"


class TestKnownResidualGaps:
    """Documented limitations, asserted so they stay visible and so a future
    fix shows up as a failing test rather than a silent behaviour change."""

    def test_bound_but_never_read_is_not_detected(self, tmp_path):
        """ns-aiml-156 detects a result that is never BOUND. Opengrep has no
        liveness analysis, so a bound-and-ignored result is a known gap."""
        src = _PREAMBLE + (
            "def handler(q):\n"
            "    result = client.moderations.create(input=q)\n"
            "    agent.run(q)\n"
        )
        assert not _scan(tmp_path, src), (
            "if this now reports, the liveness gap has been closed -- update "
            "ns-aiml-156's message and move this case to a positive test"
        )

    def test_tuple_unpacking_verdict_is_not_detected(self, tmp_path):
        """ns-aiml-158 matches single-target assignments only. LLM Guard's
        documented API returns a tuple."""
        src = (
            "from llm_guard import scan_prompt\n"
            "agent = object()\n"
            "\n"
            "def handler(q):\n"
            "    sanitized, results, score = scan_prompt(q)\n"
            "    if not all(results.values()):\n"
            "        print('bad')\n"
            "    agent.run(q)\n"
        )
        assert not _scan(tmp_path, src, "ns-aiml-158"), (
            "if this now reports, the tuple-unpacking gap has been closed -- "
            "update ns-aiml-158's message and move this to a positive test"
        )


class TestReviewProbes53:
    """Shapes from the #53 review: result-consuming forms, fail-closed
    handlers and if/else gating are not findings; the async forms are."""

    @pytest.mark.parametrize(
        "body",
        [
            "async def h(text):\n    result = await moderate(text)\n    return result\n",
            "def h(text):\n    return llm(moderate(text))\n",
            "def h(texts):\n    ok = all(check_safety(t) for t in texts)\n    return ok\n",
            "def h(text):\n    assert moderate(text)\n",
            "@guardrails.guard(name='x')\ndef h(text):\n    return text\n",
            "def setup(x):\n    guardrails.register_action(x)\n",
        ],
    )
    def test_156_result_consumed_or_not_a_check(self, tmp_path, body):
        assert _scan(tmp_path, _PREAMBLE + body, "ns-aiml-156") == []

    def test_156_awaited_bare_call_flagged(self, tmp_path):
        src = _PREAMBLE + "async def h(text):\n    await moderate(text)\n    return llm(text)\n"
        assert _scan(tmp_path, src, "ns-aiml-156")

    @pytest.mark.parametrize(
        "handler",
        [
            "    except Exception:\n        flagged = True\n",
            "    except Exception:\n        continue\n",
        ],
    )
    def test_157_fail_closed_handler_not_flagged(self, tmp_path, handler):
        src = _PREAMBLE + (
            "def h(texts):\n"
            "    for text in texts:\n"
            "        try:\n"
            "            flagged = moderate(text)\n"
            "        " + handler.replace("\n    ", "\n        ").lstrip() +
            "        if flagged:\n"
            "            continue\n"
            "        llm(text)\n"
        )
        assert _scan(tmp_path, src, "ns-aiml-157") == []

    def test_158_if_else_gating_not_flagged(self, tmp_path):
        src = _PREAMBLE + (
            "def h(text):\n"
            "    verdict = guard(text)\n"
            "    if verdict.ok:\n"
            "        answer = llm(text)\n"
            "    else:\n"
            "        answer = 'refused'\n"
            "    return answer\n"
        )
        assert _scan(tmp_path, src, "ns-aiml-158") == []

    def test_158_async_log_only_branch_flagged(self, tmp_path):
        src = _PREAMBLE + (
            "async def h(text):\n"
            "    r = await moderate(text)\n"
            "    if r.flagged:\n"
            "        logging.warning('flagged')\n"
            "    return llm(text)\n"
        )
        assert _scan(tmp_path, src, "ns-aiml-158")
