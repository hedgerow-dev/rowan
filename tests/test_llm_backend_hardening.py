"""LLMBackend.generate hardening (BACKLOG CN-02: HN-08, HN-09, HN-11, HN-15, HN-19).
No network: httpx.post is patched throughout."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import httpx

from rowan.agents.llm_backend import LLMBackend


def _ok(text: str = "hi") -> MagicMock:
    resp = MagicMock(status_code=200, headers={})
    resp.json.return_value = {"choices": [{"message": {"content": text}}], "usage": {}}
    resp.raise_for_status.return_value = None
    return resp


def _status(code: int, retry_after: str | None = None) -> MagicMock:
    resp = MagicMock(status_code=code, headers={"Retry-After": retry_after} if retry_after else {})
    resp.raise_for_status.side_effect = httpx.HTTPStatusError(
        f"{code}", request=MagicMock(), response=resp
    )
    return resp


class TestRetry:
    @patch("threading.Event.wait", return_value=False)
    @patch("rowan.agents.llm_backend.httpx.post")
    def test_retry_after_is_capped(self, post, wait):
        post.side_effect = [_status(429, "999999"), _ok("done")]
        backend = LLMBackend(backend="openai", api_key="k")
        assert backend.generate("p").text == "done"
        wait.assert_called_once_with(30.0)

    @patch("threading.Event.wait", return_value=True)
    @patch("rowan.agents.llm_backend.httpx.post")
    def test_cancel_during_backoff_stops_retry(self, post, wait):
        post.side_effect = [_status(503), _ok("never")]
        backend = LLMBackend(backend="openai", api_key="k")
        assert backend.generate("p").text.startswith("LLM error")
        assert backend.stop_reason == "cancelled"
        assert post.call_count == 1

    @patch("rowan.agents.llm_backend.httpx.post")
    def test_insufficient_quota_does_not_retry_or_send_later_calls(self, post):
        response = _status(429)
        response.json.return_value = {"error": {"code": "insufficient_quota"}}
        post.return_value = response
        backend = LLMBackend(backend="openai", api_key="k")
        assert "quota exhausted" in backend.generate("p").text
        assert "quota exhausted" in backend.generate("later").text
        assert post.call_count == 1

    @patch("rowan.agents.llm_backend.httpx.post")
    def test_context_error_does_not_halt_other_batches(self, post):
        response = _status(400)
        response.json.return_value = {"error": {"code": "context_length_exceeded"}}
        post.side_effect = [response, _ok("smaller batch")]
        backend = LLMBackend(backend="openai", api_key="k")
        assert backend.generate("large").text.startswith("LLM error")
        assert not backend.stop_reason
        assert backend.generate("small").text == "smaller batch"

    @patch("rowan.agents.llm_backend.httpx.post")
    def test_call_ceiling_can_be_lifted_without_recreating_backend(self, post):
        post.return_value = _ok("done")
        backend = LLMBackend(backend="openai", api_key="k")
        backend.max_calls = 0
        assert backend.generate("p").text.startswith("LLM error")
        backend.max_calls = 1
        assert backend.generate("p").text == "done"

    @patch("threading.Event.wait", return_value=False)
    @patch("rowan.agents.llm_backend.httpx.post")
    def test_retries_on_429_then_succeeds(self, post, sleep):
        post.side_effect = [_status(429, "0"), _ok("done")]
        resp = LLMBackend(backend="deepseek", api_key="k").generate("p")
        assert resp.text == "done"
        assert post.call_count == 2
        assert sleep.called

    @patch("threading.Event.wait", return_value=False)
    @patch("rowan.agents.llm_backend.httpx.post")
    def test_retries_on_timeout_and_5xx_then_gives_up(self, post, sleep):
        post.side_effect = [httpx.ReadTimeout("t"), _status(503), _status(502), _status(504)]
        resp = LLMBackend(backend="deepseek", api_key="k").generate("p")
        assert resp.text.startswith("LLM error")
        assert post.call_count == 3

    @patch("threading.Event.wait", return_value=False)
    @patch("rowan.agents.llm_backend.httpx.post")
    def test_does_not_retry_401(self, post, sleep):
        post.side_effect = [_status(401), _ok("never")]
        resp = LLMBackend(backend="deepseek", api_key="k").generate("p")
        assert resp.text.startswith("LLM error")
        assert post.call_count == 1
        assert not sleep.called


class TestResponseShape:
    @patch("rowan.agents.llm_backend.httpx.post")
    def test_schema_failure_has_one_bounded_repair(self, post):
        post.side_effect = [_ok('{"verdicts": "invalid"}'), _ok('{"verdicts": []}')]
        backend = LLMBackend(backend="openai", api_key="k")
        schema = {"type": "object", "required": ["verdicts"], "properties": {"verdicts": {"type": "array"}}}
        assert backend.generate_structured("p", output_schema=schema) == {"verdicts": []}
        assert post.call_count == 2

    @patch("rowan.agents.llm_backend.httpx.post")
    def test_malformed_json_repair_is_bounded_by_call_budget(self, post):
        post.return_value = _ok("not json")
        backend = LLMBackend(backend="openai", api_key="k")
        backend.max_calls = 1
        assert "error" in backend.generate_structured("p", output_schema={"type": "object"})
        assert post.call_count == 1

    @patch("rowan.agents.llm_backend.httpx.post")
    def test_non_json_body_is_an_llm_error(self, post):
        resp = MagicMock(status_code=200, headers={})
        resp.raise_for_status.return_value = None
        resp.json.side_effect = ValueError("not json")
        post.return_value = resp
        out = LLMBackend(backend="deepseek", api_key="k").generate("p")
        assert out.text.startswith("LLM error")

    @patch("rowan.agents.llm_backend.httpx.post")
    def test_empty_choices_is_an_llm_error(self, post):
        resp = _ok()
        resp.json.return_value = {"choices": []}
        post.return_value = resp
        out = LLMBackend(backend="deepseek", api_key="k").generate("p")
        assert out.text.startswith("LLM error")


class TestProviderParams:
    @patch("rowan.agents.llm_backend.httpx.post")
    def test_openai_reasoning_model_request_shape(self, post):
        post.return_value = _ok()
        LLMBackend(backend="openai", api_key="k", model="o3-mini").generate("p")
        body = post.call_args.kwargs["json"]
        assert "max_completion_tokens" in body and "max_tokens" not in body
        assert "temperature" not in body

    @patch("rowan.agents.llm_backend.httpx.post")
    def test_other_models_keep_max_tokens_and_temperature(self, post):
        post.return_value = _ok()
        LLMBackend(backend="openai", api_key="k", model="gpt-4o").generate("p")
        body = post.call_args.kwargs["json"]
        assert "max_tokens" in body and "temperature" in body

    @patch("rowan.agents.llm_backend.httpx.post")
    def test_reasoning_model_empty_length_response_does_not_crash(self, post):
        resp = _ok("")
        resp.json.return_value = {
            "choices": [{"message": {"content": ""}, "finish_reason": "length"}],
            "usage": {"completion_tokens_details": {"reasoning_tokens": 512}},
        }
        post.return_value = resp

        out = LLMBackend(backend="openai", api_key="k", model="o3-mini").generate("p")

        assert out.text == ""


class TestEmptyCompletionConsumers:
    def test_doctor_live_empty_completion_is_not_ok(self, monkeypatch):
        from rowan.agents import doctor
        from rowan.agents.llm_backend import LLMResponse

        monkeypatch.setenv("DEEPSEEK_API_KEY", "k")
        monkeypatch.setattr(
            LLMBackend, "generate", lambda self, *a, **k: LLMResponse(text="", model="m")
        )
        monkeypatch.setattr(LLMBackend, "check_connectivity", lambda self, timeout=5: False)
        report = doctor.run_doctor(live=True, timeout=1)
        deepseek = next(c for c in report.checks if c.backend == "deepseek")
        assert deepseek.live_ok is False
        assert "empty" in deepseek.detail

    def test_empty_llm_report_falls_back_to_text_summary(self, tmp_path):
        from rowan.agents.llm_backend import LLMResponse
        from rowan.agents.workflow import HuntState, HuntWorkflow
        from rowan.config import ScanConfig

        llm = MagicMock(is_configured=True, _backend="deepseek")
        llm.generate.return_value = LLMResponse(text="", model="m")
        state = HuntState(target_path=tmp_path, config=ScanConfig(target=tmp_path), llm=llm)
        workflow = HuntWorkflow(state)
        report = workflow._llm_report()
        assert report == workflow._text_summary()
        assert any("llm_report" in e for e in state.errors)
        assert "max_tokens" not in llm.generate.call_args.kwargs


class TestCallBudget:
    @patch("rowan.agents.llm_backend.httpx.post")
    def test_calls_past_the_budget_send_no_request(self, post):
        post.return_value = _ok("fine")
        llm = LLMBackend(backend="deepseek", api_key="k")
        llm.max_calls = 2

        texts = [llm.generate("p").text for _ in range(3)]

        assert texts[:2] == ["fine", "fine"]
        assert texts[2] == "LLM error: call budget of 2 exhausted"
        assert post.call_count == 2
