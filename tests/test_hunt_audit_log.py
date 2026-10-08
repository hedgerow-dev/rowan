"""`rowan hunt --audit-log PATH` records every LLM call and live probe.

One JSON object per line: what was sent where, never the content. LLM calls
record the endpoint host, model, a hash and size of the (redacted) prompt and
the number of secrets redacted; probes record the request URL and outcome.
Without --audit-log nothing is written.
"""

from __future__ import annotations

import json
import stat

import httpx

from rowan.agents import web_exploit
from rowan.agents.audit import close_audit_log, open_audit_log
from rowan.agents.llm_backend import LLMBackend


def _lines(path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def _fake_llm(monkeypatch):
    def fake_post(url, json, headers, timeout):
        return httpx.Response(
            200,
            json={"choices": [{"message": {"content": "verdict"}, "finish_reason": "stop"}]},
            request=httpx.Request("POST", url),
        )

    monkeypatch.setattr(httpx, "post", fake_post)


def test_llm_call_is_recorded_without_content(tmp_path, monkeypatch):
    _fake_llm(monkeypatch)
    log = tmp_path / "audit.jsonl"
    handler = open_audit_log(log)
    try:
        LLMBackend(backend="openai", api_key="test-not-a-real-key").generate(
            'source: KEY = "AKIAABCDEFGHIJKLMNOP"', system="review"
        )
    finally:
        close_audit_log(handler)

    [record] = _lines(log)
    assert record["event"] == "llm_call"
    assert record["endpoint"] == "api.openai.com"
    assert record["outcome"] == "ok"
    assert record["redactions"] == 1
    assert len(record["prompt_sha256"]) == 64
    assert "AKIA" not in log.read_text() and "source:" not in log.read_text()


def test_probe_is_recorded(tmp_path, monkeypatch):
    def fake_get(url, timeout, follow_redirects=False):
        return httpx.Response(200, text="ok", request=httpx.Request("GET", url))

    monkeypatch.setattr(httpx, "get", fake_get)
    log = tmp_path / "audit.jsonl"
    handler = open_audit_log(log)
    try:
        web_exploit._safe_get("http://127.0.0.1:5000/view?f=../../etc/passwd", 5)
    finally:
        close_audit_log(handler)

    [record] = _lines(log)
    assert record["event"] == "probe"
    assert record["url"] == "http://127.0.0.1:5000/view?f=../../etc/passwd"
    assert record["status"] == 200


def test_log_file_is_owner_only_and_appended(tmp_path, monkeypatch):
    _fake_llm(monkeypatch)
    log = tmp_path / "audit.jsonl"
    for _ in range(2):
        handler = open_audit_log(log)
        try:
            LLMBackend(backend="openai", api_key="test-not-a-real-key").generate("x")
        finally:
            close_audit_log(handler)

    assert len(_lines(log)) == 2
    assert stat.S_IMODE(log.stat().st_mode) == 0o600


def test_nothing_is_written_without_a_log(tmp_path, monkeypatch):
    _fake_llm(monkeypatch)
    LLMBackend(backend="openai", api_key="test-not-a-real-key").generate("x")
    assert list(tmp_path.iterdir()) == []


def test_cli_opens_and_closes_the_audit_log(tmp_path, monkeypatch):
    import logging

    from click.testing import CliRunner

    import rowan.agents
    from rowan.agents import audit
    from rowan.cli import main

    class RecordingWorkflow:
        def __init__(self, state):
            self.state = state

        def run(self):
            audit.record("probe", method="GET", url="http://127.0.0.1:5000/x", status=200)
            self.state.run_status = "complete"
            return self.state

    monkeypatch.setattr(rowan.agents, "HuntWorkflow", RecordingWorkflow)
    monkeypatch.setenv("OPENAI_API_KEY", "test-not-a-real-key")
    (tmp_path / "app").mkdir()
    log = tmp_path / "audit.jsonl"

    result = CliRunner().invoke(
        main,
        ["hunt", str(tmp_path / "app"), "--backend", "openai", "--yes", "--audit-log", str(log)],
    )

    assert result.exit_code == 0, result.output
    assert [r["event"] for r in _lines(log)] == ["probe"]
    assert not logging.getLogger("rowan.audit").handlers
