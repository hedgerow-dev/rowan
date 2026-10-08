"""Hunt must not send secrets found in scanned source to a remote LLM.

Every prompt leaves through LLMBackend.generate, so redaction happens there:
known credential formats and high-entropy string literals assigned to
secret-named variables become [REDACTED-SECRET] before the request body and
the debug log are built. A loopback endpoint (Ollama, a local server) gets
the raw text: nothing leaves the machine.
"""

from __future__ import annotations

import logging

import httpx
import pytest

from rowan.agents.llm_backend import REDACTED, LLMBackend, redact_secrets

# Fake credentials in the shape of each format; none are real.
SECRETS = {
    "aws": "AKIAABCDEFGHIJKLMNOP",
    "github": "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8",
    "openai": "sk-proj-" + "Ab3dEf6hIj9lMn2pQr5tUv8x",
    "slack": "xoxb-1234567890-abcdefghij",
    "google": "AIza" + "SyA1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q",
    "jwt": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dQw4w9WgXcQ7rT2kLm9pQ",
}


@pytest.mark.parametrize("name", sorted(SECRETS))
def test_known_credential_formats_are_redacted(name):
    text, count = redact_secrets(f'client = make(key="{SECRETS[name]}")')
    assert SECRETS[name] not in text
    assert REDACTED in text
    assert count == 1


def test_private_key_block_is_redacted():
    block = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA1b2c3\n-----END RSA PRIVATE KEY-----"
    text, count = redact_secrets(f"KEY = '''{block}'''")
    assert "MIIEowIBAAKCAQEA1b2c3" not in text
    assert count == 1


def test_url_credentials_keep_the_rest_of_the_url():
    text, _ = redact_secrets("DB = 'postgres://app:s3cr3tP4ss@db.internal:5432/app'")
    assert "s3cr3tP4ss" not in text
    assert "postgres://app:" in text and "@db.internal:5432/app" in text


def test_high_entropy_secret_assignment_is_redacted():
    text, count = redact_secrets('API_KEY = "q8Zr2Lx9Vt4Np7Wm"')
    assert "q8Zr2Lx9Vt4Np7Wm" not in text
    assert count == 1


@pytest.mark.parametrize(
    "line",
    [
        'password = "changeme"',
        'API_KEY = os.environ["API_KEY"]',
        "token = request.headers.get('Authorization')",
        "def load(path):\n    return open(path).read()",
    ],
)
def test_placeholders_env_reads_and_plain_code_are_kept(line):
    assert redact_secrets(line) == (line, 0)


def _capture_request(monkeypatch):
    sent = {}

    def fake_post(url, json, headers, timeout):
        sent["body"] = json
        return httpx.Response(
            200,
            json={"choices": [{"message": {"content": "ok"}, "finish_reason": "stop"}]},
            request=httpx.Request("POST", url),
        )

    monkeypatch.setattr(httpx, "post", fake_post)
    return sent


def test_cloud_backend_never_sends_or_logs_the_secret(monkeypatch, caplog):
    sent = _capture_request(monkeypatch)
    llm = LLMBackend(backend="openai", api_key="test-not-a-real-key")
    caplog.set_level(logging.DEBUG, logger="rowan.agents.llm_backend")

    llm.generate(f'Review: AWS = "{SECRETS["aws"]}"', system=f"ctx {SECRETS['github']}")

    payload = str(sent["body"])
    assert SECRETS["aws"] not in payload and SECRETS["github"] not in payload
    assert SECRETS["aws"] not in caplog.text
    assert llm.redactions == 2


def test_loopback_backend_gets_the_raw_text(monkeypatch):
    sent = _capture_request(monkeypatch)
    llm = LLMBackend(backend="ollama")

    llm.generate(f'Review: AWS = "{SECRETS["aws"]}"')

    assert SECRETS["aws"] in str(sent["body"])
    assert llm.redactions == 0
