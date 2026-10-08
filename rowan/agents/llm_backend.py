"""LLM backend abstraction: supports DeepSeek, OpenAI, and any OpenAI-compatible API."""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import threading
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

import httpx
from jsonschema import Draft202012Validator

from rowan.agents import audit

logger = logging.getLogger(__name__)

# OpenRouter's base URL is fixed (not configurable via env), unlike every
# other per-backend default below.
OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"


def _env(name: str, default: str = "") -> str:
    """Read an env var at call time.

    Every other per-backend default below (model, base URL, API key) is
    resolved through this at __init__ time rather than captured as a
    module-level constant at import time. A module-level `X = os.environ.get(...)`
    is a one-time snapshot: a credential set *after* this module is first
    imported (a later `.env` load, a test's `patch.dict`, a long-running
    process that mutates os.environ) would silently never be seen. Every
    LLMBackend() call re-reads the environment fresh instead.
    """
    return os.environ.get(name, default)


@dataclass
class LLMResponse:
    text: str
    model: str
    usage: dict[str, int] = field(default_factory=dict)
    duration_ms: float = 0.0


def _require_object(value: Any, text: str) -> dict[str, Any]:
    """Every caller indexes the parsed reply as an object; a bare array,
    number or string would escape as that type and crash the batch (HN-03)."""
    if isinstance(value, dict):
        return value
    return {"raw": text, "error": f"LLM returned a JSON {type(value).__name__}, expected an object"}


_RETRY_ATTEMPTS = 3
_RETRY_BASE_SECONDS = 1.0

REDACTED = "[REDACTED-SECRET]"

# Credential formats with a recognizable shape. Each match is a whole secret.
_SECRET_FORMATS = re.compile(
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"
    r"|\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"
    r"|\bgh[pousr]_[A-Za-z0-9]{36,}\b"
    r"|\bgithub_pat_[A-Za-z0-9_]{22,}\b"
    r"|\bsk-(?:ant-|proj-)?[A-Za-z0-9_-]{20,}"
    r"|\bxox[abposr]-[A-Za-z0-9-]{10,}"
    r"|\bAIza[0-9A-Za-z_-]{35}\b"
    r"|\b[rs]k_(?:live|test)_[0-9A-Za-z]{16,}\b"
    r"|\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"
)
# The password part of scheme://user:password@host.
_URL_PASSWORD = re.compile(r"(\b[a-z][a-z0-9+.-]*://[^\s:/@'\"]+:)([^\s@/'\"]+)(@)")
# A string literal assigned to a secret-named variable or key.
_SECRET_ASSIGNMENT = re.compile(
    r"""(?i)(\b(?:password|passwd|pwd|secret|api_?key|apikey|token|access_?key|"""
    r"""private_?key|client_?secret|auth_?token)\w*["']?\s*[:=]\s*)(["'])([^"'\n]{6,})\2"""
)


def redact_secrets(text: str) -> tuple[str, int]:
    """Replace likely secrets in `text` with REDACTED; return the new text and count.

    Assignments count only when the literal looks like a real secret: not a
    placeholder (changeme, xxx, <your-key>) and not low-entropy prose.
    """
    from rowan.core.rules import _is_placeholder, _shannon_entropy

    text, count = _SECRET_FORMATS.subn(REDACTED, text)
    text, n = _URL_PASSWORD.subn(lambda m: m.group(1) + REDACTED + m.group(3), text)
    count += n

    def assignment(m: re.Match[str]) -> str:
        nonlocal count
        value = m.group(3)
        if value == REDACTED or _is_placeholder(value) or _shannon_entropy(value) < 3.0:
            return m.group(0)
        count += 1
        return f"{m.group(1)}{m.group(2)}{REDACTED}{m.group(2)}"

    text = _SECRET_ASSIGNMENT.sub(assignment, text)
    return text, count


def _is_loopback_url(url: str) -> bool:
    """True when `url` points at this machine, so a prompt never leaves it."""
    import ipaddress
    from urllib.parse import urlsplit

    host = (urlsplit(url).hostname or "").lower()
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _retry_after_seconds(header: str | None) -> float | None:
    try:
        return max(0.0, float(header)) if header else None
    except ValueError:
        return None


class LLMBackend:
    """Minimal LLM client supporting any OpenAI-compatible endpoint."""

    # "ollama" targets a local Ollama server (OpenAI-compatible /v1 API, no auth needed).
    # "local" is a generic escape hatch: set LOCAL_LLM_BASE_URL + LOCAL_LLM_MODEL.
    BACKENDS = ("deepseek", "openai", "openrouter", "alibaba", "ollama", "local")

    def __init__(
        self,
        backend: str = "deepseek",
        model: str | None = None,
        base_url: str | None = None,
        api_key: str | None = None,
        temperature: float = 0.1,
        max_tokens: int = 8192,
        timeout: int = 120,
    ):
        if backend not in self.BACKENDS:
            raise ValueError(f"Unknown backend: {backend}. Choose from {self.BACKENDS}")

        self._backend = backend
        self._temperature = temperature
        # Hunt's spend ceiling (HN-07): generate() refuses once `calls` reaches
        # `max_calls`. Retries inside one generate() count as one call.
        self.max_calls: int | None = None
        self.calls = 0
        self._calls_lock = threading.Lock()
        self.cancel_event = threading.Event()
        self.retry_count = 0
        self.stop_reason = ""
        self.usage: dict[str, int] = {}
        # Secrets replaced in prompts sent to a non-loopback endpoint.
        self.redactions = 0
        # Reasoning models (DeepSeek v4, o-series) bill thinking against
        # max_tokens, so an 8192 budget can be spent entirely on reasoning and
        # return finish_reason="length" with an empty content field. Both are
        # overridable so a reasoning model can be given room and told to think
        # less; LLM_REASONING_EFFORT is omitted from the payload when unset so
        # endpoints that reject the field are unaffected.
        self._max_tokens = int(_env("LLM_MAX_TOKENS", "") or max_tokens)
        self._reasoning_effort = _env("LLM_REASONING_EFFORT", "")
        # Reasoning models can think well past a 120s read timeout on a full
        # triage batch; LLM_TIMEOUT lifts the per-request ceiling without
        # touching every call site.
        self._timeout = int(_env("LLM_TIMEOUT", "") or timeout)

        if backend == "deepseek":
            self._model = model or _env("DEEPSEEK_MODEL", "deepseek-chat")
            self._base_url = base_url or _env("DEEPSEEK_BASE_URL", "https://api.deepseek.com/v1")
            self._api_key = api_key or _env("DEEPSEEK_API_KEY")
        elif backend == "openrouter":
            self._model = model or _env("OPENROUTER_MODEL", "deepseek/deepseek-chat")
            self._base_url = base_url or OPENROUTER_BASE_URL
            self._api_key = api_key or _env("OPENROUTER_API_KEY")
        elif backend == "alibaba":
            # Alibaba Cloud Model Studio Token Plan (OpenAI-compatible). The
            # default is the international endpoint; the China endpoint is
            # https://token-plan.cn-beijing.maas.aliyuncs.com/compatible-mode/v1
            # (set ALIBABA_BASE_URL to switch regions).
            self._model = model or _env("ALIBABA_MODEL", "qwen3.8-max")
            self._base_url = base_url or _env(
                "ALIBABA_BASE_URL",
                "https://token-plan.ap-southeast-1.maas.aliyuncs.com/compatible-mode/v1",
            )
            self._api_key = api_key or _env("ALIBABA_TOKEN_PLAN_API_KEY")
        elif backend == "ollama":
            # Ollama exposes an OpenAI-compatible /v1 API on localhost:11434.
            # No API key is required; set a dummy so is_configured returns True.
            self._model = model or _env("OLLAMA_MODEL", "llama3")
            self._base_url = base_url or _env("OLLAMA_BASE_URL", "http://localhost:11434/v1")
            self._api_key = api_key or _env("OLLAMA_API_KEY", "ollama")
        elif backend == "local":
            self._model = model or _env("LOCAL_LLM_MODEL", "local-model")
            self._base_url = base_url or _env("LOCAL_LLM_BASE_URL", "http://localhost:8080/v1")
            self._api_key = api_key or _env("LOCAL_LLM_API_KEY", "local")
        else:
            self._model = model or _env("OPENAI_MODEL", "gpt-4o-mini")
            self._base_url = base_url or _env("OPENAI_BASE_URL", "https://api.openai.com/v1")
            self._api_key = api_key or _env("OPENAI_API_KEY")

    @property
    def is_configured(self) -> bool:
        return bool(self._api_key)

    @property
    def base_url(self) -> str:
        return self._base_url

    @property
    def backend(self) -> str:
        return self._backend

    @property
    def model(self) -> str:
        return self._model

    def disable(self) -> None:
        """Force ``is_configured`` to False so no source code is sent.

        Used when the user declines (or does not opt into) sending code to the
        LLM endpoint; the hunt then degrades to a static-only scan.
        """
        self._api_key = ""

    def check_connectivity(self, timeout: int = 5) -> bool:
        """Return True if the backend endpoint is reachable.

        For cloud backends this only checks that the base URL is reachable, not
        that the key is valid.  For local backends (ollama, local) this is the
        primary way to detect a server that is not running.
        """
        try:
            httpx.get(f"{self._base_url}/models", timeout=timeout)
            return True
        except httpx.HTTPError:
            return False
        except Exception:
            return False

    def generate(
        self,
        prompt: str,
        system: str = "",
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> LLMResponse:
        """Send a prompt and get a completion."""
        if self.stop_reason == "call budget exhausted" and (self.max_calls is None or self.calls < self.max_calls):
            self.stop_reason = ""
        if self.stop_reason:
            return LLMResponse(text=f"LLM error: {self.stop_reason}", model=self._model)
        if not self.is_configured:
            hint = {
                "deepseek": "Set DEEPSEEK_API_KEY.",
                "openai": "Set OPENAI_API_KEY.",
                "openrouter": "Set OPENROUTER_API_KEY.",
                "alibaba": "Set ALIBABA_TOKEN_PLAN_API_KEY.",
                "ollama": "Start Ollama with 'ollama serve' and pull a model with 'ollama pull llama3'.",
                "local": "Set LOCAL_LLM_BASE_URL and LOCAL_LLM_MODEL, and ensure the server is running.",
            }.get(self._backend, "Check your API key or local server configuration.")
            return LLMResponse(
                text=f"LLM not configured ({self._backend}). {hint}",
                model="none",
            )

        with self._calls_lock:
            if self.max_calls is not None and self.calls >= self.max_calls:
                self.stop_reason = "call budget exhausted"
                return LLMResponse(
                    text=f"LLM error: call budget of {self.max_calls} exhausted", model="none"
                )
            self.calls += 1

        url = f"{self._base_url}/chat/completions"
        headers = {
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json",
        }

        if self._backend == "openrouter":
            headers["HTTP-Referer"] = "https://github.com/hedgerow-dev/rowan"
            headers["X-Title"] = "Rowan SAST"

        # Scanned source can hold real credentials. Redact before the body and
        # the debug log are built, unless the endpoint is on this machine.
        redacted = 0
        if not _is_loopback_url(self._base_url):
            prompt, n_prompt = redact_secrets(prompt)
            system, n_system = redact_secrets(system)
            redacted = n_prompt + n_system
            with self._calls_lock:
                self.redactions += redacted

        messages: list[dict[str, str]] = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        body: dict[str, Any] = {"model": self._model, "messages": messages}
        if self._uses_completion_tokens():
            # OpenAI o-series: fixed temperature, `max_completion_tokens`.
            body["max_completion_tokens"] = max_tokens or self._max_tokens
        else:
            body["temperature"] = temperature if temperature is not None else self._temperature
            body["max_tokens"] = max_tokens or self._max_tokens
        if self._reasoning_effort:
            body["reasoning_effort"] = self._reasoning_effort

        # Full prompt/response trace at DEBUG (enabled by `-v`) -- never logs
        # headers, so the API key never ends up in a log line.
        logger.debug(
            "LLM request [%s:%s]\n--- system ---\n%s\n--- prompt ---\n%s",
            self._backend,
            self._model,
            system,
            prompt,
        )

        start = time.perf_counter()
        data = self._post_with_retry(url, body, headers)

        def audit_call(outcome: str, response_text: str = "") -> None:
            sent = f"{system}\n{prompt}"
            audit.record(
                "llm_call",
                backend=self._backend,
                model=self._model,
                endpoint=urlsplit(url).hostname or "",
                prompt_sha256=hashlib.sha256(sent.encode()).hexdigest(),
                prompt_bytes=len(sent.encode()),
                response_bytes=len(response_text.encode()),
                redactions=redacted,
                outcome=outcome,
            )

        if isinstance(data, str):
            audit_call("error")
            return LLMResponse(text=f"LLM error: {data}", model=self._model)

        duration_ms = (time.perf_counter() - start) * 1000
        choices = data.get("choices") if isinstance(data, dict) else None
        if not choices:
            logger.warning("LLM response has no choices: %s", str(data)[:200])
            audit_call("error")
            return LLMResponse(text="LLM error: no choices in response", model=self._model)
        choice = choices[0]
        text = choice.get("message", {}).get("content", "")
        usage = data.get("usage", {})

        # A reasoning model can burn the whole token budget on thinking and
        # return empty content with finish_reason="length". Downstream that
        # used to surface as "JSON parse failed", which sends whoever is
        # debugging it hunting for a malformed response that was never sent.
        # Say what actually happened, and how to fix it.
        if not text and choice.get("finish_reason") == "length":
            reasoning = (usage.get("completion_tokens_details") or {}).get("reasoning_tokens")
            detail = f", all {reasoning} of them on reasoning" if reasoning else ""
            token_budget = body.get("max_tokens", body.get("max_completion_tokens", self._max_tokens))
            logger.warning(
                "LLM returned no content: %s exhausted its %d-token budget%s. "
                "Raise LLM_MAX_TOKENS and/or set LLM_REASONING_EFFORT=low.",
                self._model,
                token_budget,
                detail,
            )

        logger.debug(
            "LLM response [%s:%s, %.0fms]\n%s",
            self._backend,
            self._model,
            duration_ms,
            text,
        )

        with self._calls_lock:
            for key, value in usage.items():
                if isinstance(value, int):
                    self.usage[key] = self.usage.get(key, 0) + value
        audit_call("ok", text or "")
        return LLMResponse(
            text=text.strip() if text else "",
            model=self._model,
            usage=dict(usage),
            duration_ms=duration_ms,
        )

    def _uses_completion_tokens(self) -> bool:
        """OpenAI reasoning models (o1, o3, o4-mini...) reject `temperature`
        and expect `max_completion_tokens`."""
        if os.environ.get("LLM_MAX_COMPLETION_TOKENS") == "1":
            return True
        name = self._model.lower()
        return self._backend == "openai" and len(name) > 1 and name[0] == "o" and name[1].isdigit()

    def _post_with_retry(
        self, url: str, body: dict[str, Any], headers: dict[str, str]
    ) -> dict[str, Any] | str:
        """POST with retry on 429, 5xx and timeouts. Returns the parsed JSON
        object or a short error string; every other failure mode is terminal
        (401, 400) or not JSON. Retrying is what stops a rate-limited batch
        of findings from silently vanishing from a hunt (HN-08)."""
        error = "no attempt made"
        for attempt in range(_RETRY_ATTEMPTS):
            if self.cancel_event.is_set():
                self.stop_reason = "cancelled"
                return "cancelled"
            retryable, delay = False, None
            status = None
            try:
                response = httpx.post(url, json=body, headers=headers, timeout=self._timeout)
                response.raise_for_status()
            except httpx.TimeoutException as e:
                error, retryable, delay = f"{e}", True, None
            except httpx.HTTPStatusError as e:
                status = e.response.status_code
                error = f"{e}"
                retryable = status == 429 or status >= 500
                try:
                    error_code = e.response.json().get("error", {}).get("code", "")
                except (ValueError, AttributeError):
                    error_code = ""
                if status == 429:
                    if isinstance(error_code, str) and error_code in {"insufficient_quota", "billing_hard_limit_reached", "quota_exceeded"}:
                        self.stop_reason = "quota exhausted; resume after restoring backend quota"
                        return self.stop_reason
                delay = _retry_after_seconds(e.response.headers.get("Retry-After"))
            except httpx.HTTPError as e:
                return f"{e}"
            else:
                try:
                    data = response.json()
                except ValueError:
                    return f"non-JSON response ({response.status_code})"
                return data if isinstance(data, dict) else "non-object JSON response"
            if not retryable or attempt == _RETRY_ATTEMPTS - 1:
                if status in {401, 402, 403, 404} or (status == 400 and isinstance(error_code, str) and error_code in {"model_not_found", "invalid_model", "unsupported_parameter"}):
                    self.stop_reason = f"request rejected (HTTP {status}); check model, credentials and endpoint"
                break
            wait = delay if delay is not None else _RETRY_BASE_SECONDS * (2**attempt)
            wait = min(wait, 30.0)
            logger.warning("LLM request failed (%s); retrying in %.0fs", error, wait)
            self.retry_count += 1
            if self.cancel_event.wait(wait):
                self.stop_reason = "cancelled"
                return "cancelled"
        logger.warning("LLM request failed: %s", error)
        return error

    def generate_structured(
        self,
        prompt: str,
        system: str = "",
        output_schema: dict[str, Any] | None = None,
        temperature: float | None = None,
    ) -> dict[str, Any]:
        """Generate a structured JSON response."""
        schema_hint = ""
        if output_schema:
            schema_hint = f"\n\nRespond with valid JSON matching this schema:\n{json.dumps(output_schema, indent=2)}"
            schema_hint += "\n\nYour response must be valid JSON only, no other text. Escape all backslashes in file paths."

        full_prompt = f"{prompt}{schema_hint}"

        response = self.generate(full_prompt, system=system, temperature=temperature)

        if response.text.startswith("LLM"):
            return {"error": response.text}

        value = self._parse_json_response(response.text)
        if output_schema:
            Draft202012Validator.check_schema(output_schema)
            if "error" in value or not Draft202012Validator(output_schema).is_valid(value):
                # One bounded repair call; it consumes the same max_calls budget.
                repaired = self.generate(
                    full_prompt + "\nYour last response did not match the required schema. Return only a matching JSON object.",
                    system=system, temperature=temperature,
                )
                if repaired.text.startswith("LLM"):
                    return {"error": repaired.text}
                value = self._parse_json_response(repaired.text)
                if "error" in value or not Draft202012Validator(output_schema).is_valid(value):
                    return {"error": "LLM response failed schema validation after bounded repair"}
        return value

    @staticmethod
    def _parse_json_response(text: str) -> dict[str, Any]:
        """Robust JSON extraction from LLM response text."""
        text = text.strip()

        # Strategy 1: Extract JSON from markdown code blocks
        m = re.search(r"```(?:json)?\s*\n?(.*?)\n?```", text, re.DOTALL)
        if m:
            text = m.group(1).strip()

        # Strategy 2: Try parsing the whole text directly
        try:
            return _require_object(json.loads(text), text)
        except json.JSONDecodeError:
            pass

        # Strategy 3: Find first outermost { ... } brace pair
        brace_start = text.find("{")
        if brace_start >= 0:
            depth = 0
            in_string = False
            escape_next = False
            for i in range(brace_start, len(text)):
                c = text[i]
                if escape_next:
                    escape_next = False
                    continue
                if c == "\\":
                    escape_next = True
                    continue
                if c == '"' and not escape_next:
                    in_string = not in_string
                    continue
                if in_string:
                    continue
                if c == "{":
                    depth += 1
                elif c == "}":
                    depth -= 1
                    if depth == 0:
                        candidate = text[brace_start : i + 1]
                        try:
                            return _require_object(json.loads(candidate), text)
                        except json.JSONDecodeError as e:
                            logger.debug(
                                "JSON brace-match parse failed at pos %d: %s...",
                                e.pos,
                                candidate[max(0, e.pos - 20) : e.pos + 20],
                            )
                        break

        # An empty response is not a parse failure. Reporting it as one hides
        # the real cause (an exhausted token budget, a refusal, a dropped
        # stream) behind a message that points at the wrong thing.
        if not text:
            logger.warning("LLM returned an empty response; nothing to parse")
            return {"raw": "", "error": "empty LLM response"}

        logger.warning("Failed to parse LLM JSON response: %s...", text[:200])
        return {"raw": text, "error": "JSON parse failed"}

    def _installed_ollama_models(self, timeout: int = 2) -> list[str]:
        """Return locally installed Ollama model ids, or an empty list."""
        try:
            response = httpx.get(f"{self._base_url.rstrip('/')}/models", timeout=timeout)
            response.raise_for_status()
            data = response.json().get("data", [])
            return sorted(
                item["id"]
                for item in data
                if isinstance(item, dict) and isinstance(item.get("id"), str)
            )
        except (httpx.HTTPError, ValueError, TypeError):
            return []

    @staticmethod
    def _preferred_local_model(models: list[str]) -> str | None:
        """Prefer code-specialized local models, then any installed model."""
        if not models:
            return None

        def rank(model: str) -> tuple[int, int, str]:
            lowered = model.lower()
            code_score = 2 if "coder" in lowered else 0
            family_score = 1 if "qwen" in lowered else 0
            context_score = 1 if "16k" in lowered else 0
            return (code_score + family_score, context_score, model)

        return max(models, key=rank)

    @classmethod
    def from_env(cls, model: str | None = None, **kwargs: Any) -> LLMBackend:
        """Auto-detect backend from environment variables, then local Ollama.

        Priority: DEEPSEEK_API_KEY → OPENROUTER_API_KEY → OPENAI_API_KEY →
        ALIBABA_TOKEN_PLAN_API_KEY → running Ollama server → unconfigured
        deepseek (shows clear error on use).
        """
        if _env("DEEPSEEK_API_KEY"):
            return cls(backend="deepseek", model=model, **kwargs)
        if _env("OPENROUTER_API_KEY"):
            return cls(backend="openrouter", model=model, **kwargs)
        if _env("OPENAI_API_KEY"):
            return cls(backend="openai", model=model, **kwargs)
        if _env("ALIBABA_TOKEN_PLAN_API_KEY"):
            return cls(backend="alibaba", model=model, **kwargs)

        # Check for a local Ollama server before giving up.
        ollama_instance = cls(backend="ollama", model=model, **kwargs)
        if ollama_instance.check_connectivity(timeout=2):
            if model is None and not _env("OLLAMA_MODEL"):
                selected = cls._preferred_local_model(ollama_instance._installed_ollama_models())
                if selected is not None:
                    ollama_instance._model = selected
            logger.info("Auto-detected local Ollama server at %s", ollama_instance.base_url)
            return ollama_instance

        logger.warning(
            "No LLM API key or local server found. "
            "Set DEEPSEEK_API_KEY / OPENAI_API_KEY / OPENROUTER_API_KEY / "
            "ALIBABA_TOKEN_PLAN_API_KEY, or start Ollama with 'ollama serve'."
        )
        return cls(backend="deepseek", model=model, **kwargs)  # Shows "not configured" on use

    def __repr__(self) -> str:
        configured = "configured" if self.is_configured else "unconfigured"
        return f"LLMBackend({self._backend}:{self._model}, {configured})"
