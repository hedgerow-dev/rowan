"""Durable, schema-valid successful-call replay for Hunt.

Resume rebuilds deterministic workflow state against a fresh recon scan; it
replays completed calls, not serialized Python objects or live HTTP probes.
"""

from __future__ import annotations

import copy
import hashlib
import json
import math
import os
import tempfile
import threading
import time
from dataclasses import asdict
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

from rowan import __version__
from rowan.agents.llm_backend import LLMResponse


def run_identity(state) -> str:
    config = asdict(state.config)
    # Output location/spend ceiling may change when resuming without changing evidence.
    for key in ("output", "output_format", "verbose"):
        config.pop(key, None)
    llm = state.llm
    settings = {
        key: getattr(llm, key, None)
        for key in (
            "_backend",
            "_model",
            "_base_url",
            "_temperature",
            "_max_tokens",
            "_reasoning_effort",
        )
    }
    settings["credential_scope"] = hashlib.sha256(
        str(getattr(llm, "_api_key", "")).encode()
    ).hexdigest()
    implementation = hashlib.sha256()
    for module in ("workflow.py", "hunt_inventory.py", "hunt_schemas.py", "llm_backend.py"):
        implementation.update((Path(__file__).parent / module).read_bytes())
    metadata = {
        "implementation": implementation.hexdigest(),
        "version": __version__,
        "target": str(state.target_path.resolve()),
        "config": config,
        "llm": settings,
        "discovery": state.enable_discovery,
        "budgets": asdict(state.budgets),
    }
    digest = hashlib.sha256(json.dumps(metadata, sort_keys=True, default=str).encode())
    from rowan.passes.file_scan import FileScanPass

    for path in sorted(FileScanPass([])._collect_files(state.target_path, state.config)):
        digest.update(str(path.resolve().relative_to(state.target_path.resolve())).encode())
        try:
            digest.update(hashlib.sha256(path.read_bytes()).digest())
        except OSError as exc:
            raise ValueError(f"Cannot fingerprint checkpoint source: {path}") from exc
    # Dependency/config files may alter recon even if not passed to the LLM.

    _, manifests, models, configs, _ = FileScanPass([])._discover_files(
        state.target_path, state.config
    )
    for path in sorted(set(manifests + models + configs)):
        digest.update(str(path.resolve().relative_to(state.target_path.resolve())).encode())
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
    return digest.hexdigest()


class HuntCheckpoint:
    """One atomically persisted cache, guarded across workflow worker threads."""

    def __init__(self, path: Path, identity: str, *, resume: bool = False):
        path = path.resolve()
        self.path = path
        self.identity = identity
        self.lock = threading.RLock()
        self.calls: dict[str, dict[str, Any]] = {}
        self.fresh = self.reused = self.failed = 0
        self.call_locks: dict[str, threading.Lock] = {}
        self.status = "running"
        self.stage = "init"
        self.elapsed_seconds = 0.0
        self._started = time.monotonic()
        self.previous_seconds = 0.0
        self.previous_fresh = 0
        self.previous_backend_calls = 0
        self.previous_usage: dict[str, int] = {}
        self.backend = None
        # Each save rewrites every recorded call, so per-call saves are throttled.
        # Stage boundaries, failures and the end of a run always save.
        self.save_interval = 1.0
        self._last_save = 0.0
        if resume:
            if not path.is_file():
                raise ValueError(f"Checkpoint does not exist: {path}")
            try:
                data = json.loads(path.read_text())
            except (OSError, ValueError) as exc:
                raise ValueError("Checkpoint is unreadable or corrupt") from exc
            if not isinstance(data, dict):
                raise ValueError("Invalid checkpoint root object")
            if data.get("schema_version") != 1 or data.get("identity") != identity:
                raise ValueError(
                    "Checkpoint inputs changed; start a new checkpoint instead of resuming"
                )
            calls = data.get("calls")
            if not isinstance(calls, dict):
                raise ValueError("Invalid checkpoint call records")
            self.calls = calls
            seconds = data.get("elapsed_seconds", 0)
            counts = [
                data.get("cumulative_fresh_calls", 0),
                data.get("cumulative_backend_calls", 0),
            ]
            if (
                not isinstance(seconds, (int, float))
                or isinstance(seconds, bool)
                or not math.isfinite(seconds)
                or seconds < 0
                or any(not isinstance(n, int) or isinstance(n, bool) or n < 0 for n in counts)
            ):
                raise ValueError("Invalid checkpoint recovery counters")
            self.previous_seconds = float(seconds)
            self.previous_fresh = int(data.get("cumulative_fresh_calls", 0))
            self.previous_backend_calls = int(data.get("cumulative_backend_calls", 0))
            usage = data.get("cumulative_token_usage", {})
            self.previous_usage = (
                {key: value for key, value in usage.items() if isinstance(value, int)}
                if isinstance(usage, dict)
                else {}
            )
        elif path.exists():
            raise ValueError("Checkpoint already exists; use --resume or choose a new path")
        self.save()

    def save_if_due(self) -> None:
        with self.lock:
            if time.monotonic() - self._last_save >= self.save_interval:
                self.save()

    def save(self) -> None:
        with self.lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            data = {
                "schema_version": 1,
                "identity": self.identity,
                "status": self.status,
                "stage": self.stage,
                "calls": self.calls,
                "elapsed_seconds": self.previous_seconds + time.monotonic() - self._started,
                "cumulative_fresh_calls": self.previous_fresh + self.fresh,
                "cumulative_backend_calls": self.previous_backend_calls + self._backend_calls(),
                "cumulative_token_usage": self._cumulative_usage(),
            }
            fd, temporary = tempfile.mkstemp(prefix=".hunt-", dir=self.path.parent)
            try:
                with os.fdopen(fd, "w") as stream:
                    json.dump(data, stream, sort_keys=True)
                    stream.flush()
                    os.fsync(stream.fileno())
                os.replace(temporary, self.path)
                self._last_save = time.monotonic()
            finally:
                if os.path.exists(temporary):
                    os.unlink(temporary)

    def _backend_calls(self) -> int:
        value = getattr(self.backend, "calls", 0)
        return value if isinstance(value, int) else 0

    def _cumulative_usage(self) -> dict[str, int]:
        usage = getattr(self.backend, "usage", {})
        result = dict(self.previous_usage)
        if isinstance(usage, dict):
            for key, value in usage.items():
                if isinstance(value, int):
                    result[key] = result.get(key, 0) + value
        return result

    def summary(self) -> dict[str, Any]:
        return {
            "fresh_calls": self.fresh,
            "reused_calls": self.reused,
            "failed_calls": self.failed,
            "cumulative_fresh_calls": self.previous_fresh + self.fresh,
            "cumulative_backend_calls": self.previous_backend_calls + self._backend_calls(),
            "cumulative_token_usage": self._cumulative_usage(),
            "call_count_unit": "workflow_work_units; backend_calls includes schema repairs",
            "run_seconds": round(time.monotonic() - self._started, 2),
            "cumulative_seconds": round(
                self.previous_seconds + time.monotonic() - self._started, 2
            ),
        }


class CheckpointBackend:
    """Replay only responses passing the same current schema as fresh calls."""

    def __init__(self, backend, checkpoint: HuntCheckpoint):
        self.backend = backend
        self.checkpoint = checkpoint
        self.checkpoint.backend = backend

    def __getattr__(self, name):
        return getattr(self.backend, name)

    def _key(self, kind: str, prompt: str, kwargs: dict[str, Any]) -> str:
        return hashlib.sha256(
            json.dumps([kind, prompt, kwargs], sort_keys=True, default=str).encode()
        ).hexdigest()

    def generate_structured(self, prompt: str, **kwargs) -> dict[str, Any]:
        key = self._key("structured", prompt, kwargs)
        with self.checkpoint.lock:
            lock = self.checkpoint.call_locks.setdefault(key, threading.Lock())
        with lock:
            return self._generate_structured(prompt, **kwargs)

    def _generate_structured(self, prompt: str, **kwargs) -> dict[str, Any]:
        schema = kwargs.get("output_schema") or {"type": "object"}
        key = self._key("structured", prompt, kwargs)
        # Serialize access to equal calls; normal workflow prompts differ by batch/file.
        with self.checkpoint.lock:
            entry = self.checkpoint.calls.get(key)
            if isinstance(entry, dict):
                value = entry.get("value")
                if (
                    isinstance(value, dict)
                    and "error" not in value
                    and Draft202012Validator(schema).is_valid(value)
                ):
                    self.checkpoint.reused += 1
                    return copy.deepcopy(value)
        try:
            value = self.backend.generate_structured(prompt, **kwargs)
        except Exception:
            with self.checkpoint.lock:
                self.checkpoint.fresh += 1
                self.checkpoint.failed += 1
                self.checkpoint.save()
            raise
        with self.checkpoint.lock:
            self.checkpoint.fresh += 1
            if (
                isinstance(value, dict)
                and "error" not in value
                and Draft202012Validator(schema).is_valid(value)
            ):
                self.checkpoint.calls[key] = {"value": copy.deepcopy(value)}
            else:
                self.checkpoint.failed += 1
                value = {
                    "error": str(value.get("error", "Invalid structured response"))
                    if isinstance(value, dict)
                    else "Invalid structured response"
                }
            self.checkpoint.save_if_due()
        return value

    def generate(self, prompt: str, **kwargs) -> LLMResponse:
        key = self._key("text", prompt, kwargs)
        with self.checkpoint.lock:
            lock = self.checkpoint.call_locks.setdefault(key, threading.Lock())
        with lock:
            return self._generate(prompt, **kwargs)

    def _generate(self, prompt: str, **kwargs) -> LLMResponse:
        key = self._key("text", prompt, kwargs)
        with self.checkpoint.lock:
            entry = self.checkpoint.calls.get(key)
            if (
                isinstance(entry, dict)
                and isinstance(entry.get("text"), str)
                and entry["text"].strip()
                and not entry["text"].startswith("LLM")
            ):
                self.checkpoint.reused += 1
                return LLMResponse(
                    text=entry["text"], model=entry.get("model", ""), usage=entry.get("usage", {})
                )
        response = self.backend.generate(prompt, **kwargs)
        with self.checkpoint.lock:
            self.checkpoint.fresh += 1
            if response.text.strip() and not response.text.startswith("LLM"):
                self.checkpoint.calls[key] = {
                    "text": response.text,
                    "model": response.model,
                    "usage": response.usage,
                }
            else:
                self.checkpoint.failed += 1
            self.checkpoint.save_if_due()
        return response
