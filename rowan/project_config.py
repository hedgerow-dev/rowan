"""Typed project-level configuration for ``.rowan.yml``.

The public file format is deliberately smaller than :class:`ScanConfig`.
Unversioned files are interpreted as schema version 1 for compatibility;
authors may pin the contract explicitly with ``version: 1``.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping
from dataclasses import dataclass, fields
from pathlib import Path
from typing import Any

import yaml
from click import UsageError

from rowan.analysis.object_access_policy import validate_model_policies
from rowan.config import DEPLOYMENT_PROFILES, SCAN_POLICIES, ScanConfig
from rowan.core.findings import Severity
from rowan.core.paths import repo_search_dirs
from rowan.languages import normalize_languages

logger = logging.getLogger(__name__)

PROJECT_CONFIG_SCHEMA_VERSION = 1
_CONFIG_NAMES = (".rowan.yml", ".rowan.yaml")
_BOOL_FIELDS = (
    "no_sca",
    "no_taint",
    "no_cross_file",
    "enable_authz",
    "legacy_neuroscan",
    "scan_vendored",
)


class ProjectConfigError(UsageError, ValueError):
    """A project configuration file does not conform to the public schema."""


@dataclass(frozen=True)
class ProjectConfig:
    """Validated version-1 project-file settings.

    ``None`` means a key was omitted. Empty tuples are retained so an explicit
    empty list remains distinguishable from an omitted list.
    """

    version: int = PROJECT_CONFIG_SCHEMA_VERSION
    exclude: tuple[str, ...] | None = None
    languages: tuple[str, ...] | None = None
    severity: Severity | None = None
    no_sca: bool | None = None
    no_taint: bool | None = None
    no_cross_file: bool | None = None
    enable_authz: bool | None = None
    authz_model_policies: dict[str, dict[str, str]] | None = None
    legacy_neuroscan: bool | None = None
    scan_vendored: bool | None = None
    max_file_bytes: int | None = None
    policy: str | None = None
    profile: str | None = None
    baseline: str | None = None


_SUPPORTED_KEYS = frozenset(field.name for field in fields(ProjectConfig))


def find_project_config(start: Path) -> Path | None:
    """Walk up from ``start`` looking for a project config file."""
    for candidate in repo_search_dirs(start):
        for name in _CONFIG_NAMES:
            path = candidate / name
            if path.is_file():
                return path
    return None


def _error(config_path: Path, key: str | None, message: str) -> ProjectConfigError:
    location = str(config_path)
    if key is not None:
        location = f"{location}: key {key!r}"
    return ProjectConfigError(f"Invalid project config {location}: {message}")


def _string_list(
    raw: object,
    config_path: Path,
    key: str,
    *,
    allow_empty: bool = False,
) -> tuple[str, ...]:
    if not isinstance(raw, list):
        raise _error(config_path, key, "expected a YAML list of non-empty strings")

    values: list[str] = []
    for index, value in enumerate(raw):
        if not isinstance(value, str) or (not allow_empty and not value.strip()):
            raise _error(
                config_path,
                key,
                f"item {index} must be a non-empty string, got {value!r}",
            )
        values.append(value)
    return tuple(values)


def _parse_mapping(raw: Mapping[object, object], config_path: Path) -> ProjectConfig:
    non_string_keys = [repr(key) for key in raw if not isinstance(key, str)]
    if non_string_keys:
        raise _error(
            config_path,
            None,
            "all keys must be strings; invalid key(s): " + ", ".join(non_string_keys),
        )

    unknown = sorted(set(raw) - _SUPPORTED_KEYS)
    if unknown:
        supported = ", ".join(sorted(_SUPPORTED_KEYS))
        raise _error(
            config_path,
            str(unknown[0]),
            f"unknown key; supported keys are: {supported}",
        )

    values: dict[str, Any] = {}

    if "version" in raw:
        version = raw["version"]
        if isinstance(version, bool) or not isinstance(version, int):
            raise _error(config_path, "version", "expected integer 1")
        if version != PROJECT_CONFIG_SCHEMA_VERSION:
            raise _error(
                config_path,
                "version",
                f"unsupported schema version {version!r}; supported version is 1",
            )
        values["version"] = version

    if "exclude" in raw:
        values["exclude"] = _string_list(raw["exclude"], config_path, "exclude")

    if "languages" in raw:
        languages = _string_list(
            raw["languages"], config_path, "languages", allow_empty=True
        )
        try:
            values["languages"] = tuple(normalize_languages(languages))
        except ValueError as exc:
            raise _error(config_path, "languages", str(exc)) from exc

    if "severity" in raw:
        severity = raw["severity"]
        if not isinstance(severity, str):
            raise _error(
                config_path,
                "severity",
                "expected one of: critical, high, medium, low, info",
            )
        try:
            values["severity"] = Severity(severity.strip().lower())
        except ValueError as exc:
            raise _error(
                config_path,
                "severity",
                f"unknown value {severity!r}; expected one of: critical, high, medium, low, info",
            ) from exc

    for key in _BOOL_FIELDS:
        if key not in raw:
            continue
        value = raw[key]
        if not isinstance(value, bool):
            raise _error(
                config_path,
                key,
                f"expected an unquoted YAML boolean (true or false), got {value!r}",
            )
        values[key] = value

    if "max_file_bytes" in raw:
        max_file_bytes = raw["max_file_bytes"]
        if isinstance(max_file_bytes, bool) or not isinstance(max_file_bytes, int):
            raise _error(config_path, "max_file_bytes", "expected an integer")
        values["max_file_bytes"] = max_file_bytes

    if "profile" in raw:
        profile = raw["profile"]
        if not isinstance(profile, str) or profile not in DEPLOYMENT_PROFILES:
            choices = ", ".join(sorted(DEPLOYMENT_PROFILES))
            raise _error(
                config_path,
                "profile",
                f"unknown value {profile!r}; expected one of: {choices}",
            )
        values["profile"] = profile

    if "policy" in raw:
        policy = raw["policy"]
        if not isinstance(policy, str) or policy not in SCAN_POLICIES:
            choices = ", ".join(sorted(SCAN_POLICIES))
            raise _error(
                config_path,
                "policy",
                f"unknown value {policy!r}; expected one of: {choices}",
            )
        values["policy"] = policy

    if "baseline" in raw:
        baseline = raw["baseline"]
        if not isinstance(baseline, str) or not baseline.strip():
            raise _error(config_path, "baseline", "expected a non-empty path string")
        if "\x00" in baseline:
            raise _error(config_path, "baseline", "path must not contain a NUL byte")
        values["baseline"] = baseline

    if "authz_model_policies" in raw:
        try:
            validate_model_policies(raw["authz_model_policies"])
        except ValueError as exc:
            raise _error(config_path, "authz_model_policies", str(exc)) from exc
        values["authz_model_policies"] = {k: dict(v) for k, v in raw["authz_model_policies"].items()}
    return ProjectConfig(**values)


def load_project_config(config_path: Path) -> ProjectConfig:
    """Parse and validate a project config file against the public schema."""
    try:
        raw = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        mark = getattr(exc, "problem_mark", None)
        position = (
            f" at line {mark.line + 1}, column {mark.column + 1}"
            if mark is not None
            else ""
        )
        detail = getattr(exc, "problem", None) or str(exc).splitlines()[0]
        raise _error(
            config_path, None, f"could not parse YAML{position}: {detail}"
        ) from exc
    except (OSError, UnicodeError) as exc:
        detail = str(exc).splitlines()[0] if str(exc) else type(exc).__name__
        raise _error(config_path, None, f"could not read config: {detail}") from exc

    if raw is None:
        raw = {}
    if not isinstance(raw, Mapping):
        raise _error(config_path, None, "expected a top-level YAML mapping")

    config = _parse_mapping(raw, config_path)
    logger.info("Loaded project config: %s (schema v%d)", config_path, config.version)
    return config


def apply_project_config(
    project_config: ProjectConfig | Mapping[object, object],
    config_path: Path,
    scan_config: ScanConfig,
    explicit_fields: set[str] | None = None,
) -> None:
    """Apply validated project settings unless a CLI field takes precedence.

    A mapping is accepted for compatibility with programmatic callers, but it
    is validated through the exact same schema before any value is applied.
    """
    if not isinstance(project_config, ProjectConfig):
        project_config = _parse_mapping(project_config, config_path)

    explicit_fields = explicit_fields or set()
    fresh = type(scan_config)(target=scan_config.target)

    def _is_default(name: str) -> bool:
        if name in explicit_fields:
            return False
        return getattr(scan_config, name) == getattr(fresh, name)

    if project_config.exclude is not None and _is_default("extra_excludes"):
        scan_config.extra_excludes = list(project_config.exclude)

    if project_config.languages is not None and _is_default("languages"):
        scan_config.languages = list(project_config.languages)

    if project_config.severity is not None and _is_default("severity"):
        scan_config.severity = project_config.severity

    for bool_field in _BOOL_FIELDS:
        if bool_field in {"no_sca", "no_taint", "no_cross_file"}:
            continue
        value = getattr(project_config, bool_field)
        if value is not None and _is_default(bool_field):
            setattr(scan_config, bool_field, value)

    # The historic negative keys remain supported.  `true` is an explicit
    # "off" that policy resolution must see; `false` is the documented
    # default and must not force the pass on over the policy (PL-10).
    for negative_field, enable_field in (
        ("no_sca", "enable_sca"),
        ("no_taint", "enable_taint"),
        ("no_cross_file", "enable_cross_file"),
    ):
        value = getattr(project_config, negative_field)
        if (
            value is not None
            and _is_default(negative_field)
            and enable_field not in explicit_fields
        ):
            setattr(scan_config, negative_field, value)
            if value:
                setattr(scan_config, enable_field, False)

    if project_config.max_file_bytes is not None and _is_default("max_file_bytes"):
        scan_config.max_file_bytes = project_config.max_file_bytes

    if project_config.policy is not None and _is_default("policy"):
        scan_config.policy = project_config.policy
    if project_config.authz_model_policies is not None and _is_default("authz_model_policies"):
        scan_config.authz_model_policies = {k: dict(v) for k, v in project_config.authz_model_policies.items()}

    if project_config.profile is not None and _is_default("profile"):
        scan_config.profile = project_config.profile

    if project_config.baseline is not None and _is_default("baseline_path"):
        baseline_path = config_path.parent / project_config.baseline
        if baseline_path.is_file():
            scan_config.baseline_path = baseline_path
        else:
            logger.warning("Project config baseline path not found: %s", baseline_path)
