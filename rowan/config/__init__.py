"""Configuration for Rowan scans."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

from rowan.core.findings import Severity
from rowan.languages import normalize_languages

REPORT_VIEWS: frozenset[str] = frozenset({"full", "actionable", "confirmed"})
OUTPUT_FORMATS: frozenset[str] = frozenset({"text", "json", "sarif", "html"})
DEPLOYMENT_PROFILES: frozenset[str] = frozenset({"server", "library", "cli", "desktop", "auto"})
SCAN_POLICIES: frozenset[str] = frozenset({"default", "fast", "deep"})

# Explicit resource overrides are escape hatches, not permission to create an
# unbounded process/thread fan-out. Automatic policies may choose lower values
# from the target and host; these are hard safety ceilings shared by every
# entry point.
MAX_TAINT_TIMEOUT_SECONDS = 86_400
MAX_LOCAL_CONCURRENCY = 64
RESOURCE_LIMITS: dict[str, int] = {
    "taint_timeout": MAX_TAINT_TIMEOUT_SECONDS,
    "taint_workers": MAX_LOCAL_CONCURRENCY,
    "taint_jobs": MAX_LOCAL_CONCURRENCY,
    "network_concurrency": MAX_LOCAL_CONCURRENCY,
    "concurrency": MAX_LOCAL_CONCURRENCY,
}


@dataclass
class ScanConfig:
    target: Path
    output: Path | None = None
    output_format: str = "text"  # text, json, sarif, html
    severity: Severity | None = None  # minimum severity to report
    # Report view (presentation filter over the computed findings). "full"
    # returns everything (the engine/library default, so programmatic callers
    # and the benchmarks see all findings); the CLI defaults to "actionable"
    # (hide LOW/INFO + surface-signal noise, keep dangerous-sink + computed-
    # evidence); "confirmed" requires computed or self-evident evidence at
    # every severity, including HIGH/CRITICAL.
    report_view: str = "full"
    languages: list[str] = field(default_factory=list)  # empty = all
    # Policy selects a safe, predictable starting point.  Individual
    # enable_* and no_* controls below deliberately remain available as
    # explicit overrides; policy never enables LLM, live-target, or network
    # analysis.
    policy: str = "default"
    no_sca: bool = False
    enable_sca: bool | None = None  # None = policy choice; True = local user opt-in
    no_taint: bool = False
    enable_taint: bool | None = None  # None = policy choice; False = regex-only
    no_cross_file: bool = False
    enable_cross_file: bool | None = None  # None = policy choice
    enable_authz: bool | None = None  # None = policy choice; BOLA/IDOR pass
    authz_model_policies: dict[str, dict[str, str]] = field(default_factory=dict)
    enable_multiagent: bool | None = None  # None = policy choice; CrewAI handoffs
    ci_mode: bool = False
    rules_dir: Path | None = None
    neuroscan_rules: Path | None = None
    taint_rules_dir: Path | None = None
    max_file_lines: int = 5000
    timeout_per_file: int = 30  # seconds
    concurrency: int = 4
    # Maximum in-flight advisory/enrichment requests across this scan.  None
    # inherits the detector-worker budget so the safe default cannot create a
    # hidden second network pool inside SCA.
    network_concurrency: int | None = None
    verbose: bool = False
    thresholds_path: Path | None = None
    profile: str = "auto"
    taint_timeout: int | None = None  # None = derive from the published target scope
    # None selects the bounded, target-aware batch policy.  A positive value
    # remains an expert override (including 1 for deliberately serial scans).
    taint_workers: int | None = None
    taint_jobs: int | None = None  # max Opengrep cores per batch; None = automatic
    opengrep_configs: list[str] = field(default_factory=list)  # extra --config pass-through
    scan_vendored: bool = False  # True disables vendored/minified default excludes
    max_file_bytes: int = 2_000_000  # regex scan file-size cap; <=0 disables
    extra_excludes: list[str] = field(default_factory=list)  # extra glob/dir names to skip
    legacy_neuroscan: bool = False  # use legacy Python re engine for regex rules (default off: converted rules via Opengrep)
    baseline_path: Path | None = None  # report only findings absent from this baseline
    write_baseline_path: Path | None = None  # write current findings as a baseline file
    no_verify: bool = False  # skip adversarial verification stage in hunt mode
    vex_path: Path | None = None  # write an OpenVEX doc (from full, unfiltered SCA findings)
    sbom_path: Path | None = None  # write a CycloneDX SBOM of the dependency inventory

    def __post_init__(self) -> None:
        if self.thresholds_path is None:
            builtin = Path(__file__).parent / "thresholds.yaml"
            if builtin.exists():
                self.thresholds_path = builtin
        self.validate()

    def validate(self) -> None:
        """Validate and normalize the complete effective scan configuration.

        Callers that mutate a config after construction (for example, by
        applying ``.rowan.yml``) must invoke this again. ``ScanPipeline``
        does so unconditionally at its boundary before loading rules or
        running a pass.
        """
        self.languages = normalize_languages(self.languages)
        from rowan.analysis.object_access_policy import validate_model_policies

        validate_model_policies(self.authz_model_policies)

        if not self.target.exists():
            raise ValueError(f"target does not exist: {self.target}")
        if not self.target.is_dir():
            raise ValueError(f"target must be a directory: {self.target}")

        if self.report_view not in REPORT_VIEWS:
            available = ", ".join(sorted(REPORT_VIEWS))
            raise ValueError(
                f"Unsupported report_view: {self.report_view!r}. "
                f"Supported report views: {available}"
            )

        for field_name, value, supported in (
            ("output_format", self.output_format, OUTPUT_FORMATS),
            ("profile", self.profile, DEPLOYMENT_PROFILES),
            ("policy", self.policy, SCAN_POLICIES),
        ):
            if value not in supported:
                available = ", ".join(sorted(supported))
                raise ValueError(
                    f"Unsupported {field_name}: {value!r}. Supported values: {available}"
                )

        for field_name in (
            "enable_sca",
            "enable_taint",
            "enable_cross_file",
            "enable_authz",
            "enable_multiagent",
        ):
            value = getattr(self, field_name)
            if value is not None and not isinstance(value, bool):
                raise ValueError(f"{field_name} must be a boolean or None")

        for field_name in ("taint_timeout", "taint_workers", "taint_jobs", "network_concurrency"):
            value = getattr(self, field_name)
            if value is None:
                continue
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise ValueError(f"{field_name} must be a positive integer (>= 1)")
            maximum = RESOURCE_LIMITS[field_name]
            if value > maximum:
                raise ValueError(f"{field_name} must be <= {maximum}")

        if (
            isinstance(self.concurrency, bool)
            or not isinstance(self.concurrency, int)
            or self.concurrency < 1
        ):
            raise ValueError("concurrency must be a positive integer (>= 1)")
        if self.concurrency > RESOURCE_LIMITS["concurrency"]:
            raise ValueError(f"concurrency must be <= {RESOURCE_LIMITS['concurrency']}")

        if self.no_sca and (self.vex_path or self.sbom_path):
            requested_artifacts = " and ".join(
                option
                for option, path in (
                    ("--vex", self.vex_path),
                    ("--sbom", self.sbom_path),
                )
                if path is not None
            )
            raise ValueError(
                f"--no-sca cannot be used with {requested_artifacts}; "
                "dependency scanning is required to produce supply-chain artifacts"
            )

        for field_name in ("rules_dir", "taint_rules_dir"):
            path = getattr(self, field_name)
            if path is not None and not path.is_dir():
                raise ValueError(f"{field_name} must be an existing directory: {path}")

        for field_name in ("neuroscan_rules", "thresholds_path", "baseline_path"):
            path = getattr(self, field_name)
            if path is not None and not path.is_file():
                raise ValueError(f"{field_name} must be an existing file: {path}")

        for value in self.opengrep_configs:
            if not isinstance(value, str) or not value.strip():
                raise ValueError("opengrep_configs entries must be non-empty strings")
            config_value = value.strip()
            parsed = urlparse(config_value)
            if parsed.scheme and parsed.scheme not in {"http", "https"}:
                raise ValueError(f"opengrep_configs URLs must use http or https: {config_value}")
            looks_local = config_value.startswith((".", "/")) or config_value.endswith(
                (".yaml", ".yml")
            )
            if not parsed.scheme and looks_local and not Path(config_value).is_file():
                raise ValueError(
                    f"opengrep_configs local paths must be existing files: {config_value}"
                )

        path_fields = {
            "output": self.output,
            "write_baseline_path": self.write_baseline_path,
            "vex_path": self.vex_path,
            "sbom_path": self.sbom_path,
        }
        destinations: dict[Path, str] = {}
        for name, path in path_fields.items():
            if path is None:
                continue
            resolved = path.resolve(strict=False)
            if resolved.exists() and not resolved.is_file():
                raise ValueError(f"{name} must be a file path, not a directory: {path}")
            if not resolved.parent.is_dir():
                raise ValueError(f"{name} parent must be an existing directory: {resolved.parent}")
            previous = destinations.get(resolved)
            if previous is not None:
                raise ValueError(
                    f"Output paths must be distinct: {previous} and {name} "
                    f"both resolve to {resolved}"
                )
            destinations[resolved] = name

        if self.baseline_path is not None:
            baseline = self.baseline_path.resolve(strict=False)
            colliding_output = destinations.get(baseline)
            if colliding_output is not None:
                raise ValueError(
                    "baseline_path must not also be a write destination: "
                    f"it collides with {colliding_output}"
                )

    @classmethod
    def default_rules_dir(cls) -> Path:
        """The ``rules/`` tree: repo-root relative in a checkout, or the
        installed ``rules`` package's directory when running from a wheel
        (``rules/`` ships as package data, not under ``rowan/``).
        """
        checkout_rules = Path(__file__).parent.parent.parent / "rules"
        if checkout_rules.is_dir():
            return checkout_rules
        import importlib.resources

        return Path(str(importlib.resources.files("rules")))
