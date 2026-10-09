"""CLI for Rowan: SAST scanner powered by Opengrep."""

from __future__ import annotations

import logging
import sys
from pathlib import Path
from urllib.parse import urlsplit

import click
from rich.console import Console
from rich.table import Table

from rowan import __version__
from rowan.config import (
    MAX_LOCAL_CONCURRENCY,
    MAX_TAINT_TIMEOUT_SECONDS,
    ScanConfig,
)
from rowan.core.finding_clusters import cluster_findings
from rowan.core.findings import Severity
from rowan.languages import normalize_languages
from rowan.pipeline import ScanPipeline
from rowan.scan_plan import ScanPlan, build_scan_plan, execution_stage

console = Console()


def _parse_languages(languages_str: str | None) -> list[str]:
    try:
        return normalize_languages(languages_str.split(",") if languages_str else None)
    except ValueError as exc:
        raise click.UsageError(str(exc)) from exc


def _validate_effective_config(config: ScanConfig) -> None:
    """Expose library validation as a friendly Click usage error.

    Builds the plan as well: it is pure and cheap, and it holds the checks
    that need the resolved policy (for example --sbom with SCA off).
    """
    try:
        config.validate()
        build_scan_plan(config)
    except ValueError as exc:
        raise click.UsageError(str(exc)) from exc


def _emit_scan_plan(plan: ScanPlan, *, as_json: bool) -> None:
    """Print a path-free plan suitable for humans or machine inspection."""
    if as_json:
        import json

        click.echo(json.dumps(plan.as_dict(), indent=2, sort_keys=True))
        return

    console.print("[bold]Rowan scan plan[/bold]")
    policy = Table(title="Effective policy", show_header=False)
    policy.add_column("Setting", style="bold")
    policy.add_column("Value")
    for key, value in plan.effective_policy.items():
        rendered = ", ".join(value) if isinstance(value, list) else str(value).lower()
        policy.add_row(key, rendered)
    console.print(policy)

    passes = Table(title="Ordered passes")
    passes.add_column("#", justify="right")
    passes.add_column("Pass", style="bold")
    passes.add_column("Stage")
    passes.add_column("Status", no_wrap=True)
    passes.add_column("Reason")
    selected_index = 0
    for item in plan.in_execution_order():
        if item.selected:
            selected_index += 1
            order = str(selected_index)
            status = "selected"
        else:
            order = "-"
            status = "explicitly disabled"
        passes.add_row(order, item.name, execution_stage(item.name), status, item.reason)
    console.print(passes)


def _is_local_target(hostname: str) -> bool:
    """True when every address `hostname` names is loopback or private.

    Link-local is not local here: it holds cloud metadata services
    (169.254.169.254), which a probe of the scanned app should never reach
    without an explicit --allow-remote-target.
    """
    import ipaddress
    import socket

    def local(address: str) -> bool:
        ip = ipaddress.ip_address(address.split("%", 1)[0])
        # Judge an IPv4-mapped IPv6 address by its IPv4 part: some Python
        # 3.10/3.11 releases call all of ::ffff:0:0/96 private (CVE-2024-4032).
        if ip.version == 6 and ip.ipv4_mapped is not None:
            ip = ip.ipv4_mapped
        if ip.is_link_local:
            return False
        return ip.is_loopback or ip.is_private

    if hostname.lower() == "localhost":
        return True
    try:
        return local(hostname)
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(hostname, None)
    except (socket.gaierror, UnicodeError):
        return False
    return bool(infos) and all(local(info[4][0]) for info in infos)


def _validate_hunt_options(
    *,
    discover: bool,
    no_verify: bool,
    exploit: bool,
    base_url: str | None,
    allow_remote_target: bool = False,
) -> str | None:
    """Validate Hunt stage dependencies before any external setup or work."""
    if discover and no_verify:
        raise click.UsageError(
            "--discover cannot be used with --no-verify; "
            "discovery findings require adversarial verification"
        )

    if not exploit:
        if base_url is not None:
            raise click.UsageError("--base-url requires --exploit")
        return None
    if not base_url:
        raise click.UsageError("--exploit requires --base-url with an absolute HTTP(S) URL")

    if base_url != base_url.strip() or any(char.isspace() for char in base_url):
        raise click.UsageError("Invalid --base-url: whitespace is not allowed")
    try:
        parsed = urlsplit(base_url)
        # Accessing these properties performs bracket and port validation.
        hostname = parsed.hostname
        _port = parsed.port
    except ValueError as exc:
        raise click.UsageError(f"Invalid --base-url: {exc}") from exc

    if parsed.scheme.lower() not in {"http", "https"} or not hostname:
        raise click.UsageError(
            "Invalid --base-url: expected an absolute HTTP(S) URL with a hostname"
        )
    if parsed.username is not None or parsed.password is not None:
        raise click.UsageError("Invalid --base-url: embedded credentials are not allowed")
    if parsed.query or "?" in base_url:
        raise click.UsageError("Invalid --base-url: query strings are not allowed")
    if parsed.fragment or "#" in base_url:
        raise click.UsageError("Invalid --base-url: fragments are not allowed")
    # Live probes send real requests. Without an explicit opt-in they only go
    # to this machine or a private network, so a typo or a copied URL cannot
    # point them at someone else's system.
    if not allow_remote_target and not _is_local_target(hostname):
        raise click.UsageError(
            f"--base-url host {hostname!r} is not a loopback or private address "
            "(link-local addresses, including cloud metadata, are excluded). "
            "Probes against remote systems need --allow-remote-target, and you must "
            "be authorized to test the target."
        )
    return base_url


@click.group(invoke_without_command=True)
@click.version_option(version=__version__)
@click.pass_context
def main(ctx: click.Context):
    """Rowan SAST Scanner -- Open-source static analysis powered by Opengrep taint engine."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    )
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


@main.command()
@click.argument("target", type=click.Path(exists=True, path_type=Path))
@click.option("--output", "-o", type=click.Path(path_type=Path), help="Output file path")
@click.option(
    "--format",
    "-f",
    "output_format",
    type=click.Choice(["text", "json", "sarif", "html"]),
    default="text",
    help="Output format",
)
@click.option(
    "--severity",
    "-s",
    type=click.Choice(["critical", "high", "medium", "low", "info"]),
    help="Minimum severity to report",
)
@click.option(
    "--audit",
    is_flag=True,
    help="Show every finding, including LOW/INFO and surface-signal noise the default (actionable) view hides",
)
@click.option(
    "--confirmed",
    is_flag=True,
    help="Strictest view: dangerous-category findings must be taint-confirmed (intra- or cross-file); highest precision",
)
@click.option(
    "--lang", "-l", "languages_str", help="Comma-separated language filter (python,javascript,etc.)"
)
@click.option(
    "--sca/--no-sca",
    "enable_sca",
    default=None,
    help="Enable/disable dependency vulnerability analysis (network access; enabled by default and deep policies)",
)
@click.option(
    "--taint/--no-taint",
    "enable_taint",
    default=None,
    help="Enable/disable Opengrep taint dataflow (fast policy uses regex-only)",
)
@click.option(
    "--cross-file/--no-cross-file",
    "enable_cross_file",
    default=None,
    help="Enable/disable cross-file repository analysis",
)
@click.option(
    "--authz/--no-authz",
    "enable_authz",
    default=None,
    help="Enable/disable object-level authorization (BOLA/IDOR) detection",
)
@click.option(
    "--multiagent/--no-multiagent",
    "enable_multiagent",
    default=None,
    help="Enable/disable cross-agent injection propagation detection (CrewAI handoffs)",
)
@click.option(
    "--policy",
    type=click.Choice(["default", "fast", "deep"]),
    default="default",
    show_default=True,
    help="Scan policy; primitive flags override its capabilities",
)
@click.option("--ci", "ci_mode", is_flag=True, help="CI mode: exit 1 if findings found, 2 if the scan is degraded")
@click.option(
    "--fail-on-degraded",
    is_flag=True,
    help="Exit 2 if the scan is degraded (incomplete), with or without --ci",
)
@click.option(
    "--exclude",
    "excludes",
    multiple=True,
    metavar="PATTERN",
    help="Skip files or directories matching PATTERN (repeatable). Unlike the repository's own ignore file, trusted under --ci.",
)
@click.option(
    "--project-config/--no-project-config",
    default=None,
    help="Load .rowan.yml (default: enabled locally, disabled in CI)",
)
@click.option(
    "--explain-plan",
    is_flag=True,
    help="Resolve configuration and show the pass plan without running analyzers",
)
@click.option(
    "--vex",
    "vex_path",
    type=click.Path(path_type=Path),
    help="Write an OpenVEX document (dependency CVE exploitability, driven by reachability)",
)
@click.option(
    "--sbom",
    "sbom_path",
    type=click.Path(path_type=Path),
    help="Write a CycloneDX SBOM of the full dependency inventory",
)
@click.option(
    "--baseline",
    "baseline_path",
    type=click.Path(exists=True, path_type=Path),
    help="Report only findings absent from this baseline file",
)
@click.option(
    "--write-baseline",
    "write_baseline_path",
    type=click.Path(path_type=Path),
    help="Write current findings to a baseline file (for later --baseline diffs)",
)
@click.option(
    "--thresholds",
    "thresholds_path",
    type=click.Path(exists=True, path_type=Path),
    help="Path to thresholds.yaml for per-rule suppression",
)
@click.option(
    "--profile",
    type=click.Choice(["server", "library", "cli", "desktop", "auto"]),
    default="auto",
    help="Deployment profile (auto detects web frameworks)",
)
@click.option(
    "--taint-timeout",
    "taint_timeout",
    type=click.IntRange(min=1, max=MAX_TAINT_TIMEOUT_SECONDS),
    default=None,
    help="Per-batch opengrep timeout in seconds (overrides target-aware default)",
)
@click.option(
    "--taint-workers",
    "taint_workers",
    type=click.IntRange(min=1, max=MAX_LOCAL_CONCURRENCY),
    default=None,
    help="Parallel opengrep batches (default: bounded target-aware policy; 1 forces serial)",
)
@click.option(
    "--taint-jobs",
    "taint_jobs",
    type=click.IntRange(min=1, max=MAX_LOCAL_CONCURRENCY),
    default=None,
    help="Maximum Opengrep CPU workers per batch",
)
@click.option(
    "--network-concurrency",
    type=click.IntRange(min=1, max=MAX_LOCAL_CONCURRENCY),
    default=None,
    help="Maximum in-flight advisory/enrichment requests (default: --concurrency)",
)
@click.option(
    "--opengrep-config",
    "opengrep_configs",
    multiple=True,
    help="Additional opengrep --config (e.g. auto, p/python, path); repeatable",
)
@click.option(
    "--legacy-neuroscan/--no-legacy-neuroscan",
    is_flag=True,
    default=False,
    help="Use legacy Python re engine for regex rules (default off; --legacy-neuroscan to revert)",
)
@click.option("--verbose", "-v", is_flag=True, help="Verbose output")
def scan(
    target: Path,
    output: Path | None,
    output_format: str,
    severity: str | None,
    audit: bool,
    confirmed: bool,
    languages_str: str | None,
    enable_sca: bool | None,
    enable_taint: bool | None,
    enable_cross_file: bool | None,
    enable_authz: bool | None,
    enable_multiagent: bool | None,
    policy: str,
    ci_mode: bool,
    fail_on_degraded: bool,
    excludes: tuple[str, ...],
    project_config: bool | None,
    explain_plan: bool,
    vex_path: Path | None,
    sbom_path: Path | None,
    baseline_path: Path | None,
    write_baseline_path: Path | None,
    thresholds_path: Path | None,
    profile: str,
    taint_timeout: int | None,
    taint_workers: int | None,
    taint_jobs: int | None,
    network_concurrency: int | None,
    opengrep_configs: tuple[str, ...],
    legacy_neuroscan: bool,
    verbose: bool,
):
    """Scan a project directory for vulnerabilities.

    Exit codes:
      0  success (no findings, or non-CI run)
      1  CI mode: findings present and scan was NOT degraded
      2  CI mode: scan was degraded (e.g. opengrep taint timeout); results
         are incomplete and must not be treated as a clean pass
    """
    if audit and confirmed:
        raise click.UsageError("--audit and --confirmed cannot be used together")

    # Per-pass progress logs are for debugging; warnings (such as a degraded
    # pass) still print.
    logging.getLogger("rowan").setLevel(logging.DEBUG if verbose else logging.WARNING)

    languages = _parse_languages(languages_str)

    try:
        target = target.resolve()
    except OSError:
        console.print(f"[red]Error:[/red] Cannot resolve path: {target}")
        sys.exit(1)

    if not target.is_dir():
        console.print(f"[red]Error:[/red] Target must be a directory: {target}")
        sys.exit(1)

    try:
        config = ScanConfig(
            target=target,
            output=output,
            output_format=output_format,
            severity=Severity(severity) if severity else None,
            # CLI default is the actionable view; --audit shows everything, --confirmed
            # is the strictest. (The ScanConfig default is "full" for library callers.)
            report_view=("full" if audit else "confirmed" if confirmed else "actionable"),
            languages=languages,
            policy=policy,
            no_sca=enable_sca is False,
            enable_sca=enable_sca,
            no_taint=enable_taint is False,
            enable_taint=enable_taint,
            no_cross_file=enable_cross_file is False,
            enable_cross_file=enable_cross_file,
            enable_authz=enable_authz,
            enable_multiagent=enable_multiagent,
            ci_mode=ci_mode,
            verbose=verbose,
            thresholds_path=thresholds_path,
            profile=profile,
            taint_timeout=taint_timeout,
            taint_workers=taint_workers,
            taint_jobs=taint_jobs,
            network_concurrency=network_concurrency,
            opengrep_configs=list(opengrep_configs),
            legacy_neuroscan=legacy_neuroscan,
            extra_excludes=list(excludes),
            baseline_path=baseline_path,
            write_baseline_path=write_baseline_path,
            vex_path=vex_path,
            sbom_path=sbom_path,
        )
    except ValueError as exc:
        raise click.UsageError(str(exc)) from exc

    from rowan.project_config import (
        apply_project_config,
        find_project_config,
        load_project_config,
    )

    use_project_config = not ci_mode if project_config is None else project_config
    _cfg_path = find_project_config(target) if use_project_config else None
    if _cfg_path:
        # These fields have an off/default value that's also independently
        # choosable on the CLI (--no-legacy-neuroscan == the default; --profile
        # auto == the default), so "still at default" can't tell "never
        # touched" apart from "explicitly chosen the default" -- ask Click
        # directly which ones were actually passed on the command line.
        ctx = click.get_current_context()
        explicit_fields = {
            name
            for name in (
                "legacy_neuroscan",
                "profile",
                "policy",
                "enable_sca",
                "enable_taint",
                "enable_cross_file",
                "enable_authz",
                "enable_multiagent",
            )
            if ctx.get_parameter_source(name) == click.ParameterSource.COMMANDLINE
        }
        apply_project_config(
            load_project_config(_cfg_path), _cfg_path, config, explicit_fields=explicit_fields
        )

    # Project settings can change a previously valid config, so validate the
    # resolved values rather than only the raw CLI flags.
    _validate_effective_config(config)

    if explain_plan:
        _emit_scan_plan(build_scan_plan(config), as_json=output_format == "json")
        return

    raw_machine_output = output is None and output_format in {"json", "sarif", "html"}
    if not raw_machine_output:
        console.print(f"[bold]Rowan[/bold] v{__version__}")
        console.print(f"Scanning: {target}")
        # The effective config, after .rowan.yml (PL-13).
        if _cfg_path:
            console.print(f"Project config: {_cfg_path}")
        console.print(f"Severity filter: {config.severity.value if config.severity else 'all'}")
        console.print(f"Languages: {', '.join(config.languages) if config.languages else 'all'}")
        console.print()

    pipeline = ScanPipeline(config)
    result = pipeline.run()

    if raw_machine_output:
        # Machine-readable formats are often piped directly to a CI parser.
        # Keep stdout limited to the requested document; logging and degraded
        # warnings continue to use stderr.
        from rowan.reporters import to_html, to_json, to_sarif

        if output_format == "json":
            click.echo(to_json(result, str(target)))
        elif output_format == "sarif":
            import json

            click.echo(json.dumps(to_sarif(result, str(target)), indent=2))
        else:
            click.echo(to_html(result))
    else:
        if write_baseline_path:
            console.print(f"[green]Baseline written:[/green] {write_baseline_path}")
        if baseline_path:
            suppressed = result.metadata.get("baseline_suppressed", 0)
            console.print(
                f"[dim]Baseline: {suppressed} known finding(s) suppressed; showing new only.[/dim]"
            )

        _print_summary(result)
        _hidden = result.metadata.get("actionable_hidden", 0)
        if _hidden and not audit:
            _view = result.metadata.get("view", "actionable")
            _by_sev = result.metadata.get("actionable_hidden_by_severity", {})
            _detail = ", ".join(f"{n} {s}" for s, n in _by_sev.items()) or "surface/informational"
            console.print(
                f"[dim]{_view.capitalize()} view: {_hidden} finding(s) hidden "
                f"({_detail}). Rerun with --audit to see them.[/dim]"
            )
        _print_findings_table(result)

        if output:
            console.print(f"\n[green]Report written to:[/green] {output}")
        if vex_path:
            console.print(f"[green]VEX document written to:[/green] {vex_path}")
        if sbom_path:
            console.print(f"[green]SBOM written to:[/green] {sbom_path}")

    if result.degraded:
        for name, reason in result.degraded_passes.items():
            print(f"WARNING: degraded scan ({name}): {reason}", file=sys.stderr)
        print(
            "WARNING: scan results are INCOMPLETE; do not treat as a clean pass.",
            file=sys.stderr,
        )

    if (ci_mode or fail_on_degraded) and result.degraded:
        sys.exit(2)
    if ci_mode:
        if result.total_count > 0:
            sys.exit(1)


@main.command()
def self_test():
    """Check that Opengrep is installed and working."""
    from rowan.taint import OpengrepAdapter

    adapter = OpengrepAdapter()

    console.print("[bold]Rowan Self-Test[/bold]")
    console.print()

    if adapter.is_installed():
        console.print(f"[green][OK][/green] Opengrep found: {adapter.get_version()}")
    else:
        console.print("[yellow][WARN][/yellow] Opengrep not found on PATH.")
        console.print("  Run: rowan install-engine")
        console.print("  Taint analysis will be unavailable without it.")

    rules_dir = ScanConfig.default_rules_dir()
    neuroscan = rules_dir / "neuroscan.yaml"
    if neuroscan.exists():
        console.print(f"[green][OK][/green] NeuroScan rules found: {neuroscan}")
    else:
        console.print(f"[yellow][WARN][/yellow] NeuroScan rules not found: {neuroscan}")

    taint_rules = sorted(
        set(rules_dir.glob("*_taint.yaml")) | set(rules_dir.glob("*_taint_*.yaml"))
    )
    if taint_rules:
        console.print(f"[green][OK][/green] Taint rules found: {len(taint_rules)} files")
    else:
        console.print(f"[yellow][WARN][/yellow] No taint rules in {rules_dir}")

    console.print()
    console.print("[bold]Checks complete.[/bold]")
    if not adapter.is_installed():
        sys.exit(1)


@main.command("install-engine")
@click.option(
    "--prefix",
    type=click.Path(path_type=Path),
    default=None,
    help="Install prefix (binary placed in <prefix>/bin). Defaults to ~/.local",
)
@click.option(
    "--version",
    default=None,
    help="Release tag (default v1.29.0, verified by a built-in hash). Other tags, or 'latest', need cosign",
)
@click.option(
    "--allow-unverified",
    is_flag=True,
    help="Install even if cosign or the release's signature assets are unavailable. NOT recommended.",
)
def install_engine(prefix: Path | None, version: str | None, allow_unverified: bool):
    """Download and install the Opengrep taint-analysis engine.

    The default version is checked against a SHA-256 built into Rowan, so no
    extra tool is needed. Any other version needs cosign for signature
    verification; pass --allow-unverified only if you accept that risk.
    """
    from pathlib import Path as _Path

    from rowan.install_opengrep import install

    _prefix = prefix or (_Path.home() / ".local")
    try:
        install(_prefix, require_signature=not allow_unverified, version=version)
    except Exception as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise SystemExit(1) from exc


@main.command()
@click.argument("target", type=click.Path(exists=True, path_type=Path))
@click.option(
    "--backend",
    "-b",
    type=click.Choice(["auto", "deepseek", "openai", "openrouter", "alibaba", "ollama", "local"]),
    default="auto",
    show_default=True,
    help="LLM backend for triage; auto selects configured cloud credentials or local Ollama",
)
@click.option("--model", "-m", help="Override default model")
@click.option("--lang", "-l", "languages_str", help="Comma-separated language filter")
@click.option("--no-sca", is_flag=True, help="Skip dependency scan")
@click.option(
    "--no-verify",
    "no_verify",
    is_flag=True,
    help="Skip adversarial verification (second-opinion LLM pass after triage)",
)
@click.option(
    "--exploit",
    is_flag=True,
    help="Enable live HTTP exploit probes against in-scope targets (off by default; sends real requests)",
)
@click.option(
    "--discover",
    is_flag=True,
    help="Enable the LLM discovery stage: asks the model to find vulnerabilities the rule corpus cannot express, across recognized attack surfaces and files the scan implicated (off by default; costs extra LLM calls)",
)
@click.option(
    "--base-url",
    "base_url",
    help="Deployed base URL of the scanned app (e.g. http://localhost:5000) used with --exploit to build real request targets from extracted route paths; without it, --exploit has nothing live to probe",
)
@click.option(
    "--audit-log",
    "audit_log",
    type=click.Path(path_type=Path, dir_okay=False),
    help="Append one JSON line per LLM call and live probe to this file (endpoint, sizes, hashes, outcome; never content)",
)
@click.option(
    "--allow-remote-target",
    is_flag=True,
    help="Allow --exploit probes against a --base-url outside loopback and private networks (only for systems you are authorized to test)",
)
@click.option(
    "--yes",
    "-y",
    is_flag=True,
    help="Skip the prompt confirming that source code is sent to the LLM endpoint",
)
@click.option("--output", "-o", type=click.Path(path_type=Path), help="Save report to file")
@click.option(
    "--max-llm-calls",
    type=click.IntRange(min=0),
    default=None,
    help="Stop sending LLM requests after this many (a spend ceiling; `estimate` shows the expected count). Skipped batches are listed as errors.",
)
@click.option(
    "--format",
    "-f",
    "output_format",
    type=click.Choice(["text", "json"]),
    default="text",
    help="Output format (json emits structured findings + hunt triage)",
)
@click.option(
    "--project-config/--no-project-config",
    default=True,
    help="Load the target's .rowan.yml (use --no-project-config on code you do not trust: its excludes remove paths from Recon)",
)
@click.option("--discovery-files", type=click.IntRange(1, 500), default=25, show_default=True)
@click.option("--discovery-lines", type=click.IntRange(1, 10000), default=400, show_default=True)
@click.option("--verification-lines", type=click.IntRange(1, 5000), default=240, show_default=True)
@click.option("--verification-files", type=click.IntRange(1, 25), default=4, show_default=True)
@click.option("--checkpoint", type=click.Path(path_type=Path), help="Save resumable successful calls outside the scanned target; contains source-derived data")
@click.option("--resume", is_flag=True, help="Replay successful calls from --checkpoint against unchanged inputs")
@click.option("--hunt-view", type=click.Choice(["full", "verified"]), default="full", help="JSON finding view; full retains the static audit inventory")
@click.option("--verbose", "-v", is_flag=True, help="Verbose output")
def hunt(
    target: Path,
    backend: str,
    model: str | None,
    languages_str: str | None,
    no_sca: bool,
    no_verify: bool,
    exploit: bool,
    discover: bool,
    base_url: str | None,
    allow_remote_target: bool,
    audit_log: Path | None,
    yes: bool,
    output: Path | None,
    max_llm_calls: int | None,
    output_format: str,
    project_config: bool,
    verbose: bool,
    discovery_files: int,
    discovery_lines: int,
    verification_lines: int,
    verification_files: int,
    checkpoint: Path | None,
    resume: bool,
    hunt_view: str,
):
    """Autonomous vulnerability hunting with LLM-powered triage.

    Runs static scan -> LLM hypothesis generation -> adversarial verify -> deep-dive
    -> exploit confirmation -> web exploit probes -> vulnerability report.

    --discover adds a stage after deep-dive that asks the model for defects the
    rule corpus cannot express; its findings are tagged engine="llm-discovery".

    Cloud backends ask before sending source snippets unless --yes is passed.
    Ollama and local backends keep source on the configured local endpoint.
    Live HTTP probes are off unless --exploit is passed.

    Cloud backends require their API key. The default auto mode can instead use
    a reachable local Ollama service without cloud credentials or credits.
    """
    if resume and checkpoint is None:
        raise click.UsageError("--resume requires --checkpoint")
    if checkpoint and exploit:
        raise click.UsageError("Checkpoint replay cannot be combined with live exploit probes")
    if hunt_view != "full" and output_format != "json":
        raise click.UsageError("--hunt-view verified requires --format json")
    base_url = _validate_hunt_options(
        discover=discover,
        no_verify=no_verify,
        exploit=exploit,
        base_url=base_url,
        allow_remote_target=allow_remote_target,
    )

    if verbose:
        logging.getLogger("rowan").setLevel(logging.DEBUG)

    from rowan.agents import HuntState, HuntWorkflow, LLMBackend

    target = target.resolve()
    languages = _parse_languages(languages_str)

    if backend == "auto":
        llm = LLMBackend.from_env(
            model=model,
            temperature=0.1,
            max_tokens=4096,
        )
        backend = llm.backend
    else:
        llm = LLMBackend(
            backend=backend,
            model=model,
            temperature=0.1,
            max_tokens=4096,
        )

    llm.max_calls = max_llm_calls

    console.print("[bold]Rowan Hunt[/bold]")
    console.print(f"Target: {target}")
    console.print(f"LLM: {llm}")
    if max_llm_calls is not None:
        console.print(f"LLM call budget: {max_llm_calls}")
    console.print()

    if not llm.is_configured:
        console.print("[red]No LLM API key configured.[/red]")
        console.print(
            "Set DEEPSEEK_API_KEY, OPENAI_API_KEY, OPENROUTER_API_KEY, or ALIBABA_TOKEN_PLAN_API_KEY environment variable."
        )
        console.print("Running without LLM triage: static scan only.\n")
    elif backend in ("ollama", "local"):
        # For local backends, check the server is actually reachable before
        # proceeding, since an unreachable server would otherwise cause silent
        # failure deep inside the workflow with no actionable message.
        console.print(f"[dim]Checking local LLM server at {llm.base_url} ...[/dim]")
        if not llm.check_connectivity(timeout=3):
            console.print(f"[red]Cannot reach {llm.base_url}.[/red]")
            if backend == "ollama":
                console.print("  Start Ollama:  ollama serve")
                console.print(f"  Pull a model:  ollama pull {llm.model}")
            else:
                console.print(f"  Ensure your local LLM server is running at {llm.base_url}")
            console.print("Running without LLM triage: static scan only.\n")
            llm.disable()
        else:
            console.print(f"[green]Connected to {llm.base_url} (model: {llm.model})[/green]\n")
    elif not yes:
        # Confirm before any source code leaves the machine.
        console.print(
            f"[yellow]Triage will send snippets of your source code to[/yellow] "
            f"[bold]{llm.base_url}[/bold][yellow] for analysis.[/yellow]"
        )
        if not sys.stdin.isatty():
            llm.disable()
            console.print(
                "[yellow]Non-interactive session: skipping LLM triage (pass --yes to allow). Static scan only.[/yellow]\n"
            )
        elif not click.confirm("Send source code to this LLM endpoint?", default=False):
            llm.disable()
            console.print("[yellow]Declined: running static scan only (no code sent).[/yellow]\n")

    if exploit:
        console.print(
            f"[bold red]Live exploit probes enabled[/bold red] against [bold]{base_url}[/bold]: rowan will send real HTTP requests built from discovered sink routes. Only use against systems you are authorized to test.\n"
        )

    if discover:
        if not llm.is_configured:
            console.print(
                "[yellow]--discover needs an LLM backend; with none configured the stage is skipped.[/yellow]\n"
            )
        else:
            console.print(
                "[bold]LLM discovery enabled:[/bold] the model will be asked to find defects the rule corpus cannot express, across recognized attack surfaces and files the scan implicated. These findings carry no rule and are tagged [bold]engine=llm-discovery[/bold]; treat them as leads, not results.\n"
            )

    from rowan.agents.workflow import resolve_hunt_scan_config

    try:
        _note_project_config(target, project_config)
        config = resolve_hunt_scan_config(
            target,
            languages=languages,
            no_sca=no_sca,
            no_taint=False,
            no_verify=no_verify,
            project_config=project_config,
        )
    except ValueError as exc:
        raise click.UsageError(str(exc)) from exc

    from rowan.agents.hunt_inventory import HuntBudgets

    state = HuntState(
        target_path=target,
        config=config,
        llm=llm,
        enable_exploit=exploit,
        enable_discovery=discover,
        base_url=base_url,
        budgets=HuntBudgets(discovery_files, discovery_lines, verification_lines, verification_files),
        checkpoint_path=checkpoint,
        resume=resume,
    )

    workflow = HuntWorkflow(state)

    stages = ["recon", "hypothesize", "verify", "deepdive"]
    if discover:
        stages.append("discover")
    stages += ["exploit", "webexploit", "report"]
    console.print(f"[bold]Stages:[/bold] {' -> '.join(stages)}")
    console.print()

    from rowan.agents.audit import close_audit_log, open_audit_log

    audit_handler = open_audit_log(audit_log) if audit_log else None
    try:
        workflow.run()
    except ValueError as exc:
        raise click.UsageError(str(exc)) from exc
    finally:
        if audit_handler is not None:
            close_audit_log(audit_handler)

    if output_format == "json":
        from rowan.reporters import hunt_to_json

        payload = hunt_to_json(state, view=hunt_view)
        if output:
            output.write_text(payload, encoding="utf-8")
            console.print(f"[green]JSON report written to:[/green] {output}")
        else:
            click.echo(payload)
        if state.run_status in {"incomplete", "interrupted"}:
            click.get_current_context().exit(1)
        return

    # Print summary
    console.print()
    table = Table(title="Hunt Results")
    table.add_column("Stage", style="bold")
    table.add_column("Result")

    aiml_hyps = sum(1 for h in state.hypotheses if h.get("aiml"))
    aiml_chains = sum(1 for c in state.chains if c.get("aiml"))
    table.add_row("Surface findings", str(len(state.surface)))
    table.add_row("HTTP sinks", str(len(state.http_sinks)))
    table.add_row("Model files", f"{len(state.model_files)} ({len(state.model_findings)} flagged)")
    table.add_row("Hypotheses", f"{len(state.hypotheses)} ({aiml_hyps} AI/ML)")
    if discover:
        ds = state.discovery_stats
        table.add_row(
            "Discovered (LLM)",
            f"{len(state.discovered)} upheld / {ds['raw']} claimed "
            f"over {ds['files_examined']} files",
        )
    table.add_row("Chains", f"{len(state.chains)} ({aiml_chains} AI/ML kill-chains)")
    table.add_row("Vulnerable", str(state.vulnerable))

    console.print(table)

    if state.hypotheses:
        console.print()
        console.print("[bold]--- TOP HYPOTHESES ---[/bold]")
        for h in state.hypotheses[:10]:
            expl = h.get("exploitability", "?")
            color = {"confirmed": "red", "likely": "orange1", "possible": "yellow"}.get(expl, "dim")
            console.print(
                f"  [{color}]{expl:11s}[/{color}] {h.get('rule_id', '?'):20s} "
                f"{h.get('file', '?')}:{h.get('line', '?')}"
            )
            if h.get("attack_story"):
                console.print(f"    [dim]{h['attack_story']}[/dim]")
            console.print()

    if state.discovered:
        console.print()
        console.print("[bold]--- DISCOVERED (LLM, no rule behind these) ---[/bold]")
        for f in state.discovered[:10]:
            rel = f.metadata.get("relative_path", f.file_path)
            console.print(
                f"  [magenta]{f.severity.value:8s}[/magenta] {f.rule_id:26s} {rel}:{f.start_line}"
            )
            console.print(f"    {f.message}")
            if f.metadata.get("reachability"):
                console.print(f"    [dim]{f.metadata['reachability']}[/dim]")
            console.print()

    _print_chains(state.chains)

    if state.report:
        console.print()
        console.print("[bold]--- REPORT ---[/bold]")
        console.print(state.report[:2000])
        if len(state.report) > 2000:
            console.print(f"[dim]... truncated ({len(state.report)} chars total)[/dim]")

    if output:
        output.write_text(state.report, encoding="utf-8")
        console.print(f"\n[green]Report saved to:[/green] {output}")

    console.print(f"Hunt status: {state.run_status}")

    if state.errors:
        console.print()
        console.print("[yellow]Errors encountered:[/yellow]")
        for err in state.errors:
            console.print(f"  [dim]{err}[/dim]")
    if state.run_status in {"incomplete", "interrupted"}:
        click.get_current_context().exit(1)



def _print_chains(chains: list[dict]) -> None:
    """Confirmed chains and evidence leads, printed under separate headers."""
    confirmed = [c for c in chains if c.get("status") == "confirmed"]
    leads = [c for c in chains if c.get("status") != "confirmed"]
    for title, color, group in (
        ("CONFIRMED CHAINS", "red", confirmed),
        ("EVIDENCE LEADS", "yellow", leads),
    ):
        if not group:
            continue
        console.print()
        console.print(f"[bold][{color}]--- {title} ---[/{color}][/bold]")
        for c in group[:5]:
            console.print(f"  Type: {c.get('type', '?')}")
            console.print(f"  Source: {c.get('source', '?')}")
            if c.get("status") != "confirmed":
                console.print(
                    f"  Lead: {c.get('lead_reason', 'not confirmed')} "
                    f"(evidence: {c.get('evidence_state', 'unknown')})"
                )
            if c.get("reachability_assessment"):
                assessment = c["reachability_assessment"]
                console.print(f"  Reachability: {assessment.get('status', 'unresolved')}")
                if assessment.get("prerequisites"):
                    console.print("  Prerequisites: " + "; ".join(assessment["prerequisites"]))
            if c.get("attack_story"):
                console.print(f"  {c['attack_story']}")
            console.print()


def _note_project_config(target: Path, enabled: bool) -> None:
    """Say which repo config shapes a hunt, so excluded paths are not a surprise."""
    from rowan.project_config import find_project_config, load_project_config

    config_path = find_project_config(target) if enabled else None
    if config_path is None:
        return
    excludes = load_project_config(config_path).exclude or ()
    console.print(
        f"Using project config {config_path}"
        + (f" (excludes: {', '.join(excludes)})" if excludes else "")
        + "; pass --no-project-config to ignore it.\n"
    )


@main.command()
@click.argument("target", type=click.Path(exists=True, path_type=Path))
@click.option(
    "--backend",
    "-b",
    type=click.Choice(["deepseek", "openai", "openrouter", "alibaba", "ollama", "local"]),
    default="deepseek",
    help="LLM backend to project batch counts for (affects batch size only, not token math)",
)
@click.option("--lang", "-l", "languages_str", help="Comma-separated language filter")
@click.option(
    "--no-sca", is_flag=True, help="Skip dependency scan (matches the hunt run this estimates)"
)
@click.option(
    "--discover",
    is_flag=True,
    help="Include the LLM discovery stage in the estimate (matches `hunt --discover`)",
)
@click.option("--discovery-files", type=click.IntRange(1, 500), default=25, show_default=True)
@click.option("--discovery-lines", type=click.IntRange(1, 10000), default=400, show_default=True)
@click.option("--verification-lines", type=click.IntRange(1, 5000), default=240, show_default=True)
@click.option("--verification-files", type=click.IntRange(1, 25), default=4, show_default=True)
@click.option(
    "--project-config/--no-project-config",
    default=True,
    help="Load the target's .rowan.yml (use --no-project-config on code you do not trust: its excludes remove paths from Recon)",
)
def estimate(
    target: Path,
    backend: str,
    languages_str: str | None,
    no_sca: bool,
    discover: bool,
    project_config: bool,
    discovery_files: int,
    discovery_lines: int,
    verification_lines: int,
    verification_files: int,
):
    """Preview hunt's LLM scope/cost for a target (spends zero tokens).

    Runs hunt's own static recon stage (free) and applies hunt's real
    priority-filtering and batching logic to project how many LLM calls and
    roughly how many tokens a full `hunt` run against TARGET would make. No
    LLM backend is contacted.
    """
    from rowan.agents import estimate_hunt

    target = target.resolve()
    languages = _parse_languages(languages_str)

    console.print("[bold]Rowan Hunt Estimate[/bold]")
    console.print(f"Target: {target}\n")

    _note_project_config(target, project_config)
    result = estimate_hunt(
        target,
        languages=languages,
        no_sca=no_sca,
        backend=backend,
        discover=discover,
        project_config=project_config,
        discovery_files=discovery_files,
        discovery_lines=discovery_lines,
        verification_lines=verification_lines,
        verification_files=verification_files,
    )
    console.print(result.render())


@main.command()
@click.option(
    "--live",
    is_flag=True,
    help="Send one minimal completion per configured cloud backend to confirm credentials actually work (spends a few tokens)",
)
@click.option("--timeout", type=int, default=5, help="Connectivity check timeout in seconds")
def doctor(live: bool, timeout: int):
    """Check hunt's LLM backends: credentials, local server reachability, and which one auto-detection prefers.

    Static checks (env vars set, Ollama reachable) are free. Pass --live to
    also confirm each configured cloud credential actually authenticates.
    `hunt --backend auto` uses the same selection shown here.
    """
    from rowan.agents import run_doctor

    console.print("[bold]Rowan Hunt Doctor[/bold]\n")
    report = run_doctor(live=live, timeout=timeout)
    console.print(report.render())

    if not report.ok:
        raise SystemExit(1)


def _print_summary(result):
    clusters = cluster_findings(
        result.findings, str(result.metadata.get("source_root") or "")
    )
    console.print()
    console.print(f"[bold]Files scanned:[/bold] {result.files_scanned}")
    console.print(f"[bold]Duration:[/bold] {result.duration_seconds:.1f}s")
    console.print(
        f"[bold]Findings:[/bold] {result.total_count} total "
        f"([red]{result.critical_count} critical[/red], "
        f"[orange1]{result.high_count} high[/orange1], "
        f"[yellow]{result.medium_count} medium[/yellow], "
        f"[blue]{result.low_count} low[/blue])"
    )
    console.print(f"[bold]Review clusters:[/bold] {len(clusters)} root causes")


def _print_findings_table(result):
    if not result.findings:
        if result.degraded:
            console.print("\n[yellow]No findings, but the scan was INCOMPLETE (see warnings).[/yellow]")
        else:
            console.print("\n[green]No vulnerabilities found.[/green]")
        return

    table = Table(title="Findings", show_lines=False)
    table.add_column("Severity", style="bold", width=10)
    table.add_column("Rule", width=18)
    table.add_column("File:Line", width=40)
    table.add_column("Message", width=52)
    table.add_column("Reachable", width=11)
    table.add_column("Dependency", width=12)
    table.add_column("Variants", width=9)

    severity_colors = {
        Severity.CRITICAL: "red",
        Severity.HIGH: "orange1",
        Severity.MEDIUM: "yellow",
        Severity.LOW: "blue",
        Severity.INFO: "dim",
    }
    reachability_colors = {"reachable": "red", "unreachable": "dim"}

    clusters = cluster_findings(
        result.findings, str(result.metadata.get("source_root") or "")
    )
    for cluster in clusters[:50]:
        f = result.findings[cluster.primary_index]
        color = severity_colors.get(f.severity, "white")
        file_loc = f"{f.file_path}:{f.start_line}"
        msg = f.message[:80].replace("\n", " ")
        reachability = (f.metadata or {}).get("reachability", "")
        reach_color = reachability_colors.get(reachability, "dim")
        reach_display = f"[{reach_color}]{reachability}[/{reach_color}]" if reachability else "-"
        dep_display = (
            "[magenta]transitive[/magenta]" if (f.metadata or {}).get("direct") is False else "-"
        )

        table.add_row(
            f"[{color}]{f.severity.value.upper()}[/{color}]",
            f.rule_id,
            file_loc,
            msg,
            reach_display,
            dep_display,
            str(len(cluster.member_indexes)),
        )

    console.print(table)

    if len(clusters) > 50:
        console.print(f"[dim]... and {len(clusters) - 50} more root causes[/dim]")


# Without this, `python -m rowan.cli scan ...` imports this module, defines
# the Click group, and exits 0 having scanned nothing. For a security scanner
# that silent clean exit is the worst possible failure mode, so keep the guard
# even though `rowan` and `python -m rowan` are the documented forms.
if __name__ == "__main__":
    main()
