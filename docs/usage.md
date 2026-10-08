# Usage Guide

## Installation

Install the `rowan-sast` package from PyPI (it provides the `rowan` command).
It is a command-line tool, so pipx or uv keeps it in its own environment:

```bash
pipx install rowan-sast          # or: uv tool install rowan-sast
```

Inside a virtual environment or a CI container, `pip install rowan-sast` works.

Install the Opengrep taint-analysis engine (required for the `Taint` pass):

```bash
rowan install-engine       # Opengrep v1.29.0, checked against a built-in SHA-256
```

Optional: install `tree-sitter` for JS/TS and Go cross-file taint propagation (the
AST-based fixpoint layer, same role it plays for Python). Without it, JS/TS
still gets Opengrep's own intra-file cross-function taint flows. Installing
tree-sitter adds the additional Python-equivalent cross-file propagation layer:

```bash
pipx install --force "rowan-sast[js-crossfile]"
```

Verify:

```bash
rowan self-test
```

---

## Commands

### `scan`: run a security scan

```bash
rowan scan <TARGET> [OPTIONS]
```

`TARGET` is a directory.

**Output options**

| Flag | Short | Description |
|------|-------|-------------|
| `--output PATH` | `-o` | Write report to a file instead of stdout |
| `--format FORMAT` | `-f` | `text` (default), `json`, `sarif`, `html` |
| `--vex PATH` | | Write an OpenVEX document: per-CVE exploitability driven by reachability (unreachable → `not_affected`). Built from the full, unfiltered result, so `--severity` does not prune it. Not written when the dependency scan is degraded (e.g. OSV unreachable), since an empty VEX would read as clean; the SBOM is still written and marked `rowan:degraded` |
| `--sbom PATH` | | Write a CycloneDX 1.5 SBOM of the full dependency inventory |

**Report views**

The default report view is `actionable`: what a reviewer should act on now.
Low/informational and surface-signal noise drop out of it, but nothing is
deleted: the count of hidden findings is printed after every scan.

| Flag | Description |
|------|-------------|
| (default) | `actionable`: high/critical, dangerous-sink findings, anything a taint flow or evidence-bearing engine confirmed, and self-evident secret/crypto exposures |
| `--confirmed` | Strictest view: a dangerous-category finding is kept only when the taint engine actually connected a source to the sink (intra- or cross-file). Best for a low-noise CI gate |
| `--audit` | Every finding, the full unfiltered set. Use it for a thorough manual review, or to inspect what the default view hid |

The views are a presentation filter only. JSON/SARIF exports and the Python
API (`ScanConfig(report_view=...)`, default `"full"`) return whatever view
you ask for.

**Filtering**

| Flag | Short | Description |
|------|-------|-------------|
| `--severity LEVEL` | `-s` | Minimum severity: `critical`, `high`, `medium`, `low`, `info` |
| `--lang LANGS` | `-l` | Comma-separated language filter, e.g. `python,javascript`. Unknown or empty names are rejected instead of widening the scan |
| `--profile PROFILE` | | Deployment profile: `server`, `library`, `cli`, `desktop`, `auto` (default) |

**Skipping passes**

| Flag | Description |
|------|-------------|
| `--no-taint` | Disable Opengrep taint/dataflow rules. With the default converted regex engine, Opengrep still runs in regex-only mode; combine with `--legacy-neuroscan` to avoid invoking Opengrep |
| `--no-sca` | Disable dependency CVE scanning |
| `--no-cross-file` | Disable the eleven whole-repository passes: sibling-gate, Python/JS/Go cross-file, PII egress, training disclosure, model extraction, membership inference, dormant code, training approval, and config taint |

**Analysis policy**

`--policy` chooses the starting capability set; it is independent of report
view. All policies keep source analysis local: none makes an LLM request, sends
source to a remote service, or probes a live target. The comprehensive policies
do perform dependency-advisory lookup for SCA; `fast` omits that networked
capability. The plan and JSON metadata serialize this contract.

| Policy | Capability contract |
|------|-------------|
| `default` | All stable applicable analysis: source, pattern, dataflow, cross-file, dependency/SCA, specialist, MCP, and model-file analysis. This is the default. |
| `fast` | Source/pattern and specialist analysis only; Opengrep runs regex-only and whole-repository passes are omitted. |
| `deep` | `default` plus object-level authorization and cross-agent propagation analysis. |

Primitive capability flags override the selected policy. Use `--sca`,
`--taint`, `--cross-file`, `--authz`, or `--multiagent` to add a capability;
their `--no-*` forms remove one.

**Baseline / diff mode**

| Flag | Description |
|------|-------------|
| `--write-baseline PATH` | Snapshot current findings to a file |
| `--baseline PATH` | Report (and, with `--ci`, gate on) only findings absent from this file |

**CI integration**

| Flag | Description |
|------|-------------|
| `--ci` | Exit 1 if findings present; exit 2 if the scan was degraded |
| `--exclude PATTERN` | Skip matching files or directories (repeatable). Trusted under `--ci`, unlike the repository's own ignore file and `.rowan.yml` excludes, so CI can skip a known-bad path such as an unparsable vendored script |
| `--project-config` / `--no-project-config` | Enable or disable `.rowan.yml` loading. It is enabled by default locally and disabled by default with `--ci` |

**Advanced**

| Flag | Description |
|------|-------------|
| `--legacy-neuroscan` | Use the legacy Python regex engine instead of Opengrep for regex rules |
| `--policy POLICY` | `default` (default), `fast`, or `deep`; select an analysis capability contract |
| `--taint-timeout N` | Per-batch Opengrep timeout in seconds; range 1–86,400 |
| `--taint-workers N` | Parallel Opengrep batches; range 1–64 (default: bounded, target-aware auto policy) |
| `--taint-jobs N` | Maximum Opengrep CPU workers per batch; range 1–64 |
| `--network-concurrency N` | Maximum in-flight advisory and EPSS requests; range 1–64 and defaults to the detector concurrency budget |
| `--opengrep-config CONFIG` | Extra `--config` argument passed to Opengrep (repeatable) |
| `--thresholds PATH` | Path to a custom thresholds.yaml for per-rule suppression |
| `--explain-plan` | Show the effective policy, resolved detector/network budget, and ordered selected/disabled passes, then exit without reading source files or running analyzers |
| `--verbose` / `-v` | Verbose logging |

**Option validation**

- `--audit` and `--confirmed` are mutually exclusive.
- `--no-sca` cannot be combined with `--vex` or `--sbom`, because both
  artifacts require the dependency inventory. This is checked after project
  configuration is applied, so project-level `no_sca: true` is covered too.
- `--taint-timeout`, `--taint-workers`, `--taint-jobs`, and
  `--network-concurrency` accept bounded positive integers only. The timeout
  ceiling is 86,400 seconds and concurrency ceilings are 64, identically for
  CLI and programmatic callers.
- CLI `--lang` values are normalized and checked against the supported
  language keys. An unsupported or empty key is a usage error; it never
  falls back to scanning every language.

**Exit codes**

| Code | Meaning |
|------|---------|
| `0` | Success: no findings (or non-CI run) |
| `1` | CI mode: findings present and scan was complete |
| `2` | Scan was degraded (incomplete results: do not treat as clean). Needs `--ci` or `--fail-on-degraded` |

Click usage errors (bad flags) also exit `2`, and an unreadable target exits `1`, so check the
message when a script needs to tell them apart.

**Examples**

```bash
# Basic scan, text output (default: actionable view)
rowan scan ./my-project

# See everything, including low/informational and surface-signal findings
rowan scan ./my-project --audit

# Highest precision: dangerous-category findings must be taint-confirmed
rowan scan ./my-project --confirmed

# Object-level authz (BOLA/IDOR) and CrewAI cross-agent injection detection
rowan scan ./my-project --authz --multiagent

# CI: fail on high+ findings, emit SARIF
rowan scan ./my-project --ci --severity high -f sarif -o results.sarif

# Adopt on an existing codebase: baseline first, then gate on new only
rowan scan . --write-baseline .rowan-baseline.json
rowan scan . --ci --baseline .rowan-baseline.json

# No dataflow or dependency scan. Converted regex rules still use Opengrep
rowan scan ./my-project --no-taint --no-sca

# Avoid Opengrep entirely: legacy Python regex rules, no dataflow or deps
rowan scan ./my-project --no-taint --no-sca --legacy-neuroscan

# Inspect the resolved policy/pass selection without running a scan
rowan scan ./my-project --explain-plan
rowan scan ./my-project --explain-plan --format json

# Supply-chain attestation: VEX (reachability-driven) + CycloneDX SBOM
rowan scan ./my-project --vex vex.json --sbom sbom.json

# Python only, verbose
rowan scan ./my-project --lang python -v

# HTML report
rowan scan ./my-project -f html -o report.html
```

---

### `self-test`: verify installation

```bash
rowan self-test
```

Checks that Opengrep is on PATH, the NeuroScan rules file exists, and taint rule files are present.

---

### `install-engine`: download Opengrep

```bash
rowan install-engine [--prefix PATH] [--version TAG] [--allow-unverified]
```

Downloads the Opengrep binary for your OS and architecture from GitHub releases. Default install location: `~/.local/bin`.

By default it installs **Opengrep v1.29.0** and checks the download against a SHA-256 hash built into Rowan. Each hash was verified against Opengrep's [Sigstore](https://www.sigstore.dev/) signature when it was pinned. No other tool is needed, and a mismatch is always refused.

`--version` installs a different release tag, or `latest` for whatever GitHub currently calls the newest. Those need `cosign` on your `PATH` for signature verification; without it, or without signature assets, or when verification fails, the install is refused. `--allow-unverified` skips that check for a non-default version (not recommended).

```bash
rowan install-engine                      # → ~/.local/bin/opengrep, hash-verified
rowan install-engine --prefix /usr/local   # → /usr/local/bin/opengrep
rowan install-engine --version v1.14.0     # a different release (needs cosign)
rowan install-engine --version latest      # newest release (needs cosign)
```

---

### `hunt`: autonomous vulnerability hunting (experimental)

```bash
rowan hunt <TARGET> [OPTIONS]
```

Runs a 7-stage LLM-powered pipeline: static scan → LLM hypothesis generation → adversarial verify → deep-dive evidence selection → chain construction → web exploit probes → report. `--discover` inserts an eighth stage after deep-dive (see below).

Recon already runs SCA when it is enabled; the dependency stage isolates
those results and does not scan dependencies again. Deep-dive resolves files
named by surviving `confirmed`/`likely` hypotheses and attaches their existing
full-context Recon findings, without copying files or launching a duplicate
scan. The later exploit stage constructs evidence chains
but does not perform a new taint/AST confirmation. Only a `confirmed`
hypothesis with resolved, non-empty source evidence sets the vulnerable
verdict; likely-only chains remain investigation leads.

Structured Hunt chains include `evidence_state`. Values progress from
`triaged`/`verifier_upheld` to `statically_validated` only when confirmed source
evidence resolves; `actively_confirmed` is reserved for a successful opt-in
live probe. Existing `status` and `evidence_status` remain for compatibility.
Hunt JSON also exposes the projected state on hypotheses and verified
discovered findings (`verifier_upheld` for model discoveries), plus `evidence_states` record counts in both the summary
and Hunt block. These counts describe serialized evidence records, not unique
vulnerabilities.

The **verify stage** is an independent second-opinion LLM pass that tries to refute each `confirmed`/`likely` hypothesis before it advances to deep-dive. Refuted hypotheses are demoted to `false_positive` and dropped; uncertain ones are downgraded one notch. An upheld verdict requires structured source-backed evidence; insufficient evidence becomes uncertain. This can also withhold real defects whose paths cannot be established from the available context. Skip it with `--no-verify`.

**Before any source code is sent to an LLM endpoint, you will be shown the endpoint URL and asked to confirm. In non-interactive sessions (CI), the LLM stage is skipped unless `--yes` is passed.**

**The discovery stage (`--discover`, experimental)**

Discovery asks the model for defects beyond static rules. It schedules both static-implicated files and recognized Python routes, jobs, assistant tools, and sensitive operations with no static hit. File and source-line budgets bound the work; partial/skipped coverage and unsupported inventory languages remain explicit. Whole files or excerpts are supplied, rather than a guaranteed whole-repository review.

A discovery must pass snippet provenance and an independent, structured evidence review. Upheld claims cite inspected source and identify a reachable path without unresolved assumptions. Other candidates remain audit observations. Findings carry `engine="llm-discovery"` and confidence capped at 0.65; filter that engine when measuring static-rule precision.

Hunt JSON schema version 2 separates the full static inventory from verification outcomes. `--hunt-view verified` selects upheld findings; summary counts match the emitted view. Successful calls can be saved outside the target and resumed with unchanged inputs. See [coverage, evidence, and recovery](hunt-evidence-and-recovery.md) for contracts, limitations, schema changes, and examples.

**Options**

| Flag | Short | Description |
|------|-------|-------------|
| `--backend BACKEND` | `-b` | LLM backend: `auto` (default), `deepseek`, `openai`, `openrouter`, `alibaba`, `ollama`, `local`. Auto prefers configured cloud credentials, then a reachable local Ollama server. |
| `--model MODEL` | `-m` | Override the default model for the chosen backend |
| `--lang LANGS` | `-l` | Language filter |
| `--no-sca` | | Skip dependency scan |
| `--no-verify` | | Skip adversarial verification (the second-opinion LLM pass after triage) |
| `--exploit` | | Enable live HTTP exploit probes (off by default: sends real requests to targets) |
| `--base-url URL` | | Absolute HTTP(S) base URL of the scanned app (e.g. `http://localhost:5000`), required with `--exploit` and rejected without it; credentials, query strings, fragments, and whitespace are not accepted |
| `--discover` | | Enable the LLM **discovery** stage: ask the model for defects the rule corpus cannot express (off by default: costs extra LLM calls) |
| `--discovery-files N` | | Discovery file budget, default 25 (maximum 500) |
| `--discovery-lines N` | | Hard source-line budget per discovery file, default 400 |
| `--verification-lines N` | | Retrieved verification context line budget, default 240 |
| `--verification-files N` | | Retrieved verification context file budget, default 4 |
| `--checkpoint PATH` | | Atomically save successful calls outside the scanned target; contains source-derived data |
| `--resume` | | Rebuild state and reuse valid successful calls from the checkpoint; changed inputs are rejected |
| `--hunt-view full\|verified` | | JSON finding view; default full preserves static inventory |
| `--yes` / `-y` | | Skip the LLM egress confirmation prompt (for trusted CI environments) |
| `--output PATH` | `-o` | Save report to file |
| `--format FORMAT` | `-f` | `text` (default) or `json` |
| `--verbose` / `-v` | | Verbose output: includes the full prompt and response text of every LLM call (`hunt -v`), useful for monitoring what's actually being sent/received during a run (e.g. `rowan hunt . -v 2>&1 | tee hunt.log`, then `tail -f hunt.log` in another terminal) |

**LLM backends**

| Backend | Env vars | Default model | Notes |
|---------|----------|---------------|-------|
| `deepseek` | `DEEPSEEK_API_KEY`, optional `DEEPSEEK_MODEL`, `DEEPSEEK_BASE_URL` | `deepseek-chat` | Default. Cloud API, fast and cheap. |
| `openai` | `OPENAI_API_KEY`, optional `OPENAI_MODEL` | `gpt-4o-mini` | Set `OPENAI_BASE_URL` for a custom endpoint |
| `openrouter` | `OPENROUTER_API_KEY`, optional `OPENROUTER_MODEL` | `deepseek/deepseek-chat` | Access many models via one key |
| `alibaba` | `ALIBABA_TOKEN_PLAN_API_KEY`, optional `ALIBABA_MODEL` | `qwen3.8-max` | Alibaba Cloud Model Studio Token Plan (Qwen). Set `ALIBABA_BASE_URL` for the China endpoint |
| `ollama` | _(none required)_, optional `OLLAMA_MODEL`, `OLLAMA_BASE_URL` | `llama3` | Local Ollama server: **no data leaves the machine** |
| `local` | `LOCAL_LLM_BASE_URL`, `LOCAL_LLM_MODEL` | `local-model` | Any OpenAI-compatible local server |

`--model` overrides the `*_MODEL` variable. With `--backend auto`, Rowan picks the
first key it finds in this order: DeepSeek, OpenRouter, OpenAI, Alibaba, then a
reachable Ollama server. `rowan doctor` shows the choice.

Tuning variables for every backend: `LLM_MAX_TOKENS` (default 8192),
`LLM_TIMEOUT` in seconds (default 120), and `LLM_REASONING_EFFORT` (sent as
`reasoning_effort`). Reasoning models that return empty answers usually spent
the whole token budget on thinking: set `LLM_REASONING_EFFORT=low` or raise
`LLM_MAX_TOKENS`.

To avoid leaving a key in a file or shell history, load it with
`read -rs DEEPSEEK_API_KEY && export DEEPSEEK_API_KEY` (any key name works).

**Running Llama locally with Ollama**

```bash
# Install Ollama: https://ollama.com/download
ollama serve                          # start server (stays running in background)
ollama pull llama3                    # or: llama3.1, codellama, qwen2.5-coder, mistral

# rowan detects Ollama automatically when no cloud key is set
rowan hunt ./my-project

# Explicit:
rowan hunt ./my-project --backend ollama --model llama3.1

# Environment overrides:
OLLAMA_MODEL=codellama rowan hunt ./my-project --backend ollama
OLLAMA_BASE_URL=http://remote-host:11434/v1 rowan hunt . --backend ollama
```

rowan checks the Ollama server is reachable before starting the workflow. If it can't connect, it prints a clear error and falls back to static-only mode.

**Batch size note:** local models typically have smaller context windows than cloud APIs. Rowan uses a batch of 4 findings per LLM call for `ollama`/`local` backends (vs. 15 for cloud) to stay within typical 4k–8k context limits. Use `codellama` or `qwen2.5-coder` (8k+ context) for better results on large codebases.

**Other local servers (LM Studio, vLLM, llama.cpp)**

```bash
export LOCAL_LLM_BASE_URL=http://localhost:1234/v1
export LOCAL_LLM_MODEL=your-model-name
rowan hunt ./my-project --backend local
```

**Examples**

```bash
# DeepSeek (cloud, recommended for best results)
read -rs DEEPSEEK_API_KEY && export DEEPSEEK_API_KEY
rowan hunt ./my-project

# Llama 3 via Ollama (on-prem, no egress)
rowan hunt ./my-project --backend ollama --model llama3

# OpenRouter (access Anthropic, Google, Meta, etc. via one key)
read -rs OPENROUTER_API_KEY && export OPENROUTER_API_KEY
rowan hunt ./my-project --backend openrouter --model anthropic/claude-sonnet-4.5

# Alibaba Cloud Model Studio Token Plan (Qwen)
read -rs ALIBABA_TOKEN_PLAN_API_KEY && export ALIBABA_TOKEN_PLAN_API_KEY
rowan hunt ./my-project --backend alibaba
# China region endpoint instead of the default international one:
ALIBABA_BASE_URL=https://token-plan.cn-beijing.maas.aliyuncs.com/compatible-mode/v1 \
  rowan hunt ./my-project --backend alibaba

# Live HTTP exploit probes (only against targets you are authorized to test)
rowan hunt ./my-project --exploit

# Non-interactive CI (static scan only, no LLM)
rowan hunt ./my-project --no-sca < /dev/null
```

---

### `estimate`: preview hunt's scope/cost before spending anything

```bash
rowan estimate <TARGET> [OPTIONS]
```

Runs hunt's own free recon (static scan) stage against `TARGET`, then applies hunt's real priority-filtering and batching logic (the same code `hunt`'s hypothesize stage uses) to project how many LLM calls, and roughly how many tokens, a full `hunt` run would make. **No LLM backend is contacted; this command spends nothing.**

The estimate reflects static finding density plus bounded source inventory and context retrieval. With discovery enabled, Hunt may send whole files or excerpts. The same four discovery/verification budget options apply to `estimate` and `hunt`; future model-selected paths and actual claim counts remain unknown.

**Options**

| Flag | Short | Description |
|------|-------|-------------|
| `--backend BACKEND` | `-b` | Backend to project batch counts for (affects batch size only: `ollama`/`local` batch 4 findings/call, cloud backends batch 15) |
| `--lang LANGS` | `-l` | Language filter |
| `--no-sca` | | Skip dependency scan (match the `hunt` run this estimates) |
| `--discover` | | Include the LLM discovery stage in the projection (match `hunt --discover`). Reports the candidate file count as an explicit floor: it cannot know this run's deep-dive targets before hypothesize has run |

```bash
rowan estimate ./my-project
rowan estimate ./my-project --backend ollama --lang python
```

**Note:** the estimate models `hypothesize`, `verify`, and optional discovery/verification calls. It does not model `deepdive`, `report`, or `webexploit` calls, so treat it as a floor, not a full bill.

---

### `doctor`: check hunt's LLM backends before a real run

```bash
rowan doctor [OPTIONS]
```

Checks every backend `hunt` knows about (`deepseek`, `openrouter`, `openai`, `alibaba`, `ollama`): which credentials are set, whether a local Ollama server is reachable, and which backend auto-detection (`LLMBackend.from_env()`) would prefer. Exits non-zero if the auto-detected backend isn't actually usable.

`hunt --backend auto` uses the same selection shown by `doctor`. When it falls
back to Ollama and neither `--model` nor `OLLAMA_MODEL` is set, Hunt prefers an
installed code-specialized model and otherwise uses an installed local model.
Explicit backend and model flags always win.

**Options**

| Flag | Description |
|------|-------------|
| `--live` | Send one 4-token completion per configured cloud backend to confirm the credential actually authenticates (spends a few tokens). Without it, cloud backends are only checked for "is an API key present": a set-but-invalid or expired key won't be caught until a real `hunt` run. Also catches a reachable-but-unusable local server (e.g. Ollama running with no model pulled for the configured model name). |
| `--timeout SECONDS` | Connectivity check timeout (default 5) |

```bash
rowan doctor
rowan doctor --live
```

---

## Output formats

### Text (default)

Human-readable. Findings are sorted by severity, with rule ID, file:line, message, taint flow (where available), confidence, and fix guidance (where the rule provides it).

### SARIF 2.1.0

Structured format consumed by GitHub Code Scanning, VS Code SARIF Viewer, and most CI platforms. Upload to GitHub:

```yaml
- uses: github/codeql-action/upload-sarif@v4
  with:
    sarif_file: results.sarif
```

### JSON

Structured JSON with a `findings` array and summary. Schema: [docs/schema/finding.schema.json](schema/finding.schema.json).

### HTML

Self-contained single-file report. Severity-coloured summary cards + full finding table with taint flow, CWE, and remediation guidance.

---

## Evidence tiers

Every finding says how much was actually computed to support it, in
`evidence_tier` (JSON) and `metadata["evidence_tier"]` (Python API):

| Tier | What was computed | Trust |
|---|---|---|
| `taint-flow` | A source-to-sink dataflow, included in the finding as `taint_flow` | A verified path. Act on these first |
| `taint-flow-unresolved` | A trace enters a service call, but its returned value was not resolved | A review lead; verify the service return before treating it as an exploit path |
| `engine` | Structural engine evidence, such as model-file opcode analysis | The engine inspected the artifact itself |
| `presence` | Artifact capability inventory, without a malicious-operation claim | Review surface; not a vulnerability proof |
| `authorization-gap` | A request-keyed object read lacks a recognized dominating guard | Review the declared policy and runtime controls; excluded from `--confirmed` |
| `self-evident` | Nothing more was needed: the matched text *is* the claim (a hardcoded secret, an MD5 password hash) | The match is the evidence |
| `pattern-only` | A pattern matched. Nothing else | **A hypothesis, not a fact.** Confirm before acting |

A route or request read elsewhere in a file does not establish a path to a
sink. New scans no longer emit the historical `source-context` tier.
`--confirmed` requires computed or self-evident evidence even at HIGH/CRITICAL;
findings marked `taint_unconfirmed` are excluded.

**HIGH and CRITICAL require computed evidence.** A finding whose category
asserts a dataflow property (injection, deserialization, SSRF, SSTI, XSS,
command injection, path traversal, NoSQL injection, prototype pollution) but
carries only `pattern-only` evidence is capped at MEDIUM and labelled in its
own message. The scanner will not tell you input is "user-controlled" when
nothing checked whether it is.

Two context rules interact with this and are worth knowing about, because
both *lower* severity for reasons unrelated to the finding's truth:

- **Test code** (`spec/`, `tests/`, `*_test.go`, ...) caps at MEDIUM.
- **Operator tooling with no attacker surface** (`scripts/`, `migrations/`,
  importers, benchmark dirs, build configs) caps at LOW.

Nothing is deleted by either rule. Use `-s info` to see everything.

**One sink, one finding.** When several rules report the same line with the
same category and a shared CWE, they are merged into the finding with the
strongest evidence (then the highest severity). The JSON field
`duplicate_rule_ids` lists every rule merged into it, so a more specific rule
that matched the same call is still visible there.

## Scan manifest

The JSON report's `scan_manifest` records what produced the result: the Rowan
version, the Opengrep version (when the engine ran), and a SHA-256 over the rule
files used. Compare it between runs before trusting a diff. It does not yet
record the target commit or the OSV and EPSS data snapshots.

## Analysis coverage

A scan reports which languages got real dataflow analysis and which only got
pattern rules, in `analysis_capability` (JSON) and an `ANALYSIS COVERAGE`
banner in the text report:

The JSON object also includes `cross_file_languages`, listing only the
language-specific cross-file frontends that completed for the resolved source
inventory.

```
  ANALYSIS COVERAGE: patterns only (no dataflow engine) for: ruby (1190 files).
  Findings in these languages are pattern matches, not verified flows;
  absence of findings there is NOT evidence of absence.
```

This exists so a coverage cliff can never be mistaken for a clean result. If
a language appears in `patterns_only_languages`, a quiet scan of that code is
not evidence that the code is safe. Ruby is pattern-only today.

## Pass execution telemetry

JSON output includes a top-level `pass_outcomes` array in execution order.
Each scheduled pass reports:

- `name`
- `status` (`completed` or `degraded`)
- `duration_seconds`
- pass-local `files_scanned`
- net `findings_delta`
- `degraded_reasons` and `errors`, when applicable

Use this field to see which option-dependent passes actually ran, find the
expensive stages on a particular repository, and distinguish a completed
zero-finding pass from degraded analysis. `findings_delta` is net change, so
a post-processing pass that deduplicates or suppresses findings can report a
negative value. JSON also includes the path-free effective settings in
`resolved_policy` and pre/post-enrichment plus filter-stage counts in
`filter_counts`. `report_view` is always explicit, and `coverage_summary`
states whether the selected policy completed while counting completed,
not-applicable, explicitly disabled, and incomplete passes. SARIF exposes the
same policy, pass outcomes, coverage summary, report view, and filter counts as
run properties.
Passes omitted by an option are listed separately in `skipped_passes` with an
`explicitly_disabled` status and reason, rather than being confused with an
unavailable or failed analyzer. `scope_summary` gives path-free source-file and
per-language counts from the resolved inventory.

`--explain-plan` uses the same plan builder as the executable pipeline. It
applies project configuration and effective-option validation, then prints the
path-free policy and every selected or explicitly disabled pass. It does not
load rules, traverse or read the target's source files, instantiate analyzers,
invoke Opengrep, or contact dependency services. It is a policy/pass preview,
not yet an applicability preview based on repository contents.

The initial file-discovery pass traverses the source tree once and publishes
its filtered, language-classified inventory for later stages. Sibling-gate,
Python cross-file, PII-egress, training-disclosure, model-extraction,
membership-inference, dormant-code, training-approval, config-taint,
serialization-scope, web-security, authz, agent-flow, multi-agent, MCP
network-exposure, MCP sampling-approval, MCP stored-content, and MCP
tool-metadata analysis currently reuse the Python `.py` subset. JavaScript cross-file analysis uses
the JavaScript/TypeScript subset, and Go cross-file analysis uses the Go subset. Taint's keyword-count preflight uses the
Python subset, and Opengrep receives the full inventory as exact candidate
targets before reapplying its own language and path filters. This removes their
independent discovery walks while preserving pass-specific exclusions. The
instruction-smuggling pass consumes the instruction/Markdown/text subset.
The same traversal separately identifies supported dependency manifests, model
artifacts, and MCP client configs; SCA, model-file validation, and MCP config
analysis consume those authoritative candidate lists without adding artifacts
to source-file counts or regex/Opengrep targets. They retain fallback discovery
when run outside the normal pipeline.

Within one scan, sixteen Python analyzers share a lazy source snapshot:
PII-egress, training-disclosure, model-extraction, config-taint,
training-approval, dormant-code, membership-inference, agent-flow,
web-security, authz, serialization-scope, multi-agent, MCP network-exposure,
MCP sampling-approval, MCP stored-content, and MCP tool-metadata. Taint's
keyword preflight also uses cached text. Retained files are read as UTF-8 and parsed as Python once;
read and syntax failures are cached too. Text and AST caches are independently
bounded to 2,048 entries, so very large scans may evict and later recompute
older entries instead of retaining the whole repository. Each analyzer
receives a defensive AST copy, preventing its mutations from affecting later
analysis. A subsequent scan uses a fresh snapshot and sees files changed since
the previous scan. JSON and SARIF expose path-free cache hit/miss, retained
entry, read-failure, and parse-failure counts under `source_snapshot`. Any
snapshot read or Python parse failure also marks the scan degraded because
source coverage was incomplete.

## MCP evidence server

`scan_evidence` exposes the whole payload above to an agentic reviewer over
[MCP](https://modelcontextprotocol.io), so an LLM doing code review can ground
its dataflow claims in computed facts instead of inferring them.

```bash
pipx install --force "rowan-sast[mcp]"
rowan-mcp                 # stdio server; clients launch this themselves
```

Register it with any MCP client (this is `.mcp.json` for Claude Code):

```json
{
  "mcpServers": {
    "rowan-evidence": {
      "command": "rowan-mcp"
    }
  }
}
```

The repo ships a `.mcp.json` that runs the server straight from a source
checkout (`uv run python -m rowan.mcp_server`) instead, so contributors
get the tool without installing the package.

The server offers one tool, `scan_evidence(target)`, which takes an
**absolute directory** path (relative paths resolve against the server process,
not the caller) and returns the same document as `scan --format json`: tiered
findings, full taint flows, and the coverage manifest. File targets are
rejected until every pass supports a shared selected-file scope, so an
unsupported model or source file cannot look clean. SCA is disabled so the
tool never needs network access. A large repository takes minutes, so point it
at the directory under review rather than a whole monorepo.

Two environment variables bound what the tool can do, since the agent calling
it may be steered by prompt injection:

- `ROWAN_MCP_ROOTS`: directories a target must sit inside, separated by
  `:` (`;` on Windows). Default: the server's working directory, which MCP
  clients usually set to the open project. Anything outside is refused.
- `ROWAN_MCP_TIMEOUT`: seconds before a scan is stopped (default 600).
  The scan runs in a worker process, so a timed-out scan really ends.

---

## Project config file

`.rowan.yml` in the scan target (or any parent directory) sets default values for CLI flags. **CLI flags always win over config file values.**

```yaml
# .rowan.yml
version: 1
exclude:
  - vendor
  - "*.min.js"
  - migrations
  - "**/__pycache__"
languages:
  - python
  - javascript
severity: high
no_sca: false
no_taint: false
profile: server
baseline: .rowan-baseline.json
max_file_bytes: 500000
```

The public schema version is `1`; omitting `version` currently means version 1
for backward compatibility. Supported keys are `version`, `exclude`,
`languages`, `severity`, `no_sca`, `no_taint`, `no_cross_file`, `enable_authz`,
`legacy_neuroscan`, `scan_vendored`, `max_file_bytes`, `profile`, `policy`,
`authz_model_policies`, and
`baseline`.

Project configuration is parsed before any value is applied. Unknown keys,
unsupported schema versions, quoted booleans, invalid language/severity/profile
values, non-integer `max_file_bytes`, malformed list items, invalid baseline
strings, and malformed YAML fail with a usage error; YAML parse failures include
line and column when available. The schema is intentionally narrower than the
internal `ScanConfig` type.

Locally, the nearest `.rowan.yml` or `.rowan.yaml` found while walking
from the target toward the filesystem root is loaded by default. CLI values win
over project defaults. In CI, project configuration remains disabled by default
to prevent an untrusted repository change from weakening analysis; enable it
explicitly with `--project-config` only when that trust decision is intentional.
Per-field configuration provenance and a trusted external CI policy are not yet
implemented.

---

## Suppressing false positives

### Inline (per line)

```python
result = pickle.loads(trusted_bytes)  # rowan:disable
# Also accepted: # nosec  or  # noqa
```

### Managed ignore file

`.rowan-ignore.yml` in the scan target (or parent directory). Two matching modes:

**By fingerprint** (content-addressed, survives line shifts):
```yaml
ignore:
  - fingerprint: a3f9c2b1...   # from --write-baseline output
    reason: "Accepted risk: loaded from trusted internal registry only"
```

**By rule + path** (pattern-based):
```yaml
ignore:
  - rule_id: NS-PATH-003
    path: "backend/server.py"
    reason: "Path validated upstream by auth middleware"
    expires: "2027-01-01"     # optional: entry silently lapses after this date
```

Get fingerprints: `rowan scan . -f json | jq '.findings[].rule_id'`, or write a baseline file and inspect it.

---

## CI/CD integration

### GitHub Actions (recommended)

Use the bundled composite action, which handles install, scan, and SARIF upload:

```yaml
name: Security Scan
on: [push, pull_request]

permissions:
  contents: read
  security-events: write   # needed to upload SARIF to code scanning

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: hedgerow-dev/rowan@v0.3.6
        with:
          target: .
          output: rowan.sarif
          # baseline: .rowan-baseline.json
      - uses: github/codeql-action/upload-sarif@v4
        if: always()
        with:
          sarif_file: rowan.sarif
```

The action installs Rowan, Cosign, and a signature-verified Opengrep
engine, so its default CI scan includes taint analysis. It runs with `--ci`,
so the job fails when it finds issues (exit 1) or cannot finish the scan
(exit 2); `if: always()` still uploads the SARIF so the findings show up
under the repository's Security tab. A working example:
[hedgerow-dev/rowan-action-demo](https://github.com/hedgerow-dev/rowan-action-demo).

### GitLab CI

```yaml
security-scan:
  image: python:3.12
  script:
    - pip install rowan-sast
    - rowan install-engine
    - rowan scan . --ci -f sarif -o gl-sast-report.json
  artifacts:
    reports:
      sast: gl-sast-report.json
```

### Pre-commit hook

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/hedgerow-dev/rowan
    rev: v0.3.6
    hooks:
      - id: rowan
```

---

## Supported languages

| Language | Regex rules | Taint rules | Cross-file taint |
|----------|:-----------:|:-----------:|:----------------:|
| Python | Yes | Yes | Yes: AST-based fixpoint across modules |
| JavaScript | Yes | Yes | Yes: AST-based fixpoint (requires optional `tree-sitter`) |
| TypeScript | Yes | Yes | Yes: AST-based fixpoint (requires optional `tree-sitter`) |
| Java | Yes | Yes | Intra-file only: via Opengrep (cross-file is on Opengrep's own roadmap, not yet shipped) |
| Kotlin | No | Yes | Intra-file only: via Opengrep (cross-file is on Opengrep's own roadmap, not yet shipped) |
| Go | Yes | Yes | Yes: tree-sitter call-graph tracer from HTTP and MCP tool inputs to exec, path, SQL and HTTP sinks, `CF-GO-*` findings (requires optional `tree-sitter`) |
| C# | Yes | Yes | Intra-file only: via Opengrep (cross-file is on Opengrep's own roadmap, not yet shipped) |
| Ruby | Yes | No | No |
| PHP | Yes | No | No |
| Rust | Yes | No | No |
| Terraform | Yes | No | No |
| Dockerfile | Yes | No | No |

---

## Performance

| Scenario | Approximate time |
|----------|-----------------|
| 100 files, surface scan | < 1s |
| 1,000 files, surface scan | < 5s |
| 1,000 files, full (taint + SCA) | 30–120s |
| 10,000 files, surface scan | 10–30s |

Taint analysis time depends on Opengrep and codebase complexity. Use `--taint-workers N` to parallelize large repos.

### Model access policies

With `--authz`, `AUTHZ-BOLA-001` reports a missing recognized object guard. When
access requirements are unknown, it is a MEDIUM review lead; missing a guard is
not proof that the object is private. Pure existence checks are LOW signals.
The `authorization-gap` evidence tier remains visible in `--audit` and MEDIUM/HIGH
review findings remain actionable, but it is excluded from `--confirmed`.

Declare requirements in `.rowan.yml` using model identities resolved from
repository source paths and class imports, including import aliases. Identities
are relative to the scan root (a `src/` prefix is retained); use the reported
`model_identity` when declaring a policy:

```yaml
enable_authz: true
authz_model_policies:
  app.models.PublicDocument:
    read: public
    write: principal
  app.models.PrivateRecord:
    read: principal
    write: principal
```

A public-read policy removes only resolved read-only/existence guard gaps.
It does not authorize writes, opaque calls, bound-method escapes, or deferred
operations that receive the request-selected key. Bare class names and public
write policies are rejected. Unresolved, rebound, ambiguous or external models
cannot inherit a public policy. Supported resolution covers local classes and
direct class imports; re-exports and helper-returned model identities may remain
unverified. Existence-only observations remain LOW even with a principal policy,
since their impact differs from disclosing or modifying object contents.

Policy declarations describe the intended application contract, not enforcement.
JSON includes `model_identity`, `object_use`, and `authorization_requirement`;
confidence describes the static guard analysis, not exploit validation. Project
configuration is disabled by default in CI; `--project-config` is an explicit
trust decision, as for other project settings.

### Bounded log rendering

Log-forging (`TNT-LOG-001`) findings are removed only when all matched log calls
on the line have statically bounded output: numeric conversions, numeric percent
formats, immutable aliases, supported arithmetic, or straight-line repository
helpers returning such values. Numeric percent-format shortcuts for unknown arguments
require a resolved standard-library logging module or `getLogger()` receiver;
unknown loggers retain the claim. Annotations and ORM column declarations alone
are insufficient. Reassignment, ambiguous/shadowed imports, dynamic formats,
unknown helpers and analysis limits retain the finding. Character conversion
(`%c` / `:c`) is retained because the integer 10 can render as a newline.

This filter affects forging only. Sensitive-value logging (`TNT-LOG-002`) remains
reportable even when a credential is numeric. Attribute provenance, complex
control flow, decorated/async helpers and dynamic dispatch remain limits.
