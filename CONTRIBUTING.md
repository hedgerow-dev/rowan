# Contributing

## Setup

```bash
git clone https://github.com/hedgerow-dev/rowan.git
cd rowan
python -m venv .venv
source .venv/bin/activate  # macOS/Linux
# .venv/Scripts/activate   # Windows
pip install -e ".[dev]"
```

Optionally install Opengrep for taint analysis. The default version is checked
against a built-in SHA-256, so no other tool is needed:
```bash
rowan install-engine
```

Bumping the pinned engine means updating `PINNED_VERSION` and all five hashes
in `rowan/install_opengrep.py` together, after verifying each binary's Sigstore
signature.

## Running tests

```bash
pytest
pytest --cov=rowan --cov-report=term-missing
```

Tests run without Opengrep installed. The taint pass tests mock or skip
Opengrep-dependent paths.

## Linting

```bash
ruff check rowan/ tests/
ruff check --fix rowan/ tests/   # auto-fix
```

Configuration is in `pyproject.toml` under `[tool.ruff]`.

## Project structure

See [ARCHITECTURE.md](ARCHITECTURE.md) for the full module map.

## Adding a rule

### Write the message the evidence supports

A regex rule knows one thing: a pattern matched. It does not know whether the
argument is user-controlled, whether a request reaches this code, or whether
a sanitizer ran. So its message must not claim any of that.

```yaml
# No: asserts a dataflow property nothing checked.
message: "User-controlled path enables directory traversal"

# Yes: states the match and what the reader must confirm.
message: |
  Filesystem access whose path argument was not analysed for user control.
  Verify the path cannot be influenced by request input.
```

This is not a style preference. `EnrichmentPass` caps a dataflow-claiming
rule at MEDIUM when nothing computed the dataflow (`evidence_tier:
pattern-only`, see [ARCHITECTURE.md](ARCHITECTURE.md#evidence-tiers)), so a
regex rule declaring `severity: critical` will not ship at critical anyway.
Write the honest message rather than one the tier will contradict.

If you want a rule to carry HIGH or CRITICAL, it needs computed evidence: a
`mode: taint` rule with real sources and sinks, or a category whose match is
self-evidently the whole claim (a hardcoded credential needs no dataflow).

### NeuroScan (regex) rule

Add to an existing YAML file in `rules/` or create a new one:

```yaml
- id: NS-EXAMPLE-001
  pattern: "dangerous_function\\s*\\("
  message: "Dangerous function call detected"
  severity: high
  category: injection
  cwe: 94
  languages: [python]
```

Regex rules match one pattern at a time. Know these limits before writing one:

- **`patterns` is OR, not AND.** A rule with patterns A and B fires on any line with A or any line with B.
- **`pattern-not` only sees the finding's own line.** An exclusion on another line (a later Terraform attribute, a `setSecure` call, a comment above) never suppresses anything. "X without Y" across lines needs a structural Opengrep rule (`pattern` plus `pattern-not-inside`).
- **Do not write `\([^)]*kw=`.** It stops at the first `)`, so `run(build(x), shell=True)` is missed. Use `\((?:[^()]|\([^()]*\))*kw=`; a test lints for this.

### Taint rule

Add to an existing `*_taint.yaml` file in `rules/`:

```yaml
- id: TNT-EXAMPLE-001
  mode: taint
  message: User input reaches dangerous sink.
  severity: ERROR
  languages: [python]
  metadata:
    cwe: [94]
    category: injection
  pattern-sources:
    - patterns:
        - pattern: request.args.get(...)
  pattern-sinks:
    - patterns:
        - pattern: dangerous_function(...)
  pattern-sanitizers:
    - patterns:
        - pattern: safe_wrapper(...)
```

### Validating a rule (required)

**A rule earns its place by firing on code nobody wrote for it.** A passing
unit test proves only that the rule matches the fixture its own author wrote,
which is the single most common way a rule ships broken here.

This is not hypothetical. The following were found against a labelled real
application (2026-08-01). They remain useful examples of why an isolated rule
fixture is insufficient; where a purpose-built structural pass now covers the
application form, keep the narrow rule narrow rather than broadening it into a
high-noise heuristic:

* `TNT-ML-012` deliberately recognizes the raw SDK wire shape
  `call["function"]["name"]`. Real apps commonly normalize tool calls
  upstream and dispatch on `call.get("name")`; that application form belongs
  to `AGENT-CAPABILITY-001` / `AGENT-REFLECTION-SURFACE-001`, which recover
  the tool registry or advertised action surface instead of treating every
  bare `.get("name")` as model-controlled.
* `TNT-ML-014` directly recognizes SDK method-call sinks such as
  `$CLIENT.chat.completions.create`. Application-owned wrappers that send PII
  to a model endpoint through plain `requests.post(...)` are covered by
  `TNT-ML-PII-EGRESS-001` when its AST analysis can establish an LLM-facing
  request boundary; a generic `requests.post` taint sink would be too broad.
* `ns-aiml-128` requires `sampl` and `create_message`/`callback` to be
  contiguous inside one identifier. Its fixture is *named*
  `sampling_createmessage_handler` to satisfy the regex; real code names
  functions by purpose. `MCP-SAMPLING-APPROVAL-001` instead follows the MCP
  Python SDK's explicit `sampling_callback=` registration to that callback's
  body and looks for a human-review call.
* `ns-aiml-126` / `ns-aiml-127` originally required the receiver
  `mcp`/`server`/`app` calling `.run(host=..., transport=...)`, i.e. FastMCP's
  high-level API. `MCP-HTTP-BIND-001` now covers the low-level `Server` plus
  Starlette/Uvicorn deployment form; do not paper over that relationship with
  a line regex.

So, before submitting a rule:

1. **Show a true positive on an independent real codebase.** Scan the repos in
   `scan-targets/` (cloned per `benchmark/ground_truth/clean_code/manifest.json`)
   and cite a `file:line` your rule flagged. Not a fixture, not a benchmark app.
2. **Show it does not flood.** Report the rule's total hit count across that
   corpus. A rule firing hundreds of times on well-maintained OSS is wrong
   regardless of how good the pattern looks.
3. **If step 1 finds nothing, say so in the PR.** A rule with no real-world
   true positive may still be correct for a rare-but-serious class, but it
   ships as unvalidated and should be called out, not quietly counted as
   coverage. Zero false positives is not evidence of precision when there are
   also zero true positives.
4. **Write the negative case too.** The safe form of the pattern must not fire.

**Never author against `benchmark/ground_truth/`.** The labelled corpora are a
regression check, not a target. A rule tuned until a specific benchmark vuln
flips to `hit` measures nothing except itself. If you find yourself reading
sink line numbers out of a `ground_truth.yaml` while editing a pattern, stop:
that is the failure mode this section exists to prevent.

Corollary for the benchmark: a recall improvement is only a *detection*
improvement if the rules were not changed to chase it. Scorer or harness fixes
that let existing findings be credited are worth making, but report them
separately from real capability gains.

### Benchmarks measure, they do not steer

The rule above applies to every benchmark (`benchmark/ground_truth/`,
RealVuln, Langfail, any future one) and to every change, not only rules:
taint sources and sinks, enrichment, deduplication, severity, and the shape of
the output.

- **Decide on the merits, then measure.** A change needs a reason that holds
  for real code: a CWE definition, what a framework actually does, a
  reproducible false positive or miss. Test it on a fixture written for that
  reason, not one copied from a benchmark app.
- **Ship the honest choice even when it scores worse.** Example: merged
  findings list every CWE their rules assigned. RealVuln counts each CWE as a
  separate finding, so this costs precision there. It stays, because it is
  the accurate output.
- **When a benchmark surfaces a problem, fix the problem, not the score.**
  State the code-level reason in the PR and say the benchmark only revealed it.
- **Never key anything to a benchmark.** No patterns, allowlists or
  suppressions tied to benchmark repo names, paths, function names, or the
  quirks of seeded bugs.
- **Never change a scorer, parser, matcher or ground truth to move Rowan's
  number.** A harness fix is allowed only when it corrects a real misreading
  of Rowan's output, and its effect is reported separately.
- **Report regressions as they are.** Do not iterate on a change until a
  benchmark number recovers.

### Rule ID conventions

| Prefix | Engine | Scope |
|--------|--------|-------|
| `NS-*` | NeuroScan regex | General |
| `ns-<topic>-*` | NeuroScan regex | Topic-specific: `aiml`, `sec`, `secret`, `cloud`, `cicd`, `websec`, `auth`, `fw`, `bb`, `grd`, `infra`, `stl`, `log` |
| `TNT-*` | Opengrep taint | General |
| `TNT-ML-*` / `TNT-AIML-*` | Opengrep taint | AI/ML-specific |
| `TNT-A2A-*` | Opengrep taint | Agent-to-agent (A2A) protocol |
| `tnt-<lang>-*` | Opengrep taint | Language-specific taint, native Opengrep format: `cs` (C#), `go`, `ja` (Java), `js`, e.g. `tnt-go-ssrf-001` |
| `A2A-*` | NeuroScan regex | Agent-to-agent (A2A) protocol |
| `CS-*` | NeuroScan regex | C# |
| `DK-*` | NeuroScan regex | Dockerfile |
| `GO-*` | NeuroScan regex | Go |
| `JA-*` | NeuroScan regex | Java |
| `JS-*` | NeuroScan regex | JavaScript |
| `LC-*` (`LC-HARDEN-*`) | Opengrep (search-mode + taint) | LangChain hardening |
| `PHP-*` | NeuroScan regex | PHP |
| `RB-*` | NeuroScan regex | Ruby |
| `RS-*` | NeuroScan regex | Rust |
| `TF-*` | NeuroScan regex | Terraform |

Check for duplicate IDs before submitting:
```bash
grep -rhoE '^[[:space:]]*-[[:space:]]*id:[[:space:]]*[^[:space:]]+' rules/*.yaml \
  | sed -E 's/^[[:space:]]*-[[:space:]]*id:[[:space:]]*//' | sort | uniq -d
```

## Adding a language

1. Add file extension mapping in `passes/file_scan.py` (`LANGUAGE_EXTENSIONS`)
2. Add extension mapping in `taint/opengrep_adapter.py` (`ext_map`)
3. Create `rules/<language>.yaml` with regex rules
4. Optionally create `rules/<language>_taint.yaml` with taint rules
5. Add tests

## Code style

- Python 3.10+ with `from __future__ import annotations`
- Type annotations on all public functions
- No comments unless absolutely necessary for clarity
- Line length: 100 characters
- Imports sorted by ruff (`isort` compatible)
- Security lints enabled (bandit rules via ruff `S` selector)

## Pull request checklist

- [ ] All tests pass (`pytest`)
- [ ] Lint clean (`ruff check rowan/ tests/`)
- [ ] No duplicate rule IDs
- [ ] New rules have CWE IDs and categories
- [ ] Taint rules have pattern-sources, pattern-sinks, and pattern-sanitizers
- [ ] New rules cite a real-world true positive (`file:line` from
      `scan-targets/`), or explicitly declare themselves unvalidated (see
      "Validating a rule")
- [ ] New rules report their total hit count across `scan-targets/`
- [ ] No rule was authored or tuned against `benchmark/ground_truth/`
- [ ] No change was made to raise a benchmark score; each has a real-code
      reason and its own fixture (see "Benchmarks measure, they do not steer")
- [ ] Rule messages claim only what the rule computes (no "user-controlled"
      from a bare pattern match)
- [ ] `python scripts/benchmark.py --corpus clean_code` shows no high/critical
      increase on any repo: that gate is a hard budget, not a tolerance
