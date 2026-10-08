# Changelog

## v0.3.6 (alpha)

- New taint rules outside Python: open redirect for JavaScript, Go, Java and
  C#; XSS for Go; deserialization for JavaScript; template injection for
  JavaScript and Java; XXE for C#. JavaScript and Go redirects were previously
  reported as header injection.
- The new rules flag only what is unsafe in every library version: plain
  js-yaml `load` and default .NET XML parsing are not flagged, and template
  injection means user input used as the template, never as render data.
- A taint flow from a rule whose sources are request reads now keeps its
  severity in route modules without a framework import and in repositories
  detected as libraries.
- Validated on NodeGoat, WebGoat, govwa and WebGoat.NET: the new rules report
  five planted bugs in the default view, after fixing one false positive and
  one missed source found that way.

No benchmark here covers JavaScript, Go, Java or C# web code, so evidence for
the new rules is those apps plus unit fixtures. JavaScript handlers that
destructure the request (`({ query }: Request)`) are not yet modeled as
sources.

## v0.3.5 (alpha)

- Fix 117 rules that declared categories the scanner did not recognize. Some
  code-execution rules (unsafe `yaml.load`, `weights_only=False`, Keras
  `model_from_json`) were hidden from the default view as a result.
- Merge findings from different rules on the same sink into one, keeping the
  strongest evidence. Absorbed rules are listed in the new `duplicate_rule_ids`
  JSON field.
- `ns-auth-002` now sees an auth decorator above a handler. Remove
  `TNT-STORED-001`, `JS-SSRF-001` and `NS-SSRF-002`, which produced no true
  positives on RealVuln.
- RealVuln default view: precision 0.384 to 0.516, F2 26.5 to 28.1
  ([results](benchmark/results/realvuln-2026-10-08/README.md)).
- Hunt: attack-surface inventory, source-grounded verification evidence,
  configurable budgets, and resumable runs with `--checkpoint` / `--resume`.
- Baselines give identical lines distinct fingerprints and reject unknown
  versions. Opengrep runs with an allowlisted environment. JSON reports add
  `scan_manifest` and `schema_version`. New `--fail-on-degraded` flag.

A 0.3.4 baseline that covered several identical lines with one entry reports
the extra copies once. `ns-auth-002` findings on decorated handlers now point
at the first decorator line. Rowan was tuned with RealVuln in view.

## v0.3.4 (alpha)

- Calibrate log-forging findings using bounded values and resolved numeric
  formatting. Preserve claims for unknown values, mutation, shadowed helpers,
  dynamic formats and character conversion. Sensitive logging remains independent.
- Report object authorization guard gaps separately from confirmed impact.
  Unknown model policy yields MEDIUM review findings; pure existence observations
  are LOW. Add explicit qualified model read/write policies; public reads never
  authorize writes or opaque object/selector escapes.
- Expose authorization requirement, object use and model identity in JSON,
  with updated configuration and evidence schemas.

Annotations and ORM column declarations alone do not prove bounded log output.
Model policies describe intent, not runtime enforcement; guard gaps are excluded
from the confirmed view. Dynamic dispatch and complex helper protocols remain
conservative analysis limits.

## v0.3.3 (alpha)

- Require Hayward 1.2.5: distinguish TorchScript graph source from packaged
  Python, retain source presence as LOW, and report explicit packaged execution
  operations separately. Source inspection is bounded and never executes model code.
- Preserve model source presence as inventory in JSON and enrichment.
- Retain pickle detection and incomplete-coverage warnings independently.

Untrusted models remain programs. Static source analysis does not establish
reachability or malicious intent and does not fully assess graph/runtime behavior.

## v0.3.2 (alpha)

Improve Python detection across helpers, imports, and equivalent API layouts.

- Resolve static XML parser options passed through keyword dictionaries at the
  actual parser call, avoiding findings on unused option dictionaries.
- Follow request-derived streams through wrappers and repository helpers into
  `Unpickler.load()`. Preserve distinct deserialization sinks when deduplicating.
- Infer privilege fields from application guards and follow manually decoded,
  unsigned JWT claims into identity and privilege use.
- Analyze object reads through repository helpers and returned permission pairs;
  report unresolved imported object reads as authorization coverage signals.
- Add `request.stream` and `request.get_json()` to shared request-source coverage.
- Exclude resolved standard-library regex searches from vector-store and LDAP
  claims, and keep async log messages out of cross-file SQL sink summaries.

Analysis remains bounded and conservative. Dynamic dispatch, restricted-unpickler
allow-list gadgets, complex authorization protocols, and dynamic XML options
remain coverage limits. Findings remain review leads.

## v0.3.1 (alpha)

Documentation and packaging only; scanning behaviour is unchanged.

- Install docs use pipx or `uv tool`; a bare `pip install` fails on
  Homebrew and other externally managed Pythons.
- Getting started explains how to add an LLM for `rowan hunt` (Ollama,
  DeepSeek or OpenRouter), and the usage guide lists every backend env var.
- The GitHub Action has a fuller description for its Marketplace listing,
  and its docs show the `security-events: write` permission it needs.

## v0.3.0 (alpha)

First public release.

- `rowan scan`: static analysis of source code and model files, with text,
  JSON, HTML and SARIF reports.
- Opengrep within-file dataflow, plus cross-file analysis for Python and JS/TS
  and limited cross-file analysis for Go.
- Model-file scanning by [Hayward](https://github.com/hedgerow-dev/hayward)
  (pickle, PyTorch, GGUF, SafeTensors, Keras, ONNX, TensorFlow and more).
- AI/ML checks: model loading, agent tools, LLM output handling, prompt and
  instruction files, MCP configuration.
- Dependency CVE lookup with reachability hints, CycloneDX SBOM and OpenVEX output.
- Baselines, CI exit codes, a GitHub Action and a pre-commit hook.
- An MCP server (`rowan-mcp`) for coding agents.
- Experimental `rowan hunt` for LLM-assisted review.

Findings are review leads. See the README for coverage limits.
