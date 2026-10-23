# Changelog

## v0.4.0 (alpha)

Fixes from hand-verifying a random sample of 300 MCP servers from the official
registry.

- TS/JS command injection: `regex.exec(text)` is no longer a shell sink. Regex
  literals, `RegExp(...)` and regex-named receivers (`pattern`, `this.regex`)
  are excluded from the `$X.exec(...)` sink of TNT-TS-AGENT-CMDI-001 and
  TNT-TS-LLMOUT-CMDI-001. An SSH client's `conn.exec(command)` still reports.
- TS/JS SSRF: TNT-TS-AGENT-SSRF-001 no longer reports a tool argument that only
  fills the path or query of a fixed host: a literal `https://host/...` prefix,
  or a constant, `process.env` or imported base followed by `/`, `?` or `#`.
  `${BASE}${path}` still reports, because a `path` of `.evil.com/` moves the
  host. Needs the js-crossfile extra.
- MCP-CONFIG-001: base URLs, word-only paths, `your-...` placeholders,
  `${user_config.x}`-style substitutions and DSNs whose password is a
  placeholder word are no longer reported as hardcoded secrets.
- Cross-file: "leads to a sink" now spreads to a caller only through a call
  that hands it a tainted value, at every hop, not just the last one. JS/TS
  helpers that only relay into `fetch` (`getJson(url)` ->
  `fetchWithRetry(url)`) take host-position taint, so a fixed-host path built
  several calls up no longer reports as SSRF.

## v0.3.12 (alpha)

Fixes from a code audit of Rowan itself and from scanning 13 popular MCP
servers, plus Opengrep 1.31.

- `rowan install-engine` and the GitHub Action now install Opengrep v1.31.0
  (hash and Sigstore signature verified), which brings upstream taint fixes
  from v1.30.1.
- JS/TS cross-file: `obj.method()` on a receiver of unknown type follows the
  call into the project's classes that define `method`, when one to four
  classes do and the name is specific. Receivers destructured from a tool's
  arguments, builtins and module aliases are never fanned out.
- Code files skipped as build output (`dist/`, `build/`), minified or
  oversized are listed in `analysis_capability.skipped_code_files` and in the
  console and text reports. A scan that skipped a package's only bundle no
  longer prints "No vulnerabilities found."
- AI instruction files inside dot-folders (`.claude/skills/*/SKILL.md`,
  `.github/copilot-instructions.md`) now reach the Opengrep rules, so the
  Unicode smuggling rules (ns-aiml-107/108) cover them. `.git`, `.venv`, tool
  caches and `.claude/worktrees` stay excluded.
- Go: a hashed value (`sha256.Sum256`, `hex.EncodeToString`, a library
  `Digest()`/`Sum()`) and a number formatted with `%d`/`%x`/`%f` no longer
  carry taint into path, command, SQL or URL sinks. The Go SQL sinks ignore
  struct-literal option values and, for the context-first `Query(ctx, x)`
  form, receivers not named like a database handle (PromQL clients).
- MCP tools registered indirectly are now treated as tools: Python
  `mcp.tool(...)(func)`, `add_tool(func)`, wrapper decorators that register
  tools, and `apply()` on Tool subclasses; TypeScript handlers passed by name,
  through a factory, or in `{name, schema, handler}` / `{name, config, cb}`
  tool-definition objects. A referenced TS handler's own sinks are reported.
- Cross-file flows fed only by the operator's command line (`sys.argv`,
  `process.argv`) are capped at MEDIUM and marked `operator_controlled_source`,
  as the Opengrep path already did. A source read inside a nested callback no
  longer taints the function that registers it.
- Agent skill files (`SKILL.md`) are treated as AI instruction files: the
  zero-width and bidi smuggling rule (ns-aiml-108) now scans them, and Hunt
  keeps their text out of LLM context, as for `AGENTS.md`.
- `--policy deep` now runs the authz (BOLA/IDOR) and multiagent passes. They
  were selected but returned without scanning any file.
- A repo checked out under a folder named `build`, `dist`, `out`, `coverage`,
  `vendor` or `testdata` no longer loses its JS, Go and SCA files.
- JS/TS cross-file analysis reports the scan as degraded when tree-sitter is
  not installed, as Go already did. With `--ci` or `--fail-on-degraded`, a
  repo with JS or TS files now exits 2 unless `rowan[js-crossfile]` is
  installed.
- The RAG tenant-scope check no longer misses an owner-model query that
  follows an unrelated unscoped query in the same handler.
- Go cross-file analysis treats `os.Rename` as a path sink, matching the Go
  taint rules.
- SCA lists every reason the pass was degraded, not only the last one.
- A target that is not a directory, or cannot be resolved, is a usage error
  (exit 2) instead of exit 1, which CI reads as findings present.
- Hunt discovery verification no longer lets a misnumbered or repeated
  verdict overwrite another claim's verdict, and accepts citations of the
  code it showed the verifier instead of dropping those findings.

## v0.3.11 (alpha)

Fixes from a full review of the detection rules and engine (#47).

- `--confirmed` no longer hides FastAPI and Flask route-parameter flows:
  route parameters are traced as HTTP input.
- FastAPI dependencies declared through a type alias (`SessionDep =
  Annotated[Session, Depends(get_db)]`, `CurrentUser`) are no longer treated
  as request input, by the taint source or the cross-file route check.
- Engine findings (cross-file, authz) are no longer demoted by a regex over
  the first 50 lines of the file, so a route's severity no longer depends on
  the router's variable name.
- The auto deployment profile checks every file in sorted order instead of
  the first 20 in filesystem order, and never demotes a finding with a taint
  trace.
- Test-path detection no longer treats production files such as
  `demo_server.py` or `mock_server.py` as tests; demo and tool-directory
  files that serve requests are not demoted.
- Two taint sinks close together stay two findings; `occurrence_count` and
  `cluster_lines` report folded repeats.
- Duplicate merging: an unconfirmed taint finding no longer wins the merge,
  and code injection and command injection on one line stay separate.
- Taint sinks focus on the dangerous argument and accept extra arguments:
  - SSRF: the URL, so a tainted body or `params=` to a fixed host is not
    SSRF; `requests.get(u, timeout=5)` and session calls are matched.
  - SSTI: the template string, not the render context.
  - Deserialization and `exec`/`eval`: `yaml.load(d, Loader=...)`,
    `exec(code, {})` and `pickle.load(f, encoding=...)` are matched.
- Fixed rules: the Dockerfile setuid rule flagged `chmod 644` and missed
  setuid modes; a Java AI-key rule reported model names as CRITICAL secrets;
  Ruby backtick command injection could never match.
- A conversion-manifest load failure marks the scan degraded.

## v0.3.10 (alpha)

- FastAPI route parameters are taint sources. A parameter of a route
  handler (`@app.get("/x") def f(name: str, q: str = Query(), item: Item)`)
  now reaches the Python taint rules as user input. Validated types (`int`,
  `UUID`, ...), `Depends()`/`Security()` values and framework objects are not
  sources. XSS gains an `HTMLResponse` sink.
- SQL injection (`TNT-SQLI-002`) and vector-store query (`TNT-ML-004`) rules
  sink only the query argument. A database handle that carried user data no
  longer makes parameterized ORM lookups look like injection.
- One issue, one finding. Findings on one line merge when their rules use
  related CWEs (`eval()` tagged CWE-78, 94 or 95; debug mode as 215 or 489),
  and a pattern finding on a line a taint trace passes through merges into
  the taint finding. The merged finding keeps every CWE and the highest
  severity and confidence of its reports.
- `eval()`/`exec()` are reported as code injection (CWE-95), no longer as OS
  command injection (`TNT-CMDI-001`).
- CONTRIBUTING.md: benchmarks measure changes, they do not steer them.

RealVuln (63 repos, measured after the changes, not used to make them): TP
650 to 669, FP 1264 to 1226, precision 0.340 to 0.353, recall 0.353 to 0.364.

## v0.3.9 (alpha)

- Opengrep runs with a 4 GiB memory cap per rule per file. A file that hits
  the cap is reported as an incomplete taint scan with the file named, never
  as a clean result. SECURITY.md lists the limits Rowan actually has.
- JavaScript path traversal also accepts the guard as an early exit:
  `if (name.includes('/')) return ...` or `throw ...` clears uses of `name`
  after it.
- Header injection (`TNT-HEADER-001`) no longer flags `set_cookie`: the
  cookie encoders in Werkzeug, Django and Starlette quote or reject CR/LF.
  On RealVuln this removes 18 false positives (precision 0.336 to 0.340,
  recall unchanged).
- `JS-CRYPTO-002` (`Math.random()`) and `DK-CONFIG-006` (no Dockerfile
  HEALTHCHECK) are now INFO, out of the default view.
- The installer authenticates its Opengrep release lookup with
  `GITHUB_TOKEN` when one is set, avoiding API rate limits in CI.

## v0.3.8 (alpha)

- JavaScript taint rules see request fields destructured in a handler's
  parameters, as in `({ query }: Request, res) => ...`. Juice Shop's open
  redirect is now found.
- JavaScript path traversal no longer flags a name used inside an
  `if (!name.includes('/'))` block, and the NoSQL rule no longer treats
  Sequelize `where`/`include` options as MongoDB filters. On Juice Shop this
  removes 22 findings judged to be false positives.
- `--exploit` no longer treats link-local addresses, including the cloud
  metadata service, as local targets.
- Remove four disabled rules that had no effect on output.

The `includes('/')` guard is incomplete on Windows, where `\` is also a path
separator.

## v0.3.7 (alpha)

Safety release for `rowan hunt`.

- Prompts sent to an LLM endpoint that is not on this machine have likely
  secrets replaced with `[REDACTED-SECRET]`: private keys, cloud and API
  tokens, JWTs, URL passwords, and high-entropy literals in secret-named
  variables. Local endpoints (Ollama, a local server) receive source unchanged.
- `--exploit` only probes a `--base-url` on loopback or a private network.
  Pass `--allow-remote-target` to probe anything else you are authorized to
  test.
- New `--audit-log PATH` appends one JSON line per LLM call and live probe:
  endpoint, sizes, hashes and outcome, never content.

Redaction is pattern-based, so a secret in an unusual format can still reach a
cloud model. `--allow-remote-target` is your confirmation, not a check.
Link-local addresses, including cloud metadata endpoints, count as local.

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
