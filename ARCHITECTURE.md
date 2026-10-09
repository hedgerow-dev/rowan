# Architecture

Rowan is a static application security testing (SAST) scanner that wraps
Opengrep's compiled-OCaml taint engine via subprocess and augments it with
regex-based surface scanning, dependency analysis, cross-file propagation,
model file validation, and optional LLM-powered autonomous hunting.

## System overview

```
                          ┌──────────────┐
                          │  rowan  │
                          │     CLI      │
                          └──────┬───────┘
                                 │
                          ┌──────▼───────┐
                          │ ScanPipeline │
                          └──────┬───────┘
                                 │
          ┌──────────────────────┼──────────────────────┐
          │                      │                      │
    ┌─────▼─────┐         ┌─────▼─────┐         ┌─────▼─────┐
    │ FileScan   │         │  Taint    │         │   SCA     │
    │   Pass     │         │   Pass    │         │   Pass    │
    │ (regex)    │         │(Opengrep) │         │(OSV.dev)  │
    └─────┬─────┘         └─────┬─────┘         └─────┬─────┘
          │                      │                      │
          └──────────────────────┼──────────────────────┘
                                 │
                          ┌──────▼───────┐
                          │  CrossFile   │
                          │ Pass + JS    │
                          │ (AST fixpt)  │
                          └──────┬───────┘
                                 │
                          ┌──────▼───────┐
                          │AST Enrichment│
                          │Pass (implicit│
                          │ sanitizers)  │
                          └──────┬───────┘
                                 │
                          ┌──────▼───────┐
                          │  ModelFile   │
                          │  Scan Pass   │
                          │(pickle/GGUF) │
                          └──────┬───────┘
                                 │
                          ┌──────▼───────┐
                          │ Enrichment   │
                          │    Pass      │
                          │(dedup/score) │
                          └──────┬───────┘
                                 │
                          ┌──────▼───────┐
                          │  Reporters   │
                          │ SARIF/JSON/  │
                          │    Text      │
                          └──────────────┘
```

## Module map

```
rowan/
├── __init__.py                 # Package version
├── cli.py                      # Click CLI entry point
├── languages.py                # Canonical language names and engine/file matching views
├── artifacts.py                # Shared dependency-manifest and model-artifact classifiers
├── project_config.py           # Versioned public .rowan.yml schema and merge
├── scan_plan.py                # Pure pass-selection plan and executable pass factories
├── config/__init__.py          # ScanConfig dataclass
├── pipeline.py                 # ScanPipeline orchestrator + analysis-capability manifest
├── reporters.py                # SARIF v2.1.0, JSON, text, HTML, OpenVEX, CycloneDX SBOM formatters
├── mcp_server.py               # MCP evidence server (`rowan-mcp`, optional [mcp] extra)
├── core/
│   ├── findings.py             # Finding, Severity, Category, TaintFlow, ScanResult
│   ├── rules.py                # NeuroScanRule model and YAML loader
│   ├── reachability.py         # AST call-graph reachability analysis (SCA)
│   ├── vuln_functions.py       # curated package -> vulnerable function names (SCA reachability)
│   ├── advisory_functions.py   # per-CVE vulnerable-symbol extraction from OSV advisory text
│   ├── phantom_deps.py         # undeclared (phantom) dependency detection
│   ├── typosquat.py            # typosquatting detection (Damerau-Levenshtein vs. popular-package corpus)
│   ├── install_hooks.py        # suspicious npm install-lifecycle-hook detection
│   ├── version_ranges.py       # pip/npm range-overlap solver + nearest-fixed-version
│   ├── scan_result.py          # Re-export convenience
│   ├── confidence.py           # single source of truth for taint confidence scoring (opengrep + crossfile), #123
│   ├── authz_predicates.py     # ownership/membership/hierarchical/status authz-predicate recognizers for AuthzPass
│   ├── agent_privilege.py      # tool-privilege recognition for MultiAgentPass's agent-handoff detection
│   ├── llm_sources.py          # recognizer for "this value came from an LLM completion/tool-call", AUTHZ-LLM-001
│   ├── mcp_config.py           # MCP deployment-config JSON scanner (hardcoded secrets, over-privileged servers)
│   ├── paths.py                # shared path-confinement check for every file-discovery walk (symlink escape guard)
│   ├── profiles.py             # deployment profile filtering (which rule categories are active)
│   ├── rule_class.py           # rule classification: vulnerability vs. attack-surface inventory
│   └── sanitizers.py           # per-category sanitizer pattern registries
├── passes/
│   ├── base.py                 # ScanContext, PipelineStep protocol
│   ├── file_scan.py            # FileScanPass (regex matching)
│   ├── taint.py                # TaintPass (Opengrep wrapper)
│   ├── sca.py                  # SCAPass (OSV.dev API + reachability)
│   ├── sibling_gate.py         # SiblingGatePass (dangerous primitive used where the repo's own wrapper is skipped)
│   ├── cross_file.py           # CrossFilePass (AST-based fixpoint, Python)
│   ├── js_cross_file.py        # JSCrossFilePass (AST-based fixpoint, JS/TS, optional tree-sitter)
│   ├── go_cross_file.py        # GoCrossFilePass (parameter-aware request-to-command/SQL tracing)
│   ├── pii_egress.py           # PiiEgressPass (PII flowing to external services)
│   ├── training_disclosure.py  # TrainingDisclosurePass (model-training data disclosure)
│   ├── model_extraction.py     # ModelExtractionPass (model extraction interfaces)
│   ├── membership_inference.py # MembershipInferencePass (membership inference exposure)
│   ├── dormant_code.py         # DormantCodePass (disabled security-sensitive code)
│   ├── training_approval.py    # TrainingApprovalPass (training without approval gates)
│   ├── config_taint.py         # ConfigTaintPass (unsafe configuration propagation)
│   ├── authz.py                # AuthzPass (object-level authz / BOLA/IDOR detection, Python, opt-in)
│   ├── js_authz.py             # JSAuthzPass (Express/Mongoose/Prisma object-level authz, optional tree-sitter)
│   ├── serialization_scope.py  # SerializationScopePass (scoping constructor param dropped by its own serializer)
│   ├── web_security.py         # WebSecurityPass (structural Python web checks)
│   ├── agent_flow.py           # AgentFlowPass (agent trust-boundary flows)
│   ├── multiagent.py           # MultiAgentPass (CrewAI cross-agent injection propagation, opt-in)
│   ├── ast_enrichment.py       # ASTEnrichmentPass (implicit sanitizer detection)
│   ├── mfv.py                  # ModelFileScanPass
│   ├── mcp_config.py           # MCPConfigScanPass (MCP client config JSON: secrets, over-privileged servers)
│   ├── mcp_network_exposure.py # MCPNetworkExposurePass
│   ├── mcp_sampling_approval.py# MCPSamplingApprovalPass
│   ├── mcp_tool_metadata.py    # MCPToolMetadataPass
│   ├── mcp_stored_content.py   # MCPStoredContentPass
│   ├── instruction_smuggling.py# InstructionSmugglingPass
│   └── enrichment.py           # EnrichmentPass (dedup, confidence, escalation)
├── taint/
│   └── opengrep_adapter.py     # Opengrep subprocess wrapper, JSON result parser
├── agents/
│   ├── llm_backend.py          # LLMBackend (DeepSeek/OpenAI/OpenRouter/Ollama/local)
│   ├── workflow.py             # HuntWorkflow (7 stages; optional discovery adds one)
│   ├── estimate.py             # estimate_hunt (free scope/cost preview, zero LLM spend)
│   ├── doctor.py               # run_doctor (backend credential/connectivity checks)
│   └── web_exploit.py          # WebExploitRunner (live HTTP probes)
```

## Pipeline

`ScanPipeline` runs an explicit staged DAG. Discovery executes first, followed
by Opengrep in an isolated engine stage because it owns bounded subprocess
batching. Other independent detectors then run concurrently within the
configured worker budget; cross-file correlation runs only after their ordered
merge; and the two mutating enrichment passes run last. Results merge in plan
order rather than completion order, preserving deterministic output. The pure
`build_scan_plan(config)` function in `scan_plan.py` is the source of truth for
pass order and option-dependent selection; the pipeline instantiates that plan
after loading its rule inputs. A normal scan selects 25 passes. `--authz` adds
two and `--multiagent` adds one, so the maximum is 28. Some selected passes can
still no-op when their optional parser or applicable input type is absent.

`concurrency` is the default cap for both detector workers and scan-owned
network work. SCA acquires the shared `ScanContext.network_semaphore` for
every OSV batch/page, advisory hydration, and EPSS request, so its internal
hydration pool cannot create a second hidden request fan-out. Advanced callers
can set `network_concurrency` independently when their advisory-service quota
requires a lower cap. Opengrep remains isolated because it manages a bounded
subprocess/CPU budget of its own.

Explicit concurrency overrides are restricted to 1–64, and an explicit
Opengrep batch timeout is restricted to 1–86,400 seconds. These hard ceilings
are enforced by `ScanConfig` as well as the CLI, so embedded callers cannot
bypass the host-safety policy.

The CLI's `scan --explain-plan` path applies project configuration, validates
the effective `ScanConfig`, and prints this plan without loading rules, reading
the target tree, constructing analyzers, invoking Opengrep, or making network
requests. Text output shows the ordered pass table; `--format json` emits the
path-free effective policy plus selected and explicitly disabled passes. The
same builder supplies the executable pipeline, but other entry points have not
yet all been migrated to one request-resolution layer.

The effective policy also carries the resolved detector-worker and network
request limits. This makes `scan --explain-plan` a cost/safety preview: a
default network limit inherits `concurrency`, while `network_concurrency`
shows as an explicit override.

The current groups and order are:

| Group | Passes | Selection |
|---|---|---|
| Discovery and engines | `FileScanPass`, `TaintPass`, `SCAPass` | File scan always runs. Taint normally runs; with `--no-taint` it still runs converted regex rules in regex-only mode unless `--legacy-neuroscan` is also selected. SCA is omitted by `--no-sca` |
| Whole-repository analysis | `SiblingGatePass`, `CrossFilePass`, `PiiEgressPass`, `TrainingDisclosurePass`, `ModelExtractionPass`, `MembershipInferencePass`, `DormantCodePass`, `TrainingApprovalPass`, `ConfigTaintPass`, `JSCrossFilePass`, `GoCrossFilePass` | All eleven are omitted by `--no-cross-file` |
| Optional analysis | `AuthzPass`, `JSAuthzPass`, `MultiAgentPass` | The authz pair requires `--authz`; multi-agent analysis requires `--multiagent` |
| Always-scheduled specialist and post-processing | `SerializationScopePass`, `WebSecurityPass`, `AgentFlowPass`, `ASTEnrichmentPass`, `ModelFileScanPass`, `MCPConfigScanPass`, `MCPNetworkExposurePass`, `MCPSamplingApprovalPass`, `MCPToolMetadataPass`, `MCPStoredContentPass`, `InstructionSmugglingPass`, `EnrichmentPass` | Always scheduled after the groups above |

Each pass implements the `PipelineStep` protocol (`name: str`,
`run(context) -> ScanResult`). The sections below describe the principal
passes in detail; the table above is the complete execution inventory.

As each scheduled pass returns, the pipeline appends an entry to
`result.metadata["pass_outcomes"]`. Every entry contains the pass `name`,
stage, `status` (`completed` or `degraded`), wall-clock `duration_seconds`, the
pass-local `files_scanned`, and its net `findings_delta`; degraded reasons
and errors are included when present. The JSON reporter exposes this list as
the top-level `pass_outcomes` field, while SARIF places it under run
properties. This records actual execution:
selected passes appear in order, omitted passes are absent, and passes that
complete with no findings still have an outcome. It does not imply that all
passes yet share one inventory or parser cache.

Configuration-omitted passes are listed separately in `skipped_passes` with
`status="explicitly_disabled"` and the controlling option. This keeps an
intentional omission distinct from an executed pass that degraded because an
engine was unavailable.

After discovery, passes whose required input is provably absent are recorded
in `inapplicable_passes` with `status="not_applicable"` and are not executed.
This currently covers dependency manifests (SCA), model artifacts (MFV), MCP
configuration files, and Python or JavaScript/TypeScript-only analyzers. It is
distinct from both a user-disabled capability and a completed empty scan.
`filter_counts` preserves counts around AST enrichment, final enrichment, view,
severity, baseline, and ignore processing. The structured reporters also
expose a path-free `scope_summary` containing
the resolved source-file total and per-language counts. `coverage_summary`
combines executed, not-applicable, and explicitly disabled pass states into a
path-free completeness verdict, while `report_view` remains explicit even when
the selected view hides no findings.

### FileScanPass

Loads all `*.yaml` rule files from `rules/` (`pipeline.py`'s discovery glob
is unfiltered; a rule file with no string `patterns` block, i.e. an
Opengrep-only rule, is dropped later inside `core/rules.py::_parse_neuroscan_rule`,
not excluded at discovery time), parses the survivors into `NeuroScanRule`
objects, then runs each rule's compiled regex against every source file.
Supports 18 language/file categories via the canonical registry in
`rowan/languages.py` (which derives the FileScan and Opengrep matching
views): `.py`/`.pyi`, `.js`/`.jsx`/`.mjs`/`.cjs`,
`.ts`/`.tsx`, `.java`, `.go`, `.cs`, `.rb`, `.php`, `.rs`, `.tf`/`.tfvars`,
`Dockerfile`, `.yaml`/`.yml`, `.json`, server-rendered templates
(`.html`/`.htm`/`.jinja`/`.jinja2`/`.j2`), AI instruction/prompt files
(`CLAUDE.md`, `AGENTS.md`, `.cursorrules`, `copilot-instructions.md`,
`.prompt.md`), `.md`, `.txt`, and the bare `.env` dotfile.

File discovery enumerates the target tree once and applies the supported
suffix/exact-name, language, ignore, vendored/minified, size, and path-safety
checks to that stream. It publishes the result as an immutable, typed
`SourceInventory` on `ScanContext`. `SiblingGatePass`, `CrossFilePass`,
`PiiEgressPass`, `TrainingDisclosurePass`, `ModelExtractionPass`,
`MembershipInferencePass`, `DormantCodePass`, `TrainingApprovalPass`,
`ConfigTaintPass`, `SerializationScopePass`, `WebSecurityPass`, `AuthzPass`,
`AgentFlowPass`, `MultiAgentPass`, `MCPNetworkExposurePass`,
`MCPSamplingApprovalPass`, `MCPStoredContentPass`, and `MCPToolMetadataPass`
consume its Python `.py` subset instead of walking the repository again. `JSCrossFilePass` consumes
the JavaScript/TypeScript subset and `GoCrossFilePass` consumes the Go subset. TaintPass reuses the Python subset for its
keyword-count preflight and hands the complete inventory to Opengrep as exact
candidate targets; the adapter reapplies its engine-specific language and path
filters without another repository walk. Each consumer retains its own hidden-directory,
`site-packages`, test-path, symlink-confinement, and ignore rules as
applicable. When one of these passes is run by itself and no inventory has
been published, it falls back to its original repository discovery behavior.

Automatic deployment-profile detection receives inventory candidates for
Python, Java/Kotlin, Go, and C#; it does not rediscover those languages during
a pipeline scan. SCA's phantom-dependency analysis likewise treats its Python
candidate list as authoritative, including package `__init__.py` files, while
standalone calls retain their conservative walk fallback. Static applicability
also omits instruction-smuggling when no instruction/prose files exist and AST
enrichment when no Python `.py` source exists; these skips are recorded as
`not_applicable` outcomes.
The same traversal also classifies dependency manifests, supported model
artifacts, and recognized MCP client configs. `SCAPass` consumes
`SourceInventory.dependency_manifests`, while
`ModelFileScanPass` passes `SourceInventory.model_artifacts` to its scanner;
`MCPConfigScanPass` consumes `SourceInventory.mcp_config_files`. Their
standalone fallback discovery is preserved. These artifact lists do not
inflate the source-file count or become regex/Opengrep source targets. The
The Unicode instruction-smuggling prose pass also consumes the relevant
instruction/Markdown/text subset and reads it through the scan-owned source
snapshot. Remaining work is richer applicability
signaling, not an additional repository-wide content walk.

`ScanContext` also owns a lazy `SourceSnapshot` for the lifetime of the scan.
It maintains independent 2,048-entry LRU caches for UTF-8 source text and
Python parse results, including cached read and syntax failures. Sixteen Python
analyzers currently use the shared AST cache: PII-egress, training-disclosure,
model-extraction, config-taint, training-approval, dormant-code,
membership-inference, agent-flow, web-security, authz, serialization-scope,
multi-agent, MCP network-exposure, MCP sampling-approval, and MCP
stored-content, plus MCP tool-metadata. Taint's keyword preflight also shares
cached text. A retained
file is therefore read and parsed once across these passes while cached.
The cached AST is canonical: every request receives a defensive deep copy,
preventing analyzer mutations from leaking into later passes. A new
`ScanContext` creates a new snapshot and therefore observes edits made between
scans. Cache eviction may repeat work later in a very large scan, but bounds
retained snapshot state.

Structured JSON and SARIF telemetry exposes path-free snapshot entry, hit,
miss, read-failure, and parse-failure counts. These counts make cache behavior
and incomplete syntax coverage observable without publishing source paths. A
snapshot read or Python parse failure also adds a `source_snapshot` degradation
reason, so incomplete cached-source coverage cannot be reported as clean.

Findings from this pass have `engine="neuroscan"`.

### TaintPass

Discovers rule files matching `*_taint.yaml`, `*_taint_*.yaml`, or
`*_opengrep.yaml` (the last added for issue #186's search-mode guardrail
rules, e.g. `guardrail_opengrep.yaml`) and delegates to `OpengrepAdapter`.
The adapter runs:

```
opengrep scan --config <rules_dir> --json --dataflow-traces --no-git-ignore --max-target-bytes <n> --timeout 0 --timeout-threshold 0 <target>
```

Opengrep's native `--json` output (not SARIF) is parsed into `Finding`
objects with full `TaintFlow` (source, sink, intermediate nodes):
`--json`'s `extra.metadata` carries a rule's full `metadata:` block inline,
which SARIF's `properties` never populates, so category/CWE/fix/confidence
are read directly at parse time with no separate manifest side-channel
needed. `--dataflow-traces` is required for `codeFlows`/taint-flow data to
be present at all. The pass is skipped gracefully if Opengrep is not
installed. `OpengrepAdapter` caches its availability/version preflight, with
locking for concurrent callers, so one adapter instance invokes
`opengrep --version` at most once even when the probe fails. An authoritative
empty source inventory returns a complete zero-target result before this
preflight, so it launches neither a version probe nor a scan subprocess and
does not advertise any language frontend as executed.

For a non-empty scope, timeout, batches, and Opengrep jobs are derived from
the selected target count and aggregate bytes when no expert override is
provided. The automatic policy is bounded to four batches and eight Opengrep
CPU jobs, further capped by the scan's `concurrency` budget, and records the
effective choices in `opengrep_execution` telemetry.

Despite its name, `--no-taint` disables Opengrep's taint/dataflow rules, not
necessarily the Opengrep process. With the default converted regex engine,
the pipeline still schedules a regex-only `TaintPass` so converted
`pattern-regex` rules run. Only `--no-taint --legacy-neuroscan` omits the
Opengrep pass entirely.

Findings from this pass have `engine="opengrep"`.

### SCAPass

Consumes dependency-manifest candidates classified during FileScan's shared
traversal using `DEPENDENCY_MANIFEST_PATTERNS` in `rowan/artifacts.py`
(`REQUIREMENT_PATTERNS` remains a compatibility alias in `passes/sca.py`). The
registry covers Python, npm, Maven/Gradle, .NET, Go, Cargo, Ruby, and Composer
manifest/lockfile forms; there is no `go.sum` pattern. `SCAPass` extracts
package names and versions
(preferring lockfiles over manifests, with transitive-dependency chains
derived from lockfile graphs), and queries the OSV.dev API in batches.
During a pipeline scan, its Python reachability and phantom-dependency checks
also consume the discovery inventory instead of starting an additional source
walk; direct pass callers retain the bounded standalone fallback.

The automatic deployment-profile heuristic is likewise evaluated from that
inventory during enrichment, so excluded Python files cannot affect the
selected profile or trigger a second traversal.

**Reachability analysis** (`core/reachability.py`, `_apply_reachability` in
`sca.py`): for each CVE finding a real Python `ast` call-graph (with
import-alias resolution) checks whether the CVE's *specific vulnerable
function* is actually invoked anywhere in the target codebase (not a
substring match, a resolved `ast.Call` node). The vulnerable-function names
come from two sources, curated first: `core/vuln_functions.py` hand-maps
high-value packages (highest precision), and for everything else
`core/advisory_functions.py` extracts the vulnerable symbol *per CVE* from the
OSV advisory `details` already fetched with the finding (qualified,
in-namespace, code-span-only, so it never causes a false downgrade). This
scales reachability past the hand-mapped set to the long tail;
`finding.metadata["vuln_func_source"]` records `"curated"` vs `"advisory"`.
Unreachable CVEs are downgraded to LOW / 0.3 confidence rather than dropped;
`finding.metadata["reachability"]` is `"reachable"`/`"unreachable"` either
way, with `reachability_evidence` naming the call site when reachable.

**Prioritization & remediation:** each finding is enriched with the nearest
safe version to upgrade to (`nearest_fixed_version`, from OSV's own `fixed`
events → `metadata["fixed_version"]` and the message) and, best-effort, an
**EPSS** exploit-probability score from FIRST.org (`_apply_epss` →
`metadata["epss"]`/`epss_percentile`, keyed on the CVE id with a GHSA→CVE
alias fallback).

**Phantom dependencies** (`core/phantom_deps.py`, `SCA-PHANTOM-001`): imports
used in code but declared in no manifest: undeclared, version-uncontrolled,
and invisible to manifest-based scanning. Precision-first (stdlib, first-party
modules, and alias-mapped distributions are all excluded).

**Malicious-package detection:** OSV `MAL-` advisories are labeled malicious,
forced to CRITICAL, and exempted from the reachability downgrade (presence is
the risk); `core/typosquat.py` (`SCA-TYPOSQUAT-001`) flags names one
Damerau-Levenshtein edit (including adjacent transpositions) from a curated
corpus of popular squat targets; `core/install_hooks.py` (`SCA-INSTALL-001`)
flags npm `preinstall`/`install`/`postinstall` scripts running network
fetches, pipe-to-shell, or inline `eval`.

**Supply-chain artifacts:** `--vex` writes an OpenVEX document whose per-CVE
status is driven by the reachability signal (reachable → `affected`; anything
else → `under_investigation`, because absence from the call index is not proof
of unreachability, so Rowan does not currently emit `not_affected`), and `--sbom` writes a
CycloneDX 1.5 bill of materials of the full inventory. Both are generated from
the complete, unfiltered result *before* the severity filter runs (`pipeline.py`),
so `--severity high` can't drop the `not_affected` VEX statements.

Findings from this pass have `engine="depguard"`.

### SiblingGatePass

A precision-first AST pass that asks a different question than a normal
rule: not "is this call dangerous?" but "does this codebase already have a
validated wrapper around this dangerous primitive, and did this call site
skip it?" It looks for a thin, validating helper function fronting one of a
short list of dangerous primitives (`requests.get`/`post`, `httpx.get`/`post`,
`urlopen`, `aiohttp.request`, `pickle.load`/`loads`, `torch.load`,
`yaml.load`, `subprocess.run`/`Popen`/`check_output`, `os.system`,
`shutil.unpack_archive`), and only treats a direct call to the same
primitive elsewhere as a bypass once the wrapper is genuinely established:
thin (at most 25 statements), demonstrably validating the value it passes
on, and used at 3+ distinct call sites across 2+ distinct files. The finding
carries evidence on both sides, the wrapper that exists and the sibling call
sites that honor it, which an LLM reviewer structurally struggles to
reproduce since it requires enumerating every call site in the repository.
Validated against the NVIDIA Dynamo assessment (2026-08-06), where
multi-backend drift produced exactly this shape.

Runs only when cross-file analysis is enabled (`--no-cross-file` disables
this pass along with CrossFilePass and JSCrossFilePass, since it shares
CrossFilePass's whole-repo Python file collection).

Findings from this pass have `engine="siblinggate"`, rule id `SIBLING-001`.

### CrossFilePass

Python-only cross-file taint propagation using the `ast` module. This stays a
bespoke AST pass rather than a set of Opengrep taint rules by deliberate
decision, not oversight: an earlier evaluation found that Opengrep OSS taint is intra-file only
(`--taint-intrafile`; inter-file taint is a closed Semgrep Pro feature), so a
pattern-based taint rule structurally cannot express a cross-file,
interprocedural, or second-order flow, which is the entire reason this pass exists.
The real motivation behind proposing the merge (duplicated source/sink/
sanitizer definitions drifting between the two engines) is instead fixed by
sharing definitions without merging the engines: `rowan/rules_registry.py`
(#159) is now the single source of truth those definitions sync from, and
`core/confidence.py` (#123, below) is the single source of truth for both
engines' confidence scoring.

Cross-file propagation itself:

1. **Parse** all `.py` files, extracting import graphs, a per-`(file, name)`
   function index (`def_nodes`, used to resolve a sanitizer call through the
   caller's OWN file/import graph first, falling back to a project-wide
   bare-name scan of every same-named candidate only when genuinely
   ambiguous; see `_classify_sanitizer_by_name` below), each file's own
   `ClassDef` names (`classes_by_file`, used the same way to resolve ORM
   model identity), a set of tainted ORM `(Model, field)` channels
   (`_collect_orm_write_channels`), and a set of recognized agent-tool
   function/method AST nodes (`_collect_agent_tool_nodes`)
2. **Annotate** functions with source/sink/propagator markers from Passes
   1-2, *plus* three structural markers computed directly from the AST
   (not dependent on any regex/taint rule having already fired). Every
   function summary (`_FunctionSig`) also records an `end_line` (from
   `ast.FunctionDef.end_lineno`, or a tree-sitter node's `end_point` row for
   JS/TS) so a finding is only attributed to a function whose body actually
   spans its line: a module-level sink below the last `def` in a file no
   longer gets misattributed to that unrelated function:
   - **Structural path-write/read sinks** (`_structural_path_sink`): a
     function parameter joined onto a base-dir-looking constant
     (`os.path.join(ARTIFACT_DIR, name)` / `Path(BASE) / name`) reaching
     `open()`/`os.makedirs()`/`os.remove()`/etc., catching service-layer
     sinks that `NS-PATH-001`'s single-line `request.*` regex can't reach
     at all. Any locally-defined "sanitizer" call found in between is
     classified `strong` (proper `realpath`/`resolve` + `commonpath`/
     `is_relative_to` containment check, or a strip that loops to a fixed
     point, suppresses), `weak` (a single non-recursive
     `.replace("../", ...)`-style strip that's bypassable, e.g. `"....//"`
     collapses to `"../"` after one pass, so it still surfaces, with the bypass
     named in the message), or `unknown` (unresolvable or unrelated to
     path traversal at all, suppressing conservatively). The sanitizer name
     is resolved through the calling function's own file/import graph first
     (`_classify_sanitizer_by_name`); if it stays ambiguous (no resolvable
     definition), every same-named candidate project-wide is classified and
     the WEAKEST verdict wins (`weak` < `unknown` < `strong` for
     suppression purposes), so two functions both named `sanitize`
     (one strong, one weak) can no longer resolve to whichever happens to
     parse first, and ambiguity never silently drops a finding.
   - **Second-order ORM-persistence taint** (`_function_reads_orm_channel`):
     a function that reads a tainted `(Model, field)` channel back out of
     the database (`db.session.get(Model, pk)` / `Model.query....()`) is
     treated as if it read a source directly, even though there's no call
     edge at all between the writer and the reader (a request handler
     persists the value; a worker/job/other endpoint reads it back later).
     Both the writer's and reader's model-class identity are resolved
     through the import graph (`_resolve_orm_class_file`: a same-file
     `ClassDef` first, then `_ImportGraph.name_to_def`); when both resolve,
     the channel is scoped `(defining_file, ClassName, field)` so two
     unrelated models sharing a bare class name (`User` in two apps of a
     monorepo) can no longer cross-contaminate each other's channel. When
     either side is unresolvable, the channel falls back to the bare
     `(ClassName, field)` shape (recall-preserving).
   - **Second-order vector-store/RAG-persistence taint** (`_collect_vector_write_channels`,
     #156): the RAG analogue of the ORM channel above: a request handler
     embeds user input into a vector store (`collection.add_documents(...)`,
     `.add_texts(...)`, ...), and an unrelated retrieval call elsewhere in
     the codebase (`.similarity_search(...)`, `.query(...)`, ...) reads it
     back out and feeds it to an LLM prompt/sink with no direct call edge
     between writer and reader. Unlike the ORM channel, a vector store has
     no AST-stable per-instance identity to scope by, so this channel is
     intentionally coarse: a single project-wide sentinel key
     (`_VECTOR_CHANNEL_KEY`) armed by any recognized vector-store write and
     read by any recognized vector-store retrieval call, gated on the
     receiver name hinting at a vector store/index/retriever (`collection`,
     `index`, `retriever`, `chroma`, `faiss`, `pinecone`, `weaviate`,
     `qdrant`, `milvus`, ...) to avoid arming on an unrelated same-named
     `.add()`/`.query()`.
   - **Scalar-annotation taint incapability** (`_scalar_annotated_params`,
     #121): a function parameter type-annotated `int`/`float`/`bool`/
     `complex` can't carry a string-shaped injection payload, so it's
     excluded from taint propagation even if the caller passes
     source-tainted data into that argument slot, cutting false positives on
     functions like `def paginate(page: int, size: int)` that structurally
     look like sinks but can't actually be reached with attacker-controlled
     *content*, only attacker-controlled *values already coerced to a safe
     type* by the caller.
   - **Structural trust-boundary sources** (`_collect_boundary_nodes`, a
     union of five detectors): any function whose own arguments are
     attacker-influenced because the *caller* is untrusted, not because a
     bare `request.*` attribute is read. Covers:
     - **Agent tools** (`_collect_agent_tool_nodes`/`_is_tool_class`): a
       LangChain/CrewAI/AutoGen-style `BaseTool` subclass's
       `_run`/`run`/`_arun`/`arun` method, or a bare `@tool`-decorated
       function: an LLM chooses a tool's arguments at runtime, and if that
       LLM's own instructions were shaped by prompt injection, the
       arguments are no more trustworthy than `request.args`.
     - **Task queues** (`_collect_task_queue_nodes`): Celery/RQ
       `@task`/`@shared_task`-decorated function bodies.
     - **gRPC** (`_collect_grpc_servicer_nodes`): public methods on a
       grpcio-generated `*Servicer` subclass.
     - **GraphQL** (`_collect_graphql_resolver_nodes`): graphene's
       `resolve_<field>` convention, or a strawberry/ariadne
       `@<...>.field(...)`-decorated resolver, gated on GraphQL-looking
       class/decorator context to avoid misfiring on an unrelated
       `resolve_*`-prefixed helper.
     - **Webhooks** (`_collect_webhook_handler_nodes`): a route whose
       decorator path argument or function name mentions
       "webhook"/"callback".

     For all five kinds, the base-dir-join requirement is dropped (any
     direct use of the tainted argument in a sensitive call is inherently
     suspicious) and the sink set is broadened to `eval`/`exec`/
     `subprocess.*`/`requests.*`/`httpx.*` (qualifier-checked, so generic
     method names like `.run()`/`.get()` don't fire project-wide). A hit is
     emitted directly as a standalone same-file finding with a kind-specific
     rule ID (`AGENT-TOOL-001`, `TASK-QUEUE-001`, `GRPC-001`,
     `GRAPHQL-001`, `WEBHOOK-001`; see below) rather than only feeding
     cross-file propagation, since the vulnerable pattern is usually
     contained within the boundary function's own body: no file boundary
     needs crossing at all.
3. **Propagate** taint across file boundaries via BFS worklist (`_propagate_cross_file`,
   #163, replacing the earlier fixed-iteration-cap fixpoint loop with three
   independent BFS closures that converge to the *true* reachable set, with
   real shortest hop distances and predecessor chains for the two
   directions that need chain reconstruction, rather than an approximation
   bounded by an arbitrary iteration cap):
   - Build the reverse call graph (callee → callers) once, up front.
   - Downward (`_bfs_taint_upward` over sinks): if a callee has a sink,
     callers inherit sink taint. A finding is only emitted for a
     caller/callee edge that also passes at least one argument
     (`_FunctionSig.calls` entries carry a `has_args` bit set at
     extraction): a caller reading a source and separately calling an
     unrelated zero-argument function that happens to have its own sink no
     longer produces a finding claiming its source data "reaches" that sink.
   - Upward (`_bfs_taint_upward` over returns): if a callee returns tainted
     data, callers get return taint. `has_return_taint` is only set when
     the function's own `Return` value actually reads a source (or a
     source-derived local), not merely because the function contains a
     source read somewhere with an unrelated return value.
   - Source propagation (`_bfs_reachable_forward`): if a caller has source,
     callees inherit it. As of #119 this is **argument-to-parameter
     threading**, not just an edge-level `has_args` bit: each call site's
     `tainted_arg_slots` (which positional index or keyword name actually
     carries source-tainted data) is resolved against the callee's real
     `params` list into `edge_bindings`, the set of callee parameter
     *indices* that receive tainted data on that edge. A call that passes
     one tainted argument and one clean argument no longer taints the
     callee's untainted parameter just because the edge "has args."
   - Callee resolution prefers receiver type inference (`_infer_receiver_class`,
     #158, walking a variable's inferred class, including inherited methods
     resolved across file boundaries via the import graph) when a method
     call's receiver type is known; only falls back to the name/qualifier
     import-graph guess when it isn't.
4. **Emit** findings for cross-file boundaries with confidence decay per hop
   (via the shared `core/confidence.py` model, see `EnrichmentPass`), plus the
   standalone structural trust-boundary findings from step 2

`KNOWN_SOURCE_PREFIXES` (the source list step 2's regular source-detection
draws from) is Flask/web-framework-biased (`request.args`, `sys.argv`,
...): the ORM-channel and structural trust-boundary mechanisms above are
what let this pass reach vulnerabilities in AI/agent codebases whose real
untrusted-input entry points aren't a bare HTTP request at all.

Findings from this pass have `engine="crossfile"` (`CF-SINK-001`/
`CF-RETURN-001` propagated findings, a fixed two-id family, not a distinct
rule id per callee; the callee is carried in `metadata["callee_name"]` and
the message instead, so baselining and per-rule metrics survive a callee
rename) or one of the dedicated structural trust-boundary rule IDs
(`AGENT-TOOL-001`, `TASK-QUEUE-001`, `GRPC-001`, `GRAPHQL-001`,
`WEBHOOK-001`; standalone findings, still emitted by this pass). `CF-*`
findings also now carry a full `taint_flow` (source in the caller, one
`TaintNode` per cross-file hop, sink at the real sink location) anchored at
the actual call site rather than the caller's `def` line, reconstructed
from a predecessor map kept during the BFS (see
`_build_cross_file_taint_flow` in `cross_file.py`).

### JSCrossFilePass

The JavaScript/TypeScript sibling of `CrossFilePass`, reusing the same
`_propagate_cross_file` fixpoint core (`js_cross_file.py` imports it
directly from `cross_file.py`). Requires the optional `tree-sitter`
dependency (`pip install rowan[js-crossfile]`); no-ops gracefully if
it isn't installed.

Import/call-graph extraction is tree-sitter-based rather than AST-based,
and is narrower than the Python pass: only `has_source`
(`_reads_known_source`, matching `req.body`/`ctx.query`/etc.),
`has_return_taint` (`_returns_known_source`, a `return_statement` check
over the same source prefixes, not merely "contains a source read"),
`calls_propagator`, and each call's `has_args` bit are structurally
detected; `has_sink` is populated exclusively from Passes 1-2 findings.
Every extracted function also records `end_line` (a tree-sitter node's
`end_point` row), same body-span attribution guard as the Python pass.
There is no JS/TS equivalent yet of `_structural_path_sink`,
`_function_reads_orm_channel`, or the structural trust-boundary detectors,
those remain Python-only capabilities (#164 parity gaps 1 and 2,
tracked as follow-up work).

Parameter extraction (`_params_of`/`_collect_pattern_identifiers`) fully
handles destructuring: `object_pattern`/`array_pattern`/
`assignment_pattern`/`rest_pattern`, nested to any depth, plus
TypeScript's `required_parameter`/`optional_parameter` wrappers (#164 bug
1: previously only bare `identifier` parameters were collected, so any
destructured handler parameter, the dominant idiom in Express/Next/Nest
code, was silently dropped).

`KNOWN_JS_SOURCE_PREFIXES` deliberately excludes `process.env` (keeping
`process.argv`), mirroring `KNOWN_SOURCE_PREFIXES` in `cross_file.py`
which has no `os.environ` entry: env vars are operator-controlled
config, not attacker-controlled input (#164 bug 2).

Call-graph resolution recognizes one level of attribute chaining off
`this` (`this.db.query()` resolves like `this.query()`, mirroring
Python's DEF-35 fix for `self.db.query()`); any other multi-level
qualifier (`services.payment.charge()`) is recorded as
`_UNRESOLVED_QUALIFIER` rather than silently dropped, so it can never
fabricate a same-file edge from an unrelated same-named function (#164
parity gap 3).

Findings from this pass have `engine="crossfile"`, same as `CrossFilePass`.

### GoCrossFilePass

The first Go cross-file layer implements a bounded MCP/web-server
slice using tree-sitter-go. It preserves parameter dependencies across direct
and interface-dispatched calls, recognizes MCP tool parameters and HTTP form or
query input, stops at validation/sanitization helpers, and reports command or
concatenated-SQL sinks. Variadic arguments are folded into the final parameter,
which is required for the common `exec.CommandContext(..., args...)` wrapper.
It consumes the scan-owned Go inventory, runs in the correlation stage, and is
disabled with `--no-cross-file`. Findings use `CF-GO-EXEC-001` or
`CF-GO-SQL-001`, include the full source/call/sink path, and deduplicate an
existing Opengrep finding at the same sink location.

### AuthzPass

Object-level authorization (BOLA/IDOR) detection, opt-in via `--authz`
(`ScanConfig.enable_authz`). Inverts the taint model: instead of asking
whether a sanitizer dominates a sink, it asks whether an authorization guard
dominates an object fetch keyed by attacker-controlled input. Covers
Django/DRF and SQLAlchemy ORM idioms against BOLARAY's four object-level
authorization models (ownership, membership, hierarchical, status); a
user-keyed read is a gap only if none of the four is satisfied on its path,
and satisfying any one suppresses the finding. Deliberately precision-first
and off by default: even the state of the art for this category reports
recall under 50%, and this pass is explicit that it does not cover
function-level authz, custom raw-SQL data-access layers, or authorization
enforced in a service it cannot see.

Findings from this pass have `engine="authz"`, rule ids `AUTHZ-BOLA-001` and
`AUTHZ-LLM-001` (issue #185: a permission-shaped guard whose condition is
itself derived from an LLM completion or tool-call argument, so anything
that can steer the model can force the allow path).

### JSAuthzPass

The JavaScript/TypeScript sibling of AuthzPass, also opt-in via `--authz`.
A precision-first MVP for Express/Koa/Next.js handlers: a
Mongoose/Sequelize/Prisma model read keyed by a route parameter
(`Doc.findById(req.params.id)`, `prisma.doc.findUnique({ where: { id:
req.params.id } })`) inside a route handler, a default-export Pages API
handler, or a named App Router export (`GET`/`POST`), with no structured
owner guard before the object escapes in a response. Mirrors AuthzPass's
stance: route auth middleware downgrades a finding, an object-level owner
check suppresses it, anything else is High. Requires the optional
`tree-sitter` dependency; no-ops gracefully if it isn't installed.

Findings from this pass have `engine="js_authz"`, rule id `AUTHZ-BOLA-001`
(shared with the Python pass).

### SerializationScopePass

Finds a class whose `__init__` accepts a security-scoping parameter
(`base_path`, `base_dir`, `allowed`, `sources`, `permission`, `role`,
`sandbox`, etc.) that its own `_to_config`/`to_config`/`to_dict` serializer
silently drops. Reload the serialized form and the constraint is gone: a
round trip through config quietly widens what the object is allowed to do.
AutoGen's `FileSurfer` (directory confinement via `base_path`) and
`TextMentionTermination` (`sources`, which scopes which agents can end a
run) are the motivating cases. Skips serializers that walk their instance's
attributes reflectively (e.g. generated OpenAPI models), since those drop
nothing. Always runs; not opt-in.

Findings from this pass have `engine="serialization-scope"`, rule id
`SER-SCOPE-001`, CWE-1188.

### MultiAgentPass

Cross-agent injection propagation detection (issue #188), opt-in via
`--multiagent` (`ScanConfig.enable_multiagent`). Scoped to CrewAI only, in
the shape the framework's own API makes source-visible within a single
file: `Task(context=[other_task])` is CrewAI's documented mechanism for
feeding one task's output into another's prompt, and this pass traces that
object reference from a low-trust agent (one holding a web-sourcing tool)
into a higher-privilege agent (one holding a code-execution or shell tool).
Deliberately does not attempt LangGraph's `Command(goto=...)`, AutoGen's
`initiate_chat`/`send`, or OpenAI Agents SDK/A2A handoffs in this phase,
since those handoffs happen through framework-internal execution rather
than a directly-traceable object reference in source the way CrewAI's
`context=[task]` is.

Findings from this pass have `engine="multiagent"`, rule id
`AGENT-HANDOFF-001`.

### ASTEnrichmentPass

AST-based post-processing to detect additional sanitizers:
- **Safe dict allowlists**: module-level dicts with all-constant values
  suppress findings that use dict lookups as sink arguments
- **Pydantic validated classes**: `BaseModel` subclasses with
  `@model_validator`/`@field_validator` are implicit sanitizers
- **UPPER_CASE constants**: hardcoded string constants downgrade
  findings from HIGH to LOW

### ModelFileScanPass

Scans model files with [Hayward](https://github.com/hedgerow-dev/hayward), a
separate MIT package that Rowan depends on. Rowan's file-scan stage finds the
model artifacts (`rowan/artifacts.py`, kept equal to Hayward's own discovery
set by a test), and the pass hands each file to `hayward.ModelFileScanner`.
Hayward parses each format itself and never imports or executes the file:
pickle is walked as opcodes, containers member by member.

Findings are converted to Rowan findings with `engine="mfv"`. An `MFV-SKIP-*`
finding marks the pass incomplete. Hayward's own tests cover the format
parsers; Rowan's tests cover the hand-off.

### MCPConfigScanPass

Scans MCP client config JSON, the deployment artifact (e.g. an MCP host's
server-launch config), for hardcoded secrets and over-privileged server
invocations. Distinct from everything else in the codebase that understands
MCP, which looks at source code instead (`mcp.run(`, `@mcp.tool`, tool-
description poisoning in `rules/ai_security.yaml` and `cross_file.py`'s
structural trust-boundary detectors): this pass is the only one that opens
the actual config artifact.

Findings from this pass have `engine="mcpconfig"`, rule ids
`MCP-CONFIG-001` (hardcoded secret in a server command/env), `MCP-CONFIG-002`,
and `MCP-CONFIG-003`.

### EnrichmentPass

Post-processing over all accumulated findings:
- **Deduplication**: groups by `(file_path, rule_id)` and merges findings
  within a line-proximity window (5 lines for `NS-*` rules, 10 otherwise).
  Cross-file (`CF-*`) and agent-tool (`AGENT-TOOL-001`) findings also carry
  `metadata["caller"]` (the reporting function's name) and group by
  `(file_path, rule_id, caller)` instead -- two genuinely different callers
  reaching the same sink from the same file are distinct vulnerable entry
  points, not near-duplicates of each other, even if their definitions
  happen to sit within the merge window.
- **Confidence scoring**: neuroscan capped at 0.7, bulk matches penalized.
  Taint findings (opengrep and crossfile) score through one shared,
  calibratable model (`core/confidence.py`, #123, replacing two
  independently hand-picked hop-confidence ladders that disagreed on what
  the same hop distance was worth): `clamp(base - hops*decay, floor, base)`
  as a function of the TRUE hop distance, accurate as of the #163 worklist.
  Opengrep's intra-file dataflow gets the higher base (0.90, a real
  sound-ish taint engine); `CrossFilePass`'s heuristic AST pass gets the
  lower base (0.75). Run `python scripts/benchmark.py --calibrate` to sweep
  these constants against the labeled corpus rather than hand-picking them.
  The confidence value is display/ranking only: the one hard output gate is
  `EnrichmentPass._apply_thresholds`, which reads `config/thresholds.yaml`
  and applies a `min_confidence: 0.5` floor to the handful of named,
  high-volume regex rule IDs listed there (e.g. `ns-aiml-047`,
  `NS-SSRF-001`, `RB-PATH-001`), not a general per-rule mechanism applied
  across the board. The file is overridable per run via `--thresholds`. No
  taint rule is currently in that gated set, so recalibrating the taint
  confidence ladder re-ranks findings without changing which ones are
  reported.
- **Java/Go guard evidence**: path findings are demoted only when an
  application-named guard correlates with the sink value, or when a concrete
  normalization idiom is paired with a base-confinement check. SSRF findings
  require URL parsing plus host-allowlist evidence. This text-based layer runs
  after severity floors and never suppresses a finding because Java/Go AST
  dominance is not available; it retains the evidence as finding metadata.
- **Attacker-context cap** (`_cap_no_attacker_context`): findings under
  `scripts/`, `migrations/`, importers, benchmark directories and build-tool
  configs cap at LOW. The code may be real, but no request reaches it, so it
  must not rank beside deployed surface. Judged on the path *relative to the
  scan root*, so a corpus checked out under `benchmark/` cannot trip it.
  Test paths (`analysis/test_paths.py`) cap at MEDIUM by the same logic.
- **Evidence-tiered severity** (`_cap_unverified_severity`): see below.
- **Framework escalation**: Flask/Django HIGH injection/SSRF/CMDi -> CRITICAL
- **Sink severity floor**: a dangerous sink (deserialization, command
  injection, injection) with proven-remote input in the file floors to HIGH.
  It deliberately skips findings already marked `test_context` or
  `no_attacker_context`, since a test file full of harness requests trivially
  matches the remote-input regex and would otherwise be re-raised straight
  after being downgraded.

#### Evidence tiers

The severity scale is only meaningful if it means the same thing in every
language, including languages where no dataflow engine exists (Ruby today).
`_cap_unverified_severity` stamps every finding with
`metadata["evidence_tier"]` recording what was actually computed:

| Tier | Established by |
|---|---|
| `taint-flow` | The finding carries a `TaintFlow` |
| `engine` | Produced by an evidence-bearing engine (`mfv`, `authz`, `js_authz`, `crossfile`, `siblinggate`) |
| `source-context` | Remote-input or route-boundary evidence in the same file |
| `self-evident` | Category outside `_DATAFLOW_CLAIM_CATEGORIES`: the match itself is the whole claim (secrets, crypto, config) |
| `pattern-only` | None of the above |

A finding in a dataflow-claim category (injection, deserialization, ssrf,
ssti, xss, command_injection, path_traversal, nosql_injection,
prototype_pollution) at `pattern-only` caps at MEDIUM and is annotated in its
message. `self-evident` is deliberately *not* capped: a hardcoded credential
needs no dataflow to be true. Stamping is total: a consumer must never have
to invent a trust policy for an untiered finding.

The pass ordering matters: `_cap_unverified_severity` runs *before*
`_apply_sink_severity_floor`, because the floor's own in-file remote-source
check is itself evidence, so anything the floor would raise also passes the
cap's evidence test.

#### Analysis-capability manifest

`ScanPipeline.run` computes which of the scanned languages are covered by at
least one `mode: taint` rule and records the rest in
`result.metadata["analysis_capability"]["patterns_only_languages"]`, which the
text and JSON reporters surface. The MFV pass's coverage-skip findings make
the same argument for model files: a file that was never analysed must never
report indistinguishably from one that came back clean.

The same manifest records `cross_file_languages` from completed, applicable
language frontends. It currently names Python, JavaScript/TypeScript, and Go
only when the corresponding cross-file pass actually ran.

## Data model

### Finding

The central data structure. Every pass produces `Finding` objects:

| Field | Type | Description |
|-------|------|-------------|
| `rule_id` | str | Unique rule identifier (e.g., `TNT-SSRF-001`) |
| `message` | str | Human-readable description |
| `severity` | Severity | CRITICAL, HIGH, MEDIUM, LOW, INFO |
| `category` | Category | 17-value enum (see below) |
| `file_path` | str | Relative or absolute path |
| `start_line` | int | 1-indexed line number |
| `end_line` | int or None | End line |
| `confidence` | float | 0.0-1.0 |
| `cwe_ids` | list[int] | CWE identifiers |
| `taint_flow` | TaintFlow or None | Source-to-sink flow |
| `engine` | str | neuroscan, opengrep, depguard, crossfile, mfv, authz, js_authz, llm-discovery, mcpconfig, multiagent, serialization-scope, siblinggate |
| `metadata` | dict | Engine-specific extra data. Always includes `evidence_tier` (see [Evidence tiers](#evidence-tiers)); may include `test_context`, `no_attacker_context`, `unverified_severity_capped` |

### Category enum

```
INJECTION, DESERIALIZATION, SSRF, SSTI, XSS, COMMAND_INJECTION,
PATH_TRAVERSAL, SECRETS, SUPPLY_CHAIN, AI_ML, PROMPT_INJECTION,
NOSQL_INJECTION, PROTOTYPE_POLLUTION, AUTH, CRYPTO, CONFIG, GENERAL
```

### TaintFlow

```
TaintFlow:
  source: TaintNode       # Where user input enters
  sink: TaintNode         # Where dangerous function is called
  intermediate: [TaintNode]  # Hops between source and sink
  sanitizers: [str]       # Sanitizer names checked/applied
```

### ScanContext

Shared mutable state carried through all passes:

```
ScanContext:
  target_path: Path       # Directory being scanned
  config: ScanConfig      # CLI options
  result: ScanResult      # Accumulated findings
  neuroscan_rules: [Rule] # Loaded regex rules
  metadata: dict          # Pass-to-pass communication
  source_inventory: SourceInventory | None  # Filtered, language-classified source scope
  source_snapshot: SourceSnapshot  # Lazy bounded text/Python-AST cache
  network_semaphore: BoundedSemaphore  # Scan-wide in-flight network cap
```

`SourceInventory` contains the filtered `SourceFile` tuple used for source
analysis plus separate immutable tuples for dependency manifests, model
artifacts, and MCP client configs. Those artifact tuples are authoritative for
SCA/MFV/MCP config during a normal
pipeline run; they are deliberately separate from source counts and language
classification.

## Rule engines

### NeuroScan (regex)

Rules defined in YAML with compiled regex patterns, severity, category,
and CWE metadata. Each rule's `check()` method runs against file content.
394 regex rules across 22 YAML files covering Python, JavaScript, TypeScript,
Java, Go, C#, Ruby, PHP, Rust, Terraform, Dockerfile, and GitHub Actions YAML.

### Taint (Opengrep)

Rules defined in YAML with `mode: taint`, using Opengrep's DSL:

```yaml
- id: TNT-SSRF-001
  mode: taint
  pattern-sources:
    - pattern: request.args.get($URL)
  pattern-sinks:
    - pattern: requests.get($URL)
  pattern-sanitizers:
    - pattern: urlparse($URL)
```

189 taint/Opengrep rules across 26 YAML files.

### Rule ID conventions

| Prefix | Engine | Example |
|--------|--------|---------|
| `NS-*` | NeuroScan regex | `NS-DESER-001` |
| `TNT-*` | Opengrep taint | `TNT-SSRF-001` |
| `TNT-ML-*` | ML-specific taint | `TNT-ML-001` |
| `CF-SINK-001` / `CF-RETURN-001` | CrossFile propagation | `CF-SINK-001` |
| `MFV-*` | Model file validation | `MFV-PICKLE-001` |
| `ns-aiml-*` | AI/ML regex | `ns-aiml-030` |
| `AGENT-TOOL-001` | CrossFilePass, standalone (agent-tool sink) | `AGENT-TOOL-001` |
| `TASK-QUEUE-001` | CrossFilePass, standalone (Celery/RQ task handler sink) | `TASK-QUEUE-001` |
| `GRPC-001` | CrossFilePass, standalone (gRPC servicer method sink) | `GRPC-001` |
| `GRAPHQL-001` | CrossFilePass, standalone (GraphQL resolver sink) | `GRAPHQL-001` |
| `WEBHOOK-001` | CrossFilePass, standalone (webhook/callback handler sink) | `WEBHOOK-001` |

## Agents (experimental)

The `hunt` command runs an LLM-powered autonomous vulnerability hunting
pipeline:

1. **Recon**: run the static pipeline, retain SCA findings, and extract HTTP/command/LFI sinks and model files
2. **Hypothesize**: LLM batch triage (15 findings/batch cloud, 4 findings/batch local)
3. **Verify**: independent adversarial second-opinion pass that refutes or downgrades hypotheses before they advance (skip with `--no-verify`)
4. **DeepDive**: resolve files named by surviving hypotheses and select their findings from Recon's full-context result; it launches no duplicate scan and labels the evidence source `recon_full_context`
5. **Discover**: optional `--discover` analysis for defects the rule corpus cannot express; mechanically grounded and independently verified. Output is tagged `engine="llm-discovery"`.
6. **Exploit**: build evidence/navigation chains. Only a confirmed hypothesis with resolved source evidence sets the vulnerable verdict
7. **WebExploit**: live HTTP probes (SSRF/LFI/SQLi/SSTI), opt-in via `--exploit`
8. **Report**: LLM-generated bug bounty report

Without optional discovery the flow has seven stages; `--discover` adds the
eighth stage between DeepDive and Exploit.

Hunt chains retain the compatibility fields `status` and `evidence_status`,
and also expose a monotonic `evidence_state`: `triaged`, `verifier_upheld`,
`statically_validated`, or `actively_confirmed`. A resolved source window plus
a confirmed hypothesis is required for `statically_validated`; only a
successful opt-in live probe produces `actively_confirmed`.
The Hunt JSON projection applies the same vocabulary to hypotheses and verified
discovered findings and reports record counts by state; it preserves the raw
objects and existing compatibility fields.

Supported backends: automatic selection (default), DeepSeek, OpenAI,
OpenRouter, Alibaba (Alibaba Cloud Model Studio / Qwen, OpenAI-compatible),
Ollama (local, no egress), or any OpenAI-compatible local server. Automatic
selection considers configured cloud credentials first, then a reachable
Ollama service. With Ollama, an explicit model remains authoritative;
otherwise Hunt prefers an installed code-specialized model instead of
assuming a particular model tag exists.

Two preflight commands avoid spending on a misconfigured or oversized run:
`estimate` projects hunt's LLM call/token cost against a target for free
(runs recon only, applies hunt's real batching logic); `doctor` checks
backend credentials and connectivity before a real run. See the `estimate`
and `doctor` sections in [`docs/usage.md`](docs/usage.md) for both.

## Output formats

| Format | Flag | Use case |
|--------|------|----------|
| Text | `-f text` | Human review in terminal |
| SARIF | `-f sarif` | GitHub Code Scanning, IDE integration |
| JSON | `-f json` | Programmatic consumption, dashboards |
| HTML | `-f html` | Standalone shareable report |
| OpenVEX | `--vex` | Per-CVE exploitability statements (VEX) |
| CycloneDX SBOM | `--sbom` | Software bill of materials (CycloneDX 1.5) |

SARIF output conforms to v2.1.0 and is directly uploadable to GitHub's
code scanning via `github/codeql-action/upload-sarif@v3`.

### MCP evidence server

`mcp_server.py` exposes the JSON document over the Model Context Protocol as
a single stdio tool, `scan_evidence(target)`, so an agentic reviewer can call
for computed dataflow facts instead of inferring them. The design constraints:

- **No new analysis.** `collect_evidence()` is `ScanPipeline` plus the
  existing JSON reporter; the payload is byte-identical to `-f json`. There
  is no second code path that could drift from the CLI's answers.
- **`no_sca=True`.** The oracle serves code-level facts and must never
  require network access mid-review. Cross-file taint stays on.
- **Directory targets only.** A file target is rejected with a structured
  error until selected-file scope can be shared by every pass. That prevents
  an unsupported model file from being reported as a complete clean scan.
- **Optional dependency.** The `mcp` SDK is an extra (`rowan[mcp]`), and
  `collect_evidence` is a plain function, so the core package never imports
  it.
- **The tool description carries the contract**, telling the model outright
  that `pattern-only` findings are hypotheses. What the consumer does with a
  finding is judgment; what was computed is not.

## External dependencies

- **Opengrep** (LGPL 2.1): taint analysis engine, invoked via subprocess.
  Not bundled. Optional: the scanner degrades gracefully without it.
- **OSV.dev API**: public CVE database for dependency scanning.
  No API key required.
- **LLM APIs** (optional): DeepSeek/OpenAI/OpenRouter for hunt mode.
  Requires API key in environment variables.

## Design decisions

1. **Subprocess over library**: Opengrep is invoked via `subprocess.run()`
   rather than imported as a library. This avoids LGPL contamination of
   MIT-licensed code and allows Opengrep to be upgraded independently.

2. **JSON internally, SARIF externally**: `OpengrepAdapter` parses Opengrep's
   native `--json` output rather than SARIF, since `--json`'s `extra.metadata`
   carries a rule's full `metadata:` block inline (category/CWE/fix/
   confidence), which SARIF's `properties` never populates. SARIF v2.1.0 is
   still produced, but only as one of the *external* reporter formats
   (`-f sarif`, for GitHub Code Scanning / IDE integration); it is no
   longer the internal pipeline interchange format.

3. **Staged pipeline**: passes run in ordered stages (see Pipeline above).
   Independent detectors run concurrently within a stage, but stages are
   sequential and results merge in plan order. This lets later passes use
   findings from earlier ones (e.g., CrossFilePass reads TaintPass results)
   while keeping output deterministic.

4. **Two rule engines**: regex rules are fast but imprecise; taint rules
   are slow but precise. The combination catches more vulnerabilities
   than either alone, and enrichment deduplicates overlap.

5. **Confidence scoring**: rather than binary true/false, every finding
   carries a 0.0-1.0 confidence score. This allows downstream consumers
   to filter by their risk tolerance.
