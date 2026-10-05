# Hunt coverage, evidence, and recovery

Hunt combines a static inventory with model triage and optional discovery. A
retained static finding is not necessarily upheld by the model. Verification is
source review; it does not establish that an exploit was reproduced.

## Coverage and budgets

With `--discover`, Hunt inventories Python functions, recognized route/tool/job
decorators, imports, and sensitive operations using the scanner's resolved file
scope. Discovery can now select surfaces without a static hit. When the file
budget is exceeded, part of the budget is reserved for files without static
anchors. Instruction files are excluded from model discovery.

The inventory is heuristic: decorator names are candidates, not proof of public
exposure. Unsupported languages and parse/read failures are marked unresolved.
Inventory parsing honors the scan configuration’s file-line limit, with larger files marked unresolved. Unrecognized frameworks, dynamic dispatch, and unavailable dependencies remain
limitations. An empty finding list is not proof that an application is safe.

```sh
rowan hunt ./app --discover --yes --format json \
  --discovery-files 25 --discovery-lines 400 \
  --verification-lines 240 --verification-files 4 \
  --output hunt.json
```

`--discovery-lines` is a hard source-line limit per file. Small files are supplied
whole; larger files use bounded windows around static and inventory locations.
Late surfaces can nominate a window, but a budget may still omit a sink or guard.
Inventory statuses distinguish reviewed, partial, skipped, and unresolved records.
Reviewed means the complete recorded source span was supplied in a successful
file-review call; it does not prove exhaustive semantic analysis. Partial records
remain partial after a successful call.

Verification retrieves enclosing functions, possible local callers/callees, and
imports under separate per-claim file and line budgets. Verification batches contain at most four claims on cloud backends and one on local backends to accommodate the richer context. Long source lines or a small model context window may still require lower line budgets. Symbol matches are navigation
candidates, not resolved call-graph edges. Omitted context is recorded. Currently
this richer navigation supports Python; it does not promise complete cross-file
or interprocedural analysis for every supported scanner language.

`rowan estimate ./app --discover` uses the same inventory, scheduling, and source
payload logic. It accepts the same four budget options and measures verification
context. Triage survival and discovered claim counts are projections; future
model-selected deep-dive targets can change the schedule. Repairs, retries,
report generation, and live probes can add work. The estimate is not a bill.

## Reachability and verification

Normalized `reachability_assessment` records are separate from existing scanner
reachability fields, severity, verifier verdicts, and `HuntEvidenceState`:

| Status | Meaning |
| --- | --- |
| `reachable` | The reviewer identifies a source-backed entry point and path |
| `conditional` | The claim depends on explicit prerequisites |
| `no_demonstrated_caller` | Unsafe helper-level behavior lacks a demonstrated caller |
| `unresolved` | Available evidence cannot settle the path |

Unstructured legacy narratives map to unresolved, not to proof of reachability.
The independent verifier must identify attacker control, the path, sink,
protection, protection failure, impact, and unresolved assumptions. Upheld answers
must cite inspected source locations, identify a reachable entry point, and have
no unresolved prerequisites or assumptions. Missing evidence becomes uncertain.
Citation validation prevents borrowing unseen source; it does not independently
prove the semantic correctness of the model's path reasoning.

Discovery emits only findings passing both source provenance and verification.
Conditional and uncertain candidates remain observations in the audit data;
refuted candidates remain distinguishable. Race, DNS, token, authorization, and
dependency claims must state their mechanism and conditions. Intended shared
access is not automatically an authorization defect.

## JSON views and counts

Hunt JSON retains its scan-compatible `summary` and `findings` shape and adds
`hunt.schema_version = 2`. Use `--hunt-view full` (default) for the complete static
inventory plus upheld discoveries. Use `--format json --hunt-view verified` for
findings joined to upheld verification outcomes. Ambiguous hypothesis joins are
left unverified; Hunt does not guess from rule ID alone.

Findings include origin, a source-relative `hunt_id`, verification verdict/reason,
normalized reachability, and structured verification evidence. Discoveries carry
their candidate IDs. Summary totals, severity counts (including info), and cluster
counts describe the emitted view. `hunt.accounting` retains the full inventory
counts and discovery-verdict counts, even when the view is filtered.

`hunt.discovery_candidates` preserves raw discovery claims and their provenance
or verification outcomes. `hunt.observations` retains candidate-level verification
records. These are useful for separate discovery and verification evaluations.
Recall and precision still require an independently adjudicated ground truth;
unmatched findings must not automatically be counted as false positives.

`evidence_states` counts workflow records, not unique vulnerabilities. In schema
version 2, model-upheld discoveries are `verifier_upheld`; source citation
matching alone does not make them `statically_validated`. Existing chain states
remain separate. Filtering the finding view does not change `vulnerable` or the
chain inventory. The CLI continues to report findings without assigning a
vulnerability-based exit code; incomplete runs return exit code 1.

The human report includes a deterministic audit footer with completion, inventory
counts, coverage, and uncertain/refuted observations. `hunt.run_manifest` records
model/backend, reasoning setting, budget, prompt hashes, and a digest of inventoried source text. Input identity is
available when checkpointing is enabled.

## Durable recovery

```sh
rowan hunt ./app --discover --yes --format json \
  --checkpoint /tmp/rowan-hunt-app.json --output hunt.json

# After resolving quota/credentials or increasing the call ceiling:
rowan hunt ./app --discover --yes --format json \
  --checkpoint /tmp/rowan-hunt-app.json --resume --output hunt.json
```

Store checkpoints outside the scanned target. They contain source-derived model
responses and reports. New checkpoint files are created with owner-only access;
API credentials are not stored. Remove the checkpoint and its `.lock` file when
the retained evidence is no longer needed.

Resume reruns reconnaissance and rebuilds workflow state. It reuses completed,
schema-valid successful calls with identical prompts and settings, avoiding
duplicate application of results. Errors, malformed objects, and invalid cached
responses are not reused. Input identity includes admitted source and artifact
content, resolved scan configuration, budgets, model/backend/credential scope,
and implementation hashes. `run_manifest.llm_configured` identifies runs using static fallback rather than an available model. Changed inputs require a new checkpoint. Prompts and
response schemas are also included in each call key. This is whole-run
invalidation; selective dependency-based invalidation is not implemented.

Writes are atomic and synchronized across workers; an exclusive process lock
prevents two Hunt runs from updating one checkpoint. Interrupted runs preserve
successful work. Checkpoint replay is rejected with live exploit probes so resume
cannot repeat external side effects.

Backend HTTP retries remain bounded. Backoff honors `Retry-After` with a 30-second
cap and can be cancelled. Quota exhaustion, rejected credentials/configuration,
and call-budget exhaustion stop additional backend work. Schema repair has one
additional attempt, charged to the same call ceiling. Cancellation does not
interrupt an HTTP request already in progress; its configured timeout still
applies.

`hunt.run_status` distinguishes complete, incomplete, and interrupted runs.
Complete means enabled workflow stages finished without recorded errors or
degraded recon, not that every repository surface was reviewed. Recovery metadata
separates fresh/reused/failed workflow work units from backend completion calls
(which include schema repairs), records retries, and retains elapsed time and
token totals across resumptions. Monetary cost is not inferred from token counts.

## Evaluation limits

The initial implementation is verified with general-purpose synthetic fixtures,
fault injection, and existing Hunt regression tests. It contains no Langfail
answer-key identifiers or benchmark-specific detection rules. The prior Astra
CLI-adapter scores motivated this work; they do not measure the new workflow.
Fresh, frozen-model repeated evaluations and independent adjudication remain
necessary before claiming a recall or precision improvement.
