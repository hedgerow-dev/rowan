# General Python security analysis

## Objective
Detect equivalent vulnerable behavior across naming, module, and wrapper changes.
Use Modelbay as a regression corpus, never as a source of symbol-specific rules.

## Implementation sequence
1. Add a shared, repository-bounded Python function index: absolute/relative imports,
   aliases, named imports, unambiguous module calls, parameter binding, bounded
   recursion, and cycle protection. Unresolved and dynamic calls remain explicit.
2. Add parameter/return trust summaries for serialization and token decoding.
   Preserve origins through buffers, streams, base64, JSON, and tuple unpacking.
   Require request provenance for deserialization and identity/privilege use for
   unsigned claims; verified decoding and unrelated data processing stay clean.
3. Extend privilege discovery to constant-name getattr on principals. Extend BOLA
   helper analysis using the shared index, bounded wrapper specialization, and
   existing authorization predicates. Report unresolved object-read coverage
   separately from established BOLA findings.
4. Add independent examples with arbitrary names, module aliases, two-hop wrappers,
   keyword arguments, safe controls, cycles, and unrelated transformations.
   Run existing detector, source inventory, and cross-file regression suites.
5. Rerun fresh tracked Modelbay corpus with unchanged flags. Preserve raw evidence,
   adjudicate new findings by defect and function anchor, and report regressions.

## Precision boundaries
Do not infer vulnerability solely from a suggestive function/field name. Do not
interpret arbitrary local-file reads as request sources. Do not treat any mention
of verification or a principal as proof that it protects the relevant value.
Bound call exploration and retain the source/sink evidence. Keep distinct sinks
and entrypoints; merge only repeated evidence for the same operation.

## Completion evidence
Tests for independent positive and negative examples, existing regression results,
and a saved benchmark comparison. Document unresolved dynamic dispatch and
restricted-unpickler gadget semantics rather than pretending they are covered.

## Implemented
- Shared import resolution, aliases/re-exports, parameter binding, cycle/depth
  bounds, and conservative treatment of dynamic or shadowed calls.
- Request-origin and token-transformation summaries across Python functions,
  including stream/buffer inputs and Flask/Django/FastAPI request layouts.
- Unsigned-claim findings require identity/privilege use. Verification must
  protect the same token and fail closed; client-chosen keys are not trusted.
- Privilege-field discovery understands constant-name getattr on principals.
- BOLA specializes expression-only repository wrappers and checks returned
  object/permission pairs at the caller. Existing guard and scope predicates
  handle safe status gates and positional parent filters. Unresolved imported
  object reads produce informational coverage signals.
- XML keyword dictionaries are resolved at the actual parser construction,
  replacing the context-free dictionary regex. Mutable/unknown options are
  left unproven, and unused dictionaries do not produce a finding.
- Deserialization deduplication preserves distinct sink coordinates.

## Limits
Function resolution excludes dynamic dispatch and ambiguous imports. Trust
summaries are bounded to four calls; retrieval-wrapper specialization is bounded
and only expands expression-only returns. Methods, runtime-generated code,
arbitrary restricted-unpickler allow-list gadgets, dynamic XML options, and
complex returned authorization protocols are not claimed as covered.

## Validation (2026-10-03)
- Broad detector, cross-file, source/registry, enrichment, and local benchmark
  regression run: 321 passed, 2 skipped. Final targeted trust/BOLA run after
  the imported-module-call crash fix: 100 passed. Ruff and registry drift checks
  pass; the literal XXE fallback and its converted rule are synchronized.
- Pinned LangChain precision gate at
  8330dfe987988c1bcbbc5e8d9af9a67e5a1c2744 passes with the prescribed command:
  2,723 files, zero HIGH/CRITICAL findings, and no degraded passes. The gate
  checks completeness and HIGH/CRITICAL claims; it is not a measurement of
  every lower-severity claim. Subsequent gate results are recorded below.
- Local Modelbay regression: 60/82 versus 46/82 at the original PR head. The
  new detections were adjudicated by defect and function anchor; safe-twin
  results are unchanged. Added claims outside its key are explicitly recorded
  as unmatched, so increased recall is not presented as proof of precision.
  The held-out mappings and raw reports remain in the local benchmark workspace.

## Follow-up after merge
PR #7 was squash-merged at 5f89f1fa555dfb89eeb87b103640934a5b820148.
The first precision follow-up disambiguates resolved standard-library regex
searches from generic vector-store and LDAP search sinks. Aliases are supported;
shadowed/reassigned imports, wildcard imports, and mixed sink calls on one line
remain unproven. Unknown search receivers retain their existing claims.

Independent production-pipeline pairs and import/mutation controls pass:
186 tests across SAST precision, AST enrichment, and cross-file analysis. The corpus rerun retains
60/82 keyed detections and the existing decoy hit, removing exactly one erroneous
vector-query claim. Source-review triage is saved locally with the benchmark.

The pinned Langflow scan completed without degradation but initially failed its
gate on two HIGH cross-file SQL claims. Both originate in an async version-warning
log containing the word "update". The follow-up extends logging-message recognition
to async log methods and applies it before cross-file sink attribution. SQL executed
inside a logging argument and separate query strings on the same line remain sinks.
Production-pipeline helper/caller pairs cover both outcomes. The full Langflow rerun
passes at 26dc6fd3bc3a49178022b81c58e44a7d0a659a34: 5,878 files, complete coverage,
zero HIGH/CRITICAL, no degraded passes, 416.7 seconds. Seven false SQL claims on
log messages were removed and no claims added. PyTorch's scan is still running.
The final LangChain rerun also passes: 2,723 files, complete coverage, zero
HIGH/CRITICAL, no degraded passes, 184.1 seconds.

Remaining precision work needs broader evidence:
- Numeric logging needs field-sensitive provenance through ORM reads, helper
  parameters, and mutations. An integer annotation or column declaration alone
  must not globally sanitize a value that might have been overwritten.
- Unscoped object reads need a declared privacy/sharing policy before assigning
  confirmed authorization impact. Existence-only uses must distinguish an oracle
  from an object disclosure or mutation. No corpus-specific public-object allowlist
  is added.

### PyTorch archive calibration (2026-10-03)

The pinned PyTorch full scan completed: 6,089 files, 2,530.6 seconds,
35 HIGH findings, all MFV-TORCH-001 on ordinary TorchScript assets. The full
precision gate failed on those claims. This exposed a format distinction:
TorchScript graph source is parsed by the JIT importer, whereas torch.package
Python modules are executed when PackageImporter imports them. Neither source
presence alone establishes a malicious operation; untrusted models remain
programs and this analysis does not assess all graph/runtime behavior.

The fix belongs in Hayward, rather than a PyTorch path exemption in Rowan:
classify source against same-root container markers, retain LOW presence,
and report explicit resolved execution calls in packaged Python separately.
Bound source reads and AST inspection; invalid, oversized, duplicate, or
budget-exhausted source yields incomplete-coverage findings. Pickle checks
remain independent. Rowan preserves presence evidence and labels it inventory
in JSON, using backend metadata rather than benchmark-specific rule names.

A targeted comparison scanned the same 200 artifacts from Rowan's inventory
at PyTorch commit 68adc973349eb25d9f3f0fb1aecd4366f01d4810. Hayward 1.2.4
reported 115 raw HIGH source-presence findings. The patched backend reports
115 LOW presence findings, zero HIGH/CRITICAL, and zero coverage skips.
Both report 390 INFO MFV-PICKLE-004 and one MEDIUM MFV-PICKLE-006. The 35 HIGH
claims above are after Rowan's report filtering, rather than raw backend counts.
This is a model-only comparison; the full source precision gate was not rerun.

Validation: 700 Hayward tests; 53 Rowan adapter/enrichment/pipeline tests;
Ruff and diff checks; a real Rowan pipeline with the local patched backend
retains HIGH packaged execution and LOW inventory presence. Tests use unrelated
fixture names, import aliases/shadowing, benign package source, malicious pickle,
and analysis limits. Scanning does not import or execute model code.

Delivery requires publishing the Hayward change, then updating Rowan's minimum
Hayward version and releasing Rowan. Rowan 0.3.2 does not include this fix.

Hayward 1.2.5 was published on 2026-10-03 after all 13 implementation and
release CI checks passed. Rowan's 0.3.3 release preparation raises its minimum
version accordingly. A clean wheel with Hayward 1.2.5 installed from PyPI passes
the same 200-artifact comparison and pipeline checks for LOW inventory presence,
HIGH packaged execution, and CRITICAL malicious pickle detection. The comparable
ModelForge/modelbay rerun (`--no-sca --authz --audit`, converted rule engine)
retains all 168 previous findings with no additions/removals or degraded analysis;
its existing adjudication remains 60/82 with one decoy FP and 28 unmatched claims.

### Numeric logging and authorization policy calibration (2026-10-03)

Add proof-based forging calibration for numeric values/formats, immutable
aliases, branch joins and bounded straight-line helper returns. Unknown values,
mutation, shadowed/rebound names, annotations and ORM field declarations do not
clear a claim. `%c` and `:c` remain unsafe even with integer provenance. Sensitive
logging is independent. The previously noted ORM-key log claim remains pending
runtime-value evidence; this change does not remove it to improve the benchmark.

Separate `AUTHZ-BOLA-001` static guard gaps from impact assertions with an
`authorization-gap` evidence tier. Unknown policy yields MEDIUM review findings;
pure existence/unused observations are LOW. Request selectors forwarded to
subsequent/deferred operations remain unknown uses rather than pure existence.
Preserve all guard gaps in audit output; exclude them from confirmed output.
Explicit qualified read/write model requirements can refine impact priority,
with public reads applying only to resolved read-only uses. Policy never permits
writes or opaque object/selector escapes. Invalid/ambiguous policies fail closed;
project declarations remain disabled by default under `--ci`.

Validation: 439 regression tests passed across authorization, configuration,
reporting, sanitizer soundness and sensitive logging. Subsequent adversarial
review checks passed 179 tests, followed by the focused final checks. A comparable
ModelForge/modelbay scan retains all 168 claim locations, no additions/removals,
and complete analysis. Three existence-only observations move MEDIUM to LOW;
the deferred sweep operation remains a MEDIUM review lead. Existing adjudication
therefore remains 60/82 (one decoy FP, 28 unmatched); no improved benchmark score
is claimed. This does not validate runtime exploitability or eliminate the
unknown ORM-field logging claim.
