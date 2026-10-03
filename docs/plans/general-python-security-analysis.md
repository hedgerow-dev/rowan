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
  every lower-severity claim. Langflow and PyTorch gates have not been run.
- Local Modelbay regression: 60/82 versus 46/82 at the original PR head. The
  new detections were adjudicated by defect and function anchor; safe-twin
  results are unchanged. Added claims outside its key are explicitly recorded
  as unmatched, so increased recall is not presented as proof of precision.
  The held-out mappings and raw reports remain in the local benchmark workspace.
