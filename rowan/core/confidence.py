"""Single source of truth for taint-finding confidence scoring (issue #123).

Before this module there were **two independently hand-picked** hop-confidence
ladders that disagreed on what the same thing was worth:

* cross-file taint (`CrossFilePass`): a linear decay
  ``max(0.25, 0.75 - hops*0.1)`` -- a *direct* flow scored 0.75.
* intra-file opengrep taint (`EnrichmentPass._score_confidence`): a step
  function 0.90 / 0.80 / 0.65 by hop bucket -- a *direct* flow scored 0.90.

So "one call-hop from source to sink" was 0.75 in one engine and 0.90 in the
other, for no articulated reason, and neither set of constants was tied to any
measurement. This module unifies them into one parameterised decay function of
the TRUE hop distance (now accurate thanks to the #163 worklist), keeping the
one dimension that legitimately differs between the two engines -- the base
trust -- as an explicit per-engine parameter rather than a divergent curve
shape:

* ``OPENGREP_TAINT`` has the higher base (0.90): opengrep's intra-file
  dataflow is a real (sound-ish) taint engine.
* ``CROSSFILE_TAINT`` has the lower base (0.75): ``CrossFilePass`` is a
  heuristic AST pass, so an equivalent hop distance is worth less.

These constants are meant to be **calibrated, not hand-picked**: run
``python scripts/benchmark.py --calibrate`` to sweep them against the labeled
corpus (requires ``ROWAN_VULN_APP_PATH``; see the script) and report the
precision/recall/F the current values achieve versus alternatives. Note the
confidence *value* is display/ranking only for taint findings -- the only
hard output gate is ``EnrichmentPass._apply_thresholds``' per-rule
``min_confidence`` (0.5), which no taint ladder value crosses -- so
recalibrating these numbers re-ranks and re-labels findings without changing
which ones are reported.
"""

from __future__ import annotations

from dataclasses import dataclass
from itertools import product


@dataclass(frozen=True)
class HopConfidenceModel:
    """A clamped linear decay ``clamp(base - hops*decay, floor, base)``.

    ``hops`` is the true source->sink call-chain distance: 0 for a direct
    flow (no intermediate hop), 1 for one intermediate function, and so on.
    """

    base: float
    decay: float
    floor: float

    def __call__(self, hops: int) -> float:
        # Rounded so the constants stay exact/legible in reports and so
        # float error doesn't leak into equality-checked tests.
        return round(max(self.floor, self.base - hops * self.decay), 4)


#: Cross-file heuristic AST taint (`CrossFilePass`). base/decay/floor chosen to
#: reproduce the previous `max(0.25, 0.75 - hops*0.1)` ladder EXACTLY, so this
#: unification is behaviour-preserving for cross-file findings.
CROSSFILE_TAINT = HopConfidenceModel(base=0.75, decay=0.10, floor=0.25)

#: Intra-file opengrep dataflow taint. Higher base trust than the heuristic
#: cross-file pass. Replaces the previous 0.90/0.80/0.65 STEP function with the
#: same shared linear-decay shape; values stay within a few hundredths of the
#: old buckets and, being display-only (see module docstring), do not change
#: which findings are reported.
OPENGREP_TAINT = HopConfidenceModel(base=0.90, decay=0.08, floor=0.65)

#: Pattern-only findings (neuroscan regex, or opengrep matches with no taint
#: flow) are capped here -- a presence match is inherently less certain than a
#: dataflow-confirmed one.
PATTERN_ONLY_CAP = 0.70

#: Structural trust-boundary findings (agent tool / Celery / gRPC / GraphQL /
#: webhook) emitted directly by CrossFilePass.
BOUNDARY_SOURCE = 0.65

#: Object-level authorization (BOLA/IDOR) findings from `AuthzPass` (issue #171,
#: ADR-0003). A heuristic *absence* detector -- it asserts an ownership predicate
#: is missing rather than confirming a dataflow -- so it sits below the
#: dataflow-confirmed taint bases. The High tier (query-fused ownership absent,
#: a principal concept present in the repo) reports at this value.
AUTHZ_BOLA_HIGH = 0.60

#: `AuthzPass` Medium tier (issue #172): an ownership guard exists somewhere in
#: the handler but does not provably dominate the object's first use on its
#: real control-flow path -- present in a sibling branch that does not lead to
#: the use, or after the use (dead). Weaker evidence than the High tier's
#: "zero guard found anywhere," so it sits below it.
AUTHZ_BOLA_MEDIUM = 0.40

#: LLM-discovered findings from hunt's opt-in `discover` stage (ADR-0004).
#: These have no rule behind them and no dataflow: the only mechanical evidence
#: is that the cited snippet provably exists at the cited line, plus an
#: adversarial verify pass that upheld the claim. That is weaker evidence than
#: any deterministic engine produces, so it sits below `PATTERN_ONLY_CAP` --
#: a regex at least encodes a reviewed hypothesis about what the pattern means.
#: Findings carrying this value are always tagged `engine="llm-discovery"` so
#: rule-corpus precision stays measurable with a single filter.
LLM_DISCOVERY_CAP = 0.35
#: `AUTHZ-LLM-001` findings from `AuthzPass` (issue #185): a guard whose
#: condition is confirmed LLM-derived is confirmed to dominate (or contain,
#: for the positive-branch shape) the object access it gates. Unlike
#: `AUTHZ_BOLA_*`, which asserts something is MISSING, this confirms a
#: PRESENT structural relationship -- closer in kind to dataflow-confirmed
#: taint than to an absence heuristic. Deliberately not set as high as
#: `OPENGREP_TAINT`'s floor (0.65) though: "is this guard permission-shaped"
#: is itself a token-matching heuristic (`allowed`/`role`/`can_*`/...) with
#: its own false-positive risk a real dataflow trace doesn't carry. Given its
#: own named constant per issue #185, rather than reusing the BOLA numbers --
#: the two detectors' evidence shapes are different enough that recalibrating
#: them together would hide which one needs adjustment later.
AUTHZ_LLM_HIGH = 0.55


# --------------------------------------------------------------------------- #
# Calibration (#123): pick base/decay from labeled data instead of by hand.
# --------------------------------------------------------------------------- #

#: One labeled observation for calibration: the true source->sink hop distance
#: of a taint finding, and whether it was a genuine vulnerability (True) or a
#: false positive (False) per a ground-truth oracle.
Observation = tuple[int, bool]


def discriminative_separation(observations: list[Observation], model: HopConfidenceModel) -> float:
    """Mean confidence of the true positives minus mean confidence of the
    false positives, under `model`.

    This is the metric a confidence score should be calibrated for here:
    because the confidence value is display/ranking only (it doesn't gate
    which findings are reported -- see the module docstring), "good" constants
    are ones that make confidence SEPARATE real findings from false ones, so a
    reviewer working top-down hits the true positives first. A positive
    separation means TPs are scored higher than FPs on average; larger is
    better. Returns 0.0 if either class is absent (nothing to separate)."""
    tp = [model(h) for h, is_tp in observations if is_tp]
    fp = [model(h) for h, is_tp in observations if not is_tp]
    if not tp or not fp:
        return 0.0
    return (sum(tp) / len(tp)) - (sum(fp) / len(fp))


def calibrate_hop_model(
    observations: list[Observation],
    *,
    bases: tuple[float, ...] = (0.70, 0.75, 0.80, 0.85, 0.90, 0.95),
    decays: tuple[float, ...] = (0.05, 0.08, 0.10, 0.12, 0.15),
    floor: float = 0.25,
) -> tuple[HopConfidenceModel, float]:
    """Grid-search the (base, decay) that maximizes true-vs-false-positive
    confidence separation on `observations`. Returns the best model and its
    separation score. Pure and deterministic (ties broken by grid order), so
    it is unit-testable without the labeled corpus; the corpus only supplies
    the `observations` (see `scripts/benchmark.py --calibrate`)."""
    best: tuple[HopConfidenceModel, float] | None = None
    for base, decay in product(bases, decays):
        model = HopConfidenceModel(base=base, decay=decay, floor=floor)
        score = discriminative_separation(observations, model)
        if best is None or score > best[1]:
            best = (model, score)
    assert best is not None  # bases/decays are non-empty
    return best
