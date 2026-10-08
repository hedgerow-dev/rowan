"""Usage: REALVULN_DIR=/path/to/Real-Vuln-Benchmark python score.py [--per-repo]

Score Rowan and the rule-based baselines with RealVuln's own scorer
(parsers.get_parser -> match_findings -> compute_scorecard), micro-averaged.

Two bases: Rowan against each baseline on the repos both have results for,
and all ground-truth repos with a missing result counted as false negatives.
"""
import json
import os
import sys
from pathlib import Path

ROOT = Path(os.environ["REALVULN_DIR"]).resolve()
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from parsers import get_parser  # noqa: E402 (needs sys.path above)
from rowan_parser import RowanParser  # noqa: E402 (needs sys.path above)
from scorer.matcher import load_ground_truth, match_findings  # noqa: E402 (needs sys.path above)
from scorer.metrics import compute_scorecard  # noqa: E402 (needs sys.path above)

FAM = json.loads((ROOT / "config" / "cwe-families.json").read_text())
ROWAN = "rowan-f40f11b"                 # --audit: every finding
ROWAN_DEFAULT = "rowan-f40f11b-default"  # the default (actionable) view
SLUGS = [ROWAN, "snyk", "sonarqube", "semgrep"]

def parser(slug):
    return RowanParser(scanner_slug=slug) if slug.startswith(ROWAN) else get_parser(slug)

gts = sorted(d for d in (ROOT / "ground-truth").iterdir() if (d / "ground-truth.json").exists())
have = {s: {d.name for d in gts if (ROOT / "scan-results" / d.name / s / "results.json").exists()} for s in SLUGS}

def f2(p, r):
    return 5 * p * r / (4 * p + r) if (4 * p + r) else 0.0

def score(slug, repos, missing_as_fn):
    tp = fp = fn = 0
    for d in gts:
        gt = load_ground_truth(str(d / "ground-truth.json"))
        rf = ROOT / "scan-results" / d.name / slug / "results.json"
        if d.name not in repos:
            if missing_as_fn:
                fn += sum(1 for v in gt.get("findings", gt.get("vulnerabilities", [])) if v.get("is_vulnerable", True))
            continue
        card = compute_scorecard(gt["repo_id"], slug, "agg", match_findings(parser(slug).parse(str(rf)), gt), FAM)
        tp, fp, fn = tp + card.tp, fp + card.fp, fn + card.fn
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    return dict(tp=tp, fp=fp, fn=fn, precision=round(p, 3), recall=round(r, 3), f2=round(f2(p, r) * 100, 1))

pairwise = {}
for s in SLUGS[1:]:
    shared = have[ROWAN] & have[s]
    pairwise[s] = {"shared_repos": len(shared), ROWAN: score(ROWAN, shared, False), s: score(s, shared, False)}
default_repos = {d.name for d in gts if (ROOT / "scan-results" / d.name / ROWAN_DEFAULT / "results.json").exists()}
out = {"ground_truth_repos": len(gts),
       "rowan_default_view": score(ROWAN_DEFAULT, default_repos, False),
       "results_per_scanner": {s: len(have[s]) for s in SLUGS},
       "pairwise_on_shared_repos": pairwise,
       "all_repos_missing_as_fn": {s: score(s, have[s], True) for s in SLUGS}}
print(json.dumps(out, indent=1))

if "--per-repo" in sys.argv:
    print("repo,tp,fp,fn,degraded")
    for d in gts:
        rf = ROOT / "scan-results" / d.name / ROWAN / "results.json"
        if not rf.exists():
            print(f"{d.name},,,,not scanned (upstream repository unavailable)")
            continue
        gt = load_ground_truth(str(d / "ground-truth.json"))
        card = compute_scorecard(gt["repo_id"], ROWAN, "agg", match_findings(parser(ROWAN).parse(str(rf)), gt), FAM)
        degraded = json.loads(rf.read_text())["summary"]["degraded"]
        print(f"{d.name},{card.tp},{card.fp},{card.fn},{'yes' if degraded else 'no'}")
