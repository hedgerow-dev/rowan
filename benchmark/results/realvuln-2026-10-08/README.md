# RealVuln, 2026-10-08

Rowan `main` at `f40f11b` on [RealVuln](https://github.com/kolega-ai/Real-Vuln-Benchmark),
an independent benchmark of 66 intentionally vulnerable Python applications
with about 1,900 labeled findings, including false-positive traps. The
[2026-10-02 run](../realvuln-2026-10-02/README.md) scored v0.3.0 the same way.

## Result

RealVuln scores a finding as correct when the file, the CWE family and the
line (within 10 lines) all match. F2 weighs recall four times as heavily as
precision. These numbers come from RealVuln's own scorer.

**Rowan against each rule-based baseline, on the repositories both have results for:**

| Scanner | Repos | Precision | Recall | F2 |
|---|---|---|---|---|
| **Rowan `f40f11b`** | 63 | 0.336 | 0.353 | **35.0** |
| Rowan v0.3.0 (2026-10-02) | 63 | 0.261 | 0.353 | 33.0 |
| SonarQube | 63 | 0.146 | 0.147 | 14.7 |
| Semgrep CE (`--config auto --oss-only`) | 63 | 0.141 | 0.067 | 7.5 |
| **Rowan `f40f11b`** | 23 | 0.336 | 0.312 | **31.7** |
| Snyk | 23 | 0.411 | 0.179 | 20.2 |

Recall is unchanged from v0.3.0; precision rose from 0.261 to 0.336. Rowan
finds more of the labeled vulnerabilities than all three tools. Its precision
is above SonarQube and Semgrep and **still below Snyk**.

**Two views.** The rows above score `--audit`, every finding including
low-confidence leads. Rowan's default view hides those; scored the same way
it reaches **precision 0.516, recall 0.252, F2 28.1** on the 63 repositories
(v0.3.0: 0.384, 0.246, 26.5).

**Duplicates count against Rowan.** The scorer counts every finding that does
not claim a new labeled vulnerability as a false positive. Different rules on
one sink are now merged into one finding, so on this run 286 of 1,282 false
positives are duplicates (v0.3.0: 616 of 2,127). Of those, 107 are one finding
listing two CWEs and 179 are two findings for one labeled bug.

**For context:** LLM-based reviewers mostly score higher. On the leaderboard
committed at RealVuln `98872da`, 22 of 26 LLM and agentic entries beat F2 35.0,
and the best reaches 84.3. Rowan is a static scanner with no LLM.

Full numbers, including a basis that counts missing repositories as misses:
[`scores.json`](scores.json). Per-repository counts: [`per-repo.csv`](per-repo.csv).

## What changed since v0.3.0

- 117 rules declared categories the scanner did not recognize, which hid
  some code-execution rules from the default view. All now use valid ones.
- `ns-auth-002` now sees an auth decorator above a handler.
- Three rules with no true positives here were removed.
- Different rules reporting the same sink are merged into one finding with
  the strongest evidence.

## Read these numbers carefully

- **Rowan was developed with this benchmark in view.** Every change listed
  above was found by studying this corpus, and earlier rules were added or
  widened after studying its misses. Expect smaller gains on code Rowan's
  authors have not studied.
- **Baseline results are RealVuln's, not ours.** Semgrep, SonarQube and Snyk
  results are the files committed in the RealVuln repository, run by its
  authors. Semgrep ran without its commercial cross-file engine. Snyk results
  exist for 25 repositories only.
- **Three repositories were not scanned:** their upstream source is no longer
  available (`owasp-web-playground`, `python-app`, `vulnerable-api`).
- **Two scans were incomplete:** `vulnerable-python-apps` and
  `vulnerable-tornado-app` contain Python 2 files Rowan cannot parse. They are
  scored as they are.
- **Severity is invisible to the scorer.** A finding counts the same at INFO or
  CRITICAL, so Rowan's evidence tiers do not affect these numbers.
- **Python only.** RealVuln says nothing about other languages.

## Setup

| | |
|---|---|
| Rowan | `main` at `f40f11b` (unreleased, after 0.3.4), `rowan scan . --no-sca --no-project-config --audit --format json` (cross-file on); default view: the same without `--audit` |
| Opengrep | 1.29.0 |
| RealVuln | commit `98872da`, benchmark 2.0.0 |
| Machine | macOS, Apple Silicon, four scans in parallel, both views of 63 repositories in about 8 minutes |

## Reproduce

```bash
git clone https://github.com/kolega-ai/Real-Vuln-Benchmark
cd Real-Vuln-Benchmark && git checkout 98872da
python clone_repos.py
export REALVULN_DIR="$PWD"
/path/to/rowan/benchmark/results/realvuln-2026-10-08/run.sh
python /path/to/rowan/benchmark/results/realvuln-2026-10-08/score.py
```

PyGoat's listed URL (`OWASP/PyGoat`) does not exist. The pinned commit is in
`adeyosemanputra/pygoat`: clone that into `repos/realvuln-pygoat` and check out
`2fb0c600`.

`run.sh` scans every repository twice (`--audit` and the default view) and
writes Rowan's reports into RealVuln's `scan-results/` folder. `score.py` uses
RealVuln's scorer with the Rowan parser in this folder
([`rowan_parser.py`](rowan_parser.py)); RealVuln needs no changes. Raw Rowan
reports are not committed because they quote third-party source code.
