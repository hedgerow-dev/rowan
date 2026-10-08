#!/usr/bin/env bash
# RealVuln static scan with Rowan, cross-file on, no SCA, no project config.
# Writes two result sets: --audit (every finding) and the default view.
# Usage: REALVULN_DIR=/path/to/Real-Vuln-Benchmark ./run.sh
set -uo pipefail
BENCH="${REALVULN_DIR:?set REALVULN_DIR to a Real-Vuln-Benchmark checkout}"
ROWAN="${ROWAN:-rowan}"
SLUG="${SLUG:-rowan-f40f11b}"
LOG=$BENCH/reports/$SLUG-run.log
: > "$LOG"
scan_one() {
  local repo_path="$1" repo slug extra
  repo="$(basename "$repo_path")"
  for view in audit default; do
    if [ "$view" = audit ]; then slug="$SLUG"; extra="--audit"; else slug="$SLUG-default"; extra=""; fi
    local out="$BENCH/scan-results/$repo/$slug"; mkdir -p "$out"
    ( cd "$repo_path" && perl -e 'alarm shift; exec @ARGV' 900 \
        "$ROWAN" scan . --no-sca --no-project-config $extra --format json --output "$out/results.json" ) \
        > "$out/scan.log" 2>&1 && echo "ok   $repo $view" >> "$LOG" || echo "WARN $repo $view (exit $?)" >> "$LOG"
  done
}
export -f scan_one; export BENCH ROWAN SLUG LOG
echo "start $(date)" >> "$LOG"
printf '%s\n' "$BENCH"/repos/*/ | xargs -P 4 -I{} bash -c 'scan_one "$@"' _ {}
echo "done $(date)" >> "$LOG"
