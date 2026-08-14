#!/usr/bin/env bash
#
# Measure the benchmarks against a saved baseline, and fail on a regression.
#
# The workflow this exists for:
#
#     ./benches/compare.sh --save before      # on the unchanged tree
#     ...make the change...
#     ./benches/compare.sh --against before   # fails if anything got slower
#
# A baseline is just a named set of results under target/criterion, so it
# survives rebuilds and can be kept around for as long as it is useful.
#
# Gating is on the *lower bound* of criterion's confidence interval for the
# change, not on the point estimate: a regression has to be one the statistics
# are confident about before this fails, or ordinary noise would cry wolf.
#
#     --save NAME            run and store the results as NAME
#     --against NAME         run and compare against NAME, failing on regression
#     --threshold PCT        how much slower is a regression (default 5)
#     --filter EXPR          only benchmarks matching EXPR
#     --list                 show saved baselines
#     --                     everything after this goes to criterion
#
# Benchmarks are only as steady as the machine under them. On a laptop, close
# everything else and expect a percent or two of drift; for numbers worth
# arguing over, pin the CPU governor to performance.

set -euo pipefail

readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly CRITERION_DIR="$ROOT/target/criterion"
readonly BENCH=pipeline

THRESHOLD=5
FILTER=""
MODE=""
NAME=""
EXTRA=()

die() { echo "error: $*" >&2; exit 1; }
usage() { sed -n '3,27p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0; }

list_baselines() {
    [[ -d "$CRITERION_DIR" ]] || die "no benchmark results yet; run --save first"
    # A baseline is a directory of results that is not criterion's own
    # bookkeeping, so collect the names and drop the reserved ones.
    find "$CRITERION_DIR" -name estimates.json -printf '%h\n' 2>/dev/null \
        | sed 's|.*/||' \
        | grep -vxE 'new|base|change' \
        | sort -u \
        || true
}

parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --save)      MODE=save;    NAME="${2:-}"; [[ -n "$NAME" ]] || die "--save needs a name"; shift 2 ;;
            --against)   MODE=against; NAME="${2:-}"; [[ -n "$NAME" ]] || die "--against needs a name"; shift 2 ;;
            --threshold) THRESHOLD="${2:-}"; [[ -n "$THRESHOLD" ]] || die "--threshold needs a percentage"; shift 2 ;;
            --filter)    FILTER="${2:-}"; [[ -n "$FILTER" ]] || die "--filter needs an expression"; shift 2 ;;
            --list)      MODE=list; shift ;;
            -h|--help)   usage ;;
            --)          shift; EXTRA=("$@"); break ;;
            *)           die "unknown argument: $1 (try --help)" ;;
        esac
    done
}

run_benchmarks() {
    local -a arguments=("$@")
    [[ -n "$FILTER" ]] && arguments=("$FILTER" "${arguments[@]}")
    (cd "$ROOT" && cargo bench --locked --bench "$BENCH" -- "${arguments[@]}" "${EXTRA[@]+"${EXTRA[@]}"}")
}

# Criterion writes the comparison to change/estimates.json for every benchmark
# it ran, and leaves the previous run's behind for every one it did not. Only
# the files written since `marker` belong to this run — without that, a
# --filter'd run would be judged partly on stale results.
check_for_regressions() {
    local marker="$1"
    python3 - "$CRITERION_DIR" "$THRESHOLD" "$marker" <<'PYTHON'
import json
import os
import sys

criterion_dir, threshold, marker = sys.argv[1], float(sys.argv[2]), sys.argv[3]
cutoff = os.path.getmtime(marker)
rows = []
stale = 0

for dirpath, _dirnames, filenames in os.walk(criterion_dir):
    if os.path.basename(dirpath) != "change" or "estimates.json" not in filenames:
        continue
    path = os.path.join(dirpath, "estimates.json")
    if os.path.getmtime(path) < cutoff:
        stale += 1
        continue
    with open(path) as handle:
        estimates = json.load(handle)

    name = os.path.relpath(os.path.dirname(dirpath), criterion_dir)
    mean = estimates["mean"]
    rows.append((
        name,
        mean["point_estimate"] * 100,
        mean["confidence_interval"]["lower_bound"] * 100,
        mean["confidence_interval"]["upper_bound"] * 100,
    ))

if not rows:
    print("no comparisons were produced; did the baseline exist?", file=sys.stderr)
    sys.exit(1)

rows.sort(key=lambda row: row[1], reverse=True)
width = max(len(row[0]) for row in rows)

print()
print(f"{'benchmark'.ljust(width)}   change      95% interval")
print("-" * (width + 32))
for name, point, low, high in rows:
    marker = ""
    if low > threshold:
        marker = "  REGRESSED"
    elif high < -threshold:
        marker = "  improved"
    print(f"{name.ljust(width)}  {point:+6.1f}%   [{low:+6.1f}%, {high:+6.1f}%]{marker}")

regressions = [row for row in rows if row[2] > threshold]
improvements = [row for row in rows if row[3] < -threshold]

print()
print(f"{len(rows)} benchmark(s), {len(regressions)} regressed, "
      f"{len(improvements)} improved, threshold {threshold:g}%")
if stale:
    print(f"({stale} benchmark(s) not run this time were ignored)")

if regressions:
    print()
    print("Regressions (confidently slower than the baseline):", file=sys.stderr)
    for name, point, low, _high in regressions:
        print(f"  {name}: {point:+.1f}% (at least {low:+.1f}%)", file=sys.stderr)
    sys.exit(1)
PYTHON
}

main() {
    parse_arguments "$@"

    case "$MODE" in
        list)
            local baselines
            baselines="$(list_baselines)"
            if [[ -z "$baselines" ]]; then
                echo "no saved baselines"
            else
                echo "saved baselines:"
                sed 's/^/  /' <<<"$baselines"
            fi
            ;;
        save)
            echo "==> benchmarking and saving as '$NAME'" >&2
            run_benchmarks --save-baseline "$NAME"
            echo >&2
            echo "==> saved. Make your change, then:" >&2
            echo "      $0 --against $NAME" >&2
            ;;
        against)
            if ! list_baselines | grep -qx "$NAME"; then
                die "no baseline called '$NAME' (see --list, or create one with --save $NAME)"
            fi
            echo "==> benchmarking against '$NAME'" >&2
            local marker
            marker="$(mktemp)"
            trap 'rm -f "$marker"' RETURN
            run_benchmarks --baseline "$NAME"
            check_for_regressions "$marker"
            ;;
        *)
            usage
            ;;
    esac
}

main "$@"
