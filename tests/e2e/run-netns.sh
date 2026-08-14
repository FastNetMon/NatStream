#!/usr/bin/env bash
#
# Run the end-to-end smoke test in a throwaway user + network namespace.
#
# An unprivileged user holds CAP_NET_ADMIN inside a user namespace it created,
# and conntrack state, the netfilter sysctls and the netlink groups are all
# per-network-namespace. That is exactly the privilege the exporter needs, so
# the whole thing runs as a normal user against a real kernel — no root, no VM.
#
#   ./tests/e2e/run-netns.sh                       # default configuration
#   ./tests/e2e/run-netns.sh --all                 # every protocol and profile
#   ./tests/e2e/run-netns.sh --protocol netflow9   # one specific configuration
#   ./tests/e2e/run-netns.sh --throughput          # real-kernel ingest load test
#
# Exits 0 on success, 1 on failure, and 77 when the host cannot run the test at
# all (the convention `cargo test` uses here to skip rather than fail).

set -euo pipefail

readonly SKIP=77
readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly SMOKE="$ROOT/tests/e2e/netns_smoke.py"
readonly THROUGHPUT="$ROOT/tests/e2e/throughput.py"

# A host that cannot provide the namespaces skips rather than fails — but in
# CI, where the environment is supposed to be able to run this, a silent skip
# would report a green build that tested nothing. Set E2E_REQUIRE=1 there.
skip() {
    if [[ -n "${E2E_REQUIRE:-}" ]]; then
        echo "error: $* (E2E_REQUIRE is set, so this is a failure)" >&2
        exit 1
    fi
    echo "SKIP: $*" >&2
    exit $SKIP
}

usage() {
    sed -n '3,16p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
    exit 0
}

# ---- What the host has to provide ----

check_prerequisites() {
    for tool in unshare ip nft python3; do
        command -v "$tool" >/dev/null 2>&1 || skip "$tool is not installed"
    done

    # nf_conntrack has to be loaded already: a user namespace cannot load a
    # module, it can only use one the host has.
    [[ -d /proc/sys/net/netfilter ]] || \
        skip "nf_conntrack is not loaded (try: modprobe nf_conntrack)"

    unshare --user --map-root-user --net true 2>/dev/null || \
        skip "unprivileged user namespaces are unavailable on this host"
}

# ---- The exporter under test ----

find_exporter() {
    if [[ -n "${EXPORTER_BIN:-}" ]]; then
        [[ -x "$EXPORTER_BIN" ]] || {
            echo "EXPORTER_BIN=$EXPORTER_BIN is not executable" >&2
            exit 1
        }
        echo "$EXPORTER_BIN"
        return
    fi

    for profile in debug release; do
        local candidate="$ROOT/target/$profile/conntrack_exporter"
        [[ -x "$candidate" ]] && { echo "$candidate"; return; }
    done

    echo "no binary found; run 'cargo build' first" >&2
    exit 1
}

run_case() {
    local exporter="$1"; shift
    # --map-root-user gives the namespace a uid to own; the process is still
    # unprivileged on the host, and holds capabilities only inside it.
    unshare --user --map-root-user --net -- \
        python3 "$SMOKE" --exporter "$exporter" "$@"
}

run_throughput() {
    local exporter="$1"; shift
    unshare --user --map-root-user --net -- \
        python3 "$THROUGHPUT" --exporter "$exporter" "$@"
}

main() {
    local -a cases=()
    local all=0
    local throughput=0

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --all) all=1; shift ;;
            --throughput) throughput=1; shift ;;
            -h|--help) usage ;;
            *) break ;;
        esac
    done

    check_prerequisites
    local exporter
    exporter="$(find_exporter)"
    echo "exporter: $exporter" >&2

    if (( throughput )); then
        # Prefer the release build: a debug one drops several times more and
        # says nothing useful about what the daemon can do.
        local release="$ROOT/target/release/conntrack_exporter"
        [[ -z "${EXPORTER_BIN:-}" && -x "$release" ]] && exporter="$release"
        run_throughput "$exporter" "$@"
        return
    fi

    if (( all )); then
        cases=(
            "--protocol ipfix    --profile full       --counter-width 8"
            "--protocol ipfix    --profile full       --counter-width 4"
            "--protocol ipfix    --profile nat-source --counter-width 8"
            "--protocol ipfix    --profile flow-only  --counter-width 8"
            "--protocol netflow9 --profile full       --counter-width 8"
            "--protocol netflow9 --profile full       --counter-width 4"
            "--protocol netflow9 --profile flow-only  --counter-width 4"
        )
    else
        cases=("$*")
    fi

    local failures=0
    for arguments in "${cases[@]}"; do
        # shellcheck disable=SC2086
        if run_case "$exporter" $arguments; then
            :
        else
            echo "FAIL: $arguments" >&2
            (( ++failures ))
        fi
    done

    if (( failures )); then
        echo "$failures of ${#cases[@]} case(s) failed" >&2
        exit 1
    fi

    echo "all ${#cases[@]} case(s) passed" >&2
}

main "$@"
