#!/usr/bin/env bash
#
# Package smoke test: install the .deb in a VM, start the service as shipped,
# and check it actually exports NAT records.
#
# The namespace test already covers the exporter itself. What only a VM can
# cover is everything around it — that the package installs, that the unit file
# starts, that `DynamicUser=yes` with a single `CAP_NET_ADMIN` really is enough
# to read conntrack and set the sysctls, and that stopping it is clean.
#
#   ./tests/e2e/qemu/run-qemu.sh              # build what is missing, then run
#   ./tests/e2e/qemu/run-qemu.sh --rebuild    # rebuild the VM image first
#   DEB=dist/foo.deb ./tests/e2e/qemu/run-qemu.sh
#
# The VM boots the host's kernel directly — no bootloader, no initramfs, and
# the host's module tree copied in — so there is nothing to download.
#
# Exits 0 on success, 1 on failure, and 77 when the host cannot run it at all.

set -euo pipefail

readonly SKIP=77
readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
readonly HERE="$ROOT/tests/e2e/qemu"
readonly WORK="$ROOT/target/qemu-e2e"
readonly IMAGE="$WORK/rootfs.ext4"
readonly CONSOLE="$WORK/console.log"

KVER="${KVER:-$(uname -r)}"
KERNEL="${KERNEL:-/boot/vmlinuz-$KVER}"
MODULES="${MODULES:-/lib/modules/$KVER}"
MEMORY="${MEMORY:-1G}"
BOOT_TIMEOUT="${BOOT_TIMEOUT:-420}"
BUILDER_IMAGE="${BUILDER_IMAGE:-debian:trixie}"

skip() { echo "SKIP: $*" >&2; exit $SKIP; }
die()  { echo "error: $*" >&2; exit 1; }
log()  { echo "==> $*" >&2; }

usage() { sed -n '3,20p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0; }

# ---- What the host has to provide ----

check_prerequisites() {
    command -v qemu-system-x86_64 >/dev/null 2>&1 || skip "qemu-system-x86_64 is not installed"
    command -v docker >/dev/null 2>&1 || skip "docker is not installed"
    docker version >/dev/null 2>&1 || skip "cannot talk to the Docker daemon"

    # The VM boots the running kernel, so both it and its modules must be
    # readable. Some distributions ship /boot/vmlinuz-* as mode 0600.
    [[ -r "$KERNEL" ]] || skip "$KERNEL is not readable (needed to boot the VM)"
    [[ -d "$MODULES" ]] || skip "$MODULES does not exist (needed for nf_conntrack)"
}

# ---- The package under test ----

find_deb() {
    if [[ -n "${DEB:-}" ]]; then
        [[ -f "$DEB" ]] || die "DEB=$DEB does not exist"
        echo "$DEB"
        return
    fi

    # The guest is Debian trixie, so it needs the package built for trixie:
    # the whole point of the per-distro build is that the libc differs.
    local candidate
    candidate=$(ls -t "$ROOT"/dist/natstream_*deb13*.deb 2>/dev/null | head -1)
    if [[ -z "$candidate" ]]; then
        log "no trixie package in dist/, building one"
        "$ROOT/build.sh" trixie >&2
        candidate=$(ls -t "$ROOT"/dist/natstream_*deb13*.deb 2>/dev/null | head -1)
    fi
    [[ -n "$candidate" ]] || die "no package to test; run ./build.sh trixie"
    echo "$candidate"
}

# ---- The VM image ----

build_image() {
    local deb="$1"
    local input="$WORK/input"

    log "staging the image inputs"
    rm -rf "$input"
    mkdir -p "$input/harness" "$WORK"
    cp "$deb" "$input/"
    # The decoder and the flow definition are shared with the namespace test.
    cp "$ROOT/tests/e2e/flowdecode.py" "$ROOT/tests/e2e/natflow.py" "$input/harness/"
    cp "$HERE/vm_smoke.py" "$HERE/run.sh" "$HERE/smoke.service" "$input/harness/"

    log "building the root filesystem (this takes a minute)"
    docker run --rm \
        --volume "$HERE/mkrootfs.sh:/mkrootfs.sh:ro" \
        --volume "$input:/input:ro" \
        --volume "$MODULES:/modules:ro" \
        --volume "$WORK:/out" \
        --env "KVER=$KVER" \
        "$BUILDER_IMAGE" \
        bash /mkrootfs.sh >&2
}

# ---- Running it ----

boot_vm() {
    local -a acceleration=()
    if [[ -r /dev/kvm && -w /dev/kvm ]]; then
        acceleration=(-enable-kvm -cpu host)
    else
        log "no access to /dev/kvm; falling back to emulation, which is slow"
    fi

    rm -f "$CONSOLE"
    log "booting the VM"

    # -snapshot keeps the image pristine: every run boots the same freshly
    # installed system rather than inheriting whatever the last one left behind.
    #
    # No network device: the collector, the traffic and the exporter are all
    # inside the guest, on its loopback. Nothing needs to reach the host.
    timeout "$BOOT_TIMEOUT" qemu-system-x86_64 \
        "${acceleration[@]}" \
        -m "$MEMORY" -smp 2 \
        -kernel "$KERNEL" \
        -drive "file=$IMAGE,format=raw,if=virtio" \
        -snapshot \
        -append "root=/dev/vda rw console=ttyS0 panic=10 systemd.show_status=false init=/lib/systemd/systemd" \
        -display none \
        -serial "file:$CONSOLE" \
        -no-reboot \
        >/dev/null 2>&1 || true
}

report() {
    if [[ ! -s "$CONSOLE" ]]; then
        die "the VM produced no console output at all; see $CONSOLE"
    fi

    # Strip the terminal escapes systemd sprinkles through boot output.
    local console
    console=$(sed 's/\x1b\[[0-9;?]*[a-zA-Z]//g' "$CONSOLE")

    if grep -q "SMOKE-RESULT: PASS" <<<"$console"; then
        sed -n '/package smoke test/,/^=\{20,\}$/p' <<<"$console" >&2
        log "PASS"
        return 0
    fi

    echo >&2
    if grep -q "SMOKE-RESULT: FAIL" <<<"$console"; then
        echo "--- the smoke test failed inside the VM ---" >&2
        sed -n '/package smoke test/,$p' <<<"$console" >&2
    else
        echo "--- the VM never reported a result (boot failure, or a timeout) ---" >&2
        tail -60 <<<"$console" >&2
    fi
    echo >&2
    die "full console log: $CONSOLE"
}

main() {
    local rebuild=0
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --rebuild) rebuild=1; shift ;;
            -h|--help) usage ;;
            *) die "unknown argument: $1" ;;
        esac
    done

    check_prerequisites
    mkdir -p "$WORK"

    local deb
    deb="$(find_deb)"
    log "package: ${deb##*/}"
    log "kernel:  $KERNEL"

    # Rebuild when asked, when there is no image, or when anything baked into
    # the image — the package or the harness — is newer than the image itself.
    local -a sources=(
        "$deb"
        "$HERE/mkrootfs.sh" "$HERE/vm_smoke.py" "$HERE/run.sh" "$HERE/smoke.service"
        "$ROOT/tests/e2e/flowdecode.py" "$ROOT/tests/e2e/natflow.py"
    )
    local stale=0
    for source in "${sources[@]}"; do
        [[ "$source" -nt "$IMAGE" ]] && stale=1
    done

    if (( rebuild )) || [[ ! -f "$IMAGE" ]] || (( stale )); then
        build_image "$deb"
    else
        log "reusing $IMAGE (pass --rebuild to rebuild it)"
    fi

    boot_vm
    report
}

main "$@"
