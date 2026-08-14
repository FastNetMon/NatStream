#!/usr/bin/env bash
# Build a .deb of the daemon for a target distribution, inside Docker.
#
# Each target builds against its own distro's glibc, because the three targets
# ship 2.39, 2.41 and 2.43 and a binary from a newer one will not run on an
# older one. The Rust toolchain is pinned and identical across targets.
set -euo pipefail

cd "$(dirname "$0")"

RUST_VERSION="${RUST_VERSION:-1.97.1}"
DEB_REVISION="${DEB_REVISION:-1}"
IMAGE_PREFIX="${IMAGE_PREFIX:-natstream-builder}"

TARGETS="trixie 24.04 26.04"

usage() {
    cat >&2 <<EOF
Usage: ./build.sh [${TARGETS// /|}|all]

Builds a Debian package for the given target inside a Docker container based on
that distribution. Packages are written to dist/.

Targets:
  trixie          Debian 13 (trixie)      -> natstream_*~deb13_*.deb
  24.04 | noble   Ubuntu 24.04 LTS        -> natstream_*~ubuntu24.04_*.deb
  26.04           Ubuntu 26.04 LTS        -> natstream_*~ubuntu26.04_*.deb
  all             every target above

Environment:
  RUST_VERSION    Rust toolchain to build with (default: ${RUST_VERSION})
  DEB_REVISION    Debian revision for the package version (default: ${DEB_REVISION})
  MAINTAINER      Package maintainer (default: taken from git config)
  NO_CACHE=1      Rebuild the builder image from scratch

Examples:
  ./build.sh trixie
  ./build.sh all
  MAINTAINER="Ops <ops@example.com>" ./build.sh 24.04
EOF
}

# target -> base image, package version suffix
resolve_target() {
    case "$1" in
        trixie|debian|deb13)  base_image=debian:trixie; dist_tag=deb13 ;;
        24.04|noble|ubuntu24) base_image=ubuntu:24.04;  dist_tag=ubuntu24.04 ;;
        26.04|ubuntu26)       base_image=ubuntu:26.04;  dist_tag=ubuntu26.04 ;;
        *) echo "error: unknown target '$1'" >&2; echo >&2; usage; exit 2 ;;
    esac
}

maintainer() {
    if [ -n "${MAINTAINER:-}" ]; then
        printf '%s' "${MAINTAINER}"
        return
    fi
    local name email
    name=$(git config user.name 2>/dev/null || true)
    email=$(git config user.email 2>/dev/null || true)
    if [ -n "${name}" ] && [ -n "${email}" ]; then
        printf '%s <%s>' "${name}" "${email}"
    else
        printf 'natstream maintainers <root@localhost>'
    fi
}

build_one() {
    local target="$1" base_image dist_tag image cache
    resolve_target "${target}"

    image="${IMAGE_PREFIX}:${dist_tag}"
    cache="${PWD}/.build-cache/${dist_tag}"

    echo
    echo "=================================================================="
    echo " ${target}  (${base_image}, rust ${RUST_VERSION})"
    echo "=================================================================="

    docker build \
        ${NO_CACHE:+--no-cache} \
        --build-arg "BASE_IMAGE=${base_image}" \
        --build-arg "RUST_VERSION=${RUST_VERSION}" \
        -t "${image}" \
        packaging

    mkdir -p dist "${cache}"

    # Run as the invoking user so dist/ and the cache are not left root-owned.
    # The source is mounted read-only; the build tree lives in the cache.
    docker run --rm \
        --user "$(id -u):$(id -g)" \
        --volume "${PWD}:/src:ro" \
        --volume "${PWD}/dist:/out" \
        --volume "${cache}:/cache" \
        --env SRC_DIR=/src \
        --env OUT_DIR=/out \
        --env HOME=/cache \
        --env CARGO_HOME=/cache/cargo \
        --env CARGO_TARGET_DIR=/cache/target \
        --env "DIST_TAG=${dist_tag}" \
        --env "DEB_REVISION=${DEB_REVISION}" \
        --env "MAINTAINER=$(maintainer)" \
        "${image}"
}

main() {
    case "${1:-}" in
        -h|--help|help) usage; exit 0 ;;
        "") usage; exit 2 ;;
    esac

    if ! docker version >/dev/null 2>&1; then
        echo "error: cannot talk to Docker. Is the daemon running, and are you in the docker group?" >&2
        exit 1
    fi

    if [ "$1" = "all" ]; then
        for target in ${TARGETS}; do
            build_one "${target}"
        done
    else
        build_one "$1"
    fi

    echo
    echo "packages in dist/:"
    ls -1 dist/*.deb 2>/dev/null | sed 's/^/  /' || echo "  (none)"
}

main "$@"
