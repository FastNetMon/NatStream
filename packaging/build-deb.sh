#!/bin/bash
# Build the release binary and assemble a .deb. Runs inside the builder
# container; see ../build.sh for the host side.
set -euo pipefail

: "${SRC_DIR:=/src}"
: "${OUT_DIR:=/out}"
: "${DIST_TAG:?DIST_TAG must be set (e.g. deb13, ubuntu24.04)}"
: "${DEB_REVISION:=1}"
: "${MAINTAINER:=natstream maintainers <root@localhost>}"

PKG=natstream
BIN=natstream

version=$(awk -F'"' '/^version[[:space:]]*=/ {print $2; exit}' "${SRC_DIR}/Cargo.toml")
[ -n "${version}" ] || { echo "could not read version from Cargo.toml" >&2; exit 1; }

arch=$(dpkg --print-architecture)
deb_version="${version}-${DEB_REVISION}~${DIST_TAG}"

echo "==> ${PKG} ${deb_version} (${arch})"
echo "    $(rustc --version)"
echo "    $(. /etc/os-release 2>/dev/null && echo "${PRETTY_NAME}")"

# The source is mounted read-only, so the build tree lives in the cache mount.
cd "${SRC_DIR}"
cargo build --release --locked

binary="${CARGO_TARGET_DIR:-${SRC_DIR}/target}/release/${BIN}"
[ -x "${binary}" ] || { echo "missing build output: ${binary}" >&2; exit 1; }

stage=$(mktemp -d)
depdir=$(mktemp -d)
trap 'rm -rf "${stage}" "${depdir}"' EXIT

install -D -m 0755 "${binary}"                              "${stage}/usr/sbin/${BIN}"
strip --strip-unneeded "${stage}/usr/sbin/${BIN}"

install -D -m 0644 "packaging/systemd/${PKG}.service"       "${stage}/lib/systemd/system/${PKG}.service"
install -D -m 0644 "packaging/default/${PKG}"               "${stage}/etc/default/${PKG}"
install -D -m 0644 README.md                                "${stage}/usr/share/doc/${PKG}/README.md"
# Debian expects a package's licence at this path.
install -D -m 0644 LICENSE                                  "${stage}/usr/share/doc/${PKG}/copyright"

install -d -m 0755 "${stage}/DEBIAN"
for script in postinst prerm postrm; do
    install -m 0755 "packaging/deb/${script}" "${stage}/DEBIAN/${script}"
done

# Files under /etc that dpkg must not clobber on upgrade.
printf '/etc/default/%s\n' "${PKG}" > "${stage}/DEBIAN/conffiles"

# Derive the real libc dependency from the binary rather than guessing, since
# the whole point of building per distro is the glibc version.
mkdir -p "${depdir}/debian"
cat > "${depdir}/debian/control" <<EOF
Source: ${PKG}

Package: ${PKG}
Architecture: ${arch}
EOF
depends=$(cd "${depdir}" && dpkg-shlibdeps -O --ignore-missing-info \
            "${stage}/usr/sbin/${BIN}" 2>/dev/null | sed -n 's/^shlibs:Depends=//p')
if [ -z "${depends}" ]; then
    echo "    warning: dpkg-shlibdeps produced nothing, falling back to libc6" >&2
    depends="libc6"
fi
echo "    Depends: ${depends}"

installed_size=$(du -ks "${stage}" | cut -f1)

cat > "${stage}/DEBIAN/control" <<EOF
Package: ${PKG}
Version: ${deb_version}
Section: net
Priority: optional
Architecture: ${arch}
Depends: ${depends}
Installed-Size: ${installed_size}
Maintainer: ${MAINTAINER}
Description: conntrack NAT event IPFIX / NetFlow v9 exporter
 Exports Linux conntrack NAT events as IPFIX (RFC 7011) or NetFlow v9
 (RFC 3954) flow records over UDP.
 .
 It subscribes to conntrack netlink notifications, filters them to IPv4 NAT
 sessions, and sends a record per session create and delete to a collector,
 carrying both the original and the translated address and port.
 .
 The packaged service runs unprivileged under a transient systemd user with
 CAP_NET_ADMIN, and must be pointed at a collector in
 /etc/default/${PKG} before it will start.
EOF

mkdir -p "${OUT_DIR}"
deb="${OUT_DIR}/${PKG}_${deb_version}_${arch}.deb"
dpkg-deb --root-owner-group --build "${stage}" "${deb}" >/dev/null

# A package that does not unpack cleanly is worse than no package.
dpkg-deb --info "${deb}" >/dev/null
echo "==> ${deb}"
dpkg-deb --contents "${deb}" | awk '{printf "    %s %s %s\n", $1, $3, $6}'
