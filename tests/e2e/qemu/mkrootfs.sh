#!/bin/bash
# Assemble the VM root filesystem and write it out as an ext4 image.
#
# Runs inside a container of the same distribution the package targets, so the
# package is installed against the libc it was built for. `mke2fs -d` populates
# the image from a directory, which is what lets this happen in a container
# rather than needing a loop mount on the host.
set -euo pipefail

: "${KVER:?KVER must be set to the kernel version the VM will boot}"
: "${IMAGE_SIZE:=3G}"

readonly INPUT=/input
readonly HOST_MODULES=/modules
readonly OUT=/out
readonly ROOTFS=/rootfs

export DEBIAN_FRONTEND=noninteractive

echo "==> installing the guest system"
apt-get update -qq
apt-get install -y --no-install-recommends \
    systemd systemd-sysv \
    nftables iproute2 \
    python3 \
    kmod udev \
    e2fsprogs \
    >/dev/null

echo "==> installing the package under test"
# Installed here rather than in the VM so a broken dependency fails the build
# loudly, instead of leaving a VM that boots but has no exporter on it.
deb=$(ls "${INPUT}"/*.deb | head -1)
[ -n "${deb}" ] || { echo "no .deb in ${INPUT}" >&2; exit 1; }
echo "    ${deb##*/}"
dpkg -i "${deb}"

# The README promises a fresh install leaves the service alone, because it has
# no collector yet and would only produce a restart loop. If that ever changed,
# the VM would start exporting before the test configured it.
if [ -e /etc/systemd/system/multi-user.target.wants/conntrack-exporter.service ]; then
    echo "the package enabled the service on install; it must not" >&2
    exit 1
fi

echo "==> staging the root filesystem"
mkdir -p "${ROOTFS}"
for directory in bin boot etc home lib lib64 opt root sbin srv usr var; do
    [ -e "/${directory}" ] && cp -a "/${directory}" "${ROOTFS}/"
done
mkdir -p "${ROOTFS}"/{proc,sys,dev,run,tmp,mnt}
chmod 1777 "${ROOTFS}/tmp"

echo "==> installing kernel modules for ${KVER}"
# nf_conntrack, nf_nat and nf_tables are modules on most kernels, and a VM
# booting the host's kernel needs the matching module tree to load them.
mkdir -p "${ROOTFS}/lib/modules"
cp -a "${HOST_MODULES}/." "${ROOTFS}/lib/modules/${KVER}/"
depmod -b "${ROOTFS}" "${KVER}" 2>/dev/null || true

echo "==> installing the test harness"
install -d -m 0755 "${ROOTFS}/opt/smoke"
install -m 0644 "${INPUT}"/harness/*.py "${ROOTFS}/opt/smoke/"
install -m 0755 "${INPUT}/harness/run.sh" "${ROOTFS}/opt/smoke/run.sh"
install -m 0644 "${INPUT}/harness/smoke.service" \
    "${ROOTFS}/etc/systemd/system/conntrack-exporter-smoke.service"

# Start the smoke test once the system is up.
ln -sf ../conntrack-exporter-smoke.service \
    "${ROOTFS}/etc/systemd/system/multi-user.target.wants/conntrack-exporter-smoke.service"

# Nothing logs in; the console belongs to the test output.
rm -f "${ROOTFS}/etc/systemd/system/getty.target.wants/"* 2>/dev/null || true

# A root filesystem check would only slow the boot down for a throwaway image.
echo "/dev/vda / ext4 defaults 0 0" > "${ROOTFS}/etc/fstab"

echo "==> building the image (${IMAGE_SIZE})"
rm -f "${OUT}/rootfs.ext4"
mke2fs -q -t ext4 -d "${ROOTFS}" -F "${OUT}/rootfs.ext4" "${IMAGE_SIZE}"
# The host runs QEMU as an ordinary user and needs to write to the image.
chmod 0666 "${OUT}/rootfs.ext4"

echo "==> $(du -h --apparent-size "${OUT}/rootfs.ext4" | cut -f1) image, $(du -sh "${ROOTFS}" | cut -f1) of content"
