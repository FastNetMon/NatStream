# Builder image for one target distribution.
#
# The base image is the target distro on purpose: the binary links that distro's
# glibc, and the three targets ship 2.39, 2.41 and 2.43, so a binary built on one
# will not run on an older one.
#
# The distro's own rustc is not usable across all targets — Ubuntu 24.04 ships
# 1.75 and this crate needs 1.85+ for edition 2024 — so a pinned toolchain is
# installed instead. Same compiler everywhere, different libc.

ARG BASE_IMAGE=debian:trixie
FROM ${BASE_IMAGE}

ARG RUST_VERSION=1.97.1

ENV DEBIAN_FRONTEND=noninteractive \
    RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      ca-certificates \
      curl \
      gcc \
      libc6-dev \
      binutils \
      dpkg-dev \
 && rm -rf /var/lib/apt/lists/*

RUN curl -fsSL --proto '=https' --tlsv1.2 https://sh.rustup.rs -o /tmp/rustup-init.sh \
 && sh /tmp/rustup-init.sh -y --no-modify-path --profile minimal \
      --default-toolchain "${RUST_VERSION}" \
 && rm /tmp/rustup-init.sh \
 && chmod -R a+rX "${RUSTUP_HOME}" "${CARGO_HOME}" \
 && rustc --version && cargo --version

COPY build-deb.sh /usr/local/bin/build-deb
RUN chmod 0755 /usr/local/bin/build-deb

ENTRYPOINT ["/usr/local/bin/build-deb"]
