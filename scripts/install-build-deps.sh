#!/usr/bin/env bash
# Install apt packages and rustup toolchain needed to dpkg-buildpackage
# the safe libgcrypt port.
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive

sudo apt-get update
sudo apt-get install -y --no-install-recommends \
  build-essential \
  ca-certificates \
  curl \
  devscripts \
  dpkg-dev \
  equivs \
  fakeroot \
  file \
  git \
  jq \
  python3 \
  rsync \
  xz-utils

if ! command -v rustup >/dev/null 2>&1; then
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
    | sh -s -- -y --profile minimal --default-toolchain 1.87.0
fi

# shellcheck source=/dev/null
. "$HOME/.cargo/env"
rustup toolchain install 1.87.0 --profile minimal
rustup default 1.87.0
rustc --version
cargo --version
