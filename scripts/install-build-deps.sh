#!/usr/bin/env bash
# Install apt packages and the latest stable rust toolchain needed to
# dpkg-buildpackage the safe libgcrypt port. The safe crate uses
# stabilized let-chains (Rust 1.88+), so 1.87.0 (the toolchain pinned by
# the previous auto-generated CI) is no longer sufficient. The rustup install lands in
# $HOME/.cargo and is written to $GITHUB_PATH so subsequent CI steps see
# the pinned cargo/rustc instead of the runner's preinstalled (older)
# system rust.
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

# Always install rustup into $HOME so we don't pick up the runner's
# preinstalled (older) system rust.
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
  | sh -s -- -y --profile minimal --default-toolchain stable --no-modify-path

# shellcheck source=/dev/null
. "$HOME/.cargo/env"
rustup default stable
rustc --version
cargo --version

# Persist for subsequent CI steps (build-debs.sh runs in a fresh shell).
if [[ -n "${GITHUB_PATH:-}" ]]; then
  printf '%s\n' "$HOME/.cargo/bin" >> "$GITHUB_PATH"
fi
