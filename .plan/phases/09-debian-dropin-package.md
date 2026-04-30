# Phase Name

Ubuntu 24.04 Debian drop-in package

# Implement Phase ID

`impl_p09_debian_dropin_package`

# Preexisting Inputs

- Phase 8 committed tree and tag.
- `safe/Cargo.toml`
- `safe/Cargo.lock`
- `safe/.cargo/config.toml`
- `.cargo/config.toml` if committed by phase 1.
- `rust-toolchain.toml`
- `safe/rust-toolchain.toml`
- `safe/scripts/check-rust-toolchain.sh`
- `safe/vendor/**`
- `safe/build.rs`
- `safe/cabi/exports.c`
- `safe/cabi/exports.h`
- `safe/abi/*`
- `safe/debian/`
- `safe/scripts/build-debs.sh`
- `safe/scripts/check-deb-metadata.sh`
- `safe/scripts/check-installed-tools.sh`
- `safe/scripts/check-no-upstream-bridge.sh`
- `safe/src/bin/dumpsexp.rs`
- `safe/src/bin/hmac256.rs`
- `safe/src/bin/mpicalc.rs`
- `original/libgcrypt20-1.10.3/debian/`

# New Outputs

- Ubuntu 24.04 installable `libgcrypt20` and `libgcrypt20-dev` packages under `safe/dist/`.
- Per-build safe package provenance manifest `safe/dist/safe-debs.manifest.json` containing package names, architectures, versions, source package names, `.deb` filenames, `.deb` SHA256 values, the phase commit, and `rustc -Vv`/`cargo -Vv` output from the pinned toolchain.
- Correct symbols file and package metadata matching the safe ABI.
- Installed helper tool smoke coverage with no upstream bridge.

# File Changes

- `safe/debian/rules`
- `safe/debian/control`
- `safe/debian/changelog`
- `safe/debian/libgcrypt20.install`
- `safe/debian/libgcrypt20-dev.install`
- `safe/debian/libgcrypt20.symbols`
- `safe/debian/clean-up-unmanaged-libraries`
- `safe/scripts/build-debs.sh`
- `safe/scripts/check-rust-toolchain.sh`
- `safe/scripts/check-deb-metadata.sh`
- `safe/scripts/check-installed-tools.sh`
- `safe/src/bin/dumpsexp.rs`
- `safe/src/bin/hmac256.rs`
- `safe/src/bin/mpicalc.rs`

# Implementation Details

- Remove `-ldl` from `safe/debian/rules` and helper link scripts after phase 6 bridge removal.
- Keep `CARGO_NET_OFFLINE=true`, `--locked`, and the committed vendor closure in package builds.
- Before invoking Cargo or `dpkg-buildpackage`, both `safe/scripts/build-debs.sh` and `safe/debian/rules` must run `safe/scripts/check-rust-toolchain.sh` and fail unless active `rustc` and `cargo` are Rust `1.85.1` from the committed toolchain contract.
- `safe/scripts/build-debs.sh` must not rely on Ubuntu 24.04 packaged Rust 1.75 even if `rustc` and `cargo` packages are installed. `safe/debian/control` may keep Debian build dependency names for package shape, but package build success is gated by the committed toolchain checker, not by ambient apt package versions.
- `safe/scripts/build-debs.sh` must write `safe/dist/safe-debs.manifest.json` after every successful build and `safe/scripts/check-deb-metadata.sh --dist safe/dist` must validate that manifest against the built `.deb` files and the pinned toolchain output.
- Install `libgcrypt.so.20.4.3`, `libgcrypt.so.20`, `libgcrypt.so`, `libgcrypt.a`, `gcrypt.h`, `libgcrypt.pc`, `libgcrypt-config`, `libgcrypt.m4`, and helper binaries in the same package split as Ubuntu's libgcrypt20 packages.
- Reconcile `safe/debian/libgcrypt20.symbols` from `safe/abi/libgcrypt.vers` and the original Debian symbols file.
- Make `check-installed-tools.sh` run only safe package contents and system dependencies, with no `SAFE_SYSTEM_LIBGCRYPT_PATH`.
- Preserve the consume-existing-artifacts contract by updating the existing Debian tree, package scripts, ABI files, and helper binaries in place.

# Verification Phases

- Phase ID: `check_p09_debian_package`
- Type: `check`
- `bounce_target`: `impl_p09_debian_dropin_package`
- Purpose: verify binary package contents, pinned Rust package-build toolchain, maintainer scripts, symbol metadata, helper tools, installed development metadata, and package install behavior.
- Commands:
  - `test "$(git rev-parse HEAD)" = "$(git rev-parse phase/impl_p09_debian_dropin_package)"`
  - `test "$(git rev-parse HEAD^)" = "$(git rev-parse phase/impl_p08_link_source_compat)"`
  - `bash -c 'test -z "$(git status --short)"'`
  - `safe/scripts/check-rust-toolchain.sh`
  - `safe/scripts/build-debs.sh`
  - `safe/scripts/check-deb-metadata.sh --dist safe/dist`
  - `safe/scripts/check-installed-tools.sh --dist safe/dist`
  - `safe/scripts/check-no-upstream-bridge.sh`

# Success Criteria

- Safe `libgcrypt20` and `libgcrypt20-dev` packages install as Ubuntu 24.04 drop-in packages.
- Package builds use the committed Rust `1.85.1` toolchain contract and offline vendored dependencies.
- `safe/dist/safe-debs.manifest.json` is generated for each successful build and validates against the built `.deb` files.
- Installed helper tools run without an upstream bridge.
- The phase is a single child commit of `phase/impl_p08_link_source_compat` and leaves a clean worktree before tests.

# Git Commit Requirement

The implementer must commit work to git before yielding. End with one commit whose subject begins `impl_p09_debian_dropin_package:` and whose first parent is `phase/impl_p08_link_source_compat`; force-update local tag `phase/impl_p09_debian_dropin_package` to that commit before yielding.
