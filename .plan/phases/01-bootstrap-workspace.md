# Phase Name

Bootstrap workspace and artifact contract

# Implement Phase ID

`impl_p01_bootstrap_workspace`

# Preexisting Inputs

- `safe/Cargo.toml`
- `safe/Cargo.lock`
- `safe/.cargo/config.toml`
- `.cargo/config.toml` if present as a worktree-only candidate.
- `rust-toolchain.toml` if present as a worktree-only candidate.
- `safe/rust-toolchain.toml` if present.
- `safe/vendor/`
- `safe/build.rs`
- `safe/src/lib.rs`
- `safe/src/ffi.rs`
- `safe/cabi/exports.c`
- `safe/cabi/exports.h`
- `safe/abi/*`
- `safe/tests/original-build/*`
- `safe/scripts/check-abi.sh`
- `safe/scripts/run-original-tests.sh`
- `original/libgcrypt20-1.10.3/src/gcrypt.h.in`
- `original/libgcrypt20-1.10.3/src/gcrypt-testapi.h`
- `original/libgcrypt20-1.10.3/src/visibility.h`
- `original/libgcrypt20-1.10.3/src/libgcrypt.vers`
- `original/libgcrypt20-1.10.3/src/libgcrypt.def`
- `original/libgcrypt20-1.10.3/src/libgcrypt.m4`
- `original/libgcrypt20-1.10.3/src/libgcrypt.pc.in`
- `original/libgcrypt20-1.10.3/src/libgcrypt-config.in`
- `original/libgcrypt20-1.10.3/tests/Makefile.am`
- `original/libgcrypt20-1.10.3/tests/testdrv.c`
- `original/libgcrypt20-1.10.3/compat/`

# New Outputs

- Committed baseline helper set for build, ABI, bridge detection, and target-root resolution.
- A deterministic offline Cargo dependency decision: either a committed vendor closure under `safe/vendor/` or no external Rust dependencies.
- Deterministic Cargo configuration for commands run from both the repository root and `safe/`, either by committing root `.cargo/config.toml` plus `safe/.cargo/config.toml` or by updating all scripts and documented commands to run Cargo from `safe/`.
- A deterministic Rust toolchain contract: committed root `rust-toolchain.toml`, committed `safe/rust-toolchain.toml`, and committed `safe/scripts/check-rust-toolchain.sh` pinning and verifying Rust/Cargo `1.85.1` for edition 2024 builds.
- Updated `safe/docs/abi-map.md` documenting which symbols are real implementations, temporary bridge implementations, or deliberate compatibility shims.
- Updated `safe/docs/bridge-inventory.md` documenting every current bridge reference and its planned removal phase.

# File Changes

- `safe/Cargo.toml`
- `safe/Cargo.lock`
- `safe/.cargo/config.toml`
- `.cargo/config.toml`
- `rust-toolchain.toml`
- `safe/rust-toolchain.toml`
- `safe/vendor/**`
- `safe/build.rs`
- `safe/src/lib.rs`
- `safe/src/ffi.rs`
- `safe/cabi/exports.c`
- `safe/cabi/exports.h`
- `safe/scripts/build-release-lib.sh`
- `safe/scripts/cargo-target-root.sh`
- `safe/scripts/check-rust-toolchain.sh`
- `safe/scripts/check-no-upstream-bridge.sh`
- `safe/scripts/check-abi.sh`
- `safe/scripts/run-original-tests.sh`
- `safe/docs/abi-map.md`
- `safe/docs/bridge-inventory.md`

# Implementation Details

- Keep `safe/build.rs` as the single renderer for `gcrypt.h`, `libgcrypt.pc`, `libgcrypt-config`, version-script exports, and bootstrap manifest files.
- Decide whether `safe/src/ffi.rs` is dead. If dead, delete it and remove stale references. If it contains needed code, move the needed functions into live modules and document ownership in `safe/docs/abi-map.md`.
- Commit or remove untracked helper files. Later phases may cite a helper only if this phase commits it.
- Ensure generated C stubs remain temporary only. `safe_gcry_stub_zero` may exist after this phase only for symbols explicitly marked as later-phase work in `safe/docs/abi-map.md`.
- Keep `safe/.cargo/config.toml` fail-closed with offline vendored sources.
- Ensure repository-root commands such as `cargo build --manifest-path safe/Cargo.toml --release --locked --offline` use the committed vendor closure without relying on the current untracked root `.cargo/config.toml`. Commit the root config if root-level Cargo invocations remain in scripts or verification commands; otherwise update every script and verification command to run Cargo from `safe/`.
- Commit identical root `rust-toolchain.toml` and `safe/rust-toolchain.toml` files pinning Rust `1.85.1`, `profile = "minimal"`, and `components = ["rustfmt"]`.
- Add `safe/scripts/check-rust-toolchain.sh` and wire it into build scripts so host Cargo builds, Debian package builds, and dependent safe-image package preparation fail before Cargo runs when the active `rustc`/`cargo` do not match the pinned toolchain.
- The toolchain checker must read the committed toolchain files, verify they agree, run `rustc -Vv` and `cargo -Vv`, require release `1.85.1`, require Cargo from the same toolchain, and fail with a clear message when the active toolchain is Ubuntu 24.04 packaged Rust 1.75 or any other unpinned version. It must not install Rust or fetch toolchains itself.
- Preserve SONAME `libgcrypt.so.20` and version node `GCRYPT_1.6`.
- Preserve the consume-existing-artifacts contract: use the committed original source snapshot, ABI templates, imported tests, and helper scripts in place rather than rediscovering or reimporting them.

# Verification Phases

- Phase ID: `check_p01_bootstrap_workspace`
- Type: `check`
- `bounce_target`: `impl_p01_bootstrap_workspace`
- Purpose: verify deterministic offline build, pinned Rust toolchain, ABI staging, committed helper status, and no stale unused bootstrap files.
- Commands:
  - `test "$(git rev-parse HEAD)" = "$(git rev-parse phase/impl_p01_bootstrap_workspace)"`
  - `bash -c 'test -z "$(git status --short)"'`
  - `safe/scripts/check-rust-toolchain.sh`
  - `cargo build --manifest-path safe/Cargo.toml --release --locked --offline`
  - `safe/scripts/check-abi.sh --check-soname --check-symbol-versions`
  - `safe/scripts/run-original-tests.sh --verify-plumbing version t-secmem`

# Success Criteria

- Root and `safe/` Cargo commands are deterministic, offline, and compatible with the pinned Rust `1.85.1` toolchain.
- `safe/scripts/check-rust-toolchain.sh` rejects Ubuntu 24.04 packaged Rust 1.75 and any unpinned or mismatched Rust/Cargo pair.
- ABI staging still exports SONAME `libgcrypt.so.20` and version node `GCRYPT_1.6`.
- Baseline original-test plumbing works for `version` and `t-secmem`.
- Only committed helpers are relied on by later phases.

# Git Commit Requirement

The implementer must commit work to git before yielding. End with one commit whose subject begins `impl_p01_bootstrap_workspace:` and force-update local tag `phase/impl_p01_bootstrap_workspace` to that commit before yielding.
