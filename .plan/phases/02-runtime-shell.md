# Phase Name

Runtime shell, control, allocation, and secure memory

# Implement Phase ID

`impl_p02_runtime_shell`

# Preexisting Inputs

- Phase 1 committed tree and tag.
- `safe/Cargo.toml`
- `safe/Cargo.lock`
- `safe/.cargo/config.toml`
- `.cargo/config.toml` if committed by phase 1.
- `safe/vendor/**`
- `safe/src/global.rs`
- `safe/src/alloc.rs`
- `safe/src/secmem.rs`
- `safe/src/log.rs`
- `safe/src/config.rs`
- `safe/src/context.rs`
- `safe/src/error.rs`
- `safe/src/hwfeatures.rs`
- `safe/src/lib.rs`
- `safe/cabi/exports.c`
- `safe/cabi/exports.h`
- `safe/abi/*`
- `safe/scripts/check-abi.sh`
- `safe/scripts/run-original-tests.sh`
- `safe/tests/original-build/*`
- `safe/docs/abi-map.md`
- `original/libgcrypt20-1.10.3/src/global.c`
- `original/libgcrypt20-1.10.3/src/misc.c`
- `original/libgcrypt20-1.10.3/src/stdmem.c`
- `original/libgcrypt20-1.10.3/src/secmem.c`
- `original/libgcrypt20-1.10.3/src/context.c`
- `original/libgcrypt20-1.10.3/src/fips.c`
- `original/libgcrypt20-1.10.3/tests/version.c`
- `original/libgcrypt20-1.10.3/tests/t-secmem.c`

# New Outputs

- Rust-owned runtime shell with no dependency on upstream libgcrypt for non-crypto global behavior.
- Updated ABI map for runtime-shell symbols.
- Expanded `check-abi.sh` runtime shell probes where behavior was previously untested.

# File Changes

- `safe/src/global.rs`
- `safe/src/alloc.rs`
- `safe/src/secmem.rs`
- `safe/src/log.rs`
- `safe/src/config.rs`
- `safe/src/context.rs`
- `safe/src/error.rs`
- `safe/src/hwfeatures.rs`
- `safe/src/lib.rs`
- `safe/cabi/exports.c`
- `safe/cabi/exports.h`
- `safe/scripts/check-abi.sh`
- `safe/docs/abi-map.md`

# Implementation Details

- Implement or harden `safe_gcry_check_version`, `safe_gcry_control_dispatch`, `safe_gcry_get_config`, libgpg-error wrappers, allocation handlers, out-of-core handlers, gettext/log/fatal/progress handlers, and `gcry_ctx_release`.
- Preserve upstream truthy `_P` control semantics for `GCRYCTL_INITIALIZATION_FINISHED_P`, `GCRYCTL_ANY_INITIALIZATION_P`, `GCRYCTL_OPERATIONAL_P`, and `GCRYCTL_FIPS_MODE_P`.
- Keep the C varargs ABI in `safe/cabi/exports.c`; pass normalized arguments to Rust dispatch functions.
- Keep unsafe code limited to C ABI pointers, `errno`, allocation calls, memory locking, and OS calls.
- Ensure secure-memory bookkeeping preserves `gcry_is_secure`, xalloc overflow handling, and expected pool accounting from `t-secmem`.
- Preserve the consume-existing-artifacts contract by updating the existing runtime modules, ABI files, scripts, tests, and documentation in place.

# Verification Phases

- Phase ID: `check_p02_runtime_shell`
- Type: `check`
- `bounce_target`: `impl_p02_runtime_shell`
- Purpose: verify version negotiation, control commands, config reporting, allocation handlers, secure memory, logging, thread-callback compatibility, and error wrappers.
- Commands:
  - `test "$(git rev-parse HEAD)" = "$(git rev-parse phase/impl_p02_runtime_shell)"`
  - `test "$(git rev-parse HEAD^)" = "$(git rev-parse phase/impl_p01_bootstrap_workspace)"`
  - `bash -c 'test -z "$(git status --short)"'`
  - `safe/scripts/check-rust-toolchain.sh`
  - `cargo build --manifest-path safe/Cargo.toml --release --locked --offline`
  - `safe/scripts/check-abi.sh --thread-cbs-noop`
  - `safe/scripts/run-original-tests.sh version t-secmem`

# Success Criteria

- Runtime shell, allocation, secure-memory, logging, config, context, error, and thread-callback behavior are Rust-owned and verified.
- `version` and `t-secmem` pass without relying on upstream libgcrypt.
- The phase is a single child commit of `phase/impl_p01_bootstrap_workspace` and leaves a clean worktree before tests.

# Git Commit Requirement

The implementer must commit work to git before yielding. End with one commit whose subject begins `impl_p02_runtime_shell:` and whose first parent is `phase/impl_p01_bootstrap_workspace`; force-update local tag `phase/impl_p02_runtime_shell` to that commit before yielding.
