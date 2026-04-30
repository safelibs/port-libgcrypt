# Phase Name

S-expressions, MPI core, and prime operations

# Implement Phase ID

`impl_p03_sexp_mpi_core`

# Preexisting Inputs

- Phase 2 committed tree and tag.
- `safe/Cargo.toml`
- `safe/Cargo.lock`
- `safe/.cargo/config.toml`
- `.cargo/config.toml` if committed by phase 1.
- `safe/vendor/**`
- `safe/src/sexp.rs`
- `safe/src/mpi/mod.rs`
- `safe/src/mpi/arith.rs`
- `safe/src/mpi/scan.rs`
- `safe/src/mpi/opaque.rs`
- `safe/src/mpi/prime.rs`
- `safe/src/mpi/consts.rs`
- `safe/src/lib.rs`
- `safe/cabi/exports.c`
- `safe/cabi/exports.h`
- `safe/scripts/run-original-tests.sh`
- `safe/tests/original-build/*`
- `safe/tests/compat/public-api-smoke.c`
- `safe/docs/abi-map.md`
- `original/libgcrypt20-1.10.3/src/sexp.c`
- `original/libgcrypt20-1.10.3/mpi/`
- `original/libgcrypt20-1.10.3/tests/mpitests.c`
- `original/libgcrypt20-1.10.3/tests/t-sexp.c`
- `original/libgcrypt20-1.10.3/tests/t-convert.c`
- `original/libgcrypt20-1.10.3/tests/t-mpi-bit.c`
- `original/libgcrypt20-1.10.3/tests/prime.c`

# New Outputs

- Rust-owned `gcry_sexp_*`, `gcry_mpi_*`, `gcry_prime_*`, and `_gcry_mpi_get_const` behavior.
- Regression fixtures for canonical length, opaque atoms, varargs builders, negative MPI formatting, and secure MPI allocation edge cases.

# File Changes

- `safe/src/sexp.rs`
- `safe/src/mpi/mod.rs`
- `safe/src/mpi/arith.rs`
- `safe/src/mpi/scan.rs`
- `safe/src/mpi/opaque.rs`
- `safe/src/mpi/prime.rs`
- `safe/src/mpi/consts.rs`
- `safe/cabi/exports.c`
- `safe/cabi/exports.h`
- `safe/tests/compat/public-api-smoke.c`
- `safe/docs/abi-map.md`

# Implementation Details

- Keep `gcry_sexp_build`, `gcry_sexp_vlist`, and `gcry_sexp_extract_param` as C varargs entries that call Rust dispatch functions with explicit `uintptr_t` argument arrays.
- Preserve upstream canonical, advanced, and default S-expression syntax including display hints, binary atoms, zero-length atoms, error offsets, and list traversal semantics.
- Preserve MPI formats `GCRYMPI_FMT_STD`, `PGP`, `SSH`, `HEX`, `USG`, and opaque MPI behavior.
- Implement arithmetic with explicit normalization so comparisons, bit counts, high-bit setting, negative values, and zero behave like upstream.
- Implement prime generation/check/group-generator behavior needed by upstream `prime` while documenting probabilistic edge cases.
- Preserve the consume-existing-artifacts contract by updating existing S-expression, MPI, compatibility, and original-test inputs in place.

# Verification Phases

- Phase ID: `check_p03_sexp_mpi_core`
- Type: `check`
- `bounce_target`: `impl_p03_sexp_mpi_core`
- Purpose: verify local S-expression parser/builder/traversal, MPI import/export/arithmetic/flags, opaque MPI handling, constants, and prime APIs.
- Commands:
  - `test "$(git rev-parse HEAD)" = "$(git rev-parse phase/impl_p03_sexp_mpi_core)"`
  - `test "$(git rev-parse HEAD^)" = "$(git rev-parse phase/impl_p02_runtime_shell)"`
  - `bash -c 'test -z "$(git status --short)"'`
  - `safe/scripts/check-rust-toolchain.sh`
  - `cargo build --manifest-path safe/Cargo.toml --release --locked --offline`
  - `safe/scripts/run-original-tests.sh mpitests t-sexp t-convert t-mpi-bit prime`

# Success Criteria

- S-expression, MPI, opaque MPI, MPI constants, and prime APIs are locally implemented and match the listed original tests.
- C varargs entrypoints retain C ABI behavior through `safe/cabi/exports.c`.
- The phase is a single child commit of `phase/impl_p02_runtime_shell` and leaves a clean worktree before tests.

# Git Commit Requirement

The implementer must commit work to git before yielding. End with one commit whose subject begins `impl_p03_sexp_mpi_core:` and whose first parent is `phase/impl_p02_runtime_shell`; force-update local tag `phase/impl_p03_sexp_mpi_core` to that commit before yielding.
