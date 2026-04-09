# 03 Sexp MPI Core

- Phase Name: S-expressions, MPI core, and prime operations
- Implement Phase ID: `impl_p03_sexp_mpi_core`

## Preexisting Inputs
- `safe/Cargo.toml`
- `safe/Cargo.lock`
- `safe/build.rs`
- `safe/.cargo/config.toml`
- `safe/src/`
- `safe/cabi/`
- `safe/abi/`
- `safe/docs/abi-map.md`
- `safe/tests/original-build/`
- `safe/scripts/check-abi.sh`
- `safe/scripts/run-original-tests.sh`
- `original/libgcrypt20-1.10.3/src/sexp.c`
- `original/libgcrypt20-1.10.3/mpi/`
- `original/libgcrypt20-1.10.3/tests/mpitests.c`
- `original/libgcrypt20-1.10.3/tests/t-sexp.c`
- `original/libgcrypt20-1.10.3/tests/t-convert.c`
- `original/libgcrypt20-1.10.3/tests/t-mpi-bit.c`
- `original/libgcrypt20-1.10.3/tests/prime.c`
- `original/libgcrypt20-1.10.3/compat/`
- `relevant_cves.json`

## New Outputs
- Working Rust S-expression parser and serializer
- Working Rust MPI layer
- Prime generation and checking support
- Updated `safe/docs/abi-map.md`

## File Changes
- `safe/src/sexp.rs`
- `safe/src/mpi/mod.rs`
- `safe/src/mpi/arith.rs`
- `safe/src/mpi/scan.rs`
- `safe/src/mpi/opaque.rs`
- `safe/src/mpi/prime.rs`
- `safe/src/mpi/consts.rs`
- `safe/src/context.rs`
- `safe/docs/abi-map.md`

## Implementation Details
- Implement the full `gcry_sexp_*` API surface, including canonical and raw parsing, builders from format strings and arrays, structured traversal (`car`, `cdr`, `cadr`, `nth_*`, `find_token`, `extract_param`), canonical-length calculation, and sprint and dump support.
- Replace the phase-1 stubs behind `gcry_sexp_build`, `gcry_sexp_vlist`, and `gcry_sexp_extract_param` with working Rust-backed logic while retaining the explicit C varargs entry shims.
- Keep ownership-transfer behavior exact for `gcry_sexp_create`, `gcry_sexp_release`, and `gcry_sexp_nth_buffer`.
- Implement MPI allocation and ownership APIs:
  - `gcry_mpi_new`, `gcry_mpi_snew`, `gcry_mpi_copy`, `gcry_mpi_snatch`, `gcry_mpi_release`
  - Flag handling and opaque-object support
  - Import, export, and print helpers
- Implement core arithmetic and bit operations with secret-aware constant-time paths where required.
- Implement `_gcry_mpi_get_const` and the `GCRYMPI_CONST_*` header macros.
- Match upstream opaque-MPI bit-length behavior for `gcry_mpi_set_opaque` and `gcry_mpi_get_opaque`.
- Implement prime generation, prime checking, and group-generator APIs on top of the MPI layer.
- Keep MPI internals reusable for phase 6 public-key work.
- Apply CVE-driven design constraints early: modular exponentiation must support later constant-time use, and secret MPIs must carry metadata that routes them into constant-time or blinded paths in later phases.

## Verification Phases
### `check_p03_sexp_mpi_core`
- Type: `check`
- `bounce_target`: `impl_p03_sexp_mpi_core`
- Purpose: verify that the direct libgcrypt data-model APIs now work: S-expression parsing and serialization, MPI arithmetic, opaque MPIs, and prime operations.
- Commands:

```bash
cargo build --manifest-path safe/Cargo.toml --release --offline
safe/scripts/run-original-tests.sh mpitests t-sexp t-convert t-mpi-bit prime
```

## Success Criteria
- `cargo build --manifest-path safe/Cargo.toml --release --offline` succeeds.
- `safe/scripts/run-original-tests.sh mpitests t-sexp t-convert t-mpi-bit prime` passes against the safe build.
- Ownership and opaque-MPI semantics match upstream behavior closely enough for the imported regression coverage.
- `safe/docs/abi-map.md` marks all `gcry_sexp_*`, `gcry_mpi_*`, `gcry_prime_*`, and `_gcry_mpi_get_const` exports as implemented.

## Git Commit Requirement
The implementer must commit the phase's work to git before yielding.
