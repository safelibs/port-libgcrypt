# 02 Runtime Shell

- Phase Name: Runtime shell: version, control, config, allocation, and secure memory
- Implement Phase ID: `impl_p02_runtime_shell`

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
- `original/libgcrypt20-1.10.3/src/global.c`
- `original/libgcrypt20-1.10.3/src/misc.c`
- `original/libgcrypt20-1.10.3/src/secmem.c`
- `original/libgcrypt20-1.10.3/src/stdmem.c`
- `original/libgcrypt20-1.10.3/src/context.c`
- `original/libgcrypt20-1.10.3/src/fips.c`
- `original/libgcrypt20-1.10.3/src/hwfeatures.c`
- `original/libgcrypt20-1.10.3/tests/version.c`
- `original/libgcrypt20-1.10.3/tests/t-secmem.c`
- `original/libgcrypt20-1.10.3/compat/`
- `relevant_cves.json`

## New Outputs
- Working Rust runtime shell
- Updated `safe/docs/abi-map.md`

## File Changes
- `safe/src/lib.rs`
- `safe/src/global.rs`
- `safe/src/alloc.rs`
- `safe/src/secmem.rs`
- `safe/src/log.rs`
- `safe/src/config.rs`
- `safe/src/context.rs`
- `safe/src/error.rs`
- `safe/src/os_rng.rs`
- `safe/cabi/exports.c`
- `safe/scripts/check-abi.sh`
- `safe/docs/abi-map.md`

## Implementation Details
- Implement `gcry_check_version` with upstream-compatible version-string negotiation so `GCRYPT_VERSION` in the header matches the library result.
- Keep the ABI-visible library version at upstream `1.10.3` / `GCRYPT_1.6`; Debian revision metadata can vary later.
- Implement the libgpg-error wrapper surface:
  - `gcry_strerror`
  - `gcry_strsource`
  - `gcry_err_code_from_errno`
  - `gcry_err_code_to_errno`
  - `gcry_err_make_from_errno`
  - `gcry_error_from_errno`
- Implement the allocation surface:
  - `gcry_malloc`, `gcry_calloc`, `gcry_realloc`, `gcry_strdup`, `gcry_free`
  - Secure allocation variants
  - The xmalloc/xcalloc/xstrdup family
  - `gcry_is_secure`
  - `gcry_set_allocation_handler`
  - `gcry_set_outofcore_handler`
- Port secure-memory behavior with a Rust allocator backed by locked pages where possible, confining unsafe code to OS boundaries such as `mlock`, `mmap`, zeroization, and raw pointer handoff.
- Implement log, progress, fatal, and gettext handler registration and dispatch.
- Implement `gcry_control` command handling for the non-crypto control plane from `original/libgcrypt20-1.10.3/src/gcrypt.h.in:255-337` and `src/global.c`, including verbosity and debug flags, secure-memory controls, initialization queries, config printing, FIPS queries and requests, hardware-feature disable requests, RNG type getters and setters, the private regression controls that do not require full crypto yet, and `GCRYCTL_SET_THREAD_CBS` as an upstream-compatible dummy compatibility hook that ignores callback contents, resets the preferred RNG type to default, and forces global initialization without reviving legacy thread-library installation.
- Preserve upstream truthy semantics where `gcry_control(..._P)` returns `GPG_ERR_GENERAL` as success.
- Implement `gcry_get_config` and `GCRYCTL_PRINT_CONFIG` with upstream-compatible key names and formatting, including the `version`, `cpu-arch`, and `rng-type` lines used by `tests/version.c`.
- Implement minimal secure random allocation for `gcry_random_bytes_secure`, sufficient for `t-secmem`, with the full RNG design deferred to phase 4.
- Extend `safe/scripts/check-abi.sh` with a runtime `--thread-cbs-noop` mode that compiles a C probe against the generated header, expands `GCRY_THREAD_OPTION_PTHREAD_IMPL`, calls `gcry_control(GCRYCTL_SET_THREAD_CBS, &gcry_threads_pthread)`, and verifies the compatibility no-op succeeds without dereferencing callback pointers while also resetting the preferred RNG type to the default and forcing global initialization.
- Update `safe/docs/abi-map.md` to mark runtime-shell symbols as implemented and identify any remaining phase-owned stubs.

## Verification Phases
### `check_p02_runtime_shell`
- Type: `check`
- `bounce_target`: `impl_p02_runtime_shell`
- Purpose: verify the non-cryptographic runtime shell that everything else depends on: version negotiation, `gcry_control`, handler registration, config reporting, secure-memory allocation, the obsolete-but-public thread-callback compatibility hook, and the minimal secure random allocation needed by `t-secmem`.
- Commands:

```bash
cargo build --manifest-path safe/Cargo.toml --release --offline
safe/scripts/check-abi.sh --thread-cbs-noop
safe/scripts/run-original-tests.sh version t-secmem
```

## Success Criteria
- `cargo build --manifest-path safe/Cargo.toml --release --offline` succeeds.
- `safe/scripts/check-abi.sh --thread-cbs-noop` proves the public thread-compatibility surface remains available and that `GCRYCTL_SET_THREAD_CBS` behaves as the required compatibility no-op while resetting the preferred RNG type to the default and forcing global initialization.
- `safe/scripts/run-original-tests.sh version t-secmem` passes against the safe build.
- `gcry_get_config("no-such-item")` returns `NULL` with `errno == 0`, matching `tests/version.c`.
- `safe/docs/abi-map.md` reflects the implemented runtime-shell symbols and remaining ownership boundaries.

## Git Commit Requirement
The implementer must commit the phase's work to git before yielding.
