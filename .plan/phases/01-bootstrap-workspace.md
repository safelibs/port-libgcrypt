# 01 Bootstrap Workspace

- Phase Name: Bootstrap safe workspace and ABI contract mirror
- Implement Phase ID: `impl_p01_bootstrap_workspace`

## Preexisting Inputs
- `original/libgcrypt20-1.10.3/configure.ac`
- `original/libgcrypt20-1.10.3/config.h.in`
- `original/libgcrypt20-1.10.3/src/Makefile.am`
- `original/libgcrypt20-1.10.3/src/gcrypt.h.in`
- `original/libgcrypt20-1.10.3/src/gcrypt-testapi.h`
- `original/libgcrypt20-1.10.3/src/visibility.h`
- `original/libgcrypt20-1.10.3/src/g10lib.h`
- `original/libgcrypt20-1.10.3/src/libgcrypt.vers`
- `original/libgcrypt20-1.10.3/src/libgcrypt.def`
- `original/libgcrypt20-1.10.3/src/libgcrypt.m4`
- `original/libgcrypt20-1.10.3/src/libgcrypt.pc.in`
- `original/libgcrypt20-1.10.3/src/libgcrypt-config.in`
- `original/libgcrypt20-1.10.3/debian/libgcrypt20.install`
- `original/libgcrypt20-1.10.3/debian/libgcrypt20-dev.install`
- `original/libgcrypt20-1.10.3/debian/libgcrypt20.dirs`
- `original/libgcrypt20-1.10.3/debian/libgcrypt20.postinst`
- `original/libgcrypt20-1.10.3/debian/clean-up-unmanaged-libraries`
- `original/libgcrypt20-1.10.3/debian/libgcrypt20.symbols`
- `original/libgcrypt20-1.10.3/debian/patches/12_lessdeps_libgcrypt-config.diff`
- `original/libgcrypt20-1.10.3/debian/patches/15_multiarchpath_in_-L.diff`
- `original/libgcrypt20-1.10.3/tests/Makefile.am`
- `original/libgcrypt20-1.10.3/tests/testdrv.c`
- `original/libgcrypt20-1.10.3/tests/basic-disable-all-hwf.in`
- `original/libgcrypt20-1.10.3/tests/hashtest-256g.in`
- `original/libgcrypt20-1.10.3/compat/Makefile.am`
- `original/libgcrypt20-1.10.3/compat/`

## New Outputs
- `safe/` Cargo workspace skeleton
- `safe/Cargo.lock`
- Repo-local Cargo vendor tree or an explicit std-only offline Cargo configuration
- `safe/docs/abi-map.md`
- `safe/abi/` copies of all upstream ABI spec files
- Committed upstream-test build-support artifacts under `safe/tests/original-build/`
- `safe/scripts/check-abi.sh`
- `safe/scripts/run-original-tests.sh`

## File Changes
- `safe/Cargo.toml`
- `safe/Cargo.lock`
- `safe/build.rs`
- `safe/.cargo/config.toml`
- `safe/vendor/`
- `safe/src/lib.rs`
- `safe/src/ffi.rs`
- `safe/cabi/exports.c`
- `safe/cabi/exports.h`
- `safe/abi/gcrypt.h.in`
- `safe/abi/gcrypt-testapi.h`
- `safe/abi/visibility.h`
- `safe/abi/libgcrypt.vers`
- `safe/abi/libgcrypt.def`
- `safe/abi/libgcrypt.m4`
- `safe/abi/libgcrypt.pc.in`
- `safe/abi/libgcrypt-config.in`
- `safe/docs/abi-map.md`
- `safe/tests/original-build/config.h`
- `safe/tests/original-build/test-build-vars.mk`
- `safe/tests/original-build/basic-disable-all-hwf`
- `safe/tests/original-build/hashtest-256g`
- `safe/scripts/check-abi.sh`
- `safe/scripts/run-original-tests.sh`

## Implementation Details
- Create `safe/` from scratch as a Rust package with `crate-type = ["cdylib", "staticlib", "rlib"]`, commit `Cargo.lock`, and structure the workspace so later Debian builds consume locked crate versions without changing the public surface.
- Enforce offline Cargo reproducibility from phase 1 onward:
  - `cargo build --manifest-path safe/Cargo.toml --release --offline` must pass.
  - If third-party crates are used, vendor them into `safe/vendor/` and configure `safe/.cargo/config.toml` to replace crates.io with that committed tree.
  - If the port stays `std`-only, still configure `safe/.cargo/config.toml` and helper scripts so later verifiers fail closed on network access.
- Make the shared library install as `libgcrypt.so.20` with SONAME `libgcrypt.so.20`, plus the `libgcrypt.so` linker symlink and `libgcrypt.a`.
- Vendor the upstream ABI specification files into `safe/abi/`, including `libgcrypt.m4`; do not hand-rewrite enums, macros, control codes, or autoconf metadata from scratch.
- Generate `gcrypt.h` from vendored `gcrypt.h.in` and preserve the public enums, flags, `struct gcry_thread_cbs`, `GCRY_THREAD_OPTION_*` constants, `GCRY_THREAD_OPTION_PTH_IMPL`, `GCRY_THREAD_OPTION_PTHREAD_IMPL`, `gcry_md_handle` layout, `gcry_kdf_thread_ops_t` layout, and macro helpers such as `gcry_cipher_reset`, `gcry_md_putc`, `gcry_md_final`, `gcry_fast_random_poll`, and `gcry_fips_mode_active`.
- Generate `libgcrypt-config` and `libgcrypt.pc` with Debian/Ubuntu-compatible behavior:
  - `libgcrypt-config --libs` emits `-lgcrypt` without `-lgpg-error`.
  - Standard multiarch library directories are not emitted as `-L`.
  - The dev install layout includes `/usr/share/aclocal/libgcrypt.m4`.
- Add a minimal C shim layer in `safe/cabi/` for the five public variadic ABI entry points:
  - `gcry_control`
  - `gcry_sexp_build`
  - `gcry_sexp_vlist`
  - `gcry_sexp_extract_param`
  - `gcry_log_debug`
- Keep the C shim limited to argument marshaling and forwarding into non-variadic Rust helpers.
- Seed `safe/docs/abi-map.md` from `safe/abi/libgcrypt.vers`, `safe/abi/gcrypt.h.in`, and `safe/abi/visibility.h` with one row per exported symbol, ownership classification, planned implementation location, and planned verifier or harness coverage.
- Record in `safe/docs/abi-map.md` that `gcry_md_get` and `gcry_pk_register` are the two Linux version-script exports not declared by installed `gcrypt.h`, with `gcry_md_get` owned by phase 4 and `gcry_pk_register` owned by phase 6.
- Create `safe/scripts/check-abi.sh` to verify SONAME, `GCRYPT_1.6` version-script input, generated header presence, thread-compatibility macro smoke compilation, direct C compilation and linkage for the five variadic entry points, pkg-config output, Debian-patched `libgcrypt-config` behavior, presence of `libgcrypt.m4`, and the exported symbol set against `original/libgcrypt20-1.10.3/src/libgcrypt.vers`.
- Commit the autotools-derived upstream test-build artifacts under `safe/tests/original-build/`:
  - `config.h` derived from `original/libgcrypt20-1.10.3/config.h.in` with the Ubuntu 24.04/Linux macro values actually needed by the selected tests and Linux `compat/` path.
  - Define at minimum the values consumed directly by `compat/compat.c` and the Linux test suite, including `PACKAGE_VERSION`, `BUILD_REVISION`, `BUILD_TIMESTAMP`, `HAVE_CONFIG_H`, `HAVE_W32_SYSTEM`, and `HAVE_W32CE_SYSTEM`, plus any additional feature macros required to compile the selected upstream tests on Ubuntu 24.04.
  - `test-build-vars.mk` recording fixed wrapper values including `EXEEXT=""` and `RUN_LARGE_DATA_TESTS=yes`.
  - Rendered wrappers for `basic-disable-all-hwf` and `hashtest-256g`.
- Create `safe/scripts/run-original-tests.sh` to compile selected source files directly from `original/libgcrypt20-1.10.3/tests/` against the safe build products while consuming the committed phase-1 build-support artifacts, using `-DHAVE_CONFIG_H=1`, `-I safe/tests/original-build`, the Linux `compat/` file set implied by `original/libgcrypt20-1.10.3/compat/Makefile.am`, `GCRYPT_IN_REGRESSION_TEST=1`, and the upstream `--disable-new-dtags` workaround when `LD_LIBRARY_PATH` is set.
- Add a `--verify-plumbing` mode to `safe/scripts/run-original-tests.sh` that proves the committed `config.h`, substitution manifest, rendered wrapper scripts, and selected `compat/` build path exist and are the exact artifacts used by the harness.
- Provide skeleton exports for all 217 real versioned symbols immediately, using non-crashing compatibility stubs with return-type-appropriate placeholder behavior until later phases replace them.

## Verification Phases
### `check_p01_bootstrap_workspace`
- Type: `check`
- `bounce_target`: `impl_p01_bootstrap_workspace`
- Purpose: verify that `safe/` builds a shared-library skeleton with the correct file layout, SONAME and linker inputs, generated header, ABI audit wiring, and committed upstream-test build plumbing before subsystem work starts.
- Commands:

```bash
cargo build --manifest-path safe/Cargo.toml --release --offline
safe/scripts/check-abi.sh --bootstrap
safe/scripts/run-original-tests.sh --verify-plumbing version t-secmem
```

## Success Criteria
- `cargo build --manifest-path safe/Cargo.toml --release --offline` succeeds.
- `safe/scripts/check-abi.sh --bootstrap` confirms SONAME, exported symbol inventory, generated header preservation, Debian-patched development metadata, and the five public variadic entry points.
- `safe/scripts/run-original-tests.sh --verify-plumbing version t-secmem` proves the committed `config.h`, wrapper manifest, rendered wrapper scripts, and `compat/` inputs are the exact artifacts used by the early harness.
- Manual review confirms `safe/tests/original-build/config.h` is committed from `original/libgcrypt20-1.10.3/config.h.in` and explicitly carries the required Linux test-build macros, including `PACKAGE_VERSION`, `BUILD_REVISION`, `BUILD_TIMESTAMP`, `HAVE_CONFIG_H`, `HAVE_W32_SYSTEM`, and `HAVE_W32CE_SYSTEM`.
- Manual review confirms generated `gcrypt.h` preserves `struct gcry_thread_cbs`, the `GCRY_THREAD_OPTION_*` constants, and the `GCRY_THREAD_OPTION_PTH_IMPL` / `GCRY_THREAD_OPTION_PTHREAD_IMPL` macros.
- Manual review confirms `safe/docs/abi-map.md` includes all 217 real versioned symbols from `safe/abi/libgcrypt.vers`, marks `gcry_md_get` as `visibility.h`-only, marks `gcry_pk_register` as ABI-only, and assigns explicit planned coverage ownership to every export.

## Git Commit Requirement
The implementer must commit the phase's work to git before yielding.
