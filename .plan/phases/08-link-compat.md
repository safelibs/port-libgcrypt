# 08 Link Compat

- Phase Name: Link compatibility and ABI audit harness
- Implement Phase ID: `impl_p08_link_compat`

## Preexisting Inputs
- `safe/Cargo.toml`
- `safe/Cargo.lock`
- `safe/build.rs`
- `safe/.cargo/config.toml`
- `safe/src/`
- `safe/cabi/`
- `safe/abi/`
- `safe/docs/abi-map.md`
- `safe/docs/cve-matrix.md`
- `safe/docs/test-matrix.md`
- `safe/tests/original-build/`
- `safe/tests/upstream/`
- `safe/tests/compat/`
- `safe/scripts/check-abi.sh`
- `safe/scripts/run-original-tests.sh`
- `safe/scripts/import-upstream-tests.sh`
- `safe/scripts/run-upstream-tests.sh`
- `original/libgcrypt20-1.10.3/src/gcrypt.h.in`
- `original/libgcrypt20-1.10.3/src/libgcrypt.vers`
- `original/libgcrypt20-1.10.3/src/visibility.h`
- `original/libgcrypt20-1.10.3/src/gcrypt-testapi.h`
- `original/libgcrypt20-1.10.3/debian/libgcrypt20.symbols`
- `original/libgcrypt20-1.10.3/tests/Makefile.am`
- `original/libgcrypt20-1.10.3/tests/testdrv.c`
- `original/libgcrypt20-1.10.3/tests/`
- `original/libgcrypt20-1.10.3/compat/`

## New Outputs
- Original-object relink harness
- Strong ABI comparison tooling
- Compatibility smoke harness for uncovered public APIs and installed development metadata
- ABI-only export smoke harness for header-hidden symbols

## File Changes
- `safe/scripts/relink-original-objects.sh`
- `safe/scripts/run-compat-smoke.sh`
- `safe/scripts/check-abi.sh`
- `safe/tests/compat/public-api-smoke.c`
- `safe/tests/compat/abi-only-exports.c`
- `safe/docs/test-matrix.md`

## Implementation Details
- Extend `safe/scripts/check-abi.sh` to compare safe versus original on exported symbol names, symbol versions, SONAME, `libgcrypt.pc` fields, Debian-patched `libgcrypt-config` output, installed `libgcrypt.m4`, and header smoke compilation.
- Add `safe/scripts/relink-original-objects.sh` to build original upstream tests to object files using original headers and build settings, relink those objects against the safe shared library and `libgpg-error`, and execute the relinked binaries under `LD_LIBRARY_PATH` pointing at the safe build.
- Ensure the relink harness covers every compiled regression entry from `tests/Makefile.am` that yields a binary in `tests_bin` or `tests_bin_last`, plus `testapi`. Keep the shell-backed entries covered by `safe/scripts/run-upstream-tests.sh`.
- Add `safe/scripts/run-compat-smoke.sh` plus targeted `safe/tests/compat/` probes to compile against the generated and installed safe development surface and exercise compatibility not already covered by imported upstream tests, object relink checks, or downstream dependents.
- Include targeted smoke coverage for:
  - The public thread-compatibility surface from `gcrypt.h`, including expansion of `GCRY_THREAD_OPTION_PTHREAD_IMPL` and a `gcry_control(GCRYCTL_SET_THREAD_CBS, &gcry_threads_pthread)` compatibility call.
  - Header macros with ABI-visible layout expectations such as `gcry_md_putc`, `gcry_fast_random_poll`, and `gcry_fips_mode_active`.
  - All exported public variadic entries compiled and called from C: `gcry_control`, `gcry_sexp_build`, `gcry_sexp_vlist`, `gcry_sexp_extract_param`, and `gcry_log_debug`.
  - ABI-only or header-hidden exports handled separately from normal header smoke:
    - `gcry_md_get` via a dedicated C probe that includes `gcrypt.h` for public types and adds the local declaration carried in `src/visibility.h`.
    - `gcry_pk_register` via symbol-version presence checks and a `dlsym`-based runtime probe without reintroducing it into the installed public header.
  - Installed-tool behavior for `pkg-config`, `libgcrypt-config`, and `libgcrypt.m4`.
- Keep this phase focused on public-library and development-surface compatibility. The package-installed helper CLIs and package-only manifest checks remain phase-9 responsibilities.
- Update `safe/docs/test-matrix.md` to record link-compat coverage and the public APIs or non-symbol header and control surfaces covered only by the targeted smoke harness, with dedicated rows for the thread-callback path, `gcry_md_get`, and `gcry_pk_register`.

## Verification Phases
### `check_p08_link_compat`
- Type: `check`
- `bounce_target`: `impl_p08_link_compat`
- Purpose: verify the actual link-compatibility promise using object files compiled against the original headers, while ensuring symbol names, symbol versions, and SONAME remain identical.
- Commands:

```bash
cargo build --manifest-path safe/Cargo.toml --release --offline
safe/scripts/check-abi.sh --compare-original --check-symbol-versions --check-soname
safe/scripts/relink-original-objects.sh --all
safe/scripts/run-compat-smoke.sh --all
```

## Success Criteria
- `cargo build --manifest-path safe/Cargo.toml --release --offline` succeeds.
- `safe/scripts/check-abi.sh --compare-original --check-symbol-versions --check-soname` verifies export names, version nodes, SONAME, and installed development metadata against original inputs.
- `safe/scripts/relink-original-objects.sh --all` succeeds for the full compiled upstream regression set.
- `safe/scripts/run-compat-smoke.sh --all` covers the public thread-compatibility surface, header-visible macros, all five variadic entry points, `gcry_md_get`, `gcry_pk_register`, and installed development metadata.
- `safe/docs/test-matrix.md` clearly identifies which coverage comes from imported tests, relink runs, or targeted compatibility smoke.

## Git Commit Requirement
The implementer must commit the phase's work to git before yielding.
