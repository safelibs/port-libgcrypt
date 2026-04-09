# 10 Final Sweep

- Phase Name: Final sweep, long-running tests, performance, and catch-all fixes
- Implement Phase ID: `impl_p10_final_sweep`

## Preexisting Inputs
- `safe/Cargo.toml`
- `safe/Cargo.lock`
- `safe/build.rs`
- `safe/.cargo/config.toml`
- `safe/src/`
- `safe/cabi/`
- `safe/abi/`
- `safe/tests/original-build/`
- `safe/tests/upstream/`
- `safe/tests/compat/`
- `safe/scripts/check-abi.sh`
- `safe/scripts/run-original-tests.sh`
- `safe/scripts/import-upstream-tests.sh`
- `safe/scripts/run-upstream-tests.sh`
- `safe/scripts/relink-original-objects.sh`
- `safe/scripts/run-compat-smoke.sh`
- `safe/scripts/build-debs.sh`
- `safe/scripts/check-deb-metadata.sh`
- `safe/scripts/check-installed-tools.sh`
- `safe/docs/abi-map.md`
- `safe/docs/cve-matrix.md`
- `safe/docs/test-matrix.md`
- `safe/debian/`
- `safe/dist/`
- `dependents.json`
- `test-original.sh`
- `relevant_cves.json`

## New Outputs
- Final corrected safe implementation
- Completed verification and mitigation docs

## File Changes
- `safe/src/`
- `safe/cabi/`
- `safe/tests/upstream/`
- `safe/scripts/`
- `safe/docs/abi-map.md`
- `safe/docs/cve-matrix.md`
- `safe/docs/test-matrix.md`
- `safe/debian/`
- `test-original.sh`

## Implementation Details
- Fix any remaining behavioral mismatches found by:
  - long-running upstream tests (`benchmark`, `bench-slope`, `hashtest-256g`)
  - object relink runs
  - Debian control-metadata checks
  - package install checks
  - installed helper-CLI smoke runs
  - downstream dependent runs
- Add performance-oriented hardware-gated fast paths only after correctness and side-channel requirements are satisfied, without regressing the safe software fallback.
- Review unsafe-code minimization:
  - Keep unsafe Rust confined to FFI, raw allocation and layout interop, and OS syscall edges.
  - Keep non-Rust code confined to ABI wrappers that cannot reasonably be expressed in safe Rust.
- Make `safe/docs/cve-matrix.md` final and exhaustive so each relevant CVE has both a code location and a test or review proof.
- Make `safe/docs/abi-map.md` and `safe/docs/test-matrix.md` final and accurate so maintenance can reason about symbol ownership and verification coverage.
- Resolve any remaining targeted smoke-test gaps so no exported symbol, including `gcry_md_get` and `gcry_pk_register`, or installed compatibility artifact is left without upstream-test, relink, dependent, or explicit compatibility-smoke coverage.
- Preserve the full plan-wide final verification contract rather than a reduced subset:
  - `safe/scripts/import-upstream-tests.sh --verify` and `safe/scripts/run-upstream-tests.sh --verify-plumbing` must remain part of the final verifier and must only compare committed files rather than rewriting imported artifacts.
  - The full imported-suite run must include the long-running `benchmark`, `bench-slope`, and `hashtest-256g` coverage under `safe/scripts/run-upstream-tests.sh --all`.
  - The final package verification must still prove `safe/debian/libgcrypt20.symbols` matches `safe/abi/libgcrypt.vers`, allowing only the Debian `GCRYPT_1.6` sentinel line as an extra non-symbol entry.
  - The installed-tool smoke must still cover `dumpsexp`, `hmac256`, `mpicalc`, `libgcrypt-config`, and `pkg-config` from the extracted or installed package image rather than cargo-built binaries.

## Verification Phases
### `check_p10_final_sweep`
- Type: `check`
- `bounce_target`: `impl_p10_final_sweep`
- Purpose: run the full compatibility matrix end to end, including long-running upstream tests, package install coverage, link-compat verification, downstream dependents, formatting, linting, and any final fixes required to reach drop-in status.
- Commands:

```bash
cargo build --manifest-path safe/Cargo.toml --release --offline
cargo test --manifest-path safe/Cargo.toml --release --offline
cargo fmt --manifest-path safe/Cargo.toml --check
cargo clippy --manifest-path safe/Cargo.toml --offline --all-targets -- -D warnings
safe/scripts/check-abi.sh --compare-original --check-symbol-versions --check-soname
safe/scripts/import-upstream-tests.sh --verify
safe/scripts/run-upstream-tests.sh --verify-plumbing
safe/scripts/run-upstream-tests.sh --all
safe/scripts/relink-original-objects.sh --all
safe/scripts/run-compat-smoke.sh --all
bash -lc 'cargo_home=$(mktemp -d); trap "rm -rf \"$cargo_home\"" EXIT; CARGO_HOME="$cargo_home" CARGO_NET_OFFLINE=true safe/scripts/build-debs.sh'
safe/scripts/check-deb-metadata.sh --dist safe/dist
bash -lc 'listing=$(dpkg-deb -c safe/dist/libgcrypt20-dev_*.deb); for pattern in "/usr/bin/dumpsexp$" "/usr/bin/hmac256$" "/usr/bin/mpicalc$" "/usr/bin/libgcrypt-config$" "/usr/include/gcrypt.h$" "/usr/lib/.*/libgcrypt\\.so$" "/usr/lib/.*/libgcrypt\\.a$" "/usr/lib/.*/pkgconfig/libgcrypt\\.pc$" "/usr/share/aclocal/libgcrypt\\.m4$" "/usr/share/man/man8/dumpsexp\\.8(\\.gz)?$" "/usr/share/man/man1/libgcrypt-config\\.1(\\.gz)?$" "/usr/share/man/man1/hmac256\\.1(\\.gz)?$"; do grep -Eq "$pattern" <<<"$listing" || exit 1; done'
bash -lc 'listing=$(dpkg-deb -c safe/dist/libgcrypt20_*.deb); for pattern in "/usr/lib/.*/libgcrypt\\.so\\.20$" "/usr/lib/.*/libgcrypt\\.so\\.20\\.[^/]+$" "/usr/share/libgcrypt20/clean-up-unmanaged-libraries$" "/usr/share/doc/libgcrypt20/AUTHORS(\\.gz)?$" "/usr/share/doc/libgcrypt20/NEWS(\\.gz)?$" "/usr/share/doc/libgcrypt20/README(\\.gz)?$" "/usr/share/doc/libgcrypt20/THANKS(\\.gz)?$"; do grep -Eq "$pattern" <<<"$listing" || exit 1; done'
bash -lc 'tmpdir=$(mktemp -d); dpkg-deb -e safe/dist/libgcrypt20_*.deb "$tmpdir"; test -x "$tmpdir/postinst"; rm -rf "$tmpdir"'
safe/scripts/check-installed-tools.sh --dist safe/dist
./test-original.sh --implementation safe
```

## Success Criteria
- The full offline Cargo build, test, formatting, and clippy checks succeed.
- The ABI comparison, original-object relink harness, and targeted compatibility smoke harness all pass across the full matrix, including the thread-callback compatibility path, all five public variadic exports, and the ABI-only `gcry_md_get` and `gcry_pk_register` probes.
- `safe/scripts/import-upstream-tests.sh --verify`, `safe/scripts/run-upstream-tests.sh --verify-plumbing`, and `safe/scripts/run-upstream-tests.sh --all` all pass, and the imported-suite run includes the long-running `benchmark`, `bench-slope`, and `hashtest-256g` coverage while proving it used the committed imported `config.h`, rendered wrapper scripts, and `compat/` support tree rather than files from `original/`.
- The Debian package build, metadata checks, installed-helper checks, and downstream dependent harness all pass with `CARGO_NET_OFFLINE=true` and a fresh empty `CARGO_HOME`.
- The package metadata verifier confirms `safe/debian/libgcrypt20.symbols` reconciles to the 217 real exports from `safe/abi/libgcrypt.vers`, allowing only Debian's `GCRYPT_1.6` sentinel line as an extra non-symbol entry.
- The installed-tool smoke verifier passes against the built `.deb` image and covers `dumpsexp`, `hmac256`, `mpicalc`, `libgcrypt-config`, and `pkg-config` from the extracted or installed package image rather than cargo-built binaries.
- `safe/docs/abi-map.md`, `safe/docs/cve-matrix.md`, and `safe/docs/test-matrix.md` are final, exhaustive, and consistent with the code and verification results.
- No exported symbol or installed compatibility artifact is left without explicit verification ownership.

## Git Commit Requirement
The implementer must commit the phase's work to git before yielding.
