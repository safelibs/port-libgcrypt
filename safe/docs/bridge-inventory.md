# Bridge Inventory

Phase 6 removes the runtime upstream bridge. The shipped runtime, helper scripts, compat probes, and downstream harnesses no longer rely on `SAFE_SYSTEM_LIBGCRYPT_PATH`, `dlopen`, `dlsym`, or hard-coded system `libgcrypt.so.20` paths.

## Current Status

- Rust now owns the full exported public-key surface, including ECC sign/verify/encrypt/decrypt/testkey/genkey, ECC keygrip, ECC `gcry_pk_get_nbits`, and `gcry_pubkey_get_sexp` for local contexts in [`safe/src/pubkey/ecc.rs`](../src/pubkey/ecc.rs), [`safe/src/pubkey/mod.rs`](../src/pubkey/mod.rs), and [`safe/src/pubkey/keygrip.rs`](../src/pubkey/keygrip.rs).
- The low-level ECC metadata, point, and EC-context APIs remain local in [`safe/src/mpi/ec.rs`](../src/mpi/ec.rs). Secret-sensitive scalar handling still uses the local Rust ownership boundary but keeps its hardening inside the local ECC implementation rather than through a runtime-loaded foreign library.
- [`safe/src/pubkey/encoding.rs`](../src/pubkey/encoding.rs) is now a local helper for extracting data from local S-expressions and MPIs. It no longer marshals values into an upstream library.
- [`safe/build.rs`](../build.rs), [`safe/debian/rules`](../debian/rules), [`safe/scripts/build-release-lib.sh`](../scripts/build-release-lib.sh), and [`safe/scripts/run-compat-smoke.sh`](../scripts/run-compat-smoke.sh) no longer link `-ldl`.
- [`safe/scripts/check-installed-tools.sh`](../scripts/check-installed-tools.sh) and [`test-original.sh`](../../test-original.sh) now run directly against the built safe library without provisioning or exporting a side `libgcrypt.so.20`.

## Enforcement

- [`safe/scripts/check-no-upstream-bridge.sh`](../scripts/check-no-upstream-bridge.sh) fails if bridge-era env vars, runtime lookup calls, hard-coded upstream soname paths, or bridge-era `-ldl` flags reappear under shipped code or harness paths.
- [`safe/tests/compat/abi-only-exports.c`](../tests/compat/abi-only-exports.c) now links directly against the staged safe library and calls the ABI-only `gcry_pk_register` shim instead of resolving it with `dlsym`.
- [`safe/scripts/run-compat-smoke.sh`](../scripts/run-compat-smoke.sh), [`safe/scripts/run-upstream-tests.sh`](../scripts/run-upstream-tests.sh), and [`safe/scripts/relink-original-objects.sh`](../scripts/relink-original-objects.sh) all exercise the built safe library directly.

## Historical Notes

- The removed bridge used [`safe/src/upstream.rs`](../src/upstream.rs) plus bridge-era helpers in [`safe/src/pubkey/ecc.rs`](../src/pubkey/ecc.rs) and [`safe/src/pubkey/encoding.rs`](../src/pubkey/encoding.rs) to load selected functionality from the system `libgcrypt.so.20` at runtime.
- The removed helper flow propagated `SAFE_SYSTEM_LIBGCRYPT_PATH` from build and harness scripts so the bridge could prefer a side-loaded upstream library.
- Historical bridge behavior stays documented here only. It no longer exists in `safe/src/**`, `safe/scripts/**`, `safe/tests/compat/**`, [`safe/build.rs`](../build.rs), [`safe/debian`](../debian), or [`test-original.sh`](../../test-original.sh).
