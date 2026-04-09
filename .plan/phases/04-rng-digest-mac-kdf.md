# 04 RNG Digest MAC KDF

- Phase Name: Full RNG, digests, MACs, and KDFs
- Implement Phase ID: `impl_p04_rng_digest_mac_kdf`

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
- `original/libgcrypt20-1.10.3/random/`
- `original/libgcrypt20-1.10.3/cipher/md.c`
- `original/libgcrypt20-1.10.3/cipher/mac.c`
- `original/libgcrypt20-1.10.3/cipher/kdf.c`
- `original/libgcrypt20-1.10.3/tests/random.c`
- `original/libgcrypt20-1.10.3/tests/hashtest.c`
- `original/libgcrypt20-1.10.3/tests/hmac.c`
- `original/libgcrypt20-1.10.3/tests/t-kdf.c`
- `original/libgcrypt20-1.10.3/src/gcrypt-testapi.h`
- `original/libgcrypt20-1.10.3/compat/`
- `relevant_cves.json`

## New Outputs
- Full RNG implementation
- Digest, MAC, and KDF implementations
- Updated `safe/docs/abi-map.md`
- Initial `safe/docs/cve-matrix.md`

## File Changes
- `safe/src/random.rs`
- `safe/src/drbg.rs`
- `safe/src/digest/mod.rs`
- `safe/src/digest/algorithms.rs`
- `safe/src/mac.rs`
- `safe/src/kdf.rs`
- `safe/src/os_rng.rs`
- `safe/cabi/exports.c`
- `safe/docs/abi-map.md`
- `safe/docs/cve-matrix.md`

## Implementation Details
- Implement the upstream random API semantics for `gcry_randomize`, `gcry_random_bytes`, `gcry_random_bytes_secure`, `gcry_random_add_bytes`, `gcry_create_nonce`, `gcry_mpi_randomize`, preferred-RNG controls, `GCRYCTL_FAST_POLL`, `GCRYCTL_GET_CURRENT_RNG_TYPE`, and the private regression controls used by `gcrypt-testapi.h`.
- Design the RNG around a modern DRBG backed by OS entropy and explicit reseed and fork handling instead of reproducing the old mixing design; this is the phase-4 mitigation for `CVE-2016-6313`.
- Match the fork behavior tested by `tests/random.c`, ensuring `gcry_randomize` and `gcry_create_nonce` do not repeat parent output after fork.
- Implement the complete digest and MAC registry surface and the `*_algo_info` control paths behind header macros such as `gcry_md_test_algo`, `gcry_md_get_asnoid`, and `gcry_mac_test_algo`.
- Preserve the public `gcry_md_handle` layout and `gcry_md_putc` buffering semantics exactly.
- Implement the hidden-but-exported digest compatibility symbol `gcry_md_get` with upstream-compatible buffer, error, and FIPS-state semantics, document it in `safe/docs/abi-map.md` as phase-4-owned, and leave its concrete ABI-only smoke coverage to phase 8 because installed `gcrypt.h` does not declare it.
- Implement KDFs and threaded KDF dispatch for `gcry_kdf_open`, `gcry_kdf_compute`, `gcry_kdf_final`, and `gcry_kdf_close`, covering S2K, PBKDF1, PBKDF2, scrypt, Argon2, and Balloon as defined by the public enums.
- Keep digest, MAC, and KDF algorithm names and `map_name` strings exactly aligned with upstream because tests and downstream software depend on them.
- Record RNG and timing-side-channel mitigations in `safe/docs/cve-matrix.md`.
- If any public KDF enum or subalgorithm remains unexercised after this phase, record that gap in `safe/docs/abi-map.md` so phase 8 can add targeted compatibility smoke coverage.

## Verification Phases
### `check_p04_rng_digest_mac_kdf`
- Type: `check`
- `bounce_target`: `impl_p04_rng_digest_mac_kdf`
- Purpose: verify the random subsystem, digest layer, MAC layer, and KDF layer, including private regression hooks and algorithm-info control paths.
- Commands:

```bash
cargo build --manifest-path safe/Cargo.toml --release --offline
safe/scripts/run-original-tests.sh random hashtest hmac t-kdf
```

## Success Criteria
- `cargo build --manifest-path safe/Cargo.toml --release --offline` succeeds.
- `safe/scripts/run-original-tests.sh random hashtest hmac t-kdf` passes.
- `safe/docs/cve-matrix.md` explicitly covers `CVE-2016-6313` and the digest, MAC, and KDF timing obligations.
- `safe/docs/abi-map.md` marks `gcry_md_get` as implemented while still reserving its ABI-only smoke verification for phase 8.

## Git Commit Requirement
The implementer must commit the phase's work to git before yielding.
