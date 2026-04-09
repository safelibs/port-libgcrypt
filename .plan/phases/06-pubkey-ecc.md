# 06 Pubkey ECC

- Phase Name: Public-key, ECC, keygen, and side-channel hardening
- Implement Phase ID: `impl_p06_pubkey_ecc`

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
- `safe/tests/original-build/`
- `safe/scripts/check-abi.sh`
- `safe/scripts/run-original-tests.sh`
- `original/libgcrypt20-1.10.3/cipher/`
- `original/libgcrypt20-1.10.3/mpi/`
- `original/libgcrypt20-1.10.3/tests/`
- `original/libgcrypt20-1.10.3/src/gcrypt-testapi.h`
- `original/libgcrypt20-1.10.3/compat/`
- `relevant_cves.json`

## New Outputs
- Full asymmetric crypto subsystem
- Updated `safe/docs/abi-map.md`
- Completed `safe/docs/cve-matrix.md`

## File Changes
- `safe/src/pubkey/mod.rs`
- `safe/src/pubkey/rsa.rs`
- `safe/src/pubkey/dsa.rs`
- `safe/src/pubkey/elgamal.rs`
- `safe/src/pubkey/ecc.rs`
- `safe/src/pubkey/encoding.rs`
- `safe/src/pubkey/keygrip.rs`
- `safe/src/mpi/ec.rs`
- `safe/src/context.rs`
- `safe/docs/abi-map.md`
- `safe/docs/cve-matrix.md`

## Implementation Details
- Implement the full `gcry_pk_*`, `gcry_pubkey_get_sexp`, `gcry_ecc_*`, `gcry_mpi_point_*`, and `gcry_mpi_ec_*` surfaces.
- Reuse the phase-3 MPI layer for generic big-integer and S-expression compatibility while using specialized constant-time curve code where that improves security or correctness.
- Implement the deterministic and random-override signing helpers used by tests:
  - `gcry_pk_hash_sign`
  - `gcry_pk_hash_verify`
  - `gcry_pk_random_override_new`
- Implement curve metadata and curve-parameter queries for `curves.c` and `t-mpi-point.c`.
- Preserve keygrip computation exactly because upstream tests and downstream software use it as a compatibility fingerprint.
- Address every relevant asymmetric CVE from `relevant_cves.json`:
  - `CVE-2013-4242`, `CVE-2015-0837`, `CVE-2017-7526`, `CVE-2021-33560`, `CVE-2024-2236`: constant-time private-key exponentiation, uniform error handling, RSA blinding, and ElGamal blinding.
  - `CVE-2014-3591`, `CVE-2014-5270`, `CVE-2018-0495`, `CVE-2019-13627`: scalar blinding, fixed-shape scalar arithmetic, and side-channel-resistant signing.
  - `CVE-2015-7511`, `CVE-2017-0379`, `CVE-2017-9526`: constant-time ladders, protected ephemeral scalars, and secret-aware curve operations.
  - `CVE-2018-6829`, `CVE-2021-40528`: ElGamal encoding and parameter-validation fixes.
- Implement the legacy ABI-only symbol `gcry_pk_register` as a tested compatibility shim owned by phase 6. It must remain linkable, preserve the supported-Linux "not supported / removed" behavior, and stay documented in `safe/docs/abi-map.md` as an ABI-only export whose concrete probe lives in phase 8 rather than the installed public header.
- Make RSA PKCS#1 v1.5 decryption timing-uniform and externally indistinguishable on failure.

## Verification Phases
### `check_p06_pubkey_ecc`
- Type: `check`
- `bounce_target`: `impl_p06_pubkey_ecc`
- Purpose: verify all asymmetric crypto entry points, curve metadata, key generation, keygrip computation, EC contexts, deterministic-signing hooks, and the CVE-driven hardening rules.
- Commands:

```bash
cargo build --manifest-path safe/Cargo.toml --release --offline
safe/scripts/run-original-tests.sh keygen pubkey keygrip pkcs1v2 fips186-dsa dsa-rfc6979 t-dsa curves t-ecdsa t-ed25519 t-cv25519 t-x448 t-ed448 t-rsa-pss t-rsa-15 t-rsa-testparm t-mpi-point testapi
```

## Success Criteria
- `cargo build --manifest-path safe/Cargo.toml --release --offline` succeeds.
- `safe/scripts/run-original-tests.sh keygen pubkey keygrip pkcs1v2 fips186-dsa dsa-rfc6979 t-dsa curves t-ecdsa t-ed25519 t-cv25519 t-x448 t-ed448 t-rsa-pss t-rsa-15 t-rsa-testparm t-mpi-point testapi` passes.
- `safe/docs/cve-matrix.md` maps every ID in `relevant_cves.json` to code paths and tests or review obligations.
- `safe/docs/abi-map.md` marks the implemented public-key, ECC, and ABI-only `gcry_pk_register` coverage ownership correctly.

## Git Commit Requirement
The implementer must commit the phase's work to git before yielding.
