# Phase Name

Public-key, ECC, contexts, and bridge removal

# Implement Phase ID

`impl_p06_pubkey_ecc_no_bridge`

# Preexisting Inputs

- Phase 5 committed tree and tag.
- `safe/Cargo.toml`
- `safe/Cargo.lock`
- `safe/.cargo/config.toml`
- `.cargo/config.toml` if committed by phase 1.
- `safe/src/pubkey/mod.rs`
- `safe/src/pubkey/encoding.rs`
- `safe/src/pubkey/rsa.rs`
- `safe/src/pubkey/dsa.rs`
- `safe/src/pubkey/elgamal.rs`
- `safe/src/pubkey/ecc.rs`
- `safe/src/pubkey/keygrip.rs`
- `safe/src/mpi/ec.rs`
- `safe/src/context.rs`
- `safe/src/upstream.rs`
- `safe/src/lib.rs`
- `safe/cabi/exports.c`
- `safe/cabi/exports.h`
- `safe/build.rs`
- `safe/debian/rules`
- `safe/scripts/run-original-tests.sh`
- `safe/scripts/run-upstream-tests.sh`
- `safe/scripts/check-no-upstream-bridge.sh`
- `safe/scripts/check-installed-tools.sh`
- `test-original.sh`
- `safe/tests/original-build/*`
- `safe/tests/upstream/*`
- `safe/docs/abi-map.md`
- `safe/docs/cve-matrix.md`
- `safe/docs/bridge-inventory.md`
- `original/libgcrypt20-1.10.3/cipher/pubkey.c`
- `original/libgcrypt20-1.10.3/cipher/rsa.c`
- `original/libgcrypt20-1.10.3/cipher/dsa.c`
- `original/libgcrypt20-1.10.3/cipher/elgamal.c`
- `original/libgcrypt20-1.10.3/cipher/ecc*.c`
- `original/libgcrypt20-1.10.3/mpi/ec*.c`
- Public-key and ECC upstream tests under `original/libgcrypt20-1.10.3/tests/`.
- `relevant_cves.json`

# New Outputs

- Rust-owned public-key and ECC implementation with no dependency on system `libgcrypt.so.20`.
- Deleted or inert `safe/src/upstream.rs`.
- No references to `SAFE_SYSTEM_LIBGCRYPT_PATH`, `dlopen`, `dlsym`, `rustc-link-lib=dl`, or `-ldl` outside documentation that describes removed history and the literal pattern definitions inside `safe/scripts/check-no-upstream-bridge.sh`.
- Updated `safe/docs/cve-matrix.md` proving public-key side-channel obligations and future local-implementation review rules.

# File Changes

- `safe/src/pubkey/mod.rs`
- `safe/src/pubkey/encoding.rs`
- `safe/src/pubkey/rsa.rs`
- `safe/src/pubkey/dsa.rs`
- `safe/src/pubkey/elgamal.rs`
- `safe/src/pubkey/ecc.rs`
- `safe/src/pubkey/keygrip.rs`
- `safe/src/mpi/ec.rs`
- `safe/src/context.rs`
- `safe/src/upstream.rs`
- `safe/src/lib.rs`
- `safe/build.rs`
- `safe/debian/rules`
- `safe/scripts/check-no-upstream-bridge.sh`
- `safe/scripts/check-installed-tools.sh`
- `test-original.sh`
- `safe/docs/abi-map.md`
- `safe/docs/cve-matrix.md`
- `safe/docs/bridge-inventory.md`

# Implementation Details

- Replace all public-key and ECC forwarding through `safe/src/pubkey/encoding.rs` with local Rust operations over the local S-expression and MPI representations.
- Implement RSA encrypt/decrypt/sign/verify/keygen/testkey, DSA sign/verify/keygen, ElGamal encrypt/decrypt/keygen, and ECC operations for the curves exposed by libgcrypt 1.10.3.
- Implement `gcry_mpi_point_*`, `gcry_mpi_ec_*`, `gcry_ecc_*`, `gcry_pubkey_get_sexp`, `gcry_pk_hash_sign`, `gcry_pk_hash_verify`, `gcry_pk_random_override_new`, and `gcry_ctx_release`.
- Preserve exact S-expression shapes, algorithm aliases, keygrip bytes, error codes, padding behavior, and opaque MPI handling expected by upstream tests and GnuPG dependents.
- Keep unsafe limited to C ABI pointers and explicit memory ownership transfers. This unsafe-memory boundary is part of the phase contract and should not expand into bridge loading, hidden mutable globals, or algorithm shortcuts.
- Remove `find_system_libgcrypt` from `safe/build.rs`, remove `-ldl` from build/package/link scripts, and make `safe/scripts/check-no-upstream-bridge.sh` a required passing check.
- Preserve the consume-existing-artifacts contract by updating the existing public-key, ECC, bridge scan, package-rule, test, and documentation artifacts in place.

# Verification Phases

- Phase ID: `check_p06_pubkey_ecc_no_bridge`
- Type: `check`
- `bounce_target`: `impl_p06_pubkey_ecc_no_bridge`
- Purpose: verify Rust-owned RSA, DSA, ElGamal, ECC, keygrip, public-key S-expression translation, MPI point/EC context APIs, and complete removal of runtime upstream bridge references.
- Commands:
  - `test "$(git rev-parse HEAD)" = "$(git rev-parse phase/impl_p06_pubkey_ecc_no_bridge)"`
  - `test "$(git rev-parse HEAD^)" = "$(git rev-parse phase/impl_p05_symmetric_ciphers)"`
  - `bash -c 'test -z "$(git status --short)"'`
  - `safe/scripts/check-rust-toolchain.sh`
  - `cargo build --manifest-path safe/Cargo.toml --release --locked --offline`
  - `safe/scripts/run-original-tests.sh keygen pubkey keygrip pkcs1v2 fips186-dsa dsa-rfc6979 t-dsa curves t-ecdsa t-ed25519 t-cv25519 t-x448 t-ed448 t-rsa-pss t-rsa-15 t-rsa-testparm t-mpi-point`
  - `safe/scripts/run-upstream-tests.sh keygen pubkey keygrip pkcs1v2 fips186-dsa dsa-rfc6979 t-dsa curves t-ecdsa t-ed25519 t-cv25519 t-x448 t-ed448 t-rsa-pss t-rsa-15 t-rsa-testparm t-mpi-point`
  - `safe/scripts/check-no-upstream-bridge.sh`

# Success Criteria

- Public-key, ECC, MPI point, EC context, keygrip, and public-key S-expression APIs are Rust-owned.
- Runtime upstream bridge references are removed, and the bridge scanner passes.
- Unsafe is confined to the explicit C ABI and memory ownership boundary.
- The phase is a single child commit of `phase/impl_p05_symmetric_ciphers` and leaves a clean worktree before tests.

# Git Commit Requirement

The implementer must commit work to git before yielding. End with one commit whose subject begins `impl_p06_pubkey_ecc_no_bridge:` and whose first parent is `phase/impl_p05_symmetric_ciphers`; force-update local tag `phase/impl_p06_pubkey_ecc_no_bridge` to that commit before yielding.
