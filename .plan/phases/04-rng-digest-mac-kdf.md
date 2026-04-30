# Phase Name

RNG, digest, MAC, and KDF without upstream bridge

# Implement Phase ID

`impl_p04_rng_digest_mac_kdf`

# Preexisting Inputs

- Phase 3 committed tree and tag.
- `safe/Cargo.toml`
- `safe/Cargo.lock`
- `safe/.cargo/config.toml`
- `.cargo/config.toml` if committed by phase 1.
- `safe/src/drbg.rs`
- `safe/src/random.rs`
- `safe/src/os_rng.rs`
- `safe/src/digest/mod.rs`
- `safe/src/digest/algorithms.rs`
- `safe/src/mac.rs`
- `safe/src/kdf.rs`
- `safe/src/upstream.rs`
- `safe/vendor/**`
- `safe/scripts/run-original-tests.sh`
- `safe/scripts/run-upstream-tests.sh`
- `safe/scripts/check-abi.sh`
- `safe/tests/original-build/*`
- `safe/tests/upstream/*`
- `safe/tests/compat/public-api-smoke.c`
- `safe/abi/*`
- `safe/docs/abi-map.md`
- `safe/docs/cve-matrix.md`
- `original/libgcrypt20-1.10.3/random/`
- `original/libgcrypt20-1.10.3/cipher/md.c`
- `original/libgcrypt20-1.10.3/cipher/mac.c`
- `original/libgcrypt20-1.10.3/cipher/kdf.c`
- `original/libgcrypt20-1.10.3/tests/random.c`
- `original/libgcrypt20-1.10.3/tests/hashtest.c`
- `original/libgcrypt20-1.10.3/tests/hmac.c`
- `original/libgcrypt20-1.10.3/tests/t-kdf.c`
- `relevant_cves.json`
- `all_cves.json`

# New Outputs

- Local `DigestContext`, `MacContext`, and KDF handle implementations.
- Rust-owned `gcry_md_*`, `gcry_mac_*`, `gcry_kdf_*`, and `gcry_random*` behavior.
- Updated `safe/docs/cve-matrix.md` for RNG, digest, MAC, and KDF CVEs and review obligations.

# File Changes

- `safe/Cargo.toml`
- `safe/Cargo.lock`
- `safe/vendor/**`
- `safe/src/drbg.rs`
- `safe/src/random.rs`
- `safe/src/os_rng.rs`
- `safe/src/digest/mod.rs`
- `safe/src/digest/algorithms.rs`
- `safe/src/mac.rs`
- `safe/src/kdf.rs`
- `safe/src/upstream.rs`
- `safe/docs/abi-map.md`
- `safe/docs/cve-matrix.md`
- `safe/tests/compat/public-api-smoke.c`

# Implementation Details

- Replace all digest, MAC, and KDF calls to `upstream::lib()` with local Rust state and algorithm implementations.
- Use committed vendored crates where appropriate for SHA1/SHA2/SHA3/BLAKE2/SM3/Streebog/GOST94/HMAC/CMAC/Poly1305, and port missing required algorithms from the original source into safe Rust modules.
- Preserve libgcrypt algorithm numbers, names, aliases, digest lengths, XOF behavior for SHAKE, `gcry_md_get` ABI-only export behavior, secure flags, copy/reset semantics, HMAC keyed digest behavior, and `gcry_md_hash_buffers` iovec handling.
- Implement KDF coverage for S2K, PBKDF2, scrypt, Argon2, Balloon, and handle-based `gcry_kdf_open`/`compute`/`final`/`close` as exposed by `safe/abi/gcrypt.h.in`.
- Keep DRBG reseed, fork detection, nonce creation, and random quality behavior aligned with `random.c` and the CVE matrix.
- Preserve the consume-existing-artifacts contract by updating the existing RNG, digest, MAC, KDF, upstream-test, ABI, and CVE artifacts in place, consuming both `relevant_cves.json` and `all_cves.json` rather than rediscovering security metadata.

# Verification Phases

- Phase ID: `check_p04_rng_digest_mac_kdf`
- Type: `check`
- `bounce_target`: `impl_p04_rng_digest_mac_kdf`
- Purpose: verify local random, hash, HMAC/MAC, and KDF APIs and review relevant CVE obligations.
- Commands:
  - `test "$(git rev-parse HEAD)" = "$(git rev-parse phase/impl_p04_rng_digest_mac_kdf)"`
  - `test "$(git rev-parse HEAD^)" = "$(git rev-parse phase/impl_p03_sexp_mpi_core)"`
  - `bash -c 'test -z "$(git status --short)"'`
  - `safe/scripts/check-rust-toolchain.sh`
  - `cargo build --manifest-path safe/Cargo.toml --release --locked --offline`
  - `safe/scripts/run-original-tests.sh random hashtest hmac t-kdf`
  - `safe/scripts/run-upstream-tests.sh random hashtest hmac t-kdf`
  - `safe/scripts/check-abi.sh --check-symbol-versions`
  - `bash -c 'if rg -n "upstream::lib\\(\\)" safe/src/digest safe/src/mac.rs safe/src/kdf.rs; then exit 1; fi'`

# Success Criteria

- Random, digest, MAC, and KDF surfaces are Rust-owned and have no `upstream::lib()` calls in the listed modules.
- Original and imported upstream tests for random, hash, HMAC, and KDF pass.
- CVE documentation reflects the local implementation ownership and review obligations.
- The phase is a single child commit of `phase/impl_p03_sexp_mpi_core` and leaves a clean worktree before tests.

# Git Commit Requirement

The implementer must commit work to git before yielding. End with one commit whose subject begins `impl_p04_rng_digest_mac_kdf:` and whose first parent is `phase/impl_p03_sexp_mpi_core`; force-update local tag `phase/impl_p04_rng_digest_mac_kdf` to that commit before yielding.
