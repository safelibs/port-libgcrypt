# Phase Name

Symmetric ciphers, modes, AEAD, and hardware flags

# Implement Phase ID

`impl_p05_symmetric_ciphers`

# Preexisting Inputs

- Phase 4 committed tree and tag.
- `safe/Cargo.toml`
- `safe/Cargo.lock`
- `safe/.cargo/config.toml`
- `.cargo/config.toml` if committed by phase 1.
- `safe/src/cipher/mod.rs`
- `safe/src/cipher/registry.rs`
- `safe/src/cipher/modes.rs`
- `safe/src/cipher/block.rs`
- `safe/src/cipher/aead.rs`
- `safe/src/cipher/stream.rs`
- `safe/src/hwfeatures.rs`
- `safe/src/upstream.rs`
- `safe/vendor/**`
- `safe/scripts/run-original-tests.sh`
- `safe/scripts/run-upstream-tests.sh`
- `safe/tests/original-build/*`
- `safe/tests/upstream/*`
- `safe/tests/compat/public-api-smoke.c`
- `safe/docs/abi-map.md`
- `safe/docs/cve-matrix.md`
- `original/libgcrypt20-1.10.3/cipher/`
- `original/libgcrypt20-1.10.3/tests/aeswrap.c`
- `original/libgcrypt20-1.10.3/tests/basic.c`
- `original/libgcrypt20-1.10.3/tests/t-lock.c`
- `relevant_cves.json`

# New Outputs

- Local `CipherHandle` implementation for all public cipher algorithms and modes required by `gcrypt.h`.
- Updated mode/vector regression coverage for AES, 3DES/DES, CAST5, Blowfish, Twofish, Serpent, Camellia, IDEA, RC2, ARCFOUR, Salsa20, ChaCha20, SM4, SEED, GOST28147, AES key wrap, CCM, GCM, OCB, EAX, SIV/GCM-SIV where exposed.
- Updated CVE matrix for AES and side-channel-sensitive cipher paths.

# File Changes

- `safe/src/cipher/mod.rs`
- `safe/src/cipher/registry.rs`
- `safe/src/cipher/modes.rs`
- `safe/src/cipher/block.rs`
- `safe/src/cipher/aead.rs`
- `safe/src/cipher/stream.rs`
- `safe/src/hwfeatures.rs`
- `safe/src/upstream.rs`
- `safe/Cargo.toml`
- `safe/Cargo.lock`
- `safe/vendor/**`
- `safe/tests/compat/public-api-smoke.c`
- `safe/docs/abi-map.md`
- `safe/docs/cve-matrix.md`

# Implementation Details

- Replace all `gcry_cipher_*` forwarding with local Rust algorithm and mode code.
- Reuse committed vendored crates where they cover algorithms, and port missing ciphers from the original C implementation into safe Rust.
- Preserve `gcry_cipher_open`, `close`, `ctl`, `info`, `setkey`, `setiv`, `setctr`, `encrypt`, `decrypt`, `authenticate`, `gettag`, and `checktag` semantics including in-place encryption, partial blocks, secure handles, and error code shape.
- Implement `GCRYCTL_DISABLE_HWF` and hardware-feature reporting as local bookkeeping that affects algorithm selection where applicable but never changes exported ABI.
- Keep constant-time requirements explicit for software AES and secret-dependent operations.
- Preserve the consume-existing-artifacts contract by updating the existing cipher modules, tests, vendored dependencies, and CVE artifacts in place.

# Verification Phases

- Phase ID: `check_p05_symmetric_ciphers`
- Type: `check`
- `bounce_target`: `impl_p05_symmetric_ciphers`
- Purpose: verify local cipher registry, block/stream ciphers, cipher modes, AEAD, wrapping, and hardware-feature controls.
- Commands:
  - `test "$(git rev-parse HEAD)" = "$(git rev-parse phase/impl_p05_symmetric_ciphers)"`
  - `test "$(git rev-parse HEAD^)" = "$(git rev-parse phase/impl_p04_rng_digest_mac_kdf)"`
  - `bash -c 'test -z "$(git status --short)"'`
  - `safe/scripts/check-rust-toolchain.sh`
  - `cargo build --manifest-path safe/Cargo.toml --release --locked --offline`
  - `safe/scripts/run-original-tests.sh aeswrap basic basic-disable-all-hwf t-lock benchmark bench-slope`
  - `safe/scripts/run-upstream-tests.sh aeswrap basic basic-disable-all-hwf t-lock`
  - `bash -c 'if rg -n "upstream::lib\\(\\)" safe/src/cipher; then exit 1; fi'`

# Success Criteria

- Public cipher algorithms and modes required by `gcrypt.h` are local and verified.
- No `upstream::lib()` calls remain in `safe/src/cipher`.
- Hardware-feature controls are local bookkeeping and preserve exported ABI behavior.
- The phase is a single child commit of `phase/impl_p04_rng_digest_mac_kdf` and leaves a clean worktree before tests.

# Git Commit Requirement

The implementer must commit work to git before yielding. End with one commit whose subject begins `impl_p05_symmetric_ciphers:` and whose first parent is `phase/impl_p04_rng_digest_mac_kdf`; force-update local tag `phase/impl_p05_symmetric_ciphers` to that commit before yielding.
