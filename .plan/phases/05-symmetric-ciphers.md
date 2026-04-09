# 05 Symmetric Ciphers

- Phase Name: Symmetric ciphers and mode dispatcher
- Implement Phase ID: `impl_p05_symmetric_ciphers`

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
- `original/libgcrypt20-1.10.3/tests/basic.c`
- `original/libgcrypt20-1.10.3/tests/aeswrap.c`
- `original/libgcrypt20-1.10.3/tests/t-lock.c`
- `original/libgcrypt20-1.10.3/tests/basic-disable-all-hwf.in`
- `original/libgcrypt20-1.10.3/src/hwfeatures.c`
- `original/libgcrypt20-1.10.3/src/gcrypt-testapi.h`
- `original/libgcrypt20-1.10.3/compat/`
- `relevant_cves.json`

## New Outputs
- Full symmetric cipher subsystem
- Updated `safe/docs/abi-map.md`
- Updated `safe/docs/cve-matrix.md`

## File Changes
- `safe/src/cipher/mod.rs`
- `safe/src/cipher/registry.rs`
- `safe/src/cipher/modes.rs`
- `safe/src/cipher/aead.rs`
- `safe/src/cipher/block.rs`
- `safe/src/cipher/stream.rs`
- `safe/src/hwfeatures.rs`
- `safe/src/global.rs`
- `safe/docs/abi-map.md`
- `safe/docs/cve-matrix.md`

## Implementation Details
- Implement every algorithm ID in `enum gcry_cipher_algos` and every mode in `enum gcry_cipher_modes`.
- Preserve upstream handle semantics for `gcry_cipher_open`, `gcry_cipher_close`, `gcry_cipher_ctl`, `gcry_cipher_info`, `gcry_cipher_algo_info`, `gcry_cipher_encrypt`, `gcry_cipher_decrypt`, `gcry_cipher_authenticate`, `gcry_cipher_gettag`, `gcry_cipher_checktag`, `gcry_cipher_setkey`, `gcry_cipher_setiv`, and `gcry_cipher_setctr`.
- Match the macro-backed control behavior for `gcry_cipher_reset`, `gcry_cipher_sync`, `gcry_cipher_cts`, `gcry_cipher_set_sbox`, `gcry_cipher_final`, and `gcry_cipher_set_decryption_tag`.
- Match the `basic.c` expectations that reset clears IV and CTR state where upstream does while preserving mode-specific subkeys where upstream does.
- Implement `GCRYCTL_DISABLE_HWF` so `basic-disable-all-hwf` can force software paths while preserving the exposed feature names and disable semantics.
- Avoid table-based software AES in the portable fallback; use constant-time software or hardware-gated implementations to address `CVE-2019-12904`.
- Implement GOST S-box selection and weak-key control behavior needed by `basic.c` and `gcrypt-testapi.h`.
- Update `safe/docs/cve-matrix.md` with symmetric-side timing notes and chosen mitigations.

## Verification Phases
### `check_p05_symmetric_ciphers`
- Type: `check`
- `bounce_target`: `impl_p05_symmetric_ciphers`
- Purpose: verify the symmetric-cipher handle model, registry, mode semantics, AEAD and tag behavior, S-box controls, reset and finalize behavior, and hardware-feature-disable plumbing.
- Commands:

```bash
cargo build --manifest-path safe/Cargo.toml --release --offline
safe/scripts/run-original-tests.sh aeswrap basic basic-disable-all-hwf t-lock
```

## Success Criteria
- `cargo build --manifest-path safe/Cargo.toml --release --offline` succeeds.
- `safe/scripts/run-original-tests.sh aeswrap basic basic-disable-all-hwf t-lock` passes.
- `safe/docs/cve-matrix.md` explains the software AES fallback choice and why it avoids secret-indexed table lookups.
- `safe/docs/abi-map.md` reflects the implemented symmetric-cipher surface and any remaining later-phase ownership.

## Git Commit Requirement
The implementer must commit the phase's work to git before yielding.
