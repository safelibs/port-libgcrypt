# Bridge Inventory

Phase 1 keeps the temporary upstream bridge visible and documented. The bridge exists only to preserve staged ABI/runtime coverage while later phases replace functionality with Rust-owned implementations. The planned removal phase for the runtime bridge is phase 6.

## Current Bridge References

| Path | Reference | Purpose | Planned Removal |
| --- | --- | --- | --- |
| `safe/build.rs` | `cargo:rustc-link-lib=dl` and `SAFE_SYSTEM_LIBGCRYPT_PATH` build-time env injection | Links the temporary runtime bridge and records the system `libgcrypt.so.20` path for bridge users. | Phase 6 |
| `safe/src/upstream.rs` | `dlopen`, `dlsym`, `SAFE_SYSTEM_LIBGCRYPT_PATH`, `libgcrypt.so.20` lookup | Shared runtime bridge for RNG, digest, MAC, KDF, cipher, and hardware-feature calls that are not Rust-owned at bootstrap. | Phases 4-6, fully removed in phase 6 |
| `safe/src/pubkey/encoding.rs` | `dlopen`, `dlsym`, `SAFE_SYSTEM_LIBGCRYPT_PATH`, `libgcrypt.so.20` lookup | Public-key/ECC bridge used while converting local S-expressions and MPIs to upstream handles. | Phase 6 |
| `safe/debian/rules` | `-ldl` | Keeps Debian package builds linkable while bridge code remains present. | Phase 6 |
| `safe/scripts/run-compat-smoke.sh` | `-ldl` in the ABI-only probe link line | Allows the current compatibility probe to link in the bridge era. | Phase 8 |
| `safe/scripts/check-installed-tools.sh` | `SAFE_SYSTEM_LIBGCRYPT_PATH` provisioning | Lets installed helper-tool smoke tests side-load the system runtime bridge target. | Phase 9 |
| `test-original.sh` | `SAFE_SYSTEM_LIBGCRYPT_PATH` provisioning and propagation | Lets dependent/original image checks side-load the system runtime bridge target while the safe package is under test. | Phase 10 |

## Enforcement Contract

- `safe/scripts/check-no-upstream-bridge.sh` is committed in this phase as the fail-closed scanner for bridge-era environment variables, runtime symbol lookup, hard-coded upstream soname paths, and `-ldl` flags.
- The scanner is expected to fail while the references above remain. Later removal phases must update this inventory and the scan set together.
- No bridge reference may be hidden in untracked helper files; later phases may rely only on committed scripts and docs.
