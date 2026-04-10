# Bridge Inventory

This inventory records the current hybrid baseline after the Noble toolchain downgrade. The exported ABI is no longer a single implementation surface: some symbol families are owned by local Rust code, while other families are still loaded from the system `libgcrypt.so.20` bridge at runtime.

## Baseline Split

- Rust-owned exported families: version/control/config/error/allocation/randomness/secure-memory in [`safe/src/global.rs`](../src/global.rs), [`safe/src/config.rs`](../src/config.rs), [`safe/src/error.rs`](../src/error.rs), [`safe/src/alloc.rs`](../src/alloc.rs), and [`safe/src/random.rs`](../src/random.rs); S-expression/MPI/prime families in [`safe/src/sexp.rs`](../src/sexp.rs) and [`safe/src/mpi/`](../src/mpi); logging in [`safe/src/log.rs`](../src/log.rs).
- Rust-owned exported families: digest, MAC, and KDF exports now run entirely from their owning Rust modules in [`safe/src/digest/mod.rs`](../src/digest/mod.rs), [`safe/src/mac.rs`](../src/mac.rs), and [`safe/src/kdf.rs`](../src/kdf.rs), with local registries, handles, and data paths instead of any private upstream digest/MAC/KDF bridge.
- Bridge-backed exported families: symmetric cipher families still load through [`safe/src/upstream.rs`](../src/upstream.rs); public-key, ECC, point, EC-context, and context-release families load through [`safe/src/pubkey/encoding.rs`](../src/pubkey/encoding.rs).
- Bridge-only marshalling helpers: [`safe/src/pubkey/encoding.rs`](../src/pubkey/encoding.rs) still loads upstream `gcry_sexp_*` and `gcry_mpi_*` helpers for translation, even though those exported families are Rust-owned.

## Upstream-Loaded Symbol Families

| Family | Loaded in | Consumed by | Notes |
| --- | --- | --- | --- |
| `gcry_cipher_*`, `gcry_cipher_mode_from_oid`, `gcry_cipher_get_algo_*` | [`safe/src/upstream.rs`](../src/upstream.rs) | [`safe/src/cipher/modes.rs`](../src/cipher/modes.rs), [`safe/src/cipher/block.rs`](../src/cipher/block.rs), [`safe/src/cipher/aead.rs`](../src/cipher/aead.rs), [`safe/src/cipher/registry.rs`](../src/cipher/registry.rs) | Symmetric cipher data paths and cipher metadata are still bridge-loaded. |
| `gcry_check_version` bootstrap | [`safe/src/upstream.rs`](../src/upstream.rs), [`safe/src/pubkey/encoding.rs`](../src/pubkey/encoding.rs) | Bridge library initialization in both loaders | Both bridge loaders call upstream `gcry_check_version` after `dlopen` to prove the loaded `libgcrypt.so.20` is usable before resolving additional symbols. |
| `gcry_control` for pre-init `GCRYCTL_DISABLE_HWF` forwarding | [`safe/src/upstream.rs`](../src/upstream.rs) | [`safe/src/global.rs`](../src/global.rs) | Rust owns the public `gcry_control` export; only the pre-initialization hardware-disable handoff still calls upstream control. |
| `gcry_pk_*`, `gcry_pubkey_get_sexp`, `gcry_ecc_*`, `gcry_mpi_point_*`, `gcry_mpi_ec_*`, `gcry_ctx_release` | [`safe/src/pubkey/encoding.rs`](../src/pubkey/encoding.rs) | [`safe/src/pubkey/mod.rs`](../src/pubkey/mod.rs), [`safe/src/pubkey/ecc.rs`](../src/pubkey/ecc.rs), [`safe/src/pubkey/keygrip.rs`](../src/pubkey/keygrip.rs), [`safe/src/mpi/ec.rs`](../src/mpi/ec.rs), [`safe/src/context.rs`](../src/context.rs) | Secret asymmetric work, opaque point/context handles, and EC helper paths stay bridge-loaded. |
| Bridge-only marshalling helpers: `gcry_sexp_sscan`, `gcry_sexp_sprint`, `gcry_sexp_release`, `gcry_mpi_new`, `gcry_mpi_release`, `gcry_mpi_scan`, `gcry_mpi_print`, `gcry_mpi_get_flag`, `gcry_mpi_get_opaque`, `gcry_mpi_set_opaque_copy` | [`safe/src/pubkey/encoding.rs`](../src/pubkey/encoding.rs) | [`safe/src/pubkey/mod.rs`](../src/pubkey/mod.rs), [`safe/src/pubkey/ecc.rs`](../src/pubkey/ecc.rs), [`safe/src/pubkey/keygrip.rs`](../src/pubkey/keygrip.rs), [`safe/src/mpi/ec.rs`](../src/mpi/ec.rs) | These are internal bridge dependencies used for Rust-to-upstream translation, not ownership of the public MPI/S-expression exports. |

## `SAFE_SYSTEM_LIBGCRYPT_PATH` Flow

| Role | Files | Usage |
| --- | --- | --- |
| Compile-time fallback path injection | [`safe/build.rs`](../build.rs) | Writes `cargo:rustc-env=SAFE_SYSTEM_LIBGCRYPT_PATH=...` when a system `libgcrypt.so.20` is discoverable, so the runtime bridge has an embedded fallback path. |
| Runtime bridge consumption | [`safe/src/upstream.rs`](../src/upstream.rs), [`safe/src/pubkey/encoding.rs`](../src/pubkey/encoding.rs) | Prefer the environment override before the built-in distro search paths when `dlopen`ing upstream `libgcrypt.so.20`. |
| Installed-helper bridge override | [`safe/scripts/check-installed-tools.sh`](../scripts/check-installed-tools.sh) | Accepts or discovers an upstream runtime path, then exports `SAFE_SYSTEM_LIBGCRYPT_PATH` before running the packaged helper and metadata smokes. |
| Downstream/dependent bridge override | [`test-original.sh`](../../test-original.sh) | Exports or forwards the upstream runtime path into helper smoke, GNOME Keyring, and dependent-software checks. |

## Bridge-Dependent Verifiers And Helpers

- [`safe/scripts/run-original-tests.sh`](../scripts/run-original-tests.sh): `--all` executes the original `TESTS` inventory from `original/libgcrypt20-1.10.3/tests/Makefile.am`; digest/MAC/KDF entries now go through their owning Rust modules, while cipher/pubkey coverage still exercises the remaining bridge families and `--list` / inventory-only `--dry-run` stay metadata-only.
- [`safe/scripts/run-upstream-tests.sh`](../scripts/run-upstream-tests.sh): the committed imported harness now exercises Rust-owned digest/MAC/KDF exports alongside the remaining bridge-loaded cipher/pubkey families.
- [`safe/scripts/run-compat-smoke.sh`](../scripts/run-compat-smoke.sh): public development metadata smokes and the ABI-only `gcry_pk_register` probe still run against the bridge-backed shared library.
- [`safe/scripts/relink-original-objects.sh`](../scripts/relink-original-objects.sh): relinked original objects still execute the Rust-owned digest/MAC/KDF surface plus the bridge-loaded cipher/pubkey families after linking against the safe shared library.
- [`safe/scripts/check-installed-tools.sh`](../scripts/check-installed-tools.sh): packaged helper verification exports an upstream bridge target before running `dumpsexp`, `hmac256`, `mpicalc`, and the install-surface compile/link smokes.
- [`test-original.sh`](../../test-original.sh): downstream dependent verification still provisions an upstream `libgcrypt.so.20` side library and forwards `SAFE_SYSTEM_LIBGCRYPT_PATH` while exercising the packaged safe build.
