# Bridge Inventory

This inventory records the current hybrid baseline after the Noble toolchain downgrade. The exported ABI is no longer a single implementation surface: some symbol families are owned by local Rust code, while other families are still loaded from the system `libgcrypt.so.20` bridge at runtime.

## Baseline Split

- Rust-owned exported families: version/control/config/error/allocation/randomness/secure-memory in [`safe/src/global.rs`](../src/global.rs), [`safe/src/config.rs`](../src/config.rs), [`safe/src/error.rs`](../src/error.rs), [`safe/src/alloc.rs`](../src/alloc.rs), and [`safe/src/random.rs`](../src/random.rs); S-expression/MPI/prime families in [`safe/src/sexp.rs`](../src/sexp.rs) and [`safe/src/mpi/`](../src/mpi); logging in [`safe/src/log.rs`](../src/log.rs).
- Bridge-backed exported families: MAC, KDF, and symmetric cipher families still load through [`safe/src/upstream.rs`](../src/upstream.rs); the digest surface in [`safe/src/digest/mod.rs`](../src/digest/mod.rs) is mostly a local forwarding layer over upstream helpers, with `gcry_md_get` owned locally; public-key, ECC, point, EC-context, and context-release families load through [`safe/src/pubkey/encoding.rs`](../src/pubkey/encoding.rs).
- Bridge-only marshalling helpers: [`safe/src/pubkey/encoding.rs`](../src/pubkey/encoding.rs) still loads upstream `gcry_sexp_*` and `gcry_mpi_*` helpers for translation, even though those exported families are Rust-owned.

## Upstream-Loaded Symbol Families

| Family | Loaded in | Consumed by | Notes |
| --- | --- | --- | --- |
| `gcry_md_*` bridge helpers | [`safe/src/upstream.rs`](../src/upstream.rs) | [`safe/src/digest/mod.rs`](../src/digest/mod.rs) | Most digest handle, metadata, and keyed-digest helpers still delegate to upstream; `gcry_md_get` is the local compatibility export that reuses upstream `md_read` / `md_extract` internals. |
| `gcry_mac_*` | [`safe/src/upstream.rs`](../src/upstream.rs) | [`safe/src/mac.rs`](../src/mac.rs) | MAC handle lifecycle, metadata, and read/verify paths stay bridge-loaded. |
| `gcry_kdf_*` | [`safe/src/upstream.rs`](../src/upstream.rs) | [`safe/src/kdf.rs`](../src/kdf.rs) | `derive`, `open`, `compute`, `final`, and `close` stay bridge-loaded. |
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

- [`safe/scripts/run-original-tests.sh`](../scripts/run-original-tests.sh): `--all` executes the original `TESTS` inventory from `original/libgcrypt20-1.10.3/tests/Makefile.am`; digest/MAC/KDF/cipher/pubkey entries still rely on the bridge, while `--list` and inventory-only `--dry-run` stay metadata-only.
- [`safe/scripts/run-upstream-tests.sh`](../scripts/run-upstream-tests.sh): the committed imported harness still exercises bridge-loaded digest/cipher/pubkey families through the copied upstream sources and helper binaries.
- [`safe/scripts/run-compat-smoke.sh`](../scripts/run-compat-smoke.sh): public development metadata smokes and the ABI-only `gcry_pk_register` probe still run against the bridge-backed shared library.
- [`safe/scripts/relink-original-objects.sh`](../scripts/relink-original-objects.sh): relinked original objects still execute bridge-loaded digest/cipher/pubkey families after linking against the safe shared library.
- [`safe/scripts/check-installed-tools.sh`](../scripts/check-installed-tools.sh): packaged helper verification exports an upstream bridge target before running `dumpsexp`, `hmac256`, `mpicalc`, and the install-surface compile/link smokes.
- [`test-original.sh`](../../test-original.sh): downstream dependent verification still provisions an upstream `libgcrypt.so.20` side library and forwards `SAFE_SYSTEM_LIBGCRYPT_PATH` while exercising the packaged safe build.
