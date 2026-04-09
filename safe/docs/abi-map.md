# ABI Map

Seeded from `safe/abi/libgcrypt.vers`, `safe/abi/gcrypt.h.in`, and `safe/abi/visibility.h`. This phase still exports all 217 `GCRYPT_1.6` symbols immediately, but the runtime shell now owns the version/control/config/error/allocation/randomness/secure-memory surface instead of the old bootstrap shim. Remaining crypto families stay skeletal until their owning phases land.

- `gcry_md_get` is a Linux version-script export that is not declared by installed `gcrypt.h`; it is classified as `visibility-only` and owned by phase 4.
- `gcry_pk_register` is a Linux version-script export that is not declared by installed `gcrypt.h`; it is classified as `abi-only` and owned by phase 6.
- `gcry_ctx_release` remains outside phase 2 scope and still resolves to the generic export stub until the later context/public-key work lands.

| Symbol | Classification | Planned Location | Planned Coverage | Notes |
| --- | --- | --- | --- | --- |
| `gcry_check_version` | header+visibility | `safe/src/global.rs` | `run-original-tests.sh` version + `check-abi.sh` export-set check | Implemented runtime-shell path with upstream-style version negotiation. |
| `gcry_control` | header+visibility | `safe/cabi/exports.c` -> `safe/src/global.rs` | `check-abi.sh` variadic smoke + `check-abi.sh --thread-cbs-noop` + export-set check | Implemented runtime-shell control plane, including `GCRYCTL_SET_THREAD_CBS` compatibility behavior. |
| `gcry_set_allocation_handler` | header+visibility | `safe/src/alloc.rs` | `check-abi.sh` export-set check | Implemented runtime-shell handler registration. |
| `gcry_set_fatalerror_handler` | header+visibility | `safe/src/log.rs` | `check-abi.sh` export-set check | Implemented runtime-shell handler registration and fatal-path dispatch. |
| `gcry_set_gettext_handler` | header+visibility | `safe/src/log.rs` | `check-abi.sh` export-set check | Implemented runtime-shell handler registration and translated fatal/log text dispatch. |
| `gcry_set_log_handler` | header+visibility | `safe/cabi/exports.c` + `safe/src/log.rs` | `check-abi.sh` export-set check | Implemented runtime-shell handler registration with C va_list bridge for log dispatch. |
| `gcry_set_outofcore_handler` | header+visibility | `safe/src/alloc.rs` | `run-original-tests.sh` t-secmem + `check-abi.sh` export-set check | Implemented runtime-shell handler registration and xmalloc retry path. |
| `gcry_set_progress_handler` | header+visibility | `safe/src/log.rs` | `check-abi.sh` export-set check | Implemented runtime-shell registration surface; producers remain phase-local. |
| `gcry_err_code_from_errno` | header+visibility | `safe/src/error.rs` | `check-abi.sh` export-set check | Implemented libgpg-error wrapper surface. |
| `gcry_err_code_to_errno` | header+visibility | `safe/src/error.rs` | `check-abi.sh` export-set check | Implemented libgpg-error wrapper surface. |
| `gcry_err_make_from_errno` | header+visibility | `safe/src/error.rs` | `check-abi.sh` export-set check | Implemented libgpg-error wrapper surface. |
| `gcry_error_from_errno` | header+visibility | `safe/src/error.rs` | `run-original-tests.sh` version + `check-abi.sh` export-set check | Implemented libgpg-error wrapper surface. |
| `gcry_strerror` | header+visibility | `safe/src/error.rs` | `run-original-tests.sh` version + `check-abi.sh` export-set check | Implemented libgpg-error wrapper surface. |
| `gcry_strsource` | header+visibility | `safe/src/error.rs` | `check-abi.sh` export-set check | Implemented libgpg-error wrapper surface. |
| `gcry_free` | header+visibility | `safe/src/alloc.rs` | `run-original-tests.sh` t-secmem + `check-abi.sh` export-set check | Implemented runtime-shell allocation path. |
| `gcry_malloc` | header+visibility | `safe/src/alloc.rs` | `run-original-tests.sh` t-secmem + `check-abi.sh` export-set check | Implemented runtime-shell allocation path. |
| `gcry_malloc_secure` | header+visibility | `safe/src/alloc.rs` + `safe/src/secmem.rs` | `run-original-tests.sh` t-secmem + `check-abi.sh` export-set check | Implemented runtime-shell secure allocation path with locked-page attempts and pool accounting. |
| `gcry_calloc` | header+visibility | `safe/src/alloc.rs` | `run-original-tests.sh` t-secmem + `check-abi.sh` export-set check | Implemented runtime-shell allocation path. |
| `gcry_calloc_secure` | header+visibility | `safe/src/alloc.rs` + `safe/src/secmem.rs` | `run-original-tests.sh` t-secmem + `check-abi.sh` export-set check | Implemented runtime-shell secure allocation path. |
| `gcry_realloc` | header+visibility | `safe/src/alloc.rs` + `safe/src/secmem.rs` | `run-original-tests.sh` t-secmem + `check-abi.sh` export-set check | Implemented runtime-shell realloc path for plain and secure allocations. |
| `gcry_strdup` | header+visibility | `safe/src/alloc.rs` | `run-original-tests.sh` t-secmem + `check-abi.sh` export-set check | Implemented runtime-shell duplication path, preserving secure memory when applicable. |
| `gcry_is_secure` | header+visibility | `safe/src/alloc.rs` + `safe/src/secmem.rs` | `run-original-tests.sh` t-secmem + `check-abi.sh` export-set check | Implemented runtime-shell secure-pointer query. |
| `gcry_xcalloc` | header+visibility | `safe/src/alloc.rs` | `run-original-tests.sh` t-secmem + `check-abi.sh` export-set check | Implemented runtime-shell xalloc path with out-of-core handling. |
| `gcry_xcalloc_secure` | header+visibility | `safe/src/alloc.rs` + `safe/src/secmem.rs` | `run-original-tests.sh` t-secmem + `check-abi.sh` export-set check | Implemented runtime-shell secure xalloc path with overflow support. |
| `gcry_xmalloc` | header+visibility | `safe/src/alloc.rs` | `run-original-tests.sh` t-secmem + `check-abi.sh` export-set check | Implemented runtime-shell xalloc path with out-of-core handling. |
| `gcry_xmalloc_secure` | header+visibility | `safe/src/alloc.rs` + `safe/src/secmem.rs` | `run-original-tests.sh` t-secmem + `check-abi.sh` export-set check | Implemented runtime-shell secure xalloc path with overflow support. |
| `gcry_xrealloc` | header+visibility | `safe/src/alloc.rs` + `safe/src/secmem.rs` | `run-original-tests.sh` t-secmem + `check-abi.sh` export-set check | Implemented runtime-shell xrealloc path with out-of-core handling. |
| `gcry_xstrdup` | header+visibility | `safe/src/alloc.rs` | `run-original-tests.sh` t-secmem + `check-abi.sh` export-set check | Implemented runtime-shell xstrdup path with secure-memory preservation. |
| `gcry_md_algo_info` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_md_algo_name` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_md_close` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_md_copy` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_md_ctl` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_md_enable` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_md_get` | visibility-only | `safe/src/ffi.rs` | Phase 4 md harness + bootstrap export-set check | Visibility-only export; phase 4 owner. |
| `gcry_md_get_algo` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_md_get_algo_dlen` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_md_hash_buffer` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_md_hash_buffers` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_md_info` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_md_is_enabled` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_md_is_secure` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_md_map_name` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_md_open` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_md_read` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_md_extract` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_md_reset` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_md_setkey` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_md_write` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_md_debug` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_cipher_algo_info` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_cipher_algo_name` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_cipher_close` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_cipher_ctl` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_cipher_decrypt` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_cipher_encrypt` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_cipher_get_algo_blklen` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_cipher_get_algo_keylen` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_cipher_info` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_cipher_map_name` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_cipher_mode_from_oid` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_cipher_open` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_cipher_setkey` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_cipher_setiv` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_cipher_setctr` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_cipher_authenticate` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_cipher_gettag` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_cipher_checktag` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_mac_algo_info` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_mac_algo_name` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_mac_map_name` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_mac_get_algo_maclen` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_mac_get_algo_keylen` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_mac_get_algo` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_mac_open` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_mac_close` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_mac_setkey` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_mac_setiv` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_mac_write` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_mac_read` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_mac_verify` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_mac_ctl` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_pk_algo_info` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_pk_algo_name` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_pk_ctl` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_pk_decrypt` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_pk_encrypt` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_pk_genkey` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_pk_get_keygrip` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_pk_get_nbits` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_pk_map_name` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_pk_register` | abi-only | `safe/src/ffi.rs` | Phase 6 pk harness + bootstrap export-set check | ABI-only export; phase 6 owner. |
| `gcry_pk_sign` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_pk_testkey` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_pk_verify` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_pk_get_curve` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_pk_get_param` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_pubkey_get_sexp` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_ecc_get_algo_keylen` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_ecc_mul_point` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_kdf_derive` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_prime_check` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_prime_generate` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_prime_group_generator` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_prime_release_factors` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_random_add_bytes` | header+visibility | `safe/src/alloc.rs` | `run-original-tests.sh` t-secmem + `check-abi.sh` export-set check | Implemented runtime-shell compatibility no-op. |
| `gcry_random_bytes` | header+visibility | `safe/src/alloc.rs` + `safe/src/os_rng.rs` | `run-original-tests.sh` t-secmem + `check-abi.sh` export-set check | Implemented runtime-shell OS-backed random byte allocation. |
| `gcry_random_bytes_secure` | header+visibility | `safe/src/alloc.rs` + `safe/src/os_rng.rs` + `safe/src/secmem.rs` | `run-original-tests.sh` t-secmem + `check-abi.sh` export-set check | Implemented runtime-shell secure random allocation. |
| `gcry_randomize` | header+visibility | `safe/src/alloc.rs` + `safe/src/os_rng.rs` | `run-original-tests.sh` t-secmem + `check-abi.sh` export-set check | Implemented runtime-shell OS-backed buffer fill. |
| `gcry_create_nonce` | header+visibility | `safe/src/alloc.rs` + `safe/src/os_rng.rs` | `run-original-tests.sh` t-secmem + `check-abi.sh` export-set check | Implemented runtime-shell nonce generation. |
| `gcry_sexp_alist` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_sexp_append` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_sexp_build` | header+visibility | `safe/cabi/exports.c` -> `safe/src/ffi.rs` | `check-abi.sh` variadic smoke + export-set check | Bootstrap variadic shim. |
| `gcry_sexp_build_array` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_sexp_cadr` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_sexp_canon_len` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_sexp_car` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_sexp_cdr` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_sexp_cons` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_sexp_create` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_sexp_dump` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_sexp_find_token` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_sexp_length` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_sexp_new` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_sexp_nth` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_sexp_nth_buffer` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_sexp_nth_data` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_sexp_nth_mpi` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_sexp_prepend` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_sexp_release` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_sexp_sprint` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_sexp_sscan` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_sexp_vlist` | header+visibility | `safe/cabi/exports.c` -> `safe/src/ffi.rs` | `check-abi.sh` variadic smoke + export-set check | Bootstrap variadic shim. |
| `gcry_sexp_nth_string` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_sexp_extract_param` | header+visibility | `safe/cabi/exports.c` -> `safe/src/ffi.rs` | `check-abi.sh` variadic smoke + export-set check | Bootstrap variadic shim. |
| `gcry_mpi_is_neg` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_mpi_neg` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_mpi_abs` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_mpi_add` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_mpi_add_ui` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_mpi_addm` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_mpi_aprint` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_mpi_clear_bit` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_mpi_clear_flag` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_mpi_clear_highbit` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_mpi_cmp` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_mpi_cmp_ui` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_mpi_copy` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_mpi_div` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_mpi_dump` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_mpi_gcd` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_mpi_get_flag` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_mpi_get_nbits` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_mpi_get_opaque` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_mpi_invm` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_mpi_mod` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_mpi_mul` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_mpi_mul_2exp` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_mpi_mul_ui` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_mpi_mulm` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_mpi_new` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_mpi_powm` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_mpi_print` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_mpi_randomize` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_mpi_release` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_mpi_rshift` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_mpi_scan` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_mpi_set` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_mpi_set_bit` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_mpi_set_flag` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_mpi_set_highbit` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_mpi_set_opaque` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_mpi_set_opaque_copy` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_mpi_set_ui` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_mpi_snew` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_mpi_sub` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_mpi_sub_ui` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_mpi_subm` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_mpi_swap` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_mpi_test_bit` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_mpi_lshift` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_mpi_snatch` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_mpi_point_new` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_mpi_point_release` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_mpi_point_get` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_mpi_point_snatch_get` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_mpi_point_set` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_mpi_point_snatch_set` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_mpi_ec_new` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_mpi_ec_get_mpi` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_mpi_ec_get_point` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_mpi_ec_set_mpi` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_mpi_ec_set_point` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_mpi_ec_get_affine` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_mpi_ec_dup` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_mpi_ec_add` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_mpi_ec_sub` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_mpi_ec_mul` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_mpi_ec_curve_point` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_mpi_ec_decode_point` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_mpi_point_copy` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_mpi_get_ui` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_log_debug` | header+visibility | `safe/cabi/exports.c` -> `safe/src/log.rs` | `check-abi.sh` variadic smoke + export-set check | Implemented runtime-shell variadic log dispatch. |
| `gcry_log_debughex` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_log_debugmpi` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_log_debugpnt` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_log_debugsxp` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_get_config` | header+visibility | `safe/src/config.rs` | `run-original-tests.sh` version + `check-abi.sh` export-set check | Implemented runtime-shell config surface, including `version`, `cpu-arch`, and `rng-type`. |
| `_gcry_mpi_get_const` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_ctx_release` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_pk_hash_sign` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_pk_hash_verify` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_pk_random_override_new` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_kdf_open` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_kdf_compute` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_kdf_final` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
| `gcry_kdf_close` | header+visibility | `safe/src/ffi.rs` | `check-abi.sh` export-set check | Bootstrap compatibility stub. |
