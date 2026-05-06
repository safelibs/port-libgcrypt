# High-level architecture

`safe/` is a Rust implementation of the libgcrypt 1.10.3 public surface with a deliberately small C ABI shim. The intended original ABI/API boundary is the C ABI described by `safe/abi/libgcrypt.vers` and the rendered public header produced from `safe/abi/gcrypt.h.in`. The implementation does not keep a runtime bridge to `original/libgcrypt20-1.10.3/`: `bash safe/scripts/check-no-upstream-bridge.sh` passed, and `safe/docs/bridge-inventory.md` records no current bridge or fallback references.

`safe/Cargo.toml` defines a single-member workspace whose package is `safe` version `0.1.0`, edition `2024`. The library target is named `gcrypt` and has crate types `staticlib` and `rlib`; there is no `cdylib` target, no Cargo features, and no `cbindgen` or `bindgen` build step. The three Cargo binaries are `dumpsexp`, `hmac256`, and `mpicalc`. `[profile.release] panic = "abort"` is part of the ABI/runtime contract: a panic crossing an exported C boundary aborts the process instead of unwinding through C callers.

`safe/build.rs` is the bootstrap renderer and ownership gate. It renders `safe/target/bootstrap/generated/include/gcrypt.h`, `safe/target/bootstrap/generated/pkgconfig/libgcrypt.pc`, `safe/target/bootstrap/generated/bin/libgcrypt-config`, and `safe/target/bootstrap/generated/share/aclocal/libgcrypt.m4` from the committed inputs `safe/abi/gcrypt.h.in`, `safe/abi/libgcrypt.pc.in`, `safe/abi/libgcrypt-config.in`, and `safe/abi/libgcrypt.m4`. It parses `safe/abi/libgcrypt.vers`, verifies every public symbol is owned by Rust or `safe/cabi/exports.c`, compiles `safe/cabi/exports.c` plus generated C into `libsafe_cabi.a`, links `safe_cabi`, and emits `cargo:rustc-link-lib=gmp`.

`safe/debian/rules` builds Cargo offline with the pinned toolchain and then links `safe/target/release/libgcrypt.so` from `safe/target/release/libgcrypt.a` using `safe/abi/libgcrypt.vers` plus `-lgpg-error`, `-lgmp`, `-lpthread`, `-lm`, `-lc`, and `-lgcc_s`. The runtime and development payloads are split into `libgcrypt20` and `libgcrypt20-dev` through `safe/debian/libgcrypt20.install` and `safe/debian/libgcrypt20-dev.install`. Top-level CI runs `scripts/build-debs.sh`; that script sources `scripts/lib/build-deb-common.sh`, prepares Rust, stamps `safe/debian/changelog`, performs a full source and binary `dpkg-buildpackage`, and copies artifacts to root `dist/`. The port-local `safe/scripts/build-debs.sh` builds binary packages from `safe/` into ignored `safe/dist/` and writes `safe/dist/safe-debs.manifest.json` for local validator and package checks.

Public calls enter through three shapes:

1. Direct Rust `pub extern "C"` exports with public `gcry_*` names. Example: `gcry_cipher_encrypt` is exported from `safe/src/cipher/mod.rs:133`, calls `block::encrypt` in `safe/src/cipher/block.rs:37`, validates the handle with `ctx`, rejects missing keys, converts either in-place or separate pointer/length inputs into a Rust byte vector, dispatches into `safe/src/cipher/local.rs`, and copies the output back to the caller buffer or returns a libgcrypt-compatible error code.
2. Fixed-signature public C `FORWARD*` wrappers in `safe/cabi/exports.c`. Example: `gcry_md_get` is exported by `FORWARD4` at `safe/cabi/exports.c:126`, forwards to `safe_gcry_md_get`, and reaches `safe/src/digest/mod.rs:645`. Rust validates the digest handle, output buffer, and length, rejects FIPS mode, resolves the algorithm, handles XOFs through `gcry_md_extract`, reads the digest from the Rust `DigestContext`, copies bytes into the caller buffer, and returns `0`, `GPG_ERR_INV_ARG`, `GPG_ERR_NOT_SUPPORTED`, or `GPG_ERR_TOO_SHORT` through the libgcrypt error shape. `gcry_check_version`, `gcry_pk_register`, and `gcry_log_debughex` follow the same C-forwarder pattern into `safe_gcry_check_version`, `safe_gcry_pk_register`, and `safe_gcry_log_debughex`.
3. C varargs or libc-sensitive shim exports in `safe/cabi/exports.c`. Example: `gcry_control` at `safe/cabi/exports.c:139` normalizes `va_arg` values for commands such as `GCRYCTL_DISABLE_HWF`, `GCRYCTL_PRINT_CONFIG`, and `GCRYCTL_DRBG_REINIT`, then calls `safe_gcry_control_dispatch` in `safe/src/global.rs:278`. Rust updates runtime state, disabled hardware-feature bookkeeping, secure-memory state, RNG settings, logging, or config output and returns a `gcry_error_t`. `gcry_sexp_build`, `gcry_sexp_vlist`, `gcry_sexp_extract_param`, and `gcry_log_debug` similarly normalize varargs, strings, temporary arrays, or formatted log messages before calling fixed Rust dispatchers in `safe/src/sexp.rs` and `safe/src/log.rs`.

Module ownership is split by libgcrypt surface. `alloc`, `secmem`, `context`, `global`, `config`, `error`, and `log` own runtime shell state and ABI compatibility state. `hwfeatures` owns hardware feature token validation, active-feature detection, and disabled-feature bookkeeping used by `GCRYCTL_DISABLE_HWF` and config output. `random`, `drbg`, and `os_rng` own random generation and OS entropy. `digest`, `mac`, `kdf`, and `cipher` own symmetric primitives and registry surfaces. `mpi`, `mpi/arith`, `mpi/scan`, `mpi/prime`, `mpi/ec`, `sexp`, and `pubkey` own S-expression, big integer, ECC, and public-key surfaces. `safe/src/upstream.rs` is only a compatibility struct definition for `gcry_buffer_t`; it is not an upstream runtime bridge.

Directory map:

- `safe/src`: Rust implementation modules and exported C ABI functions.
- `safe/src/bin`: installed compatibility tools `dumpsexp`, `hmac256`, and `mpicalc`, which call through the built libgcrypt ABI.
- `safe/abi`: committed ABI inputs: `safe/abi/gcrypt.h.in`, `safe/abi/libgcrypt.vers`, `safe/abi/libgcrypt.pc.in`, `safe/abi/libgcrypt-config.in`, and `safe/abi/libgcrypt.m4`.
- `safe/cabi`: fixed C forwarders, varargs shims, and C declarations for Rust `safe_*` dispatchers.
- `safe/debian`: Debian package metadata, installed-file manifests, symbols, changelog, and the shared-library link step.
- `safe/scripts`: port-local build, ABI, package, upstream, regression, dependent, validator, and bridge checks.
- `safe/tests`: imported upstream tests, compatibility smoke probes, dependent matrix fixtures, and regression scripts.
- `safe/docs`: existing ABI, bridge, test, and CVE evidence consumed by this document.
- `safe/vendor`: vendored Cargo dependency source used by offline builds through `.cargo/config.toml` and `safe/.cargo/config.toml`.
- `original/libgcrypt20-1.10.3`: source and test comparison input; it is not linked as a runtime bridge.

# Where the unsafe Rust lives

Current unsafe counts were regenerated with `rg -n '\bunsafe\b'` over the requested path sets. The implementation inventories contain 1533 matches: 780 source-owned matches in `safe/src`, `safe/build.rs`, and `safe/cabi`, plus 753 vendored matches under `safe/vendor`. After this document exists, the broader `safe/` scan that excludes `target`, `debian`, and `dist` reports 1810 matches because `safe/PORT.md` itself contributes 277 documentation matches; those are not implementation unsafe and are not included in the source or vendor inventories below. The inventory below includes all generated implementation `rg` matches, including vendored documentation or comment matches, so comment-only occurrences are explicitly categorized rather than silently excluded.

Source-owned unsafe falls into these purposes: export attributes and ABI shims, C callback and raw pointer handlers required by the libgcrypt ABI, allocator and secure-memory integration, OS/libc/libgpg-error/GMP FFI, pointer-to-slice conversions and C string reads, Box/raw ownership transfers for opaque handles, explicit `unsafe impl Send` wrappers for callback state, and helper-binary ABI self-calls. Unsafe not strictly required by the original libgcrypt ABI/API boundary includes GMP/libgpg-error/libc/OS calls, build-time C compilation, helper-binary extern declarations, and some internal pointer manipulation that can be narrowed or replaced by safer local wrappers over time.

## Source-Owned Unsafe Inventory

- `safe/src/random.rs:128` | pointer-to-slice conversion. The ABI passes pointer and length pairs that must be viewed as Rust slices after null/length checks.
- `safe/src/random.rs:181` | C string read. The ABI passes NUL-terminated strings, which Rust validates before using as text or bytes.
- `safe/src/random.rs:197` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/random.rs:199` | pointer-to-slice conversion. The ABI passes pointer and length pairs that must be viewed as Rust slices after null/length checks.
- `safe/src/random.rs:220` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/random.rs:228` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/random.rs:235` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/random.rs:244` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/random.rs:252` | pointer-to-slice conversion. The ABI passes pointer and length pairs that must be viewed as Rust slices after null/length checks.
- `safe/src/random.rs:258` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/random.rs:266` | pointer-to-slice conversion. The ABI passes pointer and length pairs that must be viewed as Rust slices after null/length checks.
- `safe/src/random.rs:272` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/random.rs:278` | pointer-to-slice conversion. The ABI passes pointer and length pairs that must be viewed as Rust slices after null/length checks.
- `safe/src/random.rs:282` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/random.rs:288` | pointer-to-slice conversion. The ABI passes pointer and length pairs that must be viewed as Rust slices after null/length checks.
- `safe/src/pubkey/encoding.rs:75` | pointer-to-slice conversion. The ABI passes pointer and length pairs that must be viewed as Rust slices after null/length checks.
- `safe/src/pubkey/encoding.rs:131` | opaque handle ownership. Opaque C handles are represented by Rust allocations and converted at the ABI boundary.
- `safe/src/pubkey/encoding.rs:198` | opaque handle ownership. Opaque C handles are represented by Rust allocations and converted at the ABI boundary.
- `safe/src/pubkey/encoding.rs:307` | C string read. The ABI passes NUL-terminated strings, which Rust validates before using as text or bytes.
- `safe/src/pubkey/keygrip.rs:152` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/pubkey/keygrip.rs:169` | raw pointer read/write. The public ABI writes C-compatible output buffers or reads caller-provided raw pointers.
- `safe/src/digest/algorithms.rs:538` | C string read. The ABI passes NUL-terminated strings, which Rust validates before using as text or bytes.
- `safe/src/pubkey/mod.rs:151` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/pubkey/mod.rs:203` | pointer-to-slice conversion. The ABI passes pointer and length pairs that must be viewed as Rust slices after null/length checks.
- `safe/src/pubkey/mod.rs:208` | C string read. The ABI passes NUL-terminated strings, which Rust validates before using as text or bytes.
- `safe/src/pubkey/mod.rs:261` | C string read. The ABI passes NUL-terminated strings, which Rust validates before using as text or bytes.
- `safe/src/pubkey/mod.rs:263` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/pubkey/mod.rs:280` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/pubkey/mod.rs:310` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/pubkey/mod.rs:340` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/pubkey/mod.rs:375` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/pubkey/mod.rs:406` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/pubkey/mod.rs:433` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/pubkey/mod.rs:467` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/pubkey/mod.rs:474` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/pubkey/mod.rs:482` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/pubkey/mod.rs:497` | raw pointer read/write. The public ABI writes C-compatible output buffers or reads caller-provided raw pointers.
- `safe/src/pubkey/mod.rs:519` | raw pointer read/write. The public ABI writes C-compatible output buffers or reads caller-provided raw pointers.
- `safe/src/pubkey/mod.rs:526` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/pubkey/mod.rs:531` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/pubkey/mod.rs:536` | C string read. The ABI passes NUL-terminated strings, which Rust validates before using as text or bytes.
- `safe/src/pubkey/mod.rs:553` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/pubkey/mod.rs:582` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/pubkey/mod.rs:603` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/pubkey/mod.rs:620` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/pubkey/mod.rs:632` | pointer-to-slice conversion. The ABI passes pointer and length pairs that must be viewed as Rust slices after null/length checks.
- `safe/src/pubkey/mod.rs:634` | opaque handle ownership. Opaque C handles are represented by Rust allocations and converted at the ABI boundary.
- `safe/src/pubkey/mod.rs:638` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/pubkey/dsa.rs:204` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/pubkey/dsa.rs:556` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/digest/mod.rs:231` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/digest/mod.rs:235` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/digest/mod.rs:243` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/digest/mod.rs:247` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/digest/mod.rs:255` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/digest/mod.rs:260` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/digest/mod.rs:264` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/digest/mod.rs:270` | raw pointer read/write. The public ABI writes C-compatible output buffers or reads caller-provided raw pointers.
- `safe/src/digest/mod.rs:288` | pointer-to-slice conversion. The ABI passes pointer and length pairs that must be viewed as Rust slices after null/length checks.
- `safe/src/digest/mod.rs:291` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/digest/mod.rs:298` | raw pointer read/write. The public ABI writes C-compatible output buffers or reads caller-provided raw pointers.
- `safe/src/digest/mod.rs:306` | raw pointer read/write. The public ABI writes C-compatible output buffers or reads caller-provided raw pointers.
- `safe/src/digest/mod.rs:317` | opaque handle ownership. Opaque C handles are represented by Rust allocations and converted at the ABI boundary.
- `safe/src/digest/mod.rs:321` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/digest/mod.rs:326` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/digest/mod.rs:334` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/digest/mod.rs:342` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/digest/mod.rs:358` | opaque handle ownership. Opaque C handles are represented by Rust allocations and converted at the ABI boundary.
- `safe/src/digest/mod.rs:362` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/digest/mod.rs:367` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/digest/mod.rs:373` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/digest/mod.rs:393` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/digest/mod.rs:405` | pointer-to-slice conversion. The ABI passes pointer and length pairs that must be viewed as Rust slices after null/length checks.
- `safe/src/digest/mod.rs:411` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/digest/mod.rs:419` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/digest/mod.rs:437` | raw pointer read/write. The public ABI writes C-compatible output buffers or reads caller-provided raw pointers.
- `safe/src/digest/mod.rs:442` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/digest/mod.rs:455` | pointer-to-slice conversion. The ABI passes pointer and length pairs that must be viewed as Rust slices after null/length checks.
- `safe/src/digest/mod.rs:458` | raw pointer read/write. The public ABI writes C-compatible output buffers or reads caller-provided raw pointers.
- `safe/src/digest/mod.rs:462` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/digest/mod.rs:494` | raw pointer read/write. The public ABI writes C-compatible output buffers or reads caller-provided raw pointers.
- `safe/src/digest/mod.rs:508` | raw pointer read/write. The public ABI writes C-compatible output buffers or reads caller-provided raw pointers.
- `safe/src/digest/mod.rs:512` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/digest/mod.rs:519` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/digest/mod.rs:524` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/digest/mod.rs:531` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/digest/mod.rs:538` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/digest/mod.rs:553` | raw pointer read/write. The public ABI writes C-compatible output buffers or reads caller-provided raw pointers.
- `safe/src/digest/mod.rs:560` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/digest/mod.rs:561` | raw pointer read/write. The public ABI writes C-compatible output buffers or reads caller-provided raw pointers.
- `safe/src/digest/mod.rs:568` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/digest/mod.rs:590` | raw pointer read/write. The public ABI writes C-compatible output buffers or reads caller-provided raw pointers.
- `safe/src/digest/mod.rs:591` | raw pointer read/write. The public ABI writes C-compatible output buffers or reads caller-provided raw pointers.
- `safe/src/digest/mod.rs:598` | raw pointer read/write. The public ABI writes C-compatible output buffers or reads caller-provided raw pointers.
- `safe/src/digest/mod.rs:605` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/digest/mod.rs:610` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/digest/mod.rs:615` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/digest/mod.rs:627` | pointer-to-slice conversion. The ABI passes pointer and length pairs that must be viewed as Rust slices after null/length checks.
- `safe/src/digest/mod.rs:633` | pointer-to-slice conversion. The ABI passes pointer and length pairs that must be viewed as Rust slices after null/length checks.
- `safe/src/digest/mod.rs:642` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/digest/mod.rs:645` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/digest/mod.rs:687` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/pubkey/ecc.rs:208` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/pubkey/ecc.rs:222` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/pubkey/ecc.rs:253` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/pubkey/ecc.rs:262` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/pubkey/ecc.rs:267` | C string read. The ABI passes NUL-terminated strings, which Rust validates before using as text or bytes.
- `safe/src/pubkey/ecc.rs:306` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/pubkey/ecc.rs:315` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/pubkey/ecc.rs:316` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/pubkey/ecc.rs:350` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/pubkey/ecc.rs:358` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/pubkey/ecc.rs:367` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/pubkey/ecc.rs:385` | pointer-to-slice conversion. The ABI passes pointer and length pairs that must be viewed as Rust slices after null/length checks.
- `safe/src/pubkey/ecc.rs:386` | pointer-to-slice conversion. The ABI passes pointer and length pairs that must be viewed as Rust slices after null/length checks.
- `safe/src/pubkey/ecc.rs:393` | raw pointer read/write. The public ABI writes C-compatible output buffers or reads caller-provided raw pointers.
- `safe/src/pubkey/ecc.rs:439` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/pubkey/ecc.rs:469` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/pubkey/ecc.rs:647` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/pubkey/ecc.rs:824` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/pubkey/ecc.rs:952` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/pubkey/ecc.rs:1058` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/pubkey/ecc.rs:1081` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/pubkey/ecc.rs:1102` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/pubkey/ecc.rs:1125` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/pubkey/elgamal.rs:227` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/pubkey/elgamal.rs:267` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/pubkey/elgamal.rs:317` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/pubkey/elgamal.rs:385` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/mpi/consts.rs:7` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/mpi/consts.rs:34` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/mpi/consts.rs:36` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/mpi/consts.rs:40` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/pubkey/rsa.rs:520` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/pubkey/rsa.rs:559` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/pubkey/rsa.rs:568` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/pubkey/rsa.rs:612` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/pubkey/rsa.rs:819` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/pubkey/rsa.rs:869` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/global.rs:100` | unsafe Send invariant. Raw callback state is stored behind a mutex and must be marked Send for global runtime state.
- `safe/src/global.rs:240` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/global.rs:243` | C string read. The ABI passes NUL-terminated strings, which Rust validates before using as text or bytes.
- `safe/src/global.rs:259` | C string read. The ABI passes NUL-terminated strings, which Rust validates before using as text or bytes.
- `safe/src/global.rs:263` | C string read. The ABI passes NUL-terminated strings, which Rust validates before using as text or bytes.
- `safe/src/global.rs:278` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/global.rs:480` | C string read. The ABI passes NUL-terminated strings, which Rust validates before using as text or bytes.
- `safe/src/global.rs:514` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/mpi/mod.rs:62` | GMP FFI declaration. The MPI implementation declares GMP entry points used by Rust-owned big integer code.
- `safe/src/mpi/mod.rs:128` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/mpi/mod.rs:142` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/mpi/mod.rs:150` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/mpi/mod.rs:220` | GMP call. Rust-owned MPI arithmetic delegates this operation to the linked GMP implementation.
- `safe/src/mpi/mod.rs:225` | GMP call. Rust-owned MPI arithmetic delegates this operation to the linked GMP implementation.
- `safe/src/mpi/mod.rs:229` | GMP call. Rust-owned MPI arithmetic delegates this operation to the linked GMP implementation.
- `safe/src/mpi/mod.rs:233` | GMP call. Rust-owned MPI arithmetic delegates this operation to the linked GMP implementation.
- `safe/src/mpi/mod.rs:237` | GMP call. Rust-owned MPI arithmetic delegates this operation to the linked GMP implementation.
- `safe/src/mpi/mod.rs:241` | GMP call. Rust-owned MPI arithmetic delegates this operation to the linked GMP implementation.
- `safe/src/mpi/mod.rs:246` | GMP call. Rust-owned MPI arithmetic delegates this operation to the linked GMP implementation.
- `safe/src/mpi/mod.rs:252` | GMP call. Rust-owned MPI arithmetic delegates this operation to the linked GMP implementation.
- `safe/src/mpi/mod.rs:258` | GMP call. Rust-owned MPI arithmetic delegates this operation to the linked GMP implementation.
- `safe/src/mpi/mod.rs:264` | GMP call. Rust-owned MPI arithmetic delegates this operation to the linked GMP implementation.
- `safe/src/mpi/mod.rs:270` | GMP call. Rust-owned MPI arithmetic delegates this operation to the linked GMP implementation.
- `safe/src/mpi/mod.rs:276` | GMP call. Rust-owned MPI arithmetic delegates this operation to the linked GMP implementation.
- `safe/src/mpi/mod.rs:282` | GMP call. Rust-owned MPI arithmetic delegates this operation to the linked GMP implementation.
- `safe/src/mpi/mod.rs:288` | GMP call. Rust-owned MPI arithmetic delegates this operation to the linked GMP implementation.
- `safe/src/mpi/mod.rs:295` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/mpi/mod.rs:308` | GMP call. Rust-owned MPI arithmetic delegates this operation to the linked GMP implementation.
- `safe/src/mpi/mod.rs:313` | GMP call. Rust-owned MPI arithmetic delegates this operation to the linked GMP implementation.
- `safe/src/mpi/mod.rs:318` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/mpi/mod.rs:335` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/mpi/mod.rs:348` | GMP call. Rust-owned MPI arithmetic delegates this operation to the linked GMP implementation.
- `safe/src/mpi/mod.rs:354` | GMP call. Rust-owned MPI arithmetic delegates this operation to the linked GMP implementation.
- `safe/src/mpi/mod.rs:360` | GMP call. Rust-owned MPI arithmetic delegates this operation to the linked GMP implementation.
- `safe/src/mpi/mod.rs:365` | GMP call. Rust-owned MPI arithmetic delegates this operation to the linked GMP implementation.
- `safe/src/mpi/mod.rs:370` | GMP call. Rust-owned MPI arithmetic delegates this operation to the linked GMP implementation.
- `safe/src/mpi/mod.rs:376` | GMP call. Rust-owned MPI arithmetic delegates this operation to the linked GMP implementation.
- `safe/src/mpi/mod.rs:415` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/mpi/mod.rs:442` | pointer-to-slice conversion. The ABI passes pointer and length pairs that must be viewed as Rust slices after null/length checks.
- `safe/src/mpi/mod.rs:505` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/mpi/mod.rs:506` | opaque handle ownership. Opaque C handles are represented by Rust allocations and converted at the ABI boundary.
- `safe/src/mpi/mod.rs:509` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/mpi/mod.rs:510` | opaque handle ownership. Opaque C handles are represented by Rust allocations and converted at the ABI boundary.
- `safe/src/mpi/mod.rs:602` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/mpi/mod.rs:626` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/mpi/mod.rs:633` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/mpi/mod.rs:637` | GMP call. Rust-owned MPI arithmetic delegates this operation to the linked GMP implementation.
- `safe/src/mpi/mod.rs:641` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/mpi/mod.rs:648` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/mpi/mod.rs:652` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/mpi/mod.rs:659` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/mpi/mod.rs:696` | GMP call. Rust-owned MPI arithmetic delegates this operation to the linked GMP implementation.
- `safe/src/mpi/mod.rs:704` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/mpi/mod.rs:724` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/mpi/mod.rs:741` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/mpi/mod.rs:746` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/mpi/mod.rs:751` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/mpi/mod.rs:757` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/mpi/mod.rs:762` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/mpi/mod.rs:767` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/mpi/mod.rs:769` | opaque handle ownership. Opaque C handles are represented by Rust allocations and converted at the ABI boundary.
- `safe/src/mpi/mod.rs:772` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/mpi/mod.rs:778` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/mpi/mod.rs:786` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/mpi/mod.rs:788` | opaque handle ownership. Opaque C handles are represented by Rust allocations and converted at the ABI boundary.
- `safe/src/mpi/mod.rs:797` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/mpi/mod.rs:806` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/mpi/mod.rs:808` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/mpi/mod.rs:813` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/mpi/mod.rs:815` | opaque handle ownership. Opaque C handles are represented by Rust allocations and converted at the ABI boundary.
- `safe/src/mpi/mod.rs:824` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/mpi/mod.rs:825` | GMP call. Rust-owned MPI arithmetic delegates this operation to the linked GMP implementation.
- `safe/src/mpi/mod.rs:829` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/mpi/mod.rs:838` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/mpi/mod.rs:843` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/mpi/mod.rs:850` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/mpi/mod.rs:852` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/mpi/mod.rs:860` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/mpi/mod.rs:863` | opaque handle ownership. Opaque C handles are represented by Rust allocations and converted at the ABI boundary.
- `safe/src/mpi/mod.rs:868` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/mpi/mod.rs:883` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/mpi/mod.rs:886` | opaque handle ownership. Opaque C handles are represented by Rust allocations and converted at the ABI boundary.
- `safe/src/mpi/mod.rs:889` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/mpi/mod.rs:902` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/mpi/mod.rs:904` | opaque handle ownership. Opaque C handles are represented by Rust allocations and converted at the ABI boundary.
- `safe/src/mpi/mod.rs:914` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/mpi/mod.rs:916` | opaque handle ownership. Opaque C handles are represented by Rust allocations and converted at the ABI boundary.
- `safe/src/mpi/mod.rs:921` | GMP call. Rust-owned MPI arithmetic delegates this operation to the linked GMP implementation.
- `safe/src/mpi/mod.rs:925` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/mpi/mod.rs:927` | opaque handle ownership. Opaque C handles are represented by Rust allocations and converted at the ABI boundary.
- `safe/src/mpi/mod.rs:933` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/mpi/mod.rs:937` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/mpi/mod.rs:946` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/mpi/mod.rs:948` | opaque handle ownership. Opaque C handles are represented by Rust allocations and converted at the ABI boundary.
- `safe/src/mpi/mod.rs:967` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/mpi/mod.rs:975` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/mpi/mod.rs:977` | opaque handle ownership. Opaque C handles are represented by Rust allocations and converted at the ABI boundary.
- `safe/src/mpi/mod.rs:980` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/mpi/mod.rs:985` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/mpi/mod.rs:987` | opaque handle ownership. Opaque C handles are represented by Rust allocations and converted at the ABI boundary.
- `safe/src/mpi/mod.rs:990` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/mpi/mod.rs:995` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/mpi/mod.rs:997` | opaque handle ownership. Opaque C handles are represented by Rust allocations and converted at the ABI boundary.
- `safe/src/mpi/mod.rs:1001` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/mpi/mod.rs:1008` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/mpi/mod.rs:1010` | opaque handle ownership. Opaque C handles are represented by Rust allocations and converted at the ABI boundary.
- `safe/src/mpi/mod.rs:1014` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/mpi/mod.rs:1020` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/mpi/mod.rs:1023` | opaque handle ownership. Opaque C handles are represented by Rust allocations and converted at the ABI boundary.
- `safe/src/mpi/mod.rs:1027` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/mpi/mod.rs:1044` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/mpi/mod.rs:1047` | opaque handle ownership. Opaque C handles are represented by Rust allocations and converted at the ABI boundary.
- `safe/src/mpi/mod.rs:1051` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/mpi/mod.rs:1068` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/mpi/mod.rs:1070` | opaque handle ownership. Opaque C handles are represented by Rust allocations and converted at the ABI boundary.
- `safe/src/mpi/mod.rs:1087` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/mpi/mod.rs:1089` | opaque handle ownership. Opaque C handles are represented by Rust allocations and converted at the ABI boundary.
- `safe/src/mpi/mod.rs:1101` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/mpi/mod.rs:1103` | opaque handle ownership. Opaque C handles are represented by Rust allocations and converted at the ABI boundary.
- `safe/src/mpi/mod.rs:1117` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/mpi/mod.rs:1119` | opaque handle ownership. Opaque C handles are represented by Rust allocations and converted at the ABI boundary.
- `safe/src/mpi/mod.rs:1123` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/mpi/mod.rs:1141` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/mpi/mod.rs:1143` | opaque handle ownership. Opaque C handles are represented by Rust allocations and converted at the ABI boundary.
- `safe/src/mpi/mod.rs:1151` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/mpi/mod.rs:1156` | C string read. The ABI passes NUL-terminated strings, which Rust validates before using as text or bytes.
- `safe/src/mpi/mod.rs:1160` | opaque handle ownership. Opaque C handles are represented by Rust allocations and converted at the ABI boundary.
- `safe/src/mpi/arith.rs:12` | opaque handle ownership. Opaque C handles are represented by Rust allocations and converted at the ABI boundary.
- `safe/src/mpi/arith.rs:19` | C FFI declaration. The Rust module declares a libc, OS, C shim, or libgcrypt ABI function.
- `safe/src/mpi/arith.rs:33` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/mpi/arith.rs:47` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/mpi/arith.rs:52` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/mpi/arith.rs:57` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/mpi/arith.rs:62` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/mpi/arith.rs:65` | opaque handle ownership. Opaque C handles are represented by Rust allocations and converted at the ABI boundary.
- `safe/src/mpi/arith.rs:69` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/mpi/arith.rs:82` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/mpi/arith.rs:85` | opaque handle ownership. Opaque C handles are represented by Rust allocations and converted at the ABI boundary.
- `safe/src/mpi/arith.rs:89` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/mpi/arith.rs:102` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/mpi/arith.rs:105` | opaque handle ownership. Opaque C handles are represented by Rust allocations and converted at the ABI boundary.
- `safe/src/mpi/arith.rs:109` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/mpi/arith.rs:127` | C FFI declaration. The Rust module declares a libc, OS, C shim, or libgcrypt ABI function.
- `safe/src/mpi/arith.rs:136` | opaque handle ownership. Opaque C handles are represented by Rust allocations and converted at the ABI boundary.
- `safe/src/mpi/arith.rs:139` | opaque handle ownership. Opaque C handles are represented by Rust allocations and converted at the ABI boundary.
- `safe/src/mpi/arith.rs:142` | opaque handle ownership. Opaque C handles are represented by Rust allocations and converted at the ABI boundary.
- `safe/src/mpi/arith.rs:146` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/mpi/arith.rs:168` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/mpi/arith.rs:178` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/mpi/arith.rs:188` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/mpi/arith.rs:198` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/mpi/arith.rs:201` | opaque handle ownership. Opaque C handles are represented by Rust allocations and converted at the ABI boundary.
- `safe/src/mpi/arith.rs:205` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/mpi/arith.rs:222` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/mpi/arith.rs:232` | opaque handle ownership. Opaque C handles are represented by Rust allocations and converted at the ABI boundary.
- `safe/src/mpi/arith.rs:235` | opaque handle ownership. Opaque C handles are represented by Rust allocations and converted at the ABI boundary.
- `safe/src/mpi/arith.rs:256` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/mpi/arith.rs:293` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/mpi/arith.rs:297` | opaque handle ownership. Opaque C handles are represented by Rust allocations and converted at the ABI boundary.
- `safe/src/mpi/arith.rs:300` | opaque handle ownership. Opaque C handles are represented by Rust allocations and converted at the ABI boundary.
- `safe/src/mpi/arith.rs:304` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/mpi/arith.rs:321` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/mpi/arith.rs:331` | opaque handle ownership. Opaque C handles are represented by Rust allocations and converted at the ABI boundary.
- `safe/src/mpi/arith.rs:334` | opaque handle ownership. Opaque C handles are represented by Rust allocations and converted at the ABI boundary.
- `safe/src/mpi/arith.rs:337` | opaque handle ownership. Opaque C handles are represented by Rust allocations and converted at the ABI boundary.
- `safe/src/mpi/arith.rs:341` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/mpi/arith.rs:373` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/mpi/arith.rs:377` | opaque handle ownership. Opaque C handles are represented by Rust allocations and converted at the ABI boundary.
- `safe/src/mpi/arith.rs:380` | opaque handle ownership. Opaque C handles are represented by Rust allocations and converted at the ABI boundary.
- `safe/src/mpi/arith.rs:384` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/mpi/arith.rs:406` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/mpi/arith.rs:410` | opaque handle ownership. Opaque C handles are represented by Rust allocations and converted at the ABI boundary.
- `safe/src/mpi/arith.rs:413` | opaque handle ownership. Opaque C handles are represented by Rust allocations and converted at the ABI boundary.
- `safe/src/mpi/arith.rs:417` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/sexp.rs:18` | C callback type. The public ABI stores caller-supplied callback function pointers with C calling convention.
- `safe/src/sexp.rs:54` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/sexp.rs:55` | opaque handle ownership. Opaque C handles are represented by Rust allocations and converted at the ABI boundary.
- `safe/src/sexp.rs:522` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/sexp.rs:532` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/sexp.rs:537` | raw pointer read/write. The public ABI writes C-compatible output buffers or reads caller-provided raw pointers.
- `safe/src/sexp.rs:770` | pointer-to-slice conversion. The ABI passes pointer and length pairs that must be viewed as Rust slices after null/length checks.
- `safe/src/sexp.rs:779` | C string read. The ABI passes NUL-terminated strings, which Rust validates before using as text or bytes.
- `safe/src/sexp.rs:794` | opaque handle ownership. Opaque C handles are represented by Rust allocations and converted at the ABI boundary.
- `safe/src/sexp.rs:809` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/sexp.rs:815` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/sexp.rs:821` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/sexp.rs:912` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/sexp.rs:922` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/sexp.rs:925` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/sexp.rs:932` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/sexp.rs:939` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/sexp.rs:944` | opaque handle ownership. Opaque C handles are represented by Rust allocations and converted at the ABI boundary.
- `safe/src/sexp.rs:946` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/sexp.rs:1008` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/sexp.rs:1018` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/sexp.rs:1027` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/sexp.rs:1065` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/sexp.rs:1210` | opaque handle ownership. Opaque C handles are represented by Rust allocations and converted at the ABI boundary.
- `safe/src/sexp.rs:1261` | C string read. The ABI passes NUL-terminated strings, which Rust validates before using as text or bytes.
- `safe/src/sexp.rs:1283` | pointer-to-slice conversion. The ABI passes pointer and length pairs that must be viewed as Rust slices after null/length checks.
- `safe/src/sexp.rs:1310` | opaque handle ownership. Opaque C handles are represented by Rust allocations and converted at the ABI boundary.
- `safe/src/sexp.rs:1335` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/sexp.rs:1345` | raw pointer read/write. The public ABI writes C-compatible output buffers or reads caller-provided raw pointers.
- `safe/src/sexp.rs:1360` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/sexp.rs:1365` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/sexp.rs:1367` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/sexp.rs:1371` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/sexp.rs:1376` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/sexp.rs:1386` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/sexp.rs:1394` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/sexp.rs:1402` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/sexp.rs:1412` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/sexp.rs:1422` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/sexp.rs:1431` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/sexp.rs:1439` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/sexp.rs:1450` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/sexp.rs:1454` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/sexp.rs:1464` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/sexp.rs:1472` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/sexp.rs:1477` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/sexp.rs:1487` | C string read. The ABI passes NUL-terminated strings, which Rust validates before using as text or bytes.
- `safe/src/sexp.rs:1491` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/sexp.rs:1502` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/sexp.rs:1511` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/sexp.rs:1519` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/sexp.rs:1524` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/sexp.rs:1531` | C string read. The ABI passes NUL-terminated strings, which Rust validates before using as text or bytes.
- `safe/src/sexp.rs:1532` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/sexp.rs:1536` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/sexp.rs:1545` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/sexp.rs:1552` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/sexp.rs:1561` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/sexp.rs:1566` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/sexp.rs:1571` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/sexp.rs:1579` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/sexp.rs:1584` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/sexp.rs:1592` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/sexp.rs:1594` | pointer-to-slice conversion. The ABI passes pointer and length pairs that must be viewed as Rust slices after null/length checks.
- `safe/src/sexp.rs:1602` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/sexp.rs:1607` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/sexp.rs:1616` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/sexp.rs:1623` | opaque handle ownership. Opaque C handles are represented by Rust allocations and converted at the ABI boundary.
- `safe/src/sexp.rs:1639` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/sexp.rs:1646` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/sexp.rs:1648` | opaque handle ownership. Opaque C handles are represented by Rust allocations and converted at the ABI boundary.
- `safe/src/sexp.rs:1656` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/sexp.rs:1659` | opaque handle ownership. Opaque C handles are represented by Rust allocations and converted at the ABI boundary.
- `safe/src/sexp.rs:1671` | C string read. The ABI passes NUL-terminated strings, which Rust validates before using as text or bytes.
- `safe/src/sexp.rs:1683` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/sexp.rs:1685` | opaque handle ownership. Opaque C handles are represented by Rust allocations and converted at the ABI boundary.
- `safe/src/sexp.rs:1688` | opaque handle ownership. Opaque C handles are represented by Rust allocations and converted at the ABI boundary.
- `safe/src/sexp.rs:1697` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/sexp.rs:1706` | raw pointer read/write. The public ABI writes C-compatible output buffers or reads caller-provided raw pointers.
- `safe/src/sexp.rs:1710` | opaque handle ownership. Opaque C handles are represented by Rust allocations and converted at the ABI boundary.
- `safe/src/sexp.rs:1720` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/sexp.rs:1722` | opaque handle ownership. Opaque C handles are represented by Rust allocations and converted at the ABI boundary.
- `safe/src/sexp.rs:1725` | opaque handle ownership. Opaque C handles are represented by Rust allocations and converted at the ABI boundary.
- `safe/src/sexp.rs:1737` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/sexp.rs:1739` | opaque handle ownership. Opaque C handles are represented by Rust allocations and converted at the ABI boundary.
- `safe/src/sexp.rs:1742` | opaque handle ownership. Opaque C handles are represented by Rust allocations and converted at the ABI boundary.
- `safe/src/sexp.rs:1754` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/sexp.rs:1760` | opaque handle ownership. Opaque C handles are represented by Rust allocations and converted at the ABI boundary.
- `safe/src/sexp.rs:1767` | C string read. The ABI passes NUL-terminated strings, which Rust validates before using as text or bytes.
- `safe/src/sexp.rs:1769` | pointer-to-slice conversion. The ABI passes pointer and length pairs that must be viewed as Rust slices after null/length checks.
- `safe/src/sexp.rs:1774` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/sexp.rs:1776` | opaque handle ownership. Opaque C handles are represented by Rust allocations and converted at the ABI boundary.
- `safe/src/sexp.rs:1781` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/sexp.rs:1783` | opaque handle ownership. Opaque C handles are represented by Rust allocations and converted at the ABI boundary.
- `safe/src/sexp.rs:1791` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/sexp.rs:1796` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/sexp.rs:1798` | opaque handle ownership. Opaque C handles are represented by Rust allocations and converted at the ABI boundary.
- `safe/src/sexp.rs:1812` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/sexp.rs:1817` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/sexp.rs:1824` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/sexp.rs:1828` | opaque handle ownership. Opaque C handles are represented by Rust allocations and converted at the ABI boundary.
- `safe/src/sexp.rs:1835` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/sexp.rs:1842` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/sexp.rs:1849` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/sexp.rs:1853` | opaque handle ownership. Opaque C handles are represented by Rust allocations and converted at the ABI boundary.
- `safe/src/sexp.rs:1863` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/sexp.rs:1870` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/sexp.rs:1872` | opaque handle ownership. Opaque C handles are represented by Rust allocations and converted at the ABI boundary.
- `safe/src/sexp.rs:1886` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/sexp.rs:1892` | opaque handle ownership. Opaque C handles are represented by Rust allocations and converted at the ABI boundary.
- `safe/src/sexp.rs:1917` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/sexp.rs:1926` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/sexp.rs:1931` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/sexp.rs:1938` | C string read. The ABI passes NUL-terminated strings, which Rust validates before using as text or bytes.
- `safe/src/sexp.rs:1942` | pointer-to-slice conversion. The ABI passes pointer and length pairs that must be viewed as Rust slices after null/length checks.
- `safe/src/sexp.rs:1946` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/sexp.rs:1953` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/sexp.rs:1962` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/sexp.rs:1968` | opaque handle ownership. Opaque C handles are represented by Rust allocations and converted at the ABI boundary.
- `safe/src/sexp.rs:1975` | raw pointer read/write. The public ABI writes C-compatible output buffers or reads caller-provided raw pointers.
- `safe/src/sexp.rs:1976` | opaque handle ownership. Opaque C handles are represented by Rust allocations and converted at the ABI boundary.
- `safe/src/sexp.rs:1986` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/sexp.rs:1994` | opaque handle ownership. Opaque C handles are represented by Rust allocations and converted at the ABI boundary.
- `safe/src/sexp.rs:2003` | C string read. The ABI passes NUL-terminated strings, which Rust validates before using as text or bytes.
- `safe/src/sexp.rs:2005` | C string read. The ABI passes NUL-terminated strings, which Rust validates before using as text or bytes.
- `safe/src/sexp.rs:2009` | pointer-to-slice conversion. The ABI passes pointer and length pairs that must be viewed as Rust slices after null/length checks.
- `safe/src/mpi/scan.rs:18` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/mpi/scan.rs:32` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/mpi/scan.rs:35` | GMP call. Rust-owned MPI arithmetic delegates this operation to the linked GMP implementation.
- `safe/src/mpi/scan.rs:37` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/mpi/scan.rs:44` | GMP call. Rust-owned MPI arithmetic delegates this operation to the linked GMP implementation.
- `safe/src/mpi/scan.rs:52` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/mpi/scan.rs:71` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/mpi/scan.rs:81` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/mpi/scan.rs:150` | C string read. The ABI passes NUL-terminated strings, which Rust validates before using as text or bytes.
- `safe/src/mpi/scan.rs:152` | pointer-to-slice conversion. The ABI passes pointer and length pairs that must be viewed as Rust slices after null/length checks.
- `safe/src/mpi/scan.rs:197` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/mpi/scan.rs:212` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/mpi/scan.rs:235` | pointer-to-slice conversion. The ABI passes pointer and length pairs that must be viewed as Rust slices after null/length checks.
- `safe/src/mpi/scan.rs:239` | pointer-to-slice conversion. The ABI passes pointer and length pairs that must be viewed as Rust slices after null/length checks.
- `safe/src/mpi/scan.rs:246` | pointer-to-slice conversion. The ABI passes pointer and length pairs that must be viewed as Rust slices after null/length checks.
- `safe/src/mpi/scan.rs:257` | pointer-to-slice conversion. The ABI passes pointer and length pairs that must be viewed as Rust slices after null/length checks.
- `safe/src/mpi/scan.rs:269` | pointer-to-slice conversion. The ABI passes pointer and length pairs that must be viewed as Rust slices after null/length checks.
- `safe/src/mpi/scan.rs:276` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/mpi/scan.rs:285` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/mpi/scan.rs:290` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/mpi/scan.rs:304` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/mpi/scan.rs:317` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/mpi/scan.rs:326` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/mpi/scan.rs:331` | opaque handle ownership. Opaque C handles are represented by Rust allocations and converted at the ABI boundary.
- `safe/src/mpi/scan.rs:343` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/mpi/scan.rs:353` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/mpi/scan.rs:362` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/mpi/scan.rs:370` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/mpi/scan.rs:375` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/mpi/scan.rs:380` | opaque handle ownership. Opaque C handles are represented by Rust allocations and converted at the ABI boundary.
- `safe/src/mpi/scan.rs:390` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/mpi/scan.rs:406` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/context.rs:23` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/context.rs:24` | opaque handle ownership. Opaque C handles are represented by Rust allocations and converted at the ABI boundary.
- `safe/src/context.rs:38` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/context.rs:39` | opaque handle ownership. Opaque C handles are represented by Rust allocations and converted at the ABI boundary.
- `safe/src/context.rs:46` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/context.rs:47` | opaque handle ownership. Opaque C handles are represented by Rust allocations and converted at the ABI boundary.
- `safe/src/context.rs:136` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/context.rs:142` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/mpi/ec.rs:602` | opaque handle ownership. Opaque C handles are represented by Rust allocations and converted at the ABI boundary.
- `safe/src/mpi/ec.rs:607` | opaque handle ownership. Opaque C handles are represented by Rust allocations and converted at the ABI boundary.
- `safe/src/mpi/ec.rs:611` | opaque handle ownership. Opaque C handles are represented by Rust allocations and converted at the ABI boundary.
- `safe/src/mpi/ec.rs:630` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/mpi/ec.rs:636` | C string read. The ABI passes NUL-terminated strings, which Rust validates before using as text or bytes.
- `safe/src/mpi/ec.rs:1030` | C string read. The ABI passes NUL-terminated strings, which Rust validates before using as text or bytes.
- `safe/src/mpi/ec.rs:1077` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/mpi/ec.rs:1082` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/mpi/ec.rs:1085` | opaque handle ownership. Opaque C handles are represented by Rust allocations and converted at the ABI boundary.
- `safe/src/mpi/ec.rs:1089` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/mpi/ec.rs:1096` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/mpi/ec.rs:1114` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/mpi/ec.rs:1125` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/mpi/ec.rs:1152` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/mpi/ec.rs:1166` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/mpi/ec.rs:1175` | raw pointer read/write. The public ABI writes C-compatible output buffers or reads caller-provided raw pointers.
- `safe/src/mpi/ec.rs:1177` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/mpi/ec.rs:1185` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/mpi/ec.rs:1191` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/mpi/ec.rs:1197` | C string read. The ABI passes NUL-terminated strings, which Rust validates before using as text or bytes.
- `safe/src/mpi/ec.rs:1223` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/mpi/ec.rs:1229` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/mpi/ec.rs:1235` | C string read. The ABI passes NUL-terminated strings, which Rust validates before using as text or bytes.
- `safe/src/mpi/ec.rs:1249` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/mpi/ec.rs:1255` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/mpi/ec.rs:1261` | C string read. The ABI passes NUL-terminated strings, which Rust validates before using as text or bytes.
- `safe/src/mpi/ec.rs:1286` | opaque handle ownership. Opaque C handles are represented by Rust allocations and converted at the ABI boundary.
- `safe/src/mpi/ec.rs:1303` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/mpi/ec.rs:1309` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/mpi/ec.rs:1315` | C string read. The ABI passes NUL-terminated strings, which Rust validates before using as text or bytes.
- `safe/src/mpi/ec.rs:1327` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/mpi/ec.rs:1333` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/mpi/ec.rs:1336` | opaque handle ownership. Opaque C handles are represented by Rust allocations and converted at the ABI boundary.
- `safe/src/mpi/ec.rs:1354` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/mpi/ec.rs:1374` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/mpi/ec.rs:1381` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/mpi/ec.rs:1389` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/mpi/ec.rs:1399` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/mpi/ec.rs:1407` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/mpi/ec.rs:1430` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/mpi/ec.rs:1438` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/mpi/ec.rs:1448` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/mpi/ec.rs:1450` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/secmem.rs:58` | C FFI declaration. The Rust module declares a libc, OS, C shim, or libgcrypt ABI function.
- `safe/src/secmem.rs:67` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/secmem.rs:91` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/secmem.rs:95` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/secmem.rs:140` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/secmem.rs:154` | runtime FFI call. The code crosses to libc, the OS, libgpg-error, GMP, or the C logging shim for ABI-compatible behavior.
- `safe/src/secmem.rs:228` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/mpi/prime.rs:15` | C FFI declaration. The Rust module declares a libc, OS, C shim, or libgcrypt ABI function.
- `safe/src/mpi/prime.rs:24` | GMP call. Rust-owned MPI arithmetic delegates this operation to the linked GMP implementation.
- `safe/src/mpi/prime.rs:51` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/mpi/prime.rs:54` | GMP call. Rust-owned MPI arithmetic delegates this operation to the linked GMP implementation.
- `safe/src/mpi/prime.rs:66` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/mpi/prime.rs:72` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/mpi/prime.rs:84` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/mpi/prime.rs:89` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/mpi/prime.rs:109` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/mpi/prime.rs:119` | GMP call. Rust-owned MPI arithmetic delegates this operation to the linked GMP implementation.
- `safe/src/mpi/prime.rs:128` | C callback invocation. Caller-supplied C callbacks are invoked from Rust with ABI-owned arguments.
- `safe/src/mpi/prime.rs:137` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/mpi/prime.rs:145` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/mpi/prime.rs:153` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/mpi/prime.rs:155` | opaque handle ownership. Opaque C handles are represented by Rust allocations and converted at the ABI boundary.
- `safe/src/mpi/prime.rs:164` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/mpi/prime.rs:172` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/mpi/prime.rs:179` | opaque handle ownership. Opaque C handles are represented by Rust allocations and converted at the ABI boundary.
- `safe/src/mpi/prime.rs:187` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/mpi/prime.rs:193` | raw pointer read/write. The public ABI writes C-compatible output buffers or reads caller-provided raw pointers.
- `safe/src/mpi/prime.rs:203` | opaque handle ownership. Opaque C handles are represented by Rust allocations and converted at the ABI boundary.
- `safe/src/mpi/prime.rs:217` | raw pointer read/write. The public ABI writes C-compatible output buffers or reads caller-provided raw pointers.
- `safe/src/mpi/prime.rs:218` | opaque handle ownership. Opaque C handles are represented by Rust allocations and converted at the ABI boundary.
- `safe/src/mpi/prime.rs:225` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/mpi/prime.rs:234` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/mpi/prime.rs:242` | GMP call. Rust-owned MPI arithmetic delegates this operation to the linked GMP implementation.
- `safe/src/mpi/prime.rs:250` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/mpi/prime.rs:256` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/mpi/prime.rs:262` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/mpi/prime.rs:269` | raw pointer read/write. The public ABI writes C-compatible output buffers or reads caller-provided raw pointers.
- `safe/src/config.rs:13` | C FFI declaration. The Rust module declares a libc, OS, C shim, or libgcrypt ABI function.
- `safe/src/config.rs:167` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/config.rs:173` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/config.rs:183` | C string read. The ABI passes NUL-terminated strings, which Rust validates before using as text or bytes.
- `safe/src/mpi/opaque.rs:14` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/mpi/opaque.rs:27` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/mpi/opaque.rs:36` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/mpi/opaque.rs:54` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/mpi/opaque.rs:62` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/mpi/opaque.rs:64` | opaque handle ownership. Opaque C handles are represented by Rust allocations and converted at the ABI boundary.
- `safe/src/mpi/opaque.rs:71` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/lib.rs:28` | C FFI declaration. The Rust module declares a libc, OS, C shim, or libgcrypt ABI function.
- `safe/src/lib.rs:29` | C callback type. The public ABI stores caller-supplied callback function pointers with C calling convention.
- `safe/src/lib.rs:30` | C callback type. The public ABI stores caller-supplied callback function pointers with C calling convention.
- `safe/src/lib.rs:32` | C FFI declaration. The Rust module declares a libc, OS, C shim, or libgcrypt ABI function.
- `safe/src/lib.rs:33` | C callback type. The public ABI stores caller-supplied callback function pointers with C calling convention.
- `safe/src/lib.rs:35` | C FFI declaration. The Rust module declares a libc, OS, C shim, or libgcrypt ABI function.
- `safe/src/lib.rs:37` | C FFI declaration. The Rust module declares a libc, OS, C shim, or libgcrypt ABI function.
- `safe/src/lib.rs:39` | C FFI declaration. The Rust module declares a libc, OS, C shim, or libgcrypt ABI function.
- `safe/src/lib.rs:50` | C FFI declaration. The Rust module declares a libc, OS, C shim, or libgcrypt ABI function.
- `safe/src/lib.rs:55` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/lib.rs:61` | runtime FFI call. The code crosses to libc, the OS, libgpg-error, GMP, or the C logging shim for ABI-compatible behavior.
- `safe/src/bin/dumpsexp.rs:7` | helper binary ABI self-call. The installed helper binary declares the libgcrypt ABI it calls after linking to the built library.
- `safe/src/bin/dumpsexp.rs:131` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/bin/dumpsexp.rs:143` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/bin/dumpsexp.rs:163` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/bin/dumpsexp.rs:165` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/bin/dumpsexp.rs:170` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/bin/dumpsexp.rs:171` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/error.rs:64` | libgpg-error FFI declaration. The error module declares libgpg-error mapping and message entry points.
- `safe/src/error.rs:89` | runtime FFI call. The code crosses to libc, the OS, libgpg-error, GMP, or the C logging shim for ABI-compatible behavior.
- `safe/src/error.rs:93` | runtime FFI call. The code crosses to libc, the OS, libgpg-error, GMP, or the C logging shim for ABI-compatible behavior.
- `safe/src/error.rs:97` | C string read. The ABI passes NUL-terminated strings, which Rust validates before using as text or bytes.
- `safe/src/error.rs:124` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/error.rs:129` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/error.rs:131` | runtime FFI call. The code crosses to libc, the OS, libgpg-error, GMP, or the C logging shim for ABI-compatible behavior.
- `safe/src/error.rs:134` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/error.rs:139` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/error.rs:144` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/error.rs:146` | runtime FFI call. The code crosses to libc, the OS, libgpg-error, GMP, or the C logging shim for ABI-compatible behavior.
- `safe/src/error.rs:149` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/error.rs:151` | runtime FFI call. The code crosses to libc, the OS, libgpg-error, GMP, or the C logging shim for ABI-compatible behavior.
- `safe/src/log.rs:46` | unsafe Send invariant. Raw callback state is stored behind a mutex and must be marked Send for global runtime state.
- `safe/src/log.rs:47` | unsafe Send invariant. Raw callback state is stored behind a mutex and must be marked Send for global runtime state.
- `safe/src/log.rs:57` | unsafe Send invariant. Raw callback state is stored behind a mutex and must be marked Send for global runtime state.
- `safe/src/log.rs:59` | C FFI declaration. The Rust module declares a libc, OS, C shim, or libgcrypt ABI function.
- `safe/src/log.rs:85` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/log.rs:106` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/log.rs:111` | C string read. The ABI passes NUL-terminated strings, which Rust validates before using as text or bytes.
- `safe/src/log.rs:114` | pointer-to-slice conversion. The ABI passes pointer and length pairs that must be viewed as Rust slices after null/length checks.
- `safe/src/log.rs:152` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/log.rs:161` | C callback invocation. Caller-supplied C callbacks are invoked from Rust with ABI-owned arguments.
- `safe/src/log.rs:173` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/log.rs:178` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/log.rs:184` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/log.rs:192` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/log.rs:200` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/log.rs:205` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/log.rs:208` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/log.rs:214` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/bin/mpicalc.rs:6` | helper binary ABI self-call. The installed helper binary declares the libgcrypt ABI it calls after linking to the built library.
- `safe/src/bin/mpicalc.rs:45` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/bin/mpicalc.rs:59` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/bin/mpicalc.rs:79` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/bin/mpicalc.rs:104` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/bin/mpicalc.rs:112` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/bin/mpicalc.rs:140` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/bin/mpicalc.rs:150` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/bin/mpicalc.rs:158` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/bin/mpicalc.rs:177` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/bin/mpicalc.rs:216` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/bin/mpicalc.rs:222` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/mac.rs:315` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/mac.rs:326` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/mac.rs:330` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/mac.rs:349` | opaque handle ownership. Opaque C handles are represented by Rust allocations and converted at the ABI boundary.
- `safe/src/mac.rs:353` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/mac.rs:356` | opaque handle ownership. Opaque C handles are represented by Rust allocations and converted at the ABI boundary.
- `safe/src/mac.rs:360` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/mac.rs:372` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/mac.rs:389` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/mac.rs:396` | C string read. The ABI passes NUL-terminated strings, which Rust validates before using as text or bytes.
- `safe/src/mac.rs:408` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/mac.rs:424` | raw pointer read/write. The public ABI writes C-compatible output buffers or reads caller-provided raw pointers.
- `safe/src/mac.rs:443` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/mac.rs:448` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/mac.rs:452` | pointer-to-slice conversion. The ABI passes pointer and length pairs that must be viewed as Rust slices after null/length checks.
- `safe/src/mac.rs:476` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/mac.rs:481` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/mac.rs:493` | pointer-to-slice conversion. The ABI passes pointer and length pairs that must be viewed as Rust slices after null/length checks.
- `safe/src/mac.rs:506` | pointer-to-slice conversion. The ABI passes pointer and length pairs that must be viewed as Rust slices after null/length checks.
- `safe/src/mac.rs:522` | pointer-to-slice conversion. The ABI passes pointer and length pairs that must be viewed as Rust slices after null/length checks.
- `safe/src/mac.rs:531` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/mac.rs:540` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/mac.rs:555` | pointer-to-slice conversion. The ABI passes pointer and length pairs that must be viewed as Rust slices after null/length checks.
- `safe/src/mac.rs:561` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/mac.rs:570` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/mac.rs:571` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/mac.rs:578` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/mac.rs:588` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/mac.rs:590` | raw pointer read/write. The public ABI writes C-compatible output buffers or reads caller-provided raw pointers.
- `safe/src/mac.rs:595` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/mac.rs:604` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/mac.rs:624` | pointer-to-slice conversion. The ABI passes pointer and length pairs that must be viewed as Rust slices after null/length checks.
- `safe/src/mac.rs:632` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/mac.rs:637` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/mac.rs:641` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/mac.rs:653` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/mac.rs:665` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/mac.rs:670` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/mac.rs:675` | C string read. The ABI passes NUL-terminated strings, which Rust validates before using as text or bytes.
- `safe/src/os_rng.rs:17` | C FFI declaration. The Rust module declares a libc, OS, C shim, or libgcrypt ABI function.
- `safe/src/os_rng.rs:59` | runtime FFI call. The code crosses to libc, the OS, libgpg-error, GMP, or the C logging shim for ABI-compatible behavior.
- `safe/src/os_rng.rs:73` | runtime FFI call. The code crosses to libc, the OS, libgpg-error, GMP, or the C logging shim for ABI-compatible behavior.
- `safe/src/os_rng.rs:83` | runtime FFI call. The code crosses to libc, the OS, libgpg-error, GMP, or the C logging shim for ABI-compatible behavior.
- `safe/src/cipher/modes.rs:19` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/cipher/modes.rs:31` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/bin/hmac256.rs:7` | helper binary ABI self-call. The installed helper binary declares the libgcrypt ABI it calls after linking to the built library.
- `safe/src/bin/hmac256.rs:88` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/bin/hmac256.rs:99` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/bin/hmac256.rs:104` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/bin/hmac256.rs:106` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/bin/hmac256.rs:116` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/bin/hmac256.rs:121` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/bin/hmac256.rs:123` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/bin/hmac256.rs:131` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/bin/hmac256.rs:133` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/bin/hmac256.rs:136` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/cipher/block.rs:18` | pointer-to-slice conversion. The ABI passes pointer and length pairs that must be viewed as Rust slices after null/length checks.
- `safe/src/cipher/block.rs:20` | pointer-to-slice conversion. The ABI passes pointer and length pairs that must be viewed as Rust slices after null/length checks.
- `safe/src/cipher/block.rs:31` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/cipher/block.rs:89` | pointer-to-slice conversion. The ABI passes pointer and length pairs that must be viewed as Rust slices after null/length checks.
- `safe/src/cipher/block.rs:101` | pointer-to-slice conversion. The ABI passes pointer and length pairs that must be viewed as Rust slices after null/length checks.
- `safe/src/cipher/block.rs:114` | pointer-to-slice conversion. The ABI passes pointer and length pairs that must be viewed as Rust slices after null/length checks.
- `safe/src/kdf.rs:10` | C callback type. The public ABI stores caller-supplied callback function pointers with C calling convention.
- `safe/src/kdf.rs:12` | C callback type. The public ABI stores caller-supplied callback function pointers with C calling convention.
- `safe/src/kdf.rs:13` | C callback type. The public ABI stores caller-supplied callback function pointers with C calling convention.
- `safe/src/kdf.rs:61` | pointer-to-slice conversion. The ABI passes pointer and length pairs that must be viewed as Rust slices after null/length checks.
- `safe/src/kdf.rs:394` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/kdf.rs:425` | pointer-to-slice conversion. The ABI passes pointer and length pairs that must be viewed as Rust slices after null/length checks.
- `safe/src/kdf.rs:449` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/kdf.rs:468` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/kdf.rs:488` | pointer-to-slice conversion. The ABI passes pointer and length pairs that must be viewed as Rust slices after null/length checks.
- `safe/src/kdf.rs:530` | opaque handle ownership. Opaque C handles are represented by Rust allocations and converted at the ABI boundary.
- `safe/src/kdf.rs:534` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/kdf.rs:539` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/kdf.rs:544` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/kdf.rs:549` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/kdf.rs:570` | raw pointer read/write. The public ABI writes C-compatible output buffers or reads caller-provided raw pointers.
- `safe/src/kdf.rs:575` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/kdf.rs:578` | opaque handle ownership. Opaque C handles are represented by Rust allocations and converted at the ABI boundary.
- `safe/src/alloc.rs:18` | C FFI declaration. The Rust module declares a libc, OS, C shim, or libgcrypt ABI function.
- `safe/src/alloc.rs:34` | runtime FFI call. The code crosses to libc, the OS, libgpg-error, GMP, or the C logging shim for ABI-compatible behavior.
- `safe/src/alloc.rs:41` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/alloc.rs:61` | C callback invocation. Caller-supplied C callbacks are invoked from Rust with ABI-owned arguments.
- `safe/src/alloc.rs:69` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/alloc.rs:81` | C callback invocation. Caller-supplied C callbacks are invoked from Rust with ABI-owned arguments.
- `safe/src/alloc.rs:89` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/alloc.rs:115` | C callback invocation. Caller-supplied C callbacks are invoked from Rust with ABI-owned arguments.
- `safe/src/alloc.rs:123` | C callback invocation. Caller-supplied C callbacks are invoked from Rust with ABI-owned arguments.
- `safe/src/alloc.rs:165` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/alloc.rs:171` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/alloc.rs:194` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/alloc.rs:208` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/alloc.rs:213` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/alloc.rs:218` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/alloc.rs:227` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/alloc.rs:236` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/alloc.rs:249` | C callback invocation. Caller-supplied C callbacks are invoked from Rust with ABI-owned arguments.
- `safe/src/alloc.rs:261` | runtime FFI call. The code crosses to libc, the OS, libgpg-error, GMP, or the C logging shim for ABI-compatible behavior.
- `safe/src/alloc.rs:268` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/alloc.rs:274` | C string read. The ABI passes NUL-terminated strings, which Rust validates before using as text or bytes.
- `safe/src/alloc.rs:278` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/alloc.rs:283` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/alloc.rs:295` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/alloc.rs:307` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/alloc.rs:312` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/alloc.rs:317` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/alloc.rs:341` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/alloc.rs:355` | C string read. The ABI passes NUL-terminated strings, which Rust validates before using as text or bytes.
- `safe/src/alloc.rs:371` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/alloc.rs:381` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/alloc.rs:387` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/cipher/aead.rs:20` | pointer-to-slice conversion. The ABI passes pointer and length pairs that must be viewed as Rust slices after null/length checks.
- `safe/src/cipher/aead.rs:29` | pointer-to-slice conversion. The ABI passes pointer and length pairs that must be viewed as Rust slices after null/length checks.
- `safe/src/cipher/aead.rs:41` | pointer-to-slice conversion. The ABI passes pointer and length pairs that must be viewed as Rust slices after null/length checks.
- `safe/src/cipher/local.rs:217` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/cipher/local.rs:223` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/cipher/local.rs:235` | pointer-to-slice conversion. The ABI passes pointer and length pairs that must be viewed as Rust slices after null/length checks.
- `safe/src/cipher/local.rs:241` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/cipher/local.rs:530` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/cipher/local.rs:551` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/cipher/local.rs:568` | pointer-to-slice conversion. The ABI passes pointer and length pairs that must be viewed as Rust slices after null/length checks.
- `safe/src/cipher/local.rs:582` | C string read. The ABI passes NUL-terminated strings, which Rust validates before using as text or bytes.
- `safe/src/cipher/local.rs:609` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/cipher/local.rs:621` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/cipher/mod.rs:35` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/cipher/mod.rs:46` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/cipher/mod.rs:61` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/cipher/mod.rs:72` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/cipher/mod.rs:82` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/cipher/mod.rs:87` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/cipher/mod.rs:97` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/cipher/mod.rs:107` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/cipher/mod.rs:117` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/cipher/mod.rs:122` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/cipher/mod.rs:127` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/cipher/mod.rs:132` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/cipher/mod.rs:143` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/cipher/mod.rs:154` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/cipher/mod.rs:163` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/cipher/mod.rs:172` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/cipher/mod.rs:181` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/cipher/mod.rs:190` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/cipher/mod.rs:199` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/cipher/mod.rs:208` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/cipher/mod.rs:213` | export attribute. Required to expose a fixed libgcrypt or C-shim symbol name from Rust.
- `safe/src/cipher/registry.rs:433` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/cipher/registry.rs:442` | ABI pointer handling. The line participates in raw pointer or ABI-boundary handling that must remain justified locally.
- `safe/src/cipher/registry.rs:472` | C string read. The ABI passes NUL-terminated strings, which Rust validates before using as text or bytes.
- `safe/src/cipher/registry.rs:485` | C string read. The ABI passes NUL-terminated strings, which Rust validates before using as text or bytes.

## Vendored Unsafe Inventory

- `safe/vendor/kisaseed/src/lib.rs:117` | vendored unsafe implementation detail.
- `safe/vendor/rand_core/CHANGELOG.md:9` | vendored docs/comment match.
- `safe/vendor/rand_core/CHANGELOG.md:36` | vendored docs/comment match.
- `safe/vendor/rand_core/src/impls.rs:70` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/rand_core/src/impls.rs:81` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/md-5/src/compress/loongarch64_asm.rs:70` | architecture intrinsics or assembly path.
- `safe/vendor/subtle/src/lib.rs:225` | vendored unsafe implementation detail.
- `safe/vendor/subtle/src/lib.rs:564` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/md-5/src/lib.rs:143` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/cipher/src/stream_wrapper.rs:56` | unchecked control-flow invariant.
- `safe/vendor/cipher/src/stream_core.rs:206` | vendored unsafe implementation detail.
- `safe/vendor/sha2/src/sha512/x86.rs:20` | architecture intrinsics or assembly path.
- `safe/vendor/sha2/src/sha512/x86.rs:29` | architecture intrinsics or assembly path.
- `safe/vendor/sha2/src/sha512/x86.rs:58` | architecture intrinsics or assembly path.
- `safe/vendor/sha2/src/sha512/x86.rs:71` | architecture intrinsics or assembly path.
- `safe/vendor/sha2/src/sha512/x86.rs:93` | architecture intrinsics or assembly path.
- `safe/vendor/sha2/src/sha512/x86.rs:126` | architecture intrinsics or assembly path.
- `safe/vendor/sha2/src/sha512/x86.rs:147` | architecture intrinsics or assembly path.
- `safe/vendor/sha2/src/sha512/x86.rs:254` | architecture intrinsics or assembly path.
- `safe/vendor/sha2/src/sha512/x86.rs:341` | architecture intrinsics or assembly path.
- `safe/vendor/sha2/src/sha512/x86.rs:346` | architecture intrinsics or assembly path.
- `safe/vendor/sha2/src/sha512/loongarch64_asm.rs:85` | architecture intrinsics or assembly path.
- `safe/vendor/sha2/src/sha512/aarch64.rs:13` | architecture intrinsics or assembly path.
- `safe/vendor/sha2/src/sha512/aarch64.rs:20` | architecture intrinsics or assembly path.
- `safe/vendor/sha2/src/sha512/aarch64.rs:186` | architecture intrinsics or assembly path.
- `safe/vendor/sha2/src/sha512/aarch64.rs:200` | architecture intrinsics or assembly path.
- `safe/vendor/sha2/src/sha512/aarch64.rs:214` | architecture intrinsics or assembly path.
- `safe/vendor/sha2/src/sha512/aarch64.rs:224` | architecture intrinsics or assembly path.
- `safe/vendor/sha2/src/sha256/loongarch64_asm.rs:86` | architecture intrinsics or assembly path.
- `safe/vendor/sha2/src/sha256/x86.rs:10` | architecture intrinsics or assembly path.
- `safe/vendor/sha2/src/sha256/x86.rs:42` | architecture intrinsics or assembly path.
- `safe/vendor/sha2/src/sha256/x86.rs:106` | architecture intrinsics or assembly path.
- `safe/vendor/blake2/src/as_bytes.rs:12` | unsafe trait invariant.
- `safe/vendor/blake2/src/as_bytes.rs:22` | vendored unsafe implementation detail.
- `safe/vendor/blake2/src/as_bytes.rs:29` | vendored unsafe implementation detail.
- `safe/vendor/blake2/src/as_bytes.rs:38` | unsafe trait invariant.
- `safe/vendor/blake2/src/as_bytes.rs:39` | unsafe trait invariant.
- `safe/vendor/blake2/src/as_bytes.rs:40` | unsafe trait invariant.
- `safe/vendor/blake2/src/as_bytes.rs:41` | unsafe trait invariant.
- `safe/vendor/blake2/src/as_bytes.rs:42` | unsafe trait invariant.
- `safe/vendor/blake2/src/as_bytes.rs:43` | unsafe trait invariant.
- `safe/vendor/blake2/src/as_bytes.rs:44` | unsafe trait invariant.
- `safe/vendor/blake2/src/as_bytes.rs:45` | unsafe trait invariant.
- `safe/vendor/inout/src/inout_buf.rs:103` | vendored unsafe implementation detail.
- `safe/vendor/inout/src/inout_buf.rs:115` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/inout/src/inout_buf.rs:121` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/inout/src/inout_buf.rs:127` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/inout/src/inout_buf.rs:168` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/inout/src/inout_buf.rs:193` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/inout/src/inout_buf.rs:221` | vendored unsafe implementation detail.
- `safe/vendor/inout/src/inout_buf.rs:249` | vendored unsafe implementation detail.
- `safe/vendor/inout/src/inout_buf.rs:293` | vendored unsafe implementation detail.
- `safe/vendor/sha2/src/sha256/aarch64.rs:17` | architecture intrinsics or assembly path.
- `safe/vendor/sha2/src/sha256/aarch64.rs:24` | architecture intrinsics or assembly path.
- `safe/vendor/sha2/src/sha256/aarch64.rs:110` | architecture intrinsics or assembly path.
- `safe/vendor/sha2/src/sha256/aarch64.rs:124` | architecture intrinsics or assembly path.
- `safe/vendor/sha2/src/sha256/aarch64.rs:138` | architecture intrinsics or assembly path.
- `safe/vendor/sha2/src/sha256/aarch64.rs:148` | architecture intrinsics or assembly path.
- `safe/vendor/inout/src/inout.rs:27` | vendored unsafe implementation detail.
- `safe/vendor/inout/src/inout.rs:33` | vendored unsafe implementation detail.
- `safe/vendor/inout/src/inout.rs:61` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/inout/src/inout.rs:74` | vendored unsafe implementation detail.
- `safe/vendor/inout/src/inout.rs:109` | vendored unsafe implementation detail.
- `safe/vendor/inout/src/inout.rs:139` | vendored unsafe implementation detail.
- `safe/vendor/inout/src/inout.rs:163` | vendored unsafe implementation detail.
- `safe/vendor/blake2/src/simd/simd_opt/u64x4.rs:115` | vendored unsafe implementation detail.
- `safe/vendor/blake2/src/simd/simd_opt/u64x4.rs:128` | vendored unsafe implementation detail.
- `safe/vendor/inout/src/reserved.rs:64` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/inout/src/reserved.rs:119` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/inout/src/reserved.rs:125` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/inout/src/reserved.rs:142` | vendored unsafe implementation detail.
- `safe/vendor/inout/src/reserved.rs:164` | vendored unsafe implementation detail.
- `safe/vendor/inout/src/reserved.rs:224` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/blake2/src/simd/simdty.rs:73` | unsafe trait invariant.
- `safe/vendor/blake2/src/simd/simdty.rs:74` | unsafe trait invariant.
- `safe/vendor/blake2/src/simd/simdty.rs:75` | unsafe trait invariant.
- `safe/vendor/blake2/src/simd/simdty.rs:76` | unsafe trait invariant.
- `safe/vendor/blake2/src/simd/simdty.rs:77` | unsafe trait invariant.
- `safe/vendor/sha2/src/sha256.rs:41` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/blake2/src/simd/simd_opt.rs:12` | vendored unsafe implementation detail.
- `safe/vendor/blake2/src/simd/simdop.rs:22` | vendored unsafe implementation detail.
- `safe/vendor/blake2/src/simd/simdop.rs:43` | vendored unsafe implementation detail.
- `safe/vendor/blake2/src/simd/simdop.rs:64` | vendored unsafe implementation detail.
- `safe/vendor/blake2/src/simd/simdop.rs:85` | vendored unsafe implementation detail.
- `safe/vendor/inout-0.2.2/src/inout_buf.rs:103` | vendored unsafe implementation detail.
- `safe/vendor/inout-0.2.2/src/inout_buf.rs:115` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/inout-0.2.2/src/inout_buf.rs:121` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/inout-0.2.2/src/inout_buf.rs:135` | vendored unsafe implementation detail.
- `safe/vendor/inout-0.2.2/src/inout_buf.rs:139` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/inout-0.2.2/src/inout_buf.rs:145` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/inout-0.2.2/src/inout_buf.rs:186` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/inout-0.2.2/src/inout_buf.rs:211` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/inout-0.2.2/src/inout_buf.rs:236` | vendored unsafe implementation detail.
- `safe/vendor/inout-0.2.2/src/inout_buf.rs:264` | vendored unsafe implementation detail.
- `safe/vendor/inout-0.2.2/src/inout_buf.rs:308` | vendored unsafe implementation detail.
- `safe/vendor/sha2/src/sha512.rs:43` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/inout-0.2.2/src/reserved.rs:64` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/inout-0.2.2/src/reserved.rs:107` | vendored unsafe implementation detail.
- `safe/vendor/inout-0.2.2/src/reserved.rs:136` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/inout-0.2.2/src/reserved.rs:142` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/inout-0.2.2/src/reserved.rs:148` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/inout-0.2.2/src/reserved.rs:176` | vendored unsafe implementation detail.
- `safe/vendor/inout-0.2.2/src/reserved.rs:195` | vendored unsafe implementation detail.
- `safe/vendor/inout-0.2.2/src/reserved.rs:246` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/blake2/src/simd.rs:101` | vendored unsafe implementation detail.
- `safe/vendor/blake2/src/simd.rs:115` | vendored unsafe implementation detail.
- `safe/vendor/blake2/src/simd.rs:129` | vendored unsafe implementation detail.
- `safe/vendor/inout-0.2.2/src/inout.rs:27` | vendored unsafe implementation detail.
- `safe/vendor/inout-0.2.2/src/inout.rs:33` | vendored unsafe implementation detail.
- `safe/vendor/inout-0.2.2/src/inout.rs:47` | vendored unsafe implementation detail.
- `safe/vendor/inout-0.2.2/src/inout.rs:51` | vendored unsafe implementation detail.
- `safe/vendor/inout-0.2.2/src/inout.rs:57` | vendored unsafe implementation detail.
- `safe/vendor/inout-0.2.2/src/inout.rs:85` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/inout-0.2.2/src/inout.rs:98` | vendored unsafe implementation detail.
- `safe/vendor/inout-0.2.2/src/inout.rs:133` | vendored unsafe implementation detail.
- `safe/vendor/inout-0.2.2/src/inout.rs:166` | vendored unsafe implementation detail.
- `safe/vendor/inout-0.2.2/src/inout.rs:185` | vendored unsafe implementation detail.
- `safe/vendor/inout-0.2.2/src/inout.rs:209` | vendored unsafe implementation detail.
- `safe/vendor/byteorder/CHANGELOG.md:15` | vendored docs/comment match.
- `safe/vendor/byteorder/CHANGELOG.md:21` | vendored docs/comment match.
- `safe/vendor/byteorder/CHANGELOG.md:88` | vendored docs/comment match.
- `safe/vendor/byteorder/CHANGELOG.md:97` | vendored docs/comment match.
- `safe/vendor/block-buffer/src/sealed.rs:27` | vendored unsafe implementation detail.
- `safe/vendor/block-buffer/src/sealed.rs:58` | vendored unsafe implementation detail.
- `safe/vendor/block-buffer/src/lib.rs:200` | vendored unsafe implementation detail.
- `safe/vendor/block-buffer/src/lib.rs:348` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/byteorder/src/lib.rs:1091` | vendored unsafe implementation detail.
- `safe/vendor/byteorder/src/lib.rs:1120` | vendored unsafe implementation detail.
- `safe/vendor/byteorder/src/lib.rs:1149` | vendored unsafe implementation detail.
- `safe/vendor/byteorder/src/lib.rs:1178` | vendored unsafe implementation detail.
- `safe/vendor/byteorder/src/lib.rs:1208` | vendored unsafe implementation detail.
- `safe/vendor/byteorder/src/lib.rs:1270` | vendored unsafe implementation detail.
- `safe/vendor/byteorder/src/lib.rs:1406` | vendored docs/comment match.
- `safe/vendor/byteorder/src/lib.rs:1429` | vendored unsafe implementation detail.
- `safe/vendor/byteorder/src/lib.rs:1457` | vendored unsafe implementation detail.
- `safe/vendor/byteorder/src/lib.rs:1485` | vendored unsafe implementation detail.
- `safe/vendor/byteorder/src/lib.rs:1513` | vendored unsafe implementation detail.
- `safe/vendor/byteorder/src/lib.rs:1541` | vendored unsafe implementation detail.
- `safe/vendor/byteorder/src/lib.rs:1570` | vendored unsafe implementation detail.
- `safe/vendor/byteorder/src/lib.rs:1599` | vendored unsafe implementation detail.
- `safe/vendor/byteorder/src/lib.rs:1700` | vendored unsafe implementation detail.
- `safe/vendor/byteorder/src/lib.rs:1725` | vendored unsafe implementation detail.
- `safe/vendor/byteorder/src/lib.rs:1750` | vendored unsafe implementation detail.
- `safe/vendor/byteorder/src/lib.rs:1775` | vendored unsafe implementation detail.
- `safe/vendor/byteorder/src/lib.rs:2001` | vendored unsafe implementation detail.
- `safe/vendor/byteorder/src/lib.rs:2015` | vendored unsafe implementation detail.
- `safe/vendor/byteorder/src/lib.rs:2105` | vendored unsafe implementation detail.
- `safe/vendor/byteorder/src/lib.rs:2117` | vendored unsafe implementation detail.
- `safe/vendor/byteorder/src/lib.rs:2187` | vendored unsafe implementation detail.
- `safe/vendor/byteorder/src/lib.rs:2197` | vendored unsafe implementation detail.
- `safe/vendor/byteorder/src/lib.rs:2283` | vendored unsafe implementation detail.
- `safe/vendor/byteorder/src/lib.rs:2295` | vendored unsafe implementation detail.
- `safe/vendor/byteorder/src/lib.rs:3898` | vendored unsafe implementation detail.
- `safe/vendor/byteorder/src/lib.rs:3919` | vendored unsafe implementation detail.
- `safe/vendor/byteorder/src/lib.rs:3940` | vendored unsafe implementation detail.
- `safe/vendor/byteorder/src/io.rs:564` | vendored unsafe implementation detail.
- `safe/vendor/byteorder/src/io.rs:599` | vendored unsafe implementation detail.
- `safe/vendor/byteorder/src/io.rs:637` | vendored unsafe implementation detail.
- `safe/vendor/byteorder/src/io.rs:678` | vendored unsafe implementation detail.
- `safe/vendor/byteorder/src/io.rs:693` | vendored docs/comment match.
- `safe/vendor/byteorder/src/io.rs:717` | vendored unsafe implementation detail.
- `safe/vendor/byteorder/src/io.rs:749` | vendored unsafe implementation detail.
- `safe/vendor/byteorder/src/io.rs:784` | vendored unsafe implementation detail.
- `safe/vendor/byteorder/src/io.rs:822` | vendored unsafe implementation detail.
- `safe/vendor/byteorder/src/io.rs:863` | vendored unsafe implementation detail.
- `safe/vendor/byteorder/src/io.rs:904` | vendored unsafe implementation detail.
- `safe/vendor/byteorder/src/io.rs:989` | vendored unsafe implementation detail.
- `safe/vendor/byteorder/src/io.rs:1008` | vendored docs/comment match.
- `safe/vendor/byteorder/src/io.rs:1584` | vendored docs/comment match.
- `safe/vendor/byteorder/src/io.rs:1587` | vendored unsafe implementation detail.
- `safe/vendor/hybrid-array/tests/mod.rs:468` | vendored test or benchmark code.
- `safe/vendor/base64ct/src/encoding.rs:107` | vendored docs/comment match.
- `safe/vendor/base64ct/src/encoding.rs:125` | vendored unsafe implementation detail.
- `safe/vendor/base64ct/src/encoding.rs:155` | vendored unsafe implementation detail.
- `safe/vendor/base64ct/src/encoding.rs:231` | unchecked UTF-8 or unchecked value invariant.
- `safe/vendor/base64ct/src/encoding.rs:245` | vendored unsafe implementation detail.
- `safe/vendor/hybrid-array/src/traits.rs:22` | unsafe trait invariant.
- `safe/vendor/keccak/src/lib.rs:187` | architecture intrinsics or assembly path.
- `safe/vendor/keccak/src/lib.rs:197` | architecture intrinsics or assembly path.
- `safe/vendor/hybrid-array/src/flatten.rs:32` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/hybrid-array/src/flatten.rs:62` | vendored unsafe implementation detail.
- `safe/vendor/hybrid-array/src/flatten.rs:83` | vendored unsafe implementation detail.
- `safe/vendor/hybrid-array/src/sizes.rs:24` | vendored docs/comment match.
- `safe/vendor/hybrid-array/src/sizes.rs:26` | unsafe trait invariant.
- `safe/vendor/whirlpool/src/lib.rs:254` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/keccak/src/armv8.rs:7` | architecture intrinsics or assembly path.
- `safe/vendor/keccak/src/armv8.rs:187` | architecture intrinsics or assembly path.
- `safe/vendor/keccak/src/armv8.rs:189` | architecture intrinsics or assembly path.
- `safe/vendor/gost-crypto/README.md:20` | vendored docs/comment match.
- `safe/vendor/hybrid-array/src/lib.rs:66` | vendored docs/comment match.
- `safe/vendor/hybrid-array/src/lib.rs:69` | vendored docs/comment match.
- `safe/vendor/hybrid-array/src/lib.rs:71` | vendored docs/comment match.
- `safe/vendor/hybrid-array/src/lib.rs:83` | vendored docs/comment match.
- `safe/vendor/hybrid-array/src/lib.rs:153` | vendored docs/comment match.
- `safe/vendor/hybrid-array/src/lib.rs:180` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/hybrid-array/src/lib.rs:188` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/hybrid-array/src/lib.rs:239` | layout or initialization invariant.
- `safe/vendor/hybrid-array/src/lib.rs:252` | vendored unsafe implementation detail.
- `safe/vendor/hybrid-array/src/lib.rs:268` | vendored unsafe implementation detail.
- `safe/vendor/hybrid-array/src/lib.rs:284` | vendored unsafe implementation detail.
- `safe/vendor/hybrid-array/src/lib.rs:302` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/hybrid-array/src/lib.rs:319` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/hybrid-array/src/lib.rs:340` | vendored unsafe implementation detail.
- `safe/vendor/hybrid-array/src/lib.rs:363` | vendored unsafe implementation detail.
- `safe/vendor/hybrid-array/src/lib.rs:384` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/hybrid-array/src/lib.rs:400` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/hybrid-array/src/lib.rs:495` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/hybrid-array/src/lib.rs:502` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/hybrid-array/src/lib.rs:509` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/hybrid-array/src/lib.rs:516` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/hybrid-array/src/lib.rs:523` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/hybrid-array/src/lib.rs:530` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/hybrid-array/src/lib.rs:550` | layout or initialization invariant.
- `safe/vendor/hybrid-array/src/lib.rs:560` | layout or initialization invariant.
- `safe/vendor/hybrid-array/src/lib.rs:561` | vendored unsafe implementation detail.
- `safe/vendor/hybrid-array/src/lib.rs:945` | unsafe trait invariant.
- `safe/vendor/hybrid-array/src/lib.rs:949` | unsafe trait invariant.
- `safe/vendor/hybrid-array/src/lib.rs:963` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/hybrid-array/src/lib.rs:979` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/hybrid-array/src/lib.rs:1106` | unsafe trait invariant.
- `safe/vendor/hybrid-array/src/lib.rs:1115` | unsafe trait invariant.
- `safe/vendor/hybrid-array/src/from_fn.rs:32` | layout or initialization invariant.
- `safe/vendor/hybrid-array/src/from_fn.rs:53` | vendored unsafe implementation detail.
- `safe/vendor/hybrid-array/src/from_fn.rs:80` | vendored unsafe implementation detail.
- `safe/vendor/hybrid-array/src/from_fn.rs:84` | vendored unsafe implementation detail.
- `safe/vendor/hybrid-array/src/from_fn.rs:98` | vendored unsafe implementation detail.
- `safe/vendor/hybrid-array/CHANGELOG.md:173` | vendored docs/comment match.
- `safe/vendor/sha1/src/compress/loongarch64_asm.rs:110` | architecture intrinsics or assembly path.
- `safe/vendor/sha1/src/compress/x86.rs:34` | architecture intrinsics or assembly path.
- `safe/vendor/sha1/src/compress/x86.rs:106` | architecture intrinsics or assembly path.
- `safe/vendor/generic-array/CHANGELOG.md:6` | vendored docs/comment match.
- `safe/vendor/sha1/src/compress.rs:38` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/argon2/src/lib.rs:464` | architecture intrinsics or assembly path.
- `safe/vendor/argon2/src/lib.rs:469` | architecture intrinsics or assembly path.
- `safe/vendor/generic-array/src/functional.rs:12` | unsafe trait invariant.
- `safe/vendor/generic-array/src/functional.rs:20` | unsafe trait invariant.
- `safe/vendor/generic-array/src/functional.rs:29` | unsafe trait invariant.
- `safe/vendor/generic-array/src/functional.rs:43` | unsafe trait invariant.
- `safe/vendor/generic-array/src/functional.rs:85` | unsafe trait invariant.
- `safe/vendor/generic-array/src/functional.rs:91` | unsafe trait invariant.
- `safe/vendor/generic-array/src/sequence.rs:12` | unsafe trait invariant.
- `safe/vendor/generic-array/src/sequence.rs:40` | vendored unsafe implementation detail.
- `safe/vendor/generic-array/src/sequence.rs:75` | unsafe trait invariant.
- `safe/vendor/generic-array/src/sequence.rs:91` | unsafe trait invariant.
- `safe/vendor/generic-array/src/sequence.rs:111` | unsafe trait invariant.
- `safe/vendor/generic-array/src/sequence.rs:152` | unsafe trait invariant.
- `safe/vendor/generic-array/src/sequence.rs:190` | unsafe trait invariant.
- `safe/vendor/generic-array/src/sequence.rs:205` | vendored unsafe implementation detail.
- `safe/vendor/generic-array/src/sequence.rs:221` | vendored unsafe implementation detail.
- `safe/vendor/generic-array/src/sequence.rs:232` | unsafe trait invariant.
- `safe/vendor/generic-array/src/sequence.rs:244` | vendored unsafe implementation detail.
- `safe/vendor/generic-array/src/sequence.rs:256` | vendored unsafe implementation detail.
- `safe/vendor/generic-array/src/sequence.rs:266` | unsafe trait invariant.
- `safe/vendor/generic-array/src/sequence.rs:279` | unsafe trait invariant.
- `safe/vendor/generic-array/src/sequence.rs:290` | vendored unsafe implementation detail.
- `safe/vendor/generic-array/src/sequence.rs:302` | unsafe trait invariant.
- `safe/vendor/generic-array/src/sequence.rs:313` | vendored unsafe implementation detail.
- `safe/vendor/generic-array/src/sequence.rs:322` | unsafe trait invariant.
- `safe/vendor/generic-array/src/sequence.rs:333` | vendored unsafe implementation detail.
- `safe/vendor/generic-array/src/sequence.rs:343` | unsafe trait invariant.
- `safe/vendor/generic-array/src/sequence.rs:357` | unsafe trait invariant.
- `safe/vendor/generic-array/src/sequence.rs:371` | vendored unsafe implementation detail.
- `safe/vendor/argon2/CHANGELOG.md:174` | vendored docs/comment match.
- `safe/vendor/generic-array/src/impls.rs:132` | layout or initialization invariant.
- `safe/vendor/generic-array/src/impls.rs:140` | layout or initialization invariant.
- `safe/vendor/generic-array/src/impls.rs:147` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/generic-array/src/impls.rs:154` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/generic-array/src/impls.rs:162` | layout or initialization invariant.
- `safe/vendor/generic-array/src/impls.rs:169` | layout or initialization invariant.
- `safe/vendor/generic-array/src/impls.rs:176` | layout or initialization invariant.
- `safe/vendor/generic-array/src/iter.rs:84` | vendored unsafe implementation detail.
- `safe/vendor/generic-array/src/iter.rs:101` | vendored unsafe implementation detail.
- `safe/vendor/generic-array/src/iter.rs:105` | vendored unsafe implementation detail.
- `safe/vendor/generic-array/src/iter.rs:126` | vendored unsafe implementation detail.
- `safe/vendor/generic-array/src/iter.rs:140` | vendored unsafe implementation detail.
- `safe/vendor/generic-array/src/iter.rs:182` | vendored unsafe implementation detail.
- `safe/vendor/generic-array/src/iter.rs:205` | vendored unsafe implementation detail.
- `safe/vendor/generic-array/src/iter.rs:215` | vendored unsafe implementation detail.
- `safe/vendor/libc/CHANGELOG.md:686` | vendored docs/comment match.
- `safe/vendor/libc/src/unix/mod.rs:619` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/libc/src/unix/mod.rs:626` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/libc/src/unix/mod.rs:1293` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/generic-array/src/lib.rs:112` | unsafe trait invariant.
- `safe/vendor/generic-array/src/lib.rs:117` | unsafe trait invariant.
- `safe/vendor/generic-array/src/lib.rs:166` | unsafe trait invariant.
- `safe/vendor/generic-array/src/lib.rs:171` | unsafe trait invariant.
- `safe/vendor/generic-array/src/lib.rs:183` | unsafe trait invariant.
- `safe/vendor/generic-array/src/lib.rs:184` | unsafe trait invariant.
- `safe/vendor/generic-array/src/lib.rs:194` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/generic-array/src/lib.rs:204` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/generic-array/src/lib.rs:222` | vendored unsafe implementation detail.
- `safe/vendor/generic-array/src/lib.rs:235` | vendored unsafe implementation detail.
- `safe/vendor/generic-array/src/lib.rs:243` | vendored unsafe implementation detail.
- `safe/vendor/generic-array/src/lib.rs:255` | vendored unsafe implementation detail.
- `safe/vendor/generic-array/src/lib.rs:277` | vendored unsafe implementation detail.
- `safe/vendor/generic-array/src/lib.rs:290` | vendored unsafe implementation detail.
- `safe/vendor/generic-array/src/lib.rs:299` | vendored unsafe implementation detail.
- `safe/vendor/generic-array/src/lib.rs:339` | vendored unsafe implementation detail.
- `safe/vendor/generic-array/src/lib.rs:372` | unsafe trait invariant.
- `safe/vendor/generic-array/src/lib.rs:384` | vendored unsafe implementation detail.
- `safe/vendor/generic-array/src/lib.rs:414` | vendored unsafe implementation detail.
- `safe/vendor/generic-array/src/lib.rs:441` | vendored unsafe implementation detail.
- `safe/vendor/generic-array/src/lib.rs:461` | unsafe trait invariant.
- `safe/vendor/generic-array/src/lib.rs:469` | unsafe trait invariant.
- `safe/vendor/generic-array/src/lib.rs:480` | vendored unsafe implementation detail.
- `safe/vendor/generic-array/src/lib.rs:511` | vendored unsafe implementation detail.
- `safe/vendor/generic-array/src/lib.rs:574` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/generic-array/src/lib.rs:588` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/generic-array/src/lib.rs:621` | vendored unsafe implementation detail.
- `safe/vendor/generic-array/src/lib.rs:653` | layout or initialization invariant.
- `safe/vendor/generic-array/src/lib.rs:670` | vendored unsafe implementation detail.
- `safe/vendor/generic-array/src/arr.rs:34` | layout or initialization invariant.
- `safe/vendor/generic-array/src/arr.rs:60` | layout or initialization invariant.
- `safe/vendor/generic-array/src/hex.rs:46` | unchecked UTF-8 or unchecked value invariant.
- `safe/vendor/generic-array/src/hex.rs:59` | unchecked UTF-8 or unchecked value invariant.
- `safe/vendor/generic-array/src/hex.rs:86` | unchecked UTF-8 or unchecked value invariant.
- `safe/vendor/generic-array/src/hex.rs:99` | unchecked UTF-8 or unchecked value invariant.
- `safe/vendor/libc/src/macros.rs:374` | vendored docs/comment match.
- `safe/vendor/libc/src/macros.rs:385` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/macros.rs:451` | vendored docs/comment match.
- `safe/vendor/libc/src/macros.rs:454` | FFI declarations or platform bindings.
- `safe/vendor/cpufeatures/src/aarch64.rs:37` | architecture intrinsics or assembly path.
- `safe/vendor/cpufeatures/src/aarch64.rs:114` | architecture intrinsics or assembly path.
- `safe/vendor/cpufeatures/src/aarch64.rs:122` | architecture intrinsics or assembly path.
- `safe/vendor/cpufeatures/src/aarch64.rs:135` | architecture intrinsics or assembly path.
- `safe/vendor/libc/src/unix/newlib/mod.rs:935` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/newlib/mod.rs:936` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/newlib/mod.rs:937` | FFI declarations or platform bindings.
- `safe/vendor/libc/tests/const_fn.rs:2` | vendored test or benchmark code.
- `safe/vendor/libc/src/solid/mod.rs:522` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/solid/mod.rs:533` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/libc/src/solid/mod.rs:547` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/libc/src/solid/mod.rs:585` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/solid/mod.rs:603` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/libc/src/solid/mod.rs:609` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/cpufeatures/src/x86.rs:47` | architecture intrinsics or assembly path.
- `safe/vendor/cpufeatures/src/x86.rs:52` | architecture intrinsics or assembly path.
- `safe/vendor/cpufeatures/src/x86.rs:56` | architecture intrinsics or assembly path.
- `safe/vendor/cpufeatures/src/x86.rs:78` | architecture intrinsics or assembly path.
- `safe/vendor/cpufeatures/src/loongarch64.rs:35` | architecture intrinsics or assembly path.
- `safe/vendor/libc/src/teeos/mod.rs:1033` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/libc/src/teeos/mod.rs:1334` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/wasi/mod.rs:66` | unsafe trait invariant.
- `safe/vendor/libc/src/wasi/mod.rs:67` | unsafe trait invariant.
- `safe/vendor/libc/src/wasi/mod.rs:547` | vendored docs/comment match.
- `safe/vendor/libc/src/wasi/mod.rs:549` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/wasi/mod.rs:551` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/wasi/mod.rs:1048` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/libc/src/vxworks/mod.rs:102` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/libc/src/vxworks/mod.rs:106` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/vxworks/mod.rs:110` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/vxworks/mod.rs:114` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/vxworks/mod.rs:118` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/vxworks/mod.rs:614` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/vxworks/mod.rs:616` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/libc/src/vxworks/mod.rs:629` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/vxworks/mod.rs:645` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/vxworks/mod.rs:657` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/vxworks/mod.rs:663` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/vxworks/mod.rs:1853` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/vxworks/mod.rs:1854` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/vxworks/mod.rs:1855` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/vxworks/mod.rs:1986` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/libc/src/vxworks/mod.rs:2433` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/new/common/posix/pthread.rs:10` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/new/common/posix/pthread.rs:11` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/new/common/posix/pthread.rs:12` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/new/common/posix/pthread.rs:275` | vendored docs/comment match.
- `safe/vendor/libc/src/new/common/posix/pthread.rs:281` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/redox/mod.rs:1269` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/redox/mod.rs:1270` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/redox/mod.rs:1271` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/windows/mod.rs:305` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/libc/src/windows/mod.rs:311` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/libc/src/new/qurt/errno.rs:148` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/new/qurt/errno.rs:152` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/cygwin/mod.rs:527` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/libc/src/unix/cygwin/mod.rs:540` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/cygwin/mod.rs:553` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/cygwin/mod.rs:557` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/cygwin/mod.rs:561` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/cygwin/mod.rs:2018` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/libc/src/unix/cygwin/mod.rs:2081` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/cygwin/mod.rs:2082` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/cygwin/mod.rs:2083` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/haiku/bsd.rs:122` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/libc/src/psp.rs:18` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/psp.rs:26` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/libc/src/psp.rs:29` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/libc/src/psp.rs:31` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/libc/src/psp.rs:34` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/libc/src/psp.rs:36` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/libc/src/psp.rs:45` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/libc/src/psp.rs:52` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/libc/src/psp.rs:55` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/psp.rs:65` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/libc/src/psp.rs:68` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/libc/src/psp.rs:70` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/libc/src/psp.rs:71` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/libc/src/psp.rs:73` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/haiku/mod.rs:88` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/libc/src/unix/haiku/mod.rs:92` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/haiku/mod.rs:96` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/haiku/mod.rs:100` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/haiku/mod.rs:1727` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/haiku/mod.rs:1728` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/haiku/mod.rs:1729` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/haiku/mod.rs:1798` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/libc/src/unix/haiku/mod.rs:1805` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/libc/src/unix/haiku/native.rs:484` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/haiku/native.rs:503` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/haiku/native.rs:1290` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/libc/src/unix/haiku/native.rs:1295` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/libc/src/unix/haiku/native.rs:1300` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/haiku/native.rs:1309` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/libc/src/unix/haiku/native.rs:1314` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/haiku/native.rs:1323` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/haiku/native.rs:1339` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/libc/src/unix/haiku/native.rs:1344` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/libc/src/unix/haiku/native.rs:1349` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/libc/src/unix/haiku/native.rs:1354` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/libc/src/unix/haiku/native.rs:1359` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/libc/src/unix/haiku/native.rs:1364` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/libc/src/unix/haiku/native.rs:1369` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/haiku/native.rs:1379` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/libc/src/unix/haiku/native.rs:1384` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/linux_like/linux_l4re_shared.rs:1883` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/aix/mod.rs:561` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/aix/mod.rs:571` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/aix/mod.rs:2551` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/aix/mod.rs:2552` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/aix/mod.rs:2553` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/aix/mod.rs:2654` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/libc/src/unix/aix/mod.rs:2756` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/aix/mod.rs:2979` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/libc/src/unix/aix/mod.rs:2997` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/libc/src/unix/nto/x86_64.rs:93` | architecture intrinsics or assembly path.
- `safe/vendor/libc/src/unix/nto/x86_64.rs:103` | architecture intrinsics or assembly path.
- `safe/vendor/libc/src/unix/nto/neutrino.rs:90` | vendored docs/comment match.
- `safe/vendor/libc/src/unix/nto/neutrino.rs:100` | vendored docs/comment match.
- `safe/vendor/libc/src/unix/nto/neutrino.rs:144` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/nto/neutrino.rs:947` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/nto/neutrino.rs:954` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/nto/neutrino.rs:989` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/libc/src/unix/nto/neutrino.rs:995` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/libc/src/unix/nto/neutrino.rs:1006` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/nto/neutrino.rs:1007` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/nto/neutrino.rs:1024` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/libc/src/unix/nto/neutrino.rs:1028` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/libc/src/unix/nto/neutrino.rs:1033` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/libc/src/unix/nto/neutrino.rs:1051` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/libc/src/unix/nto/neutrino.rs:1060` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/libc/src/unix/nto/neutrino.rs:1069` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/libc/src/unix/nto/neutrino.rs:1078` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/libc/src/unix/nto/mod.rs:582` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/libc/src/unix/nto/mod.rs:2893` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/nto/mod.rs:2894` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/nto/mod.rs:2895` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/nto/mod.rs:3055` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/nto/mod.rs:3148` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/nto/mod.rs:3157` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/libc/src/unix/nto/mod.rs:3166` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/nto/mod.rs:3175` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/nto/mod.rs:3184` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/nto/mod.rs:3193` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/aix/powerpc64.rs:351` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/libc/src/unix/aix/powerpc64.rs:355` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/aix/powerpc64.rs:359` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/aix/powerpc64.rs:363` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/aix/powerpc64.rs:367` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/aix/powerpc64.rs:376` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/aix/powerpc64.rs:386` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/fuchsia/mod.rs:3122` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/fuchsia/mod.rs:3127` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/libc/src/fuchsia/mod.rs:3131` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/libc/src/fuchsia/mod.rs:3469` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/libc/src/fuchsia/mod.rs:3977` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/fuchsia/mod.rs:3978` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/fuchsia/mod.rs:3979` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/fuchsia/mod.rs:4003` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/linux_like/l4re/uclibc/mod.rs:283` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/libc/src/unix/linux_like/l4re/uclibc/mod.rs:294` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/linux_like/l4re/uclibc/mod.rs:334` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/linux_like/l4re/uclibc/mod.rs:338` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/linux_like/l4re/uclibc/mod.rs:342` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/linux_like/l4re/uclibc/mod.rs:346` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/linux_like/l4re/uclibc/mod.rs:350` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/linux_like/l4re/uclibc/mod.rs:354` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/bsd/mod.rs:768` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/bsd/mod.rs:769` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/bsd/mod.rs:770` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/linux_like/emscripten/lfs64.rs:7` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/libc/src/unix/linux_like/emscripten/lfs64.rs:12` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/libc/src/unix/linux_like/emscripten/lfs64.rs:17` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/libc/src/unix/linux_like/emscripten/lfs64.rs:22` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/linux_like/emscripten/lfs64.rs:31` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/linux_like/emscripten/lfs64.rs:40` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/libc/src/unix/linux_like/emscripten/lfs64.rs:45` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/libc/src/unix/linux_like/emscripten/lfs64.rs:50` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/linux_like/emscripten/lfs64.rs:60` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/libc/src/unix/linux_like/emscripten/lfs64.rs:65` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/libc/src/unix/linux_like/emscripten/lfs64.rs:70` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/libc/src/unix/linux_like/emscripten/lfs64.rs:75` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/linux_like/emscripten/lfs64.rs:80` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/libc/src/unix/linux_like/emscripten/lfs64.rs:85` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/linux_like/emscripten/lfs64.rs:90` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/libc/src/unix/linux_like/emscripten/lfs64.rs:95` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/linux_like/emscripten/lfs64.rs:118` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/linux_like/emscripten/lfs64.rs:128` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/linux_like/emscripten/lfs64.rs:133` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/linux_like/emscripten/lfs64.rs:143` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/linux_like/emscripten/lfs64.rs:153` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/linux_like/emscripten/lfs64.rs:163` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/linux_like/emscripten/lfs64.rs:173` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/libc/src/unix/linux_like/emscripten/lfs64.rs:178` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/linux_like/emscripten/lfs64.rs:187` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/libc/src/unix/linux_like/emscripten/lfs64.rs:192` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/libc/src/unix/linux_like/emscripten/lfs64.rs:197` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/libc/src/unix/linux_like/emscripten/lfs64.rs:202` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/libc/src/unix/linux_like/emscripten/lfs64.rs:207` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/libc/src/unix/linux_like/emscripten/lfs64.rs:212` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/libc/src/unix/bsd/netbsdlike/openbsd/mod.rs:784` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/bsd/netbsdlike/openbsd/mod.rs:797` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/bsd/netbsdlike/openbsd/mod.rs:804` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/libc/src/unix/bsd/netbsdlike/openbsd/mod.rs:808` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/bsd/netbsdlike/openbsd/mod.rs:812` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/bsd/netbsdlike/openbsd/mod.rs:816` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/bsd/netbsdlike/openbsd/mod.rs:828` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/bsd/netbsdlike/openbsd/mod.rs:841` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/bsd/netbsdlike/openbsd/mod.rs:855` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/bsd/netbsdlike/openbsd/mod.rs:890` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/bsd/netbsdlike/openbsd/mod.rs:908` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/bsd/netbsdlike/openbsd/mod.rs:2001` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/libc/src/unix/bsd/netbsdlike/openbsd/mod.rs:2028` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/libc/src/unix/bsd/netbsdlike/openbsd/mod.rs:2035` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/libc/src/unix/linux_like/android/b32/arm.rs:63` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/linux_like/android/b32/arm.rs:69` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/bsd/freebsdlike/dragonfly/mod.rs:526` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/libc/src/unix/linux_like/android/b32/x86/mod.rs:64` | architecture intrinsics or assembly path.
- `safe/vendor/libc/src/unix/linux_like/android/b32/x86/mod.rs:70` | architecture intrinsics or assembly path.
- `safe/vendor/libc/src/unix/linux_like/linux/musl/lfs64.rs:5` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/libc/src/unix/linux_like/linux/musl/lfs64.rs:10` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/linux_like/linux/musl/lfs64.rs:20` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/libc/src/unix/linux_like/linux/musl/lfs64.rs:25` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/libc/src/unix/linux_like/linux/musl/lfs64.rs:30` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/linux_like/linux/musl/lfs64.rs:39` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/linux_like/linux/musl/lfs64.rs:48` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/libc/src/unix/linux_like/linux/musl/lfs64.rs:53` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/libc/src/unix/linux_like/linux/musl/lfs64.rs:58` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/linux_like/linux/musl/lfs64.rs:68` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/libc/src/unix/linux_like/linux/musl/lfs64.rs:73` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/libc/src/unix/linux_like/linux/musl/lfs64.rs:78` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/libc/src/unix/linux_like/linux/musl/lfs64.rs:83` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/linux_like/linux/musl/lfs64.rs:88` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/libc/src/unix/linux_like/linux/musl/lfs64.rs:93` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/linux_like/linux/musl/lfs64.rs:98` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/libc/src/unix/linux_like/linux/musl/lfs64.rs:103` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/linux_like/linux/musl/lfs64.rs:126` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/linux_like/linux/musl/lfs64.rs:136` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/linux_like/linux/musl/lfs64.rs:141` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/linux_like/linux/musl/lfs64.rs:151` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/linux_like/linux/musl/lfs64.rs:161` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/linux_like/linux/musl/lfs64.rs:171` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/linux_like/linux/musl/lfs64.rs:181` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/linux_like/linux/musl/lfs64.rs:191` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/libc/src/unix/linux_like/linux/musl/lfs64.rs:196` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/linux_like/linux/musl/lfs64.rs:205` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/linux_like/linux/musl/lfs64.rs:215` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/libc/src/unix/linux_like/linux/musl/lfs64.rs:220` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/libc/src/unix/linux_like/linux/musl/lfs64.rs:225` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/libc/src/unix/linux_like/linux/musl/lfs64.rs:230` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/libc/src/unix/linux_like/linux/musl/lfs64.rs:235` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/libc/src/unix/linux_like/linux/musl/lfs64.rs:240` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/libc/src/unix/bsd/apple/b64/x86_64/mod.rs:16` | architecture intrinsics or assembly path.
- `safe/vendor/libc/src/unix/bsd/apple/b64/x86_64/mod.rs:18` | architecture intrinsics or assembly path.
- `safe/vendor/libc/src/unix/bsd/apple/b64/x86_64/mod.rs:20` | architecture intrinsics or assembly path.
- `safe/vendor/libc/src/unix/bsd/apple/b64/x86_64/mod.rs:27` | architecture intrinsics or assembly path.
- `safe/vendor/libc/src/unix/bsd/apple/b64/x86_64/mod.rs:28` | architecture intrinsics or assembly path.
- `safe/vendor/libc/src/unix/bsd/apple/b64/x86_64/mod.rs:30` | architecture intrinsics or assembly path.
- `safe/vendor/libc/src/unix/bsd/apple/b64/x86_64/mod.rs:36` | architecture intrinsics or assembly path.
- `safe/vendor/libc/src/unix/bsd/apple/b64/x86_64/mod.rs:39` | architecture intrinsics or assembly path.
- `safe/vendor/libc/src/unix/bsd/apple/b64/x86_64/mod.rs:47` | architecture intrinsics or assembly path.
- `safe/vendor/libc/src/unix/bsd/apple/b64/x86_64/mod.rs:56` | architecture intrinsics or assembly path.
- `safe/vendor/libc/src/unix/bsd/apple/b64/x86_64/mod.rs:63` | architecture intrinsics or assembly path.
- `safe/vendor/libc/src/unix/bsd/apple/b64/x86_64/mod.rs:65` | architecture intrinsics or assembly path.
- `safe/vendor/libc/src/unix/bsd/apple/b64/x86_64/mod.rs:67` | architecture intrinsics or assembly path.
- `safe/vendor/libc/src/unix/bsd/freebsdlike/mod.rs:67` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/libc/src/unix/bsd/freebsdlike/mod.rs:71` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/bsd/freebsdlike/mod.rs:75` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/bsd/freebsdlike/mod.rs:79` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/bsd/freebsdlike/mod.rs:83` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/bsd/freebsdlike/mod.rs:1745` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/libc/src/unix/linux_like/android/mod.rs:585` | unsafe trait invariant.
- `safe/vendor/libc/src/unix/linux_like/android/mod.rs:667` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/libc/src/unix/linux_like/android/mod.rs:3705` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/libc/src/unix/linux_like/android/mod.rs:3713` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/libc/src/unix/linux_like/android/mod.rs:3783` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/libc/src/unix/linux_like/android/mod.rs:3794` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/linux_like/android/mod.rs:3809` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/linux_like/android/mod.rs:3813` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/linux_like/android/mod.rs:3817` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/linux_like/android/mod.rs:3821` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/linux_like/android/mod.rs:3825` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/linux_like/android/mod.rs:3829` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/bsd/freebsdlike/freebsd/x86_64/mod.rs:156` | architecture intrinsics or assembly path.
- `safe/vendor/libc/src/unix/linux_like/linux/musl/mod.rs:56` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/libc/src/unix/linux_like/linux/musl/mod.rs:67` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/linux_like/linux/musl/mod.rs:107` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/linux_like/linux/musl/mod.rs:111` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/linux_like/linux/musl/mod.rs:115` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/linux_like/linux/musl/mod.rs:119` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/linux_like/linux/musl/mod.rs:123` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/linux_like/linux/musl/mod.rs:127` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/bsd/freebsdlike/freebsd/freebsd15/mod.rs:398` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/libc/src/unix/linux_like/mod.rs:1790` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/linux_like/mod.rs:1794` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/bsd/netbsdlike/netbsd/riscv64.rs:28` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/bsd/netbsdlike/netbsd/riscv64.rs:34` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/bsd/apple/mod.rs:1632` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/libc/src/unix/bsd/apple/mod.rs:1636` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/bsd/apple/mod.rs:1652` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/bsd/apple/mod.rs:1656` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/bsd/apple/mod.rs:1660` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/bsd/apple/mod.rs:1677` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/bsd/apple/mod.rs:1683` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/bsd/apple/mod.rs:1702` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/bsd/apple/mod.rs:1703` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/bsd/apple/mod.rs:1704` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/bsd/apple/mod.rs:1705` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/bsd/apple/mod.rs:1714` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/bsd/apple/mod.rs:1721` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/bsd/apple/mod.rs:1730` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/bsd/apple/mod.rs:1759` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/bsd/apple/mod.rs:1784` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/bsd/apple/mod.rs:1790` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/bsd/apple/mod.rs:1791` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/bsd/apple/mod.rs:1797` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/bsd/apple/mod.rs:1818` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/bsd/apple/mod.rs:5120` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/libc/src/unix/bsd/apple/mod.rs:5126` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/bsd/freebsdlike/freebsd/freebsd13/mod.rs:396` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/libc/src/unix/bsd/freebsdlike/freebsd/freebsd11/mod.rs:318` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/libc/src/unix/linux_like/android/b64/x86_64/mod.rs:174` | architecture intrinsics or assembly path.
- `safe/vendor/libc/src/unix/linux_like/android/b64/x86_64/mod.rs:180` | architecture intrinsics or assembly path.
- `safe/vendor/libc/src/unix/bsd/netbsdlike/netbsd/mod.rs:65` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/libc/src/unix/bsd/netbsdlike/netbsd/mod.rs:69` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/bsd/netbsdlike/netbsd/mod.rs:73` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/bsd/netbsdlike/netbsd/mod.rs:77` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/bsd/netbsdlike/netbsd/mod.rs:90` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/bsd/netbsdlike/netbsd/mod.rs:104` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/bsd/netbsdlike/netbsd/mod.rs:119` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/bsd/netbsdlike/netbsd/mod.rs:813` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/bsd/netbsdlike/netbsd/mod.rs:818` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/bsd/netbsdlike/netbsd/mod.rs:2157` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/libc/src/unix/bsd/netbsdlike/netbsd/mod.rs:2269` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/libc/src/unix/bsd/netbsdlike/netbsd/mod.rs:2336` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/libc/src/unix/bsd/netbsdlike/netbsd/mod.rs:2337` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/libc/src/unix/bsd/freebsdlike/freebsd/freebsd12/mod.rs:357` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/libc/src/unix/bsd/freebsdlike/freebsd/freebsd14/mod.rs:396` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/libc/src/unix/linux_like/linux/gnu/b32/riscv32/mod.rs:120` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/linux_like/linux/uclibc/mod.rs:159` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/libc/src/unix/linux_like/linux/uclibc/mod.rs:170` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/linux_like/linux/uclibc/mod.rs:210` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/linux_like/linux/uclibc/mod.rs:214` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/linux_like/linux/uclibc/mod.rs:218` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/linux_like/linux/uclibc/mod.rs:222` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/linux_like/linux/uclibc/mod.rs:226` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/linux_like/linux/uclibc/mod.rs:230` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/linux_like/linux/mod.rs:1298` | unsafe trait invariant.
- `safe/vendor/libc/src/unix/linux_like/linux/mod.rs:1401` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/libc/src/unix/linux_like/linux/gnu/mod.rs:384` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/libc/src/unix/linux_like/linux/gnu/mod.rs:395` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/linux_like/linux/gnu/mod.rs:444` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/linux_like/linux/gnu/mod.rs:448` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/linux_like/linux/gnu/mod.rs:452` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/linux_like/linux/gnu/mod.rs:456` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/linux_like/linux/gnu/mod.rs:460` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/linux_like/linux/gnu/mod.rs:464` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/linux_like/linux/gnu/mod.rs:481` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/linux_like/linux/gnu/mod.rs:493` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/linux_like/linux/gnu/mod.rs:965` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/libc/src/unix/bsd/netbsdlike/netbsd/aarch64.rs:44` | architecture intrinsics or assembly path.
- `safe/vendor/libc/src/unix/bsd/netbsdlike/netbsd/aarch64.rs:56` | architecture intrinsics or assembly path.
- `safe/vendor/libc/src/unix/linux_like/linux/gnu/b64/riscv64/mod.rs:155` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/solarish/compat.rs:12` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/libc/src/unix/solarish/compat.rs:37` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/libc/src/unix/solarish/compat.rs:46` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/solarish/compat.rs:59` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/solarish/compat.rs:133` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/solarish/compat.rs:184` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/solarish/compat.rs:204` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/bsd/freebsdlike/freebsd/mod.rs:1793` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/bsd/freebsdlike/freebsd/mod.rs:1799` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/bsd/freebsdlike/freebsd/mod.rs:1823` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/bsd/freebsdlike/freebsd/mod.rs:1835` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/bsd/freebsdlike/freebsd/mod.rs:1857` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/bsd/freebsdlike/freebsd/mod.rs:1858` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/bsd/freebsdlike/freebsd/mod.rs:1859` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/bsd/freebsdlike/freebsd/mod.rs:1860` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/bsd/freebsdlike/freebsd/mod.rs:1861` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/bsd/freebsdlike/freebsd/mod.rs:1862` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/bsd/freebsdlike/freebsd/mod.rs:1863` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/bsd/freebsdlike/freebsd/mod.rs:1864` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/bsd/freebsdlike/freebsd/mod.rs:1865` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/bsd/freebsdlike/freebsd/mod.rs:1866` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/bsd/freebsdlike/freebsd/mod.rs:1867` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/bsd/freebsdlike/freebsd/mod.rs:1868` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/bsd/freebsdlike/freebsd/mod.rs:1869` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/bsd/freebsdlike/freebsd/mod.rs:1870` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/bsd/freebsdlike/freebsd/mod.rs:1871` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/bsd/freebsdlike/freebsd/mod.rs:1877` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/bsd/freebsdlike/freebsd/mod.rs:1883` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/bsd/freebsdlike/freebsd/mod.rs:1884` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/bsd/freebsdlike/freebsd/mod.rs:1890` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/bsd/freebsdlike/freebsd/mod.rs:1896` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/bsd/freebsdlike/freebsd/mod.rs:1905` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/bsd/freebsdlike/freebsd/mod.rs:1911` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/bsd/freebsdlike/freebsd/mod.rs:4752` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/libc/src/unix/solarish/x86_64.rs:104` | architecture intrinsics or assembly path.
- `safe/vendor/libc/src/unix/solarish/x86_64.rs:117` | architecture intrinsics or assembly path.
- `safe/vendor/libc/src/unix/solarish/mod.rs:628` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/solarish/mod.rs:637` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/solarish/mod.rs:645` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/solarish/mod.rs:654` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/solarish/mod.rs:707` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/solarish/mod.rs:710` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/libc/src/unix/solarish/mod.rs:714` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/solarish/mod.rs:718` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/solarish/mod.rs:722` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/solarish/mod.rs:726` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/solarish/mod.rs:730` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/solarish/mod.rs:734` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/solarish/mod.rs:2274` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/solarish/mod.rs:2278` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/solarish/mod.rs:2746` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/solarish/mod.rs:2747` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/solarish/mod.rs:2748` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/solarish/mod.rs:2863` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/libc/src/unix/solarish/mod.rs:3010` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/solarish/mod.rs:3014` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/solarish/mod.rs:3018` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/hurd/mod.rs:1050` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/libc/src/unix/hurd/mod.rs:1054` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/hurd/mod.rs:1058` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/hurd/mod.rs:1062` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/hurd/mod.rs:1066` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/hurd/mod.rs:3924` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/hurd/mod.rs:3925` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/hurd/mod.rs:3926` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/hurd/mod.rs:4311` | raw pointer or byte/slice reinterpretation.
- `safe/vendor/libc/src/unix/hurd/mod.rs:4456` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/hurd/mod.rs:4488` | FFI declarations or platform bindings.
- `safe/vendor/libc/src/unix/hurd/mod.rs:4492` | FFI declarations or platform bindings.

# Remaining unsafe FFI beyond the original ABI/API boundary

The intended original boundary is the libgcrypt C ABI from `safe/abi/libgcrypt.vers` and the generated `safe/target/bootstrap/generated/include/gcrypt.h` rendered from `safe/abi/gcrypt.h.in`. Anything below is runtime, build-time, helper-tool, or internal shim FFI beyond that boundary.

| Surface | Provider | Why it remains | Plausible safe-Rust replacement path |
| --- | --- | --- | --- |
| `malloc`, `realloc`, and `free` in `safe/src/alloc.rs:18` | libc allocator ABI | Public allocation APIs return memory that C callers release through `gcry_free`, and custom allocation handlers must remain C-compatible. | Replace plain internal allocation with `std::alloc` only after proving cross-ABI ownership never reaches libc `free`; keep a small C-owned compatibility layer if C callers allocate/free across the boundary. |
| `malloc`, `calloc`, `free`, `mlock`, and `munlock` in `safe/src/secmem.rs:58` | libc and POSIX memory-locking ABI | Secure-memory allocation tracks locked pages and zeroizes before release while preserving libgcrypt secure-memory behavior. | Use a narrower Rust wrapper around page locking, or a reviewed safe crate, while keeping explicit secure-memory accounting and zeroization. |
| `__errno_location` in `safe/src/lib.rs:50` | glibc errno ABI | The public API sets errno-compatible state after C allocation/config errors. | Reduce errno use to the C shim or replace with a tiny safe wrapper module; there is no fully safe standard-library errno setter. |
| `getrandom`, `getpid`, and `clock_gettime` in `safe/src/os_rng.rs:17` | Linux/glibc OS ABI | Random generation needs OS entropy, fork detection, and monotonic timing material for fast polling. | Use safe wrappers such as `std::process::id` and `std::time::Instant` where behavior matches; use a reviewed randomness crate for entropy acquisition. |
| `fwrite` in `safe/src/config.rs:13` | libc stdio ABI | `GCRYCTL_PRINT_CONFIG` receives an opaque `FILE *`, so Rust must write to a C stream. | Keep this in a narrow C shim or require callers to use `gcry_get_config`; Rust cannot safely write to an arbitrary `FILE *` without FFI. |
| `fputs` and `stderr` in `safe/cabi/exports.c:85` | libc stdio ABI | Default logging is implemented in the C shim because log callbacks use C varargs and default stderr behavior. | Move default logging to Rust stderr only if the C shim continues to own `va_list` callback dispatch. |
| `vsnprintf` in `safe/cabi/exports.c:552` | libc formatting ABI | `gcry_log_debug` is a varargs function; C normalizes the formatted string before Rust dispatch. | Keep the varargs front end in C; stable Rust cannot implement C varargs exports safely. |
| `strchr`, `malloc`, `free`, and `errno` in `safe/cabi/exports.c:394`, `safe/cabi/exports.c:451`, and `safe/cabi/exports.c:499` | libc string, allocation, and errno ABI | The varargs S-expression shims count and store arguments before calling fixed Rust dispatchers. | Use fixed-signature public APIs where possible; otherwise keep the smallest C normalization shim. |
| `gpg_strerror`, `gpg_strsource`, `gpg_err_code_from_errno`, `gpg_err_code_to_errno`, and `gpg_error_check_version` in `safe/src/error.rs:63` | libgpg-error | Libgcrypt error values and messages must match the system libgpg-error ABI used by callers. | Replace with a generated Rust table only if it is kept in lockstep with libgpg-error and packaging no longer depends on that shared library. |
| `__gmpz_abs`, `__gmpz_add`, `__gmpz_add_ui`, `__gmpz_clear`, `__gmpz_clrbit`, `__gmpz_cmp`, `__gmpz_cmp_ui`, `__gmpz_export`, `__gmpz_fdiv_q_2exp`, `__gmpz_fdiv_qr`, `__gmpz_fdiv_r`, `__gmpz_fdiv_r_2exp`, `__gmpz_fdiv_ui`, `__gmpz_gcd`, `__gmpz_import`, `__gmpz_init`, `__gmpz_init2`, `__gmpz_invert`, `__gmpz_mod`, `__gmpz_mul`, `__gmpz_mul_2exp`, `__gmpz_mul_ui`, `__gmpz_neg`, `__gmpz_nextprime`, `__gmpz_ior`, `__gmpz_powm`, `__gmpz_powm_sec`, `__gmpz_probab_prime_p`, `__gmpz_set`, `__gmpz_set_ui`, `__gmpz_setbit`, `__gmpz_sizeinbase`, `__gmpz_sub`, `__gmpz_sub_ui`, `__gmpz_swap`, `__gmpz_tdiv_q_2exp`, `__gmpz_tdiv_qr`, `__gmpz_tstbit`, and `__gmpz_xor` in `safe/src/mpi/mod.rs:61` | GMP | MPI, prime, scan/export, ECC, and public-key paths use GMP for arbitrary-precision arithmetic and `__gmpz_powm_sec` for secret exponentiation. | A pure-Rust big integer implementation with reviewed constant-time secret operations would remove this dependency; bounded `crypto-bigint`-style replacements would need substantial ABI adaptation. |
| `safe_cabi_dispatch_log_message` and `safe_cabi_set_log_handler` in `safe/src/log.rs:59` and `safe/cabi/exports.c:46` | Internal C shim | Rust-owned logging state must interoperate with public C `gcry_set_log_handler` and varargs log formatting. | Keep only the callback/varargs bridge in C; move all non-varargs policy to Rust. |
| `Command::new(cc)` and `Command::new(ar)` in `safe/build.rs:472`, `safe/build.rs:491`, and `safe/build.rs:503` | Build host C compiler and archiver | The build compiles `safe/cabi/exports.c` and generated C into `libsafe_cabi.a`. | Replace with a checked-in object is not maintainable; a `cc` crate wrapper would still invoke a C compiler but could reduce hand-rolled command handling. |
| `$(CC)` and final shared-library link flags in `safe/debian/rules:38` | Debian build compiler/linker | Debian packaging links `target/release/libgcrypt.a` into `target/release/libgcrypt.so` with `safe/abi/libgcrypt.vers` and system libraries. | A Cargo `cdylib` build could remove this custom link if it can preserve the exact version script, soname, and export ownership. |
| `cc -shared` and final shared-library link flags in `safe/scripts/build-release-lib.sh:32` | Local build compiler/linker | Local ABI/test flows need the same shared object shape as Debian packaging without running the full package build. | Same replacement as packaging: a version-script-capable Cargo shared-library flow. |
| Helper-binary `unsafe extern "C"` declarations in `safe/src/bin/dumpsexp.rs:7`, `safe/src/bin/hmac256.rs:7`, and `safe/src/bin/mpicalc.rs:6` | The installed libgcrypt ABI produced by this port | The helper tools intentionally exercise the installed ABI rather than reaching into Rust internals. | Use safe Rust crate calls only if the tools stop being ABI compatibility tools; otherwise keep the self-call classification. |

# Remaining issues

## Behavioral Compatibility And Bit-For-Bit Status

`validator-report.md` records the final direct-wrapper libgcrypt suite at validator commit `87b321fe728340d6fc6dd2f638583cca82c667c3`: 175 total port cases, 171 passed, 0 failed, and 4 active port-mode skips. The active skips are `usage-gpg-symmetric-cipher-camellia128`, `usage-gpg-symmetric-compress-z9-decrypt`, `usage-gpg-symmetric-list-packets-s2k-sha256`, `usage-gpg-symmetric-s2k-mode1-salted`, and their reasons are stored in `safe/scripts/validator-libgcrypt-skips.json`. The ignored final validator artifact evidence is present and was checked with `python3 safe/scripts/check-validator-port-evidence.py --port-lock validator-local/proof/local-port-debs-lock.json --override-root validator-local/override-debs --artifact-root validator-artifacts/p08-final`, which passed after the nested `validator/` checkout was confirmed clean.

The official validator inventory path was unavailable at that commit because the checkout reported `unknown libraries in config: libgcrypt`; `validator-report.md` classifies that as a validator-side inventory/proof limitation, not as a port test pass. The port-owned fallback wrapper is therefore the final validator evidence for this tree.

Known compatibility caveats from checked artifacts:

- The four active skips in `safe/scripts/validator-libgcrypt-skips.json` are validator testcase defects that also fail against the original baseline at `validator-report.md:850`; impact is that those four usage cases are not positive port evidence for this commit.
- `validator-report.md:674` records five original-baseline failures, and `validator-report.md:694` records that the final safe candidate has no non-skipped failures; impact is that final port status is clean only under the port-owned fallback wrapper and skip policy.
- `safe/docs/cve-matrix.md:32` states that RSA padding code is behavior-compatible but is not proof of fully uniform failure timing; impact is that side-channel hardening remains a review obligation for future RSA padding changes.
- `safe/docs/cve-matrix.md:20`, `safe/docs/cve-matrix.md:22`, and `safe/docs/cve-matrix.md:30` keep review obligations around GMP-backed field arithmetic, scalar-bit selection, and ECDSA/ECC side-channel hardening; impact is that current tests prove functional compatibility, not a broad constant-time proof.
- `safe/tests/regressions/manifest.json` lists retained regressions for dependent image metadata, Ed25519/Curve25519/X448 behavior, GPG usage, ASNOID, keygrip, and ECC alias fixes; impact is that these previously fixed safe-side gaps must stay in the regression set.

No direct bit-for-bit comparison between original libgcrypt and the safe implementation was found in `validator-report.md`, `safe/docs/test-matrix.md`, `safe/docs/abi-map.md`, `safe/docs/bridge-inventory.md`, `safe/tests/compat/`, `safe/tests/regressions/manifest.json`, `dependents.json`, `relevant_cves.json`, or `all_cves.json`. This document therefore does not claim bit-for-bit equivalence. Residual risk remains for untested libgcrypt surfaces, output formatting edge cases, error timing, performance-sensitive behavior, and caller patterns not represented by the upstream, validator, regression, compatibility, or dependent matrices.

## Dependent Coverage

`dependents.json` and `safe/tests/dependents/metadata/matrix-manifest.json` cover 15 packages. Library probes cover `libapt-pkg6.0t64`, `libssh-gcrypt-4`, `libxmlsec1t64-gcrypt`. Executable scenarios cover `gpg`, `gnome-keyring`, `munge`, `aircrack-ng`, `wireshark-common`, `gpgv`, `gpgsm`, `seccure`, `pdfgrep`, `rng-tools5`, `libotr5-bin`, `tcplay`. The metadata inputs are committed in `safe/tests/dependents/metadata/`, including `safe/tests/dependents/metadata/base-image.noble.digest`, `safe/tests/dependents/metadata/install-packages.noble.lock`, `safe/tests/dependents/metadata/matrix-manifest.json`, `safe/tests/dependents/metadata/package-evidence.noble.json`, `safe/tests/dependents/metadata/safe-debs.noble.lock`, and `safe/tests/dependents/metadata/ubuntu-snapshot.noble.sources`.

## CVE Review Coverage

`relevant_cves.json` reports 16 included relevant CVEs and 1 excluded memory-corruption CVE. The included set is `CVE-2013-4242`, `CVE-2014-3591`, `CVE-2014-5270`, `CVE-2015-0837`, `CVE-2015-7511`, `CVE-2016-6313`, `CVE-2017-0379`, `CVE-2017-7526`, `CVE-2017-9526`, `CVE-2018-0495`, `CVE-2018-6829`, `CVE-2019-12904`, `CVE-2019-13627`, `CVE-2021-33560`, `CVE-2021-40528`, `CVE-2024-2236`. The excluded memory-corruption CVE is `CVE-2021-3345`. `safe/docs/cve-matrix.md` maps each included CVE to current code paths and either verifier coverage or an explicit future review obligation. The main residual obligations are algorithmic rather than memory-safety-only: RSA/ElGamal/ECC side-channel behavior, ECDSA nonce/scalar hardening, RNG fork/reseed behavior, AES software timing, and RSA padding failure observability.

## Performance

`safe/docs/test-matrix.md` lists upstream `benchmark` and `bench-slope` as `safe/scripts/run-upstream-tests.sh --all` coverage, and lists `pkbench` as a build-only helper under `safe/scripts/run-upstream-tests.sh --verify-plumbing`. `safe/tests/upstream/benchmark.c` and `safe/tests/upstream/bench-slope.c` are imported from `original/libgcrypt20-1.10.3/tests/benchmark.c` and `original/libgcrypt20-1.10.3/tests/bench-slope.c`; `safe/tests/upstream/pkbench.c` is also present as a helper. The checked artifacts did not contain a direct original-vs-safe benchmark comparison or throughput/latency threshold. This document therefore does not claim no performance regression. Residual risk remains for slower symmetric modes, public-key operations, DRBG behavior, GMP-backed MPI, and helper-tool throughput even when functional tests pass.

## TODO And Unsupported Markers

The owned-code marker search found no `panic!`, `unimplemented!`, or `todo!` in `safe/src`. Relevant owned-script markers are operational: `safe/scripts/run-regression-tests.sh:142` rejects unsupported regression kinds, and temporary directory uses in scripts are test harness mechanics. Upstream imported comments such as `safe/tests/upstream/bench-slope.c:558`, `safe/tests/upstream/basic.c:11823`, `safe/tests/upstream/t-sexp.c:593`, `safe/tests/upstream/t-mpi-point.c:833`, and `safe/tests/upstream/t-secmem.c:227` are inherited upstream test comments, not current Rust port implementation issues unless a future behavior gap points to them.

# Dependencies and other libraries used

Rust dependency resolution is offline and vendored through `.cargo/config.toml`, `safe/.cargo/config.toml`, and `safe/vendor`. Both `rust-toolchain.toml` and `safe/rust-toolchain.toml` pin Rust `1.85.1`. `cargo metadata` and `cargo tree` were run with `--locked --offline`; `safe/Cargo.lock` currently resolves `sha3` to `0.10.9` even though `safe/Cargo.toml` requests `0.10.8`.

## Direct Rust Dependencies

| Dependency | Version | Purpose | Unsafe posture |
| --- | --- | --- | --- |
| `argon2` | `0.5.3` | Argon2 KDF | none, 2 unsafe lines. |
| `blake2` | `0.10.6` | BLAKE2 digests | none, 26 unsafe lines. |
| `blowfish` | `0.10.0` | Blowfish cipher | deny unsafe code, 0 unsafe lines. |
| `camellia` | `0.2.0` | Camellia cipher | deny unsafe code, 0 unsafe lines. |
| `cast5` | `0.12.0` | CAST5 cipher | deny unsafe code, 0 unsafe lines. |
| `cipher04 / cipher` | `0.4.4` | older RustCrypto cipher traits | none, 2 unsafe lines. |
| `cipher05 / cipher` | `0.5.1` | newer RustCrypto cipher traits | forbid unsafe code, 0 unsafe lines. |
| `des` | `0.9.0` | DES and 3DES cipher | deny unsafe code, 0 unsafe lines. |
| `digest` | `0.10.7` | digest trait integration | forbid unsafe code, 0 unsafe lines. |
| `gost94` | `0.10.4` | GOST digest support | forbid unsafe code, 0 unsafe lines. |
| `gost-crypto` | `0.3.0` | GOST cipher support | none, 0 unsafe lines. |
| `hmac` | `0.12.1` | HMAC | forbid unsafe code, 0 unsafe lines. |
| `idea` | `0.6.0` | IDEA cipher | deny unsafe code, 0 unsafe lines. |
| `kisaseed` | `0.1.3` | SEED cipher | none, 1 unsafe line. |
| `md4` | `0.10.2` | MD4 digest | forbid unsafe code, 0 unsafe lines. |
| `md-5` | `0.10.6` | MD5 digest | none, 2 unsafe lines. |
| `pbkdf2` | `0.12.2` | PBKDF2 KDF | none, 0 unsafe lines. |
| `rc2` | `0.9.0` | RC2 cipher | deny unsafe code, 0 unsafe lines. |
| `ripemd` | `0.1.3` | RIPEMD digest algorithms | forbid unsafe code, 0 unsafe lines. |
| `scrypt` | `0.11.0` | scrypt KDF | none, 0 unsafe lines. |
| `serpent` | `0.6.0` | Serpent cipher | deny unsafe code, 0 unsafe lines. |
| `sha1` | `0.10.6` | SHA-1 digest | none, 4 unsafe lines. |
| `sha2` | `0.10.9` | SHA-2 digests | none, 29 unsafe lines. |
| `sha3` | `0.10.8 requested, 0.10.9 resolved` | SHA-3 and SHAKE digests | forbid unsafe code, 0 unsafe lines. |
| `sm3` | `0.4.2` | SM3 digest | forbid unsafe code, 0 unsafe lines. |
| `sm4` | `0.6.0` | SM4 cipher | deny unsafe code, 0 unsafe lines. |
| `streebog` | `0.10.2` | Streebog digest | forbid unsafe code, 0 unsafe lines. |
| `tiger` | `0.2.1` | Tiger digest | forbid unsafe code, 0 unsafe lines. |
| `twofish` | `0.8.0` | Twofish cipher | deny unsafe code, 0 unsafe lines. |
| `whirlpool` | `0.10.4` | Whirlpool digest | none, 1 unsafe line. |

## Dependency Safety

`cargo geiger --manifest-path safe/Cargo.toml --locked --offline` was attempted and failed because this environment has no `cargo geiger` subcommand. The fallback evidence is `cargo metadata`, `cargo tree`, the generated dependency safety TSV, and the `safe/vendor` unsafe inventory above.

| Scope | Package | Version | Manifest | Unsafe policy | Unsafe lines | Evidence | Acceptance and replacement path |
| --- | --- | --- | --- | --- | ---: | --- | --- |
| direct | `argon2` | `0.5.3` | `safe/vendor/argon2/Cargo.toml` | `none` | 2 | `safe/vendor/argon2/src/lib.rs:464` | Accepted because the unsafe use is narrow in vendored, locked code; replacement path is an audited dependency version that forbids unsafe or a local wrapper that removes this call site. |
| transitive | `base64ct` | `1.8.3` | `safe/vendor/base64ct/Cargo.toml` | `none` | 4 | `safe/vendor/base64ct/src/encoding.rs:107` | Accepted because the unsafe use is narrow in vendored, locked code; replacement path is an audited dependency version that forbids unsafe or a local wrapper that removes this call site. |
| direct | `blake2` | `0.10.6` | `safe/vendor/blake2/Cargo.toml` | `none` | 26 | `safe/vendor/blake2/src/as_bytes.rs:12` | Accepted because it is vendored, locked, and exercised through the port test matrix; replacement path is an audited crate release with unsafe-code denial or a local safe implementation for the specific primitive. |
| transitive | `block-buffer` | `0.10.4` | `safe/vendor/block-buffer/Cargo.toml` | `none` | 4 | `safe/vendor/block-buffer/src/sealed.rs:27` | Accepted because the unsafe use is narrow in vendored, locked code; replacement path is an audited dependency version that forbids unsafe or a local wrapper that removes this call site. |
| direct | `blowfish` | `0.10.0` | `safe/vendor/blowfish/Cargo.toml` | `#![deny(unsafe_code)]` | 0 | `safe/vendor/blowfish/src/lib.rs:1` | Accepted because the unsafe use is narrow in vendored, locked code; replacement path is an audited dependency version that forbids unsafe or a local wrapper that removes this call site. |
| transitive | `byteorder` | `1.5.0` | `safe/vendor/byteorder/Cargo.toml` | `none` | 43 | `safe/vendor/byteorder/CHANGELOG.md:15` | Accepted because it is vendored, locked, and exercised through the port test matrix; replacement path is an audited crate release with unsafe-code denial or a local safe implementation for the specific primitive. |
| direct | `camellia` | `0.2.0` | `safe/vendor/camellia/Cargo.toml` | `#![deny(unsafe_code)]` | 0 | `safe/vendor/camellia/src/lib.rs:1` | Accepted because the unsafe use is narrow in vendored, locked code; replacement path is an audited dependency version that forbids unsafe or a local wrapper that removes this call site. |
| direct | `cast5` | `0.12.0` | `safe/vendor/cast5/Cargo.toml` | `#![deny(unsafe_code)]` | 0 | `safe/vendor/cast5/src/lib.rs:1` | Accepted because the unsafe use is narrow in vendored, locked code; replacement path is an audited dependency version that forbids unsafe or a local wrapper that removes this call site. |
| transitive | `cfg-if` | `1.0.4` | `safe/vendor/cfg-if/Cargo.toml` | `none` | 0 | `safe/vendor/cfg-if/src/lib.rs:1` | Accepted as locked transitive/direct code with no current source unsafe matches; replacement path is an upstream release with crate-root unsafe-code denial. |
| direct | `cipher` | `0.4.4` | `safe/vendor/cipher/Cargo.toml` | `none` | 2 | `safe/vendor/cipher/src/stream_wrapper.rs:56` | Accepted because the unsafe use is narrow in vendored, locked code; replacement path is an audited dependency version that forbids unsafe or a local wrapper that removes this call site. |
| direct | `cipher` | `0.5.1` | `safe/vendor/cipher-0.5.1/Cargo.toml` | `#![forbid(unsafe_code)]` | 0 | `safe/vendor/cipher-0.5.1/src/lib.rs:1` | Accepted because the unsafe use is narrow in vendored, locked code; replacement path is an audited dependency version that forbids unsafe or a local wrapper that removes this call site. |
| transitive | `cpufeatures` | `0.2.17` | `safe/vendor/cpufeatures/Cargo.toml` | `none` | 9 | `safe/vendor/cpufeatures/src/aarch64.rs:37` | Accepted because the unsafe use is narrow in vendored, locked code; replacement path is an audited dependency version that forbids unsafe or a local wrapper that removes this call site. |
| transitive | `crypto-common` | `0.1.7` | `safe/vendor/crypto-common/Cargo.toml` | `#![forbid(unsafe_code)]` | 0 | `safe/vendor/crypto-common/src/lib.rs:1` | Accepted because the unsafe use is narrow in vendored, locked code; replacement path is an audited dependency version that forbids unsafe or a local wrapper that removes this call site. |
| transitive | `crypto-common` | `0.2.1` | `safe/vendor/crypto-common-0.2.1/Cargo.toml` | `#![forbid(unsafe_code)]` | 0 | `safe/vendor/crypto-common-0.2.1/src/lib.rs:1` | Accepted because the unsafe use is narrow in vendored, locked code; replacement path is an audited dependency version that forbids unsafe or a local wrapper that removes this call site. |
| direct | `des` | `0.9.0` | `safe/vendor/des/Cargo.toml` | `#![deny(unsafe_code)]` | 0 | `safe/vendor/des/src/lib.rs:1` | Accepted because the unsafe use is narrow in vendored, locked code; replacement path is an audited dependency version that forbids unsafe or a local wrapper that removes this call site. |
| direct | `digest` | `0.10.7` | `safe/vendor/digest/Cargo.toml` | `#![forbid(unsafe_code)]` | 0 | `safe/vendor/digest/src/lib.rs:1` | Accepted because the unsafe use is narrow in vendored, locked code; replacement path is an audited dependency version that forbids unsafe or a local wrapper that removes this call site. |
| transitive | `generic-array` | `0.14.7` | `safe/vendor/generic-array/Cargo.toml` | `none` | 78 | `safe/vendor/generic-array/CHANGELOG.md:6` | Accepted because it is vendored, locked, and exercised through the port test matrix; replacement path is an audited crate release with unsafe-code denial or a local safe implementation for the specific primitive. |
| direct | `gost-crypto` | `0.3.0` | `safe/vendor/gost-crypto/Cargo.toml` | `none` | 0 | `safe/vendor/gost-crypto/README.md:20` | Accepted as locked transitive/direct code with no current source unsafe matches; replacement path is an upstream release with crate-root unsafe-code denial. |
| direct | `gost94` | `0.10.4` | `safe/vendor/gost94/Cargo.toml` | `#![forbid(unsafe_code)]` | 0 | `safe/vendor/gost94/src/lib.rs:1` | Accepted because the unsafe use is narrow in vendored, locked code; replacement path is an audited dependency version that forbids unsafe or a local wrapper that removes this call site. |
| direct | `hmac` | `0.12.1` | `safe/vendor/hmac/Cargo.toml` | `#![forbid(unsafe_code)]` | 0 | `safe/vendor/hmac/src/lib.rs:1` | Accepted because the unsafe use is narrow in vendored, locked code; replacement path is an audited dependency version that forbids unsafe or a local wrapper that removes this call site. |
| transitive | `hybrid-array` | `0.4.11` | `safe/vendor/hybrid-array/Cargo.toml` | `none` | 38 | `safe/vendor/hybrid-array/tests/mod.rs:468` | Accepted because it is vendored, locked, and exercised through the port test matrix; replacement path is an audited crate release with unsafe-code denial or a local safe implementation for the specific primitive. |
| direct | `idea` | `0.6.0` | `safe/vendor/idea/Cargo.toml` | `#![deny(unsafe_code)]` | 0 | `safe/vendor/idea/src/lib.rs:1` | Accepted because the unsafe use is narrow in vendored, locked code; replacement path is an audited dependency version that forbids unsafe or a local wrapper that removes this call site. |
| transitive | `inout` | `0.1.4` | `safe/vendor/inout/Cargo.toml` | `none` | 22 | `safe/vendor/inout/src/inout_buf.rs:103` | Accepted because it is vendored, locked, and exercised through the port test matrix; replacement path is an audited crate release with unsafe-code denial or a local safe implementation for the specific primitive. |
| transitive | `inout` | `0.2.2` | `safe/vendor/inout-0.2.2/Cargo.toml` | `none` | 30 | `safe/vendor/inout-0.2.2/src/inout_buf.rs:103` | Accepted because it is vendored, locked, and exercised through the port test matrix; replacement path is an audited crate release with unsafe-code denial or a local safe implementation for the specific primitive. |
| transitive | `keccak` | `0.1.6` | `safe/vendor/keccak/Cargo.toml` | `none` | 5 | `safe/vendor/keccak/src/lib.rs:187` | Accepted because the unsafe use is narrow in vendored, locked code; replacement path is an audited dependency version that forbids unsafe or a local wrapper that removes this call site. |
| direct | `kisaseed` | `0.1.3` | `safe/vendor/kisaseed/Cargo.toml` | `none` | 1 | `safe/vendor/kisaseed/src/lib.rs:117` | Accepted because the unsafe use is narrow in vendored, locked code; replacement path is an audited dependency version that forbids unsafe or a local wrapper that removes this call site. |
| transitive | `libc` | `0.2.186` | `safe/vendor/libc/Cargo.toml` | `none` | 429 | `safe/vendor/libc/CHANGELOG.md:686` | Accepted because it is vendored and locked for transitive platform bindings; replacement path is to remove consumers or move to narrower safe std/rustix wrappers. |
| direct | `md-5` | `0.10.6` | `safe/vendor/md-5/Cargo.toml` | `none` | 2 | `safe/vendor/md-5/src/compress/loongarch64_asm.rs:70` | Accepted because the unsafe use is narrow in vendored, locked code; replacement path is an audited dependency version that forbids unsafe or a local wrapper that removes this call site. |
| direct | `md4` | `0.10.2` | `safe/vendor/md4/Cargo.toml` | `#![forbid(unsafe_code)]` | 0 | `safe/vendor/md4/src/lib.rs:1` | Accepted because the unsafe use is narrow in vendored, locked code; replacement path is an audited dependency version that forbids unsafe or a local wrapper that removes this call site. |
| transitive | `password-hash` | `0.5.0` | `safe/vendor/password-hash/Cargo.toml` | `#![forbid(unsafe_code)]` | 0 | `safe/vendor/password-hash/src/lib.rs:1` | Accepted because the unsafe use is narrow in vendored, locked code; replacement path is an audited dependency version that forbids unsafe or a local wrapper that removes this call site. |
| direct | `pbkdf2` | `0.12.2` | `safe/vendor/pbkdf2/Cargo.toml` | `none` | 0 | `safe/vendor/pbkdf2/src/lib.rs:1` | Accepted as locked transitive/direct code with no current source unsafe matches; replacement path is an upstream release with crate-root unsafe-code denial. |
| transitive | `rand_core` | `0.6.4` | `safe/vendor/rand_core/Cargo.toml` | `none` | 2 | `safe/vendor/rand_core/CHANGELOG.md:9` | Accepted because the unsafe use is narrow in vendored, locked code; replacement path is an audited dependency version that forbids unsafe or a local wrapper that removes this call site. |
| direct | `rc2` | `0.9.0` | `safe/vendor/rc2/Cargo.toml` | `#![deny(unsafe_code)]` | 0 | `safe/vendor/rc2/src/lib.rs:1` | Accepted because the unsafe use is narrow in vendored, locked code; replacement path is an audited dependency version that forbids unsafe or a local wrapper that removes this call site. |
| direct | `ripemd` | `0.1.3` | `safe/vendor/ripemd/Cargo.toml` | `#![forbid(unsafe_code)]` | 0 | `safe/vendor/ripemd/src/lib.rs:1` | Accepted because the unsafe use is narrow in vendored, locked code; replacement path is an audited dependency version that forbids unsafe or a local wrapper that removes this call site. |
| transitive | `salsa20` | `0.10.2` | `safe/vendor/salsa20/Cargo.toml` | `#![forbid(unsafe_code)]` | 0 | `safe/vendor/salsa20/src/lib.rs:1` | Accepted because the unsafe use is narrow in vendored, locked code; replacement path is an audited dependency version that forbids unsafe or a local wrapper that removes this call site. |
| direct | `scrypt` | `0.11.0` | `safe/vendor/scrypt/Cargo.toml` | `none` | 0 | `safe/vendor/scrypt/src/lib.rs:1` | Accepted as locked transitive/direct code with no current source unsafe matches; replacement path is an upstream release with crate-root unsafe-code denial. |
| direct | `serpent` | `0.6.0` | `safe/vendor/serpent/Cargo.toml` | `#![deny(unsafe_code)]` | 0 | `safe/vendor/serpent/src/lib.rs:1` | Accepted because the unsafe use is narrow in vendored, locked code; replacement path is an audited dependency version that forbids unsafe or a local wrapper that removes this call site. |
| direct | `sha1` | `0.10.6` | `safe/vendor/sha1/Cargo.toml` | `none` | 4 | `safe/vendor/sha1/src/compress/loongarch64_asm.rs:110` | Accepted because the unsafe use is narrow in vendored, locked code; replacement path is an audited dependency version that forbids unsafe or a local wrapper that removes this call site. |
| direct | `sha2` | `0.10.9` | `safe/vendor/sha2/Cargo.toml` | `none` | 29 | `safe/vendor/sha2/src/sha512/x86.rs:20` | Accepted because it is vendored, locked, and exercised through the port test matrix; replacement path is an audited crate release with unsafe-code denial or a local safe implementation for the specific primitive. |
| direct | `sha3` | `0.10.9` | `safe/vendor/sha3/Cargo.toml` | `#![forbid(unsafe_code)]` | 0 | `safe/vendor/sha3/src/lib.rs:1` | Accepted because the unsafe use is narrow in vendored, locked code; replacement path is an audited dependency version that forbids unsafe or a local wrapper that removes this call site. |
| direct | `sm3` | `0.4.2` | `safe/vendor/sm3/Cargo.toml` | `#![forbid(unsafe_code)]` | 0 | `safe/vendor/sm3/src/lib.rs:1` | Accepted because the unsafe use is narrow in vendored, locked code; replacement path is an audited dependency version that forbids unsafe or a local wrapper that removes this call site. |
| direct | `sm4` | `0.6.0` | `safe/vendor/sm4/Cargo.toml` | `#![deny(unsafe_code)]` | 0 | `safe/vendor/sm4/src/lib.rs:1` | Accepted because the unsafe use is narrow in vendored, locked code; replacement path is an audited dependency version that forbids unsafe or a local wrapper that removes this call site. |
| direct | `streebog` | `0.10.2` | `safe/vendor/streebog/Cargo.toml` | `#![forbid(unsafe_code)]` | 0 | `safe/vendor/streebog/src/lib.rs:1` | Accepted because the unsafe use is narrow in vendored, locked code; replacement path is an audited dependency version that forbids unsafe or a local wrapper that removes this call site. |
| transitive | `subtle` | `2.6.1` | `safe/vendor/subtle/Cargo.toml` | `none` | 2 | `safe/vendor/subtle/src/lib.rs:225` | Accepted because the unsafe use is narrow in vendored, locked code; replacement path is an audited dependency version that forbids unsafe or a local wrapper that removes this call site. |
| direct | `tiger` | `0.2.1` | `safe/vendor/tiger/Cargo.toml` | `#![forbid(unsafe_code)]` | 0 | `safe/vendor/tiger/src/lib.rs:1` | Accepted because the unsafe use is narrow in vendored, locked code; replacement path is an audited dependency version that forbids unsafe or a local wrapper that removes this call site. |
| direct | `twofish` | `0.8.0` | `safe/vendor/twofish/Cargo.toml` | `#![deny(unsafe_code)]` | 0 | `safe/vendor/twofish/src/lib.rs:1` | Accepted because the unsafe use is narrow in vendored, locked code; replacement path is an audited dependency version that forbids unsafe or a local wrapper that removes this call site. |
| transitive | `typenum` | `1.20.0` | `safe/vendor/typenum/Cargo.toml` | `#![forbid(unsafe_code)]` | 0 | `safe/vendor/typenum/src/lib.rs:1` | Accepted because the unsafe use is narrow in vendored, locked code; replacement path is an audited dependency version that forbids unsafe or a local wrapper that removes this call site. |
| transitive | `version_check` | `0.9.5` | `safe/vendor/version_check/Cargo.toml` | `none` | 0 | `safe/vendor/version_check/src/lib.rs:1` | Accepted as locked transitive/direct code with no current source unsafe matches; replacement path is an upstream release with crate-root unsafe-code denial. |
| direct | `whirlpool` | `0.10.4` | `safe/vendor/whirlpool/Cargo.toml` | `none` | 1 | `safe/vendor/whirlpool/src/lib.rs:254` | Accepted because the unsafe use is narrow in vendored, locked code; replacement path is an audited dependency version that forbids unsafe or a local wrapper that removes this call site. |

## System, Build, And Test Libraries

`safe/debian/control` declares build dependencies `build-essential`, `debhelper-compat (= 13)`, `cargo`, `dpkg-dev`, `libgmp-dev`, `libgpg-error-dev`, and `rustc`. `safe/debian/rules`, `safe/build.rs`, and `safe/scripts/build-release-lib.sh` link or emit link directives for `gpg-error`, `gmp`, `pthread`, `m`, `c`, and `gcc_s`. `scripts/install-build-deps.sh` installs CI/bootstrap tools `ca-certificates`, `curl`, `devscripts`, `equivs`, `fakeroot`, `file`, `git`, `jq`, `python3`, `rsync`, and `xz-utils`, and then installs the pinned Rustup toolchain. `devscripts` and `equivs` provide `mk-build-deps` support for `scripts/lib/build-deb-common.sh`; `cc` and `ar` are invoked directly by `safe/build.rs` to compile the C shim archive.

Validation and metadata scripts also use tools that are not library build dependencies: `pkg-config`, `automake`, `autoconf`, `objdump`, `nm`, `dpkg-deb`, and Docker-dependent dependent-image scripts. The public header and metadata files are generated from committed templates under `safe/abi/`; the port does not use `cbindgen` or `bindgen`.

# How this document was produced

The worktree initially had an unrelated dirty `workflow.yaml`; it was left unstaged and unmodified. The nested `validator/` checkout was clean at `87b321fe728340d6fc6dd2f638583cca82c667c3` before validator-derived evidence was used.

Commands run or attempted for this document:

- `git status --short`
- `git -C validator rev-parse HEAD`
- `test -z "$(git -C validator status --short)"`
- `git -C validator diff --exit-code`
- `git -C validator diff --cached --exit-code`
- `test -f safe/PORT.md && sed -n '1,240p' safe/PORT.md || true`
- `cargo metadata --manifest-path safe/Cargo.toml --locked --offline --format-version 1 --no-deps`
- `cargo metadata --manifest-path safe/Cargo.toml --locked --offline --format-version 1`
- `cargo tree --manifest-path safe/Cargo.toml --locked --offline`
- `rg -n 'extern\s+"C"|#\[unsafe\((no_mangle|export_name)|#\[link\(' safe/src safe/src/bin`
- `rg -n 'FORWARD|gcry_control|gcry_sexp_build|gcry_sexp_vlist|gcry_sexp_extract_param|gcry_log_debug' safe/cabi/exports.c safe/cabi/exports.h`
- `cargo build --manifest-path safe/Cargo.toml --release --locked --offline --bins --lib`
- `bash safe/scripts/build-release-lib.sh`
- `objdump -T safe/target/release/libgcrypt.so | rg 'GCRYPT_1\.6|gcry_md_get|gcry_pk_register|gcry_check_version'`
- `nm -D --defined-only safe/target/release/libgcrypt.so | rg 'gcry_md_get|gcry_pk_register|gcry_check_version'`
- `rg -n 'extern\s+"C"|unsafe\s+extern|#\[unsafe\((no_mangle|export_name)|#\[link\(|cargo:rustc-link-lib|\bCommand::new|\bcc -shared\b|\$\(CC\)|\bmalloc\b|\bcalloc\b|\brealloc\b|\bfree\b|\bfputs\b|\bfwrite\b|\bvsnprintf\b|\bstrchr\b|\berrno\b|\bstderr\b|\bmlock\b|\bmunlock\b|\bgetrandom\b|\bgetpid\b|\bclock_gettime\b|__errno_location|gpg_|__gmpz_|\bsafe_cabi_[A-Za-z0-9_]+\b|-lgpg-error|-lgmp|-lpthread|-lm|-lc|-lgcc_s' safe/src safe/src/bin safe/build.rs safe/cabi safe/debian/rules safe/scripts/build-release-lib.sh`
- `bash safe/scripts/check-no-upstream-bridge.sh`
- `rg -n '\bunsafe\b' safe/src safe/build.rs safe/cabi --glob '!target/**'`
- `rg -n '\bunsafe\b' safe/vendor --glob '!target/**'`
- `rg -n '\bunsafe\b' safe --glob '!target/**' --glob '!debian/**' --glob '!dist/**'`
- `cargo geiger --manifest-path safe/Cargo.toml --locked --offline || true`
- `python3 safe/scripts/check-validator-port-evidence.py --port-lock validator-local/proof/local-port-debs-lock.json --override-root validator-local/override-debs --artifact-root validator-artifacts/p08-final`
- `bash scripts/check-layout.sh`
- `bash safe/scripts/check-abi.sh --all`
- `bash safe/scripts/run-compat-smoke.sh --all`
- `bash safe/scripts/run-regression-tests.sh --all`
- `bash safe/scripts/run-upstream-tests.sh --verify-plumbing`
- `bash safe/scripts/check-deb-metadata.sh --dist safe/dist`
- `bash safe/scripts/build-debs.sh`
- `bash safe/scripts/check-installed-tools.sh --dist safe/dist`
- `rg -n 'non[- ]?equiv|bit-for-bit|compatib|mismatch|differ|diverg|unsupported|skip|xfail|known issue|not yet|TODO|FIXME|XXX|panic!|unimplemented!|todo!|not implemented' safe/docs safe/tests safe/src safe/scripts validator-report.md README.md dependents.json relevant_cves.json all_cves.json`
- `rg -n 'benchmark|bench-slope|performance|perf|slow|throughput|latency|regression' safe/docs safe/tests original/libgcrypt20-1.10.3/tests validator-report.md README.md relevant_cves.json dependents.json`
- `rg -n 'TODO|FIXME|XXX|panic!|unimplemented!|todo!|not implemented|unsupported' safe/src safe/scripts safe/tests safe/docs README.md validator-report.md`

Command outcomes that affect interpretation:

- `cargo build --manifest-path safe/Cargo.toml --release --locked --offline --bins --lib` passed with existing dead-code warnings in public-key and MPI helper code.
- `bash safe/scripts/build-release-lib.sh` passed and refreshed `safe/target/release/libgcrypt.so` from the current checkout.
- `objdump -T safe/target/release/libgcrypt.so | rg 'GCRYPT_1\.6|gcry_md_get|gcry_pk_register|gcry_check_version'` passed and showed versioned exports.
- `nm -D --defined-only safe/target/release/libgcrypt.so | rg 'gcry_md_get|gcry_pk_register|gcry_check_version'` passed.
- `bash safe/scripts/check-no-upstream-bridge.sh` passed.
- `python3 safe/scripts/check-validator-port-evidence.py --port-lock validator-local/proof/local-port-debs-lock.json --override-root validator-local/override-debs --artifact-root validator-artifacts/p08-final` passed.
- `bash scripts/check-layout.sh`, `bash safe/scripts/check-abi.sh --all`, `bash safe/scripts/run-compat-smoke.sh --all`, and `bash safe/scripts/run-upstream-tests.sh --verify-plumbing` passed. The compatibility smoke run emitted the existing generated `libgcrypt-config` host-triplet warning.
- `bash safe/scripts/run-regression-tests.sh --all` was attempted before a local phase tag pointed at the documentation commit and failed at `safe/tests/regressions/dependent-image-current-phase-tag.sh` with `no local phase tag points at HEAD`; after creating the documentation commit and the matching `phase/impl_document_libgcrypt_port` tag, it was rerun and passed.
- `bash safe/scripts/check-deb-metadata.sh --dist safe/dist` was attempted against the preexisting ignored package output and failed with `manifest phase_commit does not match HEAD`; `bash safe/scripts/build-debs.sh` was then used to refresh ignored `safe/dist/`, after which `bash safe/scripts/check-deb-metadata.sh --dist safe/dist` and `bash safe/scripts/check-installed-tools.sh --dist safe/dist` passed.
- `cargo geiger --manifest-path safe/Cargo.toml --locked --offline` did not run because `cargo geiger` is unavailable in this environment; dependency safety falls back to `rg`, `cargo metadata`, `cargo tree`, and the generated dependency safety TSV.
- The official validator proof/site path was not run for this phase because `validator-report.md` records the validator-side `unknown libraries in config: libgcrypt` limitation at commit `87b321fe728340d6fc6dd2f638583cca82c667c3`, and the final fallback artifact includes active skipped port results.
- No direct original-vs-safe benchmark comparison was found or run during this documentation phase.

Files and directories consulted:

- `safe/Cargo.toml`
- `safe/Cargo.lock`
- `.cargo/config.toml`
- `safe/.cargo/config.toml`
- `rust-toolchain.toml`
- `safe/rust-toolchain.toml`
- `safe/vendor/`
- `safe/src/`
- `safe/src/bin/dumpsexp.rs`
- `safe/src/bin/hmac256.rs`
- `safe/src/bin/mpicalc.rs`
- `safe/build.rs`
- `safe/abi/`
- `safe/abi/gcrypt.h.in`
- `safe/abi/libgcrypt.vers`
- `safe/abi/libgcrypt.pc.in`
- `safe/abi/libgcrypt-config.in`
- `safe/abi/libgcrypt.m4`
- `safe/cabi/exports.c`
- `safe/cabi/exports.h`
- `safe/debian/control`
- `safe/debian/rules`
- `safe/debian/changelog`
- `safe/debian/libgcrypt20.symbols`
- `safe/debian/libgcrypt20.install`
- `safe/debian/libgcrypt20-dev.install`
- `packaging/package.env`
- `scripts/build-debs.sh`
- `scripts/install-build-deps.sh`
- `scripts/lib/build-deb-common.sh`
- `safe/scripts/`
- `safe/scripts/build-debs.sh`
- `safe/scripts/build-release-lib.sh`
- `safe/scripts/validator-libgcrypt-skips.json`
- `safe/docs/abi-map.md`
- `safe/docs/bridge-inventory.md`
- `safe/docs/test-matrix.md`
- `safe/docs/cve-matrix.md`
- `validator-report.md`
- `validator/`
- `validator-artifacts/p08-final/`
- `validator-local/proof/local-port-debs-lock.json`
- `validator-local/override-debs/`
- `dependents.json`
- `relevant_cves.json`
- `all_cves.json`
- `safe/tests/upstream/`
- `safe/tests/compat/`
- `safe/tests/dependents/`
- `safe/tests/dependents/metadata/base-image.noble.digest`
- `safe/tests/dependents/metadata/install-packages.noble.lock`
- `safe/tests/dependents/metadata/matrix-manifest.json`
- `safe/tests/dependents/metadata/package-evidence.noble.json`
- `safe/tests/dependents/metadata/safe-debs.noble.lock`
- `safe/tests/dependents/metadata/ubuntu-snapshot.noble.sources`
- `safe/tests/regressions/`
- `safe/tests/regressions/manifest.json`
- `original/libgcrypt20-1.10.3/`
- `original/libgcrypt20-1.10.3/tests/benchmark.c`
- `original/libgcrypt20-1.10.3/tests/bench-slope.c`
- `original/libgcrypt20-1.10.3/tests/pkbench.c`
- `safe/target/release/libgcrypt.so`
- `safe/dist/`
