# Phase Name

Produce authoritative libgcrypt port documentation

# Implement Phase ID

`impl_document_libgcrypt_port`

# Preexisting Inputs

Consume these artifacts in place. If a listed generated artifact already exists, use it as evidence after checking freshness; do not rediscover, refetch, or regenerate it from scratch unless a verifier explicitly requires a rebuild for freshness.

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
- `scripts/`
- `scripts/lib/build-deb-common.sh`
- `safe/scripts/`
- `safe/scripts/validator-libgcrypt-skips.json`
- `safe/docs/abi-map.md`
- `safe/docs/bridge-inventory.md`
- `safe/docs/test-matrix.md`
- `safe/docs/cve-matrix.md`
- `validator-report.md`
- Existing ignored validator evidence directories: `validator/`, `validator-artifacts/`, and `validator-local/`; consume them only after proving the nested `validator/` checkout is clean
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
- Existing `safe/target/release/libgcrypt.so`, only after verifying it matches current source or rebuilding it
- Existing `safe/dist/`, only after verifying freshness or rebuilding it

# New Outputs

- `safe/PORT.md`
- A git commit containing `safe/PORT.md`, with a message such as `docs: document libgcrypt Rust port`
- Optional incidental fixes only if required to reconcile documentation claims with current source; these must be committed together with `safe/PORT.md`

# File Changes

- Create `safe/PORT.md` if absent.
- If `safe/PORT.md` exists, update it in place and preserve accurate prose.
- Do not modify `.plan/plan.md` or other `.plan/` files during implementation of this phase.
- Do not edit existing code, scripts, tests, or packaging unless a documentation claim reveals real drift that must be fixed to make the documented state true.
- Do not create, refresh, or edit the nested `validator/` checkout.

# Implementation Details

## Worktree And Validator Guard

1. Run `git status --short`.
2. If unrelated user changes exist, do not revert them. Work around them and stage only the intended documentation changes and any strictly required incidental fixes.
3. If `validator/.git` exists, run these commands before relying on validator-derived evidence:

```sh
git -C validator rev-parse HEAD
test -z "$(git -C validator status --short)"
git -C validator diff --exit-code
git -C validator diff --cached --exit-code
```

Treat a dirty nested validator checkout as a blocker. Do not edit `validator/`, validator tests, shared helpers, tools, inventories, or `validator/test.sh` to make port documentation claims true.

## Documentation Baseline

1. Run:

```sh
test -f safe/PORT.md && sed -n '1,240p' safe/PORT.md || true
```

2. Create or refresh `safe/PORT.md` with exactly these six required top-level sections in this order:

- `High-level architecture`
- `Where the unsafe Rust lives`
- `Remaining unsafe FFI beyond the original ABI/API boundary`
- `Remaining issues`
- `Dependencies and other libraries used`
- `How this document was produced`

## Architecture Evidence

Read these inputs and verify claims against source before writing:

- `safe/Cargo.toml`
- `safe/src/lib.rs`
- `safe/build.rs`
- `safe/cabi/exports.c`
- `safe/cabi/exports.h`
- `safe/debian/control`
- `safe/debian/rules`
- `safe/debian/changelog`
- `packaging/package.env`
- `scripts/build-debs.sh`
- `safe/scripts/build-debs.sh`
- `scripts/lib/build-deb-common.sh`
- `scripts/install-build-deps.sh`
- `rust-toolchain.toml`
- `safe/rust-toolchain.toml`

Run:

```sh
cargo metadata --manifest-path safe/Cargo.toml --locked --offline --format-version 1 --no-deps
cargo tree --manifest-path safe/Cargo.toml --locked --offline
```

Document these implementation facts:

- `safe/Cargo.toml` defines a single-member workspace, package `safe` version `0.1.0`, Rust edition `2024`, one library target named `gcrypt` with crate types `staticlib` and `rlib`, no Cargo features, and three binaries: `dumpsexp`, `hmac256`, and `mpicalc`.
- `safe/Cargo.toml` sets `[profile.release] panic = "abort"`; document the release panic behavior as part of the ABI/runtime contract.
- `safe/Cargo.toml` builds no `cdylib` and does not use cbindgen or bindgen.
- `safe/build.rs` renders `gcrypt.h`, `libgcrypt.pc`, `libgcrypt-config`, and `libgcrypt.m4` into `target/bootstrap/generated/` from the committed ABI inputs `safe/abi/gcrypt.h.in`, `safe/abi/libgcrypt.pc.in`, `safe/abi/libgcrypt-config.in`, and `safe/abi/libgcrypt.m4`.
- `safe/build.rs` verifies that every `safe/abi/libgcrypt.vers` public symbol is owned, compiles `safe/cabi/exports.c` into `libsafe_cabi.a`, links `safe_cabi`, and links GMP via `cargo:rustc-link-lib=gmp`.
- `safe/debian/rules` builds Cargo offline with the pinned toolchain, links the final `target/release/libgcrypt.so` from `target/release/libgcrypt.a` with the version script and `-lgpg-error -lgmp -lpthread -lm -lc -lgcc_s`, and installs runtime/development files into `libgcrypt20` and `libgcrypt20-dev`.
- Top-level CI runs `scripts/build-debs.sh`, which sources `scripts/lib/build-deb-common.sh`, stamps `safe/debian/changelog`, performs a full source and binary `dpkg-buildpackage`, and copies artifacts to root `dist/`.
- The port-local `safe/scripts/build-debs.sh` builds binary packages from `safe/` into ignored `safe/dist/` with `safe-debs.manifest.json` for local validator and package checks.

Document the module responsibilities:

- `alloc`, `secmem`, `context`, `global`, `config`, `error`, and `log` own runtime shell and ABI compatibility state.
- `hwfeatures` owns hardware feature token validation, active-feature detection, and disabled-feature bookkeeping consumed by `GCRYCTL_DISABLE_HWF` handling and config output.
- `random`, `drbg`, and `os_rng` own random generation and OS entropy.
- `digest`, `mac`, `kdf`, and `cipher` own symmetric primitives and registry surfaces.
- `mpi`, `mpi/arith`, `mpi/scan`, `mpi/prime`, `mpi/ec`, `sexp`, and `pubkey` own S-expression, big integer, ECC, and public-key surfaces.
- `upstream.rs` is a compatibility struct definition, not an upstream bridge.

Section 1 must describe actual data flow through all three public entry shapes:

- Direct Rust `pub extern "C"` functions exported under public fixed-signature `gcry_*` names.
- Fixed-signature public C `FORWARD*` wrappers in `safe/cabi/exports.c`, such as `gcry_check_version`, allocation/error/random/config functions, `gcry_md_get`, `gcry_pk_register`, and `gcry_log_debughex`, which export public `gcry_*` symbols from C and dispatch to Rust `safe_*` exports.
- C varargs/libc-sensitive shim exports in `safe/cabi/exports.c`, including `gcry_control`, `gcry_sexp_build`, `gcry_sexp_vlist`, `gcry_sexp_extract_param`, and `gcry_log_debug`, which normalize calls before Rust dispatch.

Trace at least one representative call path for each entry shape. Each path must continue through raw-pointer, C-string, buffer-length, callback, or opaque-handle validation where applicable; into internal RustCrypto, DRBG, OS entropy, hardware-feature disable state, S-expression, GMP-backed MPI, public-key, or runtime-state implementation; and back out through C-compatible buffers, allocated handles, return codes, logging callbacks, or errno-compatible state.

Include a concise directory map covering:

- `safe/src`
- `safe/src/bin`
- `safe/abi`, including `safe/abi/gcrypt.h.in`, `safe/abi/libgcrypt.vers`, `safe/abi/libgcrypt.pc.in`, `safe/abi/libgcrypt-config.in`, and `safe/abi/libgcrypt.m4`
- `safe/cabi`
- `safe/debian`
- `safe/scripts`
- `safe/tests`
- `safe/docs`
- `safe/vendor`
- `original/libgcrypt20-1.10.3`

## ABI And FFI Evidence

Run:

```sh
rg -n 'extern\s+"C"|#\[unsafe\((no_mangle|export_name)|#\[link\(' safe/src safe/src/bin
rg -n 'FORWARD|gcry_control|gcry_sexp_build|gcry_sexp_vlist|gcry_sexp_extract_param|gcry_log_debug' safe/cabi/exports.c safe/cabi/exports.h
```

Before ABI inspection, ensure `safe/target/release/libgcrypt.so` is current by running these commands, unless an earlier verification command in this same phase already rebuilt it from the current checkout:

```sh
cargo build --manifest-path safe/Cargo.toml --release --locked --offline --bins --lib
bash safe/scripts/build-release-lib.sh
objdump -T safe/target/release/libgcrypt.so | rg 'GCRYPT_1\.6|gcry_md_get|gcry_pk_register|gcry_check_version'
```

Explain that the intended original ABI/API boundary is the libgcrypt C ABI from `safe/abi/libgcrypt.vers` and rendered `gcrypt.h`.

Build a complete non-libgcrypt FFI index with:

```sh
rg -n 'extern\s+"C"|unsafe\s+extern|#\[unsafe\((no_mangle|export_name)|#\[link\(|cargo:rustc-link-lib|\bCommand::new|\bcc -shared\b|\$\(CC\)|\bmalloc\b|\bcalloc\b|\brealloc\b|\bfree\b|\bfputs\b|\bfwrite\b|\bvsnprintf\b|\bstrchr\b|\berrno\b|\bstderr\b|\bmlock\b|\bmunlock\b|\bgetrandom\b|\bgetpid\b|\bclock_gettime\b|__errno_location|gpg_|__gmpz_|\bsafe_cabi_[A-Za-z0-9_]+\b|-lgpg-error|-lgmp|-lpthread|-lm|-lc|-lgcc_s' safe/src safe/src/bin safe/build.rs safe/cabi safe/debian/rules safe/scripts/build-release-lib.sh
```

Treat the regex output as an index, then read matched source and surrounding declarations. In Section 3, record every FFI surface beyond the intended libgcrypt ABI/API boundary with symbol(s), provider, reason, and plausible safe-Rust replacement. Required concrete surfaces include:

- libc allocation and secure-memory calls in `safe/src/alloc.rs` and `safe/src/secmem.rs`: `malloc`, `calloc`, `realloc`, `free`, `mlock`, and `munlock`.
- libc errno/process/entropy/time calls in `safe/src/lib.rs` and `safe/src/os_rng.rs`: `__errno_location`, `getrandom`, `getpid`, and `clock_gettime`.
- libc/stdio/string/errno use in `safe/src/config.rs` and `safe/cabi/exports.c`: `fwrite`, `fputs`, `stderr`, `vsnprintf`, `strchr`, `malloc`, `free`, and `errno`.
- libgpg-error calls in `safe/src/error.rs`: `gpg_strerror`, `gpg_strsource`, `gpg_err_code_from_errno`, `gpg_err_code_to_errno`, and `gpg_error_check_version`.
- GMP calls in `safe/src/mpi/mod.rs` and uses from `safe/src/mpi/*.rs`: every declared `__gmpz_*` symbol, including `__gmpz_powm_sec`, `__gmpz_import`, `__gmpz_export`, arithmetic helpers, scan/export helpers, and prime helpers.
- Internal C shim callbacks between Rust and `safe/cabi/exports.c`: `safe_cabi_dispatch_log_message` and `safe_cabi_set_log_handler`.
- Build-time C compiler/archive invocations in `safe/build.rs`: `Command::new(cc)` and `Command::new(ar)`.
- Linker invocations and runtime system libraries in `safe/debian/rules` and `safe/scripts/build-release-lib.sh`: `$(CC)`, `cc -shared`, `-lgpg-error`, `-lgmp`, `-lpthread`, `-lm`, `-lc`, and `-lgcc_s`.
- Helper binaries' `unsafe extern "C"` declarations in `safe/src/bin/*.rs`; classify these as self-calls through the installed libgcrypt ABI and still list them.

State whether any runtime upstream bridge remains only after running:

```sh
bash safe/scripts/check-no-upstream-bridge.sh
```

and reviewing `safe/docs/bridge-inventory.md`.

## Unsafe Inventory

Generate current grep outputs:

```sh
rg -n '\bunsafe\b' safe/src safe/build.rs safe/cabi --glob '!target/**' > /tmp/libgcrypt-port-owned-unsafe.txt
rg -n '\bunsafe\b' safe/vendor --glob '!target/**' > /tmp/libgcrypt-vendor-unsafe.txt
rg -n '\bunsafe\b' safe --glob '!target/**' --glob '!debian/**' --glob '!dist/**' > /tmp/libgcrypt-port-unsafe.txt
```

Reconcile exact counts with the observed evidence from the source plan. The earlier inventory produced 1533 lines: 780 in `safe/src`, `safe/build.rs`, and `safe/cabi`, and 753 under `safe/vendor`. Use regenerated current counts in `safe/PORT.md`.

Group source-owned unsafe by purpose:

- Export attributes and ABI shims: `#[unsafe(no_mangle)]`, `#[unsafe(export_name = "...")]`, and `pub extern "C" fn`.
- C callback and raw pointer handlers required by the libgcrypt ABI.
- Allocator and secure-memory integration.
- OS/libc/libgpg-error/GMP FFI.
- Pointer-to-slice conversions and C string reads.
- Box/raw ownership transfers for opaque handles.
- Explicit `unsafe impl Send` wrappers for handler state.
- Helper binary extern declarations.

Call out unsafe not strictly required by the C ABI/API boundary, including GMP/libgpg-error/libc/OS calls, build-time C compilation, helper binary extern declarations, and any internal pointer manipulation that can be narrowed or justified separately.

Include vendored dependency unsafe. Use a generated inventory subsection or appendix if needed for all current vendored `unsafe` lines, but still show exact file:line entries and map every entry to a narrow category such as architecture intrinsics, byte/slice reinterpretation, unchecked UTF-8, typenum/generic-array trait invariants, raw pointer code, FFI declarations, unsafe trait invariants, or vendored test-only code. Do not reduce `safe/vendor/` to a single crate-level note, and do not silently omit it.

## Remaining Issues

Read:

- `validator-report.md`
- `safe/docs/cve-matrix.md`
- `safe/docs/test-matrix.md`
- `safe/docs/bridge-inventory.md`
- `safe/scripts/validator-libgcrypt-skips.json`
- `safe/tests/regressions/manifest.json`
- `dependents.json`
- `relevant_cves.json`
- `all_cves.json`

Investigate behavioral compatibility and bit-for-bit non-equivalence before writing Section 4:

```sh
rg -n 'non[- ]?equiv|bit-for-bit|compatib|mismatch|differ|diverg|unsupported|skip|xfail|known issue|not yet|TODO|FIXME|XXX|panic!|unimplemented!|todo!|not implemented' safe/docs safe/tests safe/src safe/scripts validator-report.md README.md dependents.json relevant_cves.json all_cves.json
```

Section 4 must include a behavioral compatibility subsection. If known non-equivalences, skips, unsupported modes, validator caveats, or compatibility gaps are present, list each with a repository-relative evidence pointer and impact. If no known behavioral non-equivalence is found in the checked artifacts, state that exact conclusion, name the artifacts checked, and describe residual risk from untested libgcrypt surfaces. Do not claim full bit-for-bit equivalence unless a direct bit-for-bit comparison exists.

If citing ignored validator artifact evidence directly, first re-run the nested validator clean checks. When these paths exist, verify the artifact root with:

```sh
python3 safe/scripts/check-validator-port-evidence.py --port-lock validator-local/proof/local-port-debs-lock.json --override-root validator-local/override-debs --artifact-root validator-artifacts/p08-final
```

If ignored validator artifacts are absent, cite `validator-report.md` and `safe/scripts/validator-libgcrypt-skips.json` instead and record the absence in the production note rather than regenerating them.

Include the validator status currently recorded in `validator-report.md`: full direct-wrapper libgcrypt suite closed with 171 passed, 0 failed, and 4 active port-mode skips at validator commit `87b321fe728340d6fc6dd2f638583cca82c667c3`, with skips listed in `safe/scripts/validator-libgcrypt-skips.json`.

Include that the official validator inventory path was unavailable at that commit because the checkout reported `unknown libraries in config: libgcrypt`; this is a validator-side limitation, not a port test pass.

Include committed dependent coverage: `dependents.json` and `safe/tests/dependents/metadata/matrix-manifest.json` cover 15 packages, with library probes for `libapt-pkg6.0t64`, `libssh-gcrypt-4`, and `libxmlsec1t64-gcrypt`, plus executable scenarios for `gpg`, `gnome-keyring`, `munge`, `aircrack-ng`, `wireshark-common`, `gpgv`, `gpgsm`, `seccure`, `pdfgrep`, `rng-tools5`, `libotr5-bin`, and `tcplay`.

Include CVE coverage from `relevant_cves.json`: 16 included relevant CVEs and 1 excluded memory-corruption CVE. Tie each limitation or review obligation back to `safe/docs/cve-matrix.md` and current code paths.

Cover performance explicitly:

- Read `safe/docs/test-matrix.md` entries for upstream `benchmark`, `bench-slope`, and `pkbench` coverage.
- Inspect `safe/tests/upstream/benchmark.c`, `safe/tests/upstream/bench-slope.c`, and corresponding originals under `original/libgcrypt20-1.10.3/tests/`.
- Run:

```sh
rg -n 'benchmark|bench-slope|performance|perf|slow|throughput|latency|regression' safe/docs safe/tests original/libgcrypt20-1.10.3/tests validator-report.md README.md relevant_cves.json dependents.json
```

If no direct original-vs-safe benchmark comparison was run, Section 4 must say so and list residual risk. Do not claim no performance regression or bit-for-bit performance equivalence unless comparative measurements exist in the checked artifacts.

Search for TODO/FIXME/unimplemented markers in owned code and scripts:

```sh
rg -n 'TODO|FIXME|XXX|panic!|unimplemented!|todo!|not implemented|unsupported' safe/src safe/scripts safe/tests safe/docs README.md validator-report.md
```

Do not treat upstream imported test comments as port issues unless they affect current port behavior; distinguish imported upstream files from owned Rust port files.

## Dependencies And System Libraries

Extract direct dependencies from `safe/Cargo.toml` and list each with version and purpose:

- `argon2 0.5.3` for Argon2 KDF.
- `blake2 0.10.6` for BLAKE2 digests.
- `blowfish 0.10.0` for Blowfish cipher.
- `camellia 0.2.0` for Camellia cipher.
- `cast5 0.12.0` for CAST5 cipher.
- `cipher04`, package `cipher 0.4.4`, for older RustCrypto cipher traits.
- `cipher05`, package `cipher 0.5.1`, for newer RustCrypto cipher traits.
- `des 0.9.0` for DES/3DES.
- `digest 0.10.7` for digest trait integration.
- `gost94 0.10.4` and `gost-crypto 0.3.0` for GOST digest/cipher support.
- `hmac 0.12.1` for HMAC.
- `idea 0.6.0` for IDEA cipher.
- `kisaseed 0.1.3` for SEED cipher.
- `md4 0.10.2`, `md-5 0.10.6`, `ripemd 0.1.3`, `sha1 0.10.6`, `sha2 0.10.9`, `sha3 0.10.8`, `sm3 0.4.2`, `streebog 0.10.2`, `tiger 0.2.1`, and `whirlpool 0.10.4` for digest algorithms.
- `pbkdf2 0.12.2` and `scrypt 0.11.0` for KDFs.
- `rc2 0.9.0`, `serpent 0.6.0`, `sm4 0.6.0`, and `twofish 0.8.0` for symmetric ciphers.

Cross-check versions against `cargo metadata` and `Cargo.lock`; note that `Cargo.lock` currently resolves `sha3` to `0.10.9` even though `safe/Cargo.toml` requests `0.10.8`.

Run the dependency unsafe-posture script from `check_unsafe_ffi_dependency_inventory` and use `/tmp/libgcrypt-dependency-safety.tsv`, `/tmp/libgcrypt-vendor-unsafe.txt`, `cargo metadata`, and `cargo tree` to document dependency safety rather than relying on crate reputation or stale notes.

In Section 5, add a dependency safety subsection that covers direct and transitive dependencies. Identify every crate that lacks crate-root `#![forbid(unsafe_code)]` or `#![deny(unsafe_code)]`, every crate with at least 10 non-comment `unsafe` occurrences in vendored Rust source, and any lower-count crate whose unsafe is security-relevant because it uses architecture intrinsics, raw pointers, FFI declarations, unchecked UTF-8, or unsafe trait invariants. For each such crate, record whether it is direct or transitive, cite representative `safe/vendor/<crate>/...` file:line evidence, explain why the port accepts it, and name a safer replacement path if one is plausible.

For direct dependencies that forbid or deny unsafe code and have no code unsafe occurrences, state that status in the direct dependency table.

List system/build dependencies from `safe/debian/control` and link flags from `safe/debian/rules`: `build-essential`, `debhelper-compat (= 13)`, `cargo`, `dpkg-dev`, `libgmp-dev`, `libgpg-error-dev`, `rustc`, plus link-time `gpg-error`, `gmp`, `pthread`, `m`, `c`, and `gcc_s`.

List CI/bootstrap tools from `scripts/install-build-deps.sh`: `ca-certificates`, `curl`, `devscripts`, `equivs`, `fakeroot`, `file`, `git`, `jq`, `python3`, `rsync`, `xz-utils`, and the Rustup-installed pinned toolchain. Explain that `devscripts`/`equivs` provide `mk-build-deps` support for the top-level CI build helper, while `cc`/`ar` are invoked directly by `safe/build.rs`.

Call out test and metadata tools used by validation scripts but not by the library build itself, including `pkg-config`, `automake`, `autoconf`, `objdump`, `nm`, `dpkg-deb`, and Docker-dependent dependent-image scripts where applicable.

Explicitly state that the port does not use cbindgen or bindgen; the public header and metadata files are generated from committed templates under `safe/abi/`.

Mention Rust toolchain pin `1.85.1` from `safe/rust-toolchain.toml` and root `rust-toolchain.toml`.

Note that vendored dependencies are supplied via `.cargo/config.toml` and `safe/.cargo/config.toml` with offline mode and `safe/vendor`.

## Production Note

Section 6 of `safe/PORT.md` must list the exact commands and files consulted, including commands that were unavailable, skipped, or failed. It must not claim a passing run for a skipped or failed command.

Prefer repository-relative paths in prose and file:line references. If an absolute path from the original request is repeated, it must be rooted under the current repository and point to an existing path. Avoid bare filenames such as `Cargo.toml` unless that exact path exists at repository root; use `safe/Cargo.toml` or another unambiguous path.

Before committing, audit every cited code symbol in `safe/PORT.md` with:

```sh
rg -n --fixed-strings -- '<symbol>' safe original
```

This audit must cover all code-spanned and prose-cited symbols that are not commands, paths, package/crate names, versions, section names, or ordinary English words. Do not limit the audit to a fixed example list.

Do not mention transient scratch paths such as `/tmp/libgcrypt-port-unsafe.txt` in `safe/PORT.md` unless those paths are intentionally created before path verification and still exist when the verifier runs. Prefer listing the underlying command without scratch redirection in Section 6.

## Critical File Guidance

Treat these files as evidence sources and preserve their intended ownership. Read them to verify documentation claims; edit them only when a real drift bug blocks truthful documentation.

- `safe/PORT.md`: the only planned authored documentation output. It must include architecture, unsafe Rust inventory, remaining FFI beyond the intended libgcrypt ABI boundary, remaining issues, dependencies, and reproducibility notes.
- `safe/Cargo.toml`: source of truth for the direct Rust dependency list, crate layout, library crate types, build script, absence of Cargo features, and `[profile.release] panic = "abort"` release panic behavior.
- `safe/Cargo.lock`: source of truth for resolved dependency versions and transitive packages.
- `.cargo/config.toml` and `safe/.cargo/config.toml`: source of truth for vendored offline dependency resolution from `safe/vendor/`.
- `safe/src/lib.rs`: crate root, module map, C handler type aliases, errno FFI, and direct Rust `gcry_*` export evidence.
- `safe/src/hwfeatures.rs`: hardware feature token validation, active-feature detection, and disabled-feature bookkeeping used by `GCRYCTL_DISABLE_HWF` and config output.
- `safe/src/alloc.rs`, `safe/src/secmem.rs`, `safe/src/os_rng.rs`, `safe/src/error.rs`, `safe/src/config.rs`, `safe/src/log.rs`, `safe/src/mpi/mod.rs`, and `safe/src/sexp.rs`: allocation, secure memory, OS entropy, libgpg-error, config output, logging, GMP-backed MPI, and S-expression FFI evidence.
- `safe/src/cipher/`, `safe/src/digest/`, `safe/src/mac.rs`, `safe/src/kdf.rs`, `safe/src/pubkey/`, `safe/src/mpi/ec.rs`, and `safe/src/context.rs`: symmetric crypto, public-key, ECC, context, and opaque-handle implementation evidence.
- `safe/src/bin/dumpsexp.rs`, `safe/src/bin/hmac256.rs`, and `safe/src/bin/mpicalc.rs`: installed compatibility tools and their libgcrypt ABI self-calls.
- `safe/build.rs`: renders `gcrypt.h`, `libgcrypt.pc`, `libgcrypt-config`, and `libgcrypt.m4`; checks public export ownership; compiles the C shim archive; and emits build link directives.
- `safe/cabi/exports.c` and `safe/cabi/exports.h`: C `FORWARD*` wrappers, varargs/libc-sensitive shims, and Rust `safe_*` dispatch declarations.
- `safe/abi/libgcrypt.vers`, `safe/abi/gcrypt.h.in`, `safe/abi/libgcrypt.pc.in`, `safe/abi/libgcrypt-config.in`, and `safe/abi/libgcrypt.m4`: specific ABI metadata/template inputs.
- `safe/debian/control`, `safe/debian/rules`, `safe/debian/changelog`, `safe/debian/libgcrypt20.symbols`, `safe/debian/libgcrypt20.install`, and `safe/debian/libgcrypt20-dev.install`: Debian packaging evidence, including the link from `target/release/libgcrypt.a` to `target/release/libgcrypt.so`.
- `safe/scripts/`, `scripts/`, and `scripts/lib/build-deb-common.sh`: build, test, ABI, packaging, validator, regression, and dependent harness evidence.
- `safe/docs/abi-map.md`, `safe/docs/bridge-inventory.md`, `safe/docs/test-matrix.md`, `safe/docs/cve-matrix.md`, `validator-report.md`, `dependents.json`, `relevant_cves.json`, `all_cves.json`, `safe/tests/`, and `original/libgcrypt20-1.10.3/`: existing evidence and comparison inputs to consume in place.

## Commit

1. Run formatting only if it applies to changed code; Markdown does not require a formatter in this repo.
2. Re-run planned verification commands that are practical before commit.
3. Stage `safe/PORT.md` and any necessary incidental fixes.
4. Commit with a documentation summary message, for example:

```sh
git add safe/PORT.md
git commit -m "docs: document libgcrypt Rust port"
```

# Verification Phases

## `check_port_doc_structure_and_paths`

- Type: `check`
- Fixed `bounce_target`: `impl_document_libgcrypt_port`
- Purpose: Verify that `safe/PORT.md` exists, is self-contained, keeps the six required sections in exact order, references only existing paths, and cites findable symbols.
- Commands/checks to run:

```sh
test -f safe/PORT.md
python3 - <<'PY'
from pathlib import Path
import re

text = Path("safe/PORT.md").read_text()
required = [
    "High-level architecture",
    "Where the unsafe Rust lives",
    "Remaining unsafe FFI beyond the original ABI/API boundary",
    "Remaining issues",
    "Dependencies and other libraries used",
    "How this document was produced",
]
headings = []
for match in re.finditer(r"^(#{1,6})\s+(.+?)\s*$", text, re.MULTILINE):
    raw = match.group(2).strip().strip("*").strip()
    normalized = re.sub(r"\s+", " ", raw.rstrip(".")).strip()
    headings.append((normalized, match.start()))
positions = []
for section in required:
    matches = [pos for name, pos in headings if name == section]
    if len(matches) != 1:
        raise SystemExit(f"expected exactly one heading {section!r}, found {len(matches)}")
    positions.append(matches[0])
if positions != sorted(positions):
    raise SystemExit("required PORT.md headings are not in the required order")
PY
python3 - <<'PY'
from pathlib import Path
import re

repo = Path.cwd().resolve()
text = Path("safe/PORT.md").read_text()
prefixes = (
    "safe/", "original/", "scripts/", "tests/", "packaging/", ".github/", ".cargo/",
    ".plan/phases/", "validator/", "validator-artifacts/", "validator-local/",
)
root_files = {
    "AGENTS.md", "CLAUDE.md", "README.md", "rust-toolchain.toml",
    "dependents.json", "relevant_cves.json", "all_cves.json", "validator-report.md",
}
candidates = set()
link_targets = re.findall(r"\[[^\]]+\]\(([^)]+)\)", text)
code_spans = re.findall(r"`([^`]+)`", text)
chunks = link_targets + code_spans + text.split()
token_re = re.compile(
    r"(?<![\w./-])("
    r"(?:safe|original|scripts|tests|packaging|validator|validator-artifacts|validator-local|\.github|\.cargo|\.plan/phases)/[^\s`'\"),;]+"
    r"|/[^\s`'\"),;]+"
    r"|[A-Za-z0-9_.-]+\.(?:md|json|toml|lock|rs|c|h|sh|py|in|vers|pc|m4|symbols|install|rules|changelog)"
    r")"
)
def normalize(token):
    token = token.strip("<>").strip(".,;:")
    token = re.sub(r":\d+(?::\d+)?$", "", token)
    token = re.sub(r"#L?\d+(?:-L?\d+)?$", "", token)
    if "*" in token:
        token = token.split("*", 1)[0].rstrip("/")
    if not token or token.startswith(("http://", "https://", "//")):
        return None
    path = Path(token)
    if path.is_absolute():
        try:
            return str(path.resolve().relative_to(repo))
        except ValueError:
            return str(path)
    if token.startswith(prefixes) or token in root_files or ("/" not in token and "." in token):
        return token
    return None
for chunk in chunks:
    for match in token_re.finditer(chunk):
        token = normalize(match.group(1))
        if token:
            candidates.add(token)
missing = sorted(path for path in candidates if not Path(path).exists())
if missing:
    raise SystemExit("PORT.md references missing paths:\n" + "\n".join(missing))
PY
python3 - <<'PY' > /tmp/libgcrypt-port-symbol-candidates.txt
from pathlib import Path
import re

text = Path("safe/PORT.md").read_text()
code_spans = re.findall(r"`([^`]+)`", text)
symbol_re = re.compile(
    r"\b(?:gcry|safe_gcry|safe_cabi|GCRY|__gmpz|gpg_|__errno_location|"
    r"getrandom|getpid|clock_gettime|mlock|munlock|malloc|calloc|realloc|"
    r"free|fputs|fwrite|vsnprintf|strchr|errno|stderr)[A-Za-z0-9_]*\b"
)
pathish = re.compile(r"[/]|[.](?:md|json|toml|lock|rs|c|h|sh|py|in|vers|pc|m4|symbols|install|rules|changelog)$")
commands = {
    "cargo", "cargo metadata", "cargo tree", "cargo geiger", "rg", "grep",
    "objdump", "nm", "bash", "python3", "git", "test", "cat",
}
versions = re.compile(r"^\d+(?:\.\d+)+(?:[A-Za-z0-9_.+-]*)?$")
candidates = set(symbol_re.findall(text))
for span in code_spans:
    cleaned = span.strip().strip(".,;:")
    if not cleaned or cleaned in commands or pathish.search(cleaned) or versions.match(cleaned):
        continue
    if re.match(r"^[A-Za-z_][A-Za-z0-9_]*(?:\([^)]*\))?$", cleaned):
        candidates.add(cleaned.rstrip("()"))
for symbol in sorted(candidates):
    print(symbol)
PY
cat /tmp/libgcrypt-port-symbol-candidates.txt
```

Agent review requirements:

- Audit every code-spanned or prose-cited symbol in Sections 1-5 of `safe/PORT.md`. Do not limit the audit to the generated candidate list or examples.
- Exclude only commands, paths, package/crate names, versions, section names, and ordinary English words.
- For every remaining cited symbol, run `rg -n --fixed-strings -- '<symbol>' safe original`; fail if the symbol is absent or cited under a name that does not match source.
- Confirm Section 1 contains concrete data flow for direct Rust `gcry_*` exports, fixed-signature C `FORWARD*` wrappers calling Rust `safe_*` exports, and C varargs/libc-sensitive shims normalizing calls before Rust dispatch.
- Confirm at least one fixed-signature `FORWARD*` path such as `gcry_check_version`, `gcry_md_get`, `gcry_pk_register`, or `gcry_log_debughex` is traced through validation, internal implementation, and C-compatible output.

## `check_unsafe_ffi_dependency_inventory`

- Type: `check`
- Fixed `bounce_target`: `impl_document_libgcrypt_port`
- Purpose: Verify that unsafe, FFI, and dependency sections match current source.
- Commands/checks to run:

```sh
rg -n '\bunsafe\b' safe --glob '!target/**' --glob '!debian/**' --glob '!dist/**' > /tmp/libgcrypt-port-unsafe.txt
rg -n '\bunsafe\b' safe/src safe/build.rs safe/cabi --glob '!target/**' > /tmp/libgcrypt-port-owned-unsafe.txt
rg -n '\bunsafe\b' safe/vendor --glob '!target/**' > /tmp/libgcrypt-vendor-unsafe.txt
rg -n 'extern\s+"C"|unsafe\s+extern|#\[unsafe\((no_mangle|export_name)|#\[link\(|cargo:rustc-link-lib|\bCommand::new|\bcc -shared\b|\$\(CC\)|\bmalloc\b|\bcalloc\b|\brealloc\b|\bfree\b|\bfputs\b|\bfwrite\b|\bvsnprintf\b|\bstrchr\b|\berrno\b|\bstderr\b|\bmlock\b|\bmunlock\b|\bgetrandom\b|\bgetpid\b|\bclock_gettime\b|__errno_location|gpg_|__gmpz_|\bsafe_cabi_[A-Za-z0-9_]+\b|-lgpg-error|-lgmp|-lpthread|-lm|-lc|-lgcc_s' safe/src safe/src/bin safe/build.rs safe/cabi safe/debian/rules safe/scripts/build-release-lib.sh
cargo metadata --manifest-path safe/Cargo.toml --locked --offline --format-version 1
cargo tree --manifest-path safe/Cargo.toml --locked --offline
python3 - <<'PY' > /tmp/libgcrypt-dependency-safety.tsv
from pathlib import Path
import json
import re
import subprocess

repo = Path.cwd().resolve()
metadata = json.loads(subprocess.check_output([
    "cargo", "metadata",
    "--manifest-path", "safe/Cargo.toml",
    "--locked", "--offline", "--format-version", "1",
], text=True))
packages = {pkg["id"]: pkg for pkg in metadata["packages"]}
root = metadata["resolve"]["root"]
root_node = next(node for node in metadata["resolve"]["nodes"] if node["id"] == root)
direct_ids = {dep["pkg"] for dep in root_node["deps"]}
print("scope\tpackage\tversion\tmanifest\tunsafe_policy\tunsafe_lines\tunsafe_heavy")
for pkg_id, pkg in sorted(packages.items(), key=lambda item: (item[1]["name"], item[1]["version"], item[1]["manifest_path"])):
    if pkg_id == root:
        continue
    manifest = Path(pkg["manifest_path"])
    pkg_dir = manifest.parent
    if "safe/vendor" not in str(pkg_dir):
        continue
    rs_files = sorted(path for path in pkg_dir.rglob("*.rs") if "target" not in path.parts)
    policy = "none"
    for root_file in (pkg_dir / "src/lib.rs", pkg_dir / "src/main.rs"):
        if root_file.exists():
            for line in root_file.read_text(errors="replace").splitlines():
                stripped = line.strip()
                if re.search(r"^#!\[(forbid|deny)\(unsafe_code\)\]", stripped):
                    policy = stripped
                    break
    unsafe_lines = 0
    for path in rs_files:
        for line in path.read_text(errors="replace").splitlines():
            stripped = line.strip()
            if re.search(r"^#!\[(forbid|deny)\(unsafe_code\)\]", stripped):
                continue
            if "unsafe" in stripped and "unsafe_code" not in stripped and not stripped.startswith("//") and not stripped.startswith("//!"):
                unsafe_lines += 1
    scope = "direct" if pkg_id in direct_ids else "transitive"
    heavy = "yes" if unsafe_lines >= 10 else "no"
    manifest_display = manifest.resolve().relative_to(repo)
    print(f"{scope}\t{pkg['name']}\t{pkg['version']}\t{manifest_display}\t{policy}\t{unsafe_lines}\t{heavy}")
PY
cat /tmp/libgcrypt-dependency-safety.tsv
cargo geiger --manifest-path safe/Cargo.toml --locked --offline || true
```

Agent review requirements:

- If `cargo geiger` is unavailable, require `safe/PORT.md` to say that and include fallback `rg` evidence.
- Compare `/tmp/libgcrypt-port-unsafe.txt` against the unsafe inventory in `safe/PORT.md`.
- Require the document to enumerate every source-owned `unsafe` block, `unsafe fn`, `unsafe impl`, `unsafe extern`, unsafe export attribute, and unsafe link attribute with file:line references and one-sentence justifications.
- For `safe/vendor/`, require an exact file:line inventory and a narrow justification category for every entry. Comments and strings may be excluded only if the document explains the exclusion and the checker confirms the remaining code occurrences match.
- Verify Section 3 lists every non-libgcrypt runtime/build FFI surface found in `safe/src/`, `safe/src/bin/`, `safe/cabi/`, `safe/build.rs`, `safe/debian/rules`, and `safe/scripts/build-release-lib.sh`, including C shim libc/stdio/string/errno use. Record symbol(s), provider, reason, and plausible safe-Rust replacement for each.
- Ensure every direct dependency in `safe/Cargo.toml` is listed with version and purpose.
- Ensure system libraries from `safe/debian/control`, `safe/debian/rules`, `safe/build.rs`, `safe/cabi/`, `safe/src/`, `safe/src/bin/`, and `safe/scripts/build-release-lib.sh` are covered.
- Compare `/tmp/libgcrypt-dependency-safety.tsv`, `/tmp/libgcrypt-vendor-unsafe.txt`, and `cargo tree` against Section 5. Identify every direct and transitive dependency that either lacks `#![forbid(unsafe_code)]` / `#![deny(unsafe_code)]` or is unsafe-heavy.

## `check_build_test_and_abi_evidence`

- Type: `check`
- Fixed `bounce_target`: `impl_document_libgcrypt_port`
- Purpose: Verify that build, packaging, exported-symbol, test, dependent-coverage, validator-limitation, and bridge-removal claims are command-backed.
- Commands/checks to run:

```sh
bash scripts/check-layout.sh
cargo metadata --manifest-path safe/Cargo.toml --locked --offline --format-version 1 --no-deps
cargo tree --manifest-path safe/Cargo.toml --locked --offline
bash safe/scripts/check-no-upstream-bridge.sh
if [ -d validator/.git ]; then test -z "$(git -C validator status --short)" && git -C validator diff --exit-code && git -C validator diff --cached --exit-code; fi
bash safe/scripts/check-abi.sh --all
bash safe/scripts/run-compat-smoke.sh --all
bash safe/scripts/run-regression-tests.sh --all
bash safe/scripts/run-upstream-tests.sh --verify-plumbing
rg -n 'benchmark|bench-slope|performance|perf|slow|throughput|latency|regression' safe/docs safe/tests original/libgcrypt20-1.10.3/tests validator-report.md README.md relevant_cves.json dependents.json
rg -n 'non[- ]?equiv|bit-for-bit|compatib|mismatch|differ|diverg|unsupported|skip|xfail|known issue|not yet|TODO|FIXME|XXX|panic!|unimplemented!|todo!|not implemented' safe/docs safe/tests safe/src safe/scripts validator-report.md README.md dependents.json relevant_cves.json all_cves.json
bash safe/scripts/check-deb-metadata.sh --dist safe/dist
bash safe/scripts/check-installed-tools.sh --dist safe/dist
```

If `safe/dist/` is missing or either package checker fails, run:

```sh
bash safe/scripts/build-debs.sh
bash safe/scripts/check-deb-metadata.sh --dist safe/dist
bash safe/scripts/check-installed-tools.sh --dist safe/dist
```

Treat a passing `check-deb-metadata.sh` as the freshness check because it compares the manifest commit, package hashes, versions, symbols, and pinned toolchain against the current checkout.

If `validator-local/proof/local-port-debs-lock.json`, `validator-local/override-debs/`, and `validator-artifacts/p08-final/` exist and `safe/PORT.md` cites final validator artifact evidence, run:

```sh
python3 safe/scripts/check-validator-port-evidence.py --port-lock validator-local/proof/local-port-debs-lock.json --override-root validator-local/override-debs --artifact-root validator-artifacts/p08-final
```

Before `objdump` or `nm`, ensure the shared library was built from the current checkout by running these commands, unless a previous command in this same verifier already rebuilt `safe/target/release/libgcrypt.so`:

```sh
cargo build --manifest-path safe/Cargo.toml --release --locked --offline --bins --lib
bash safe/scripts/build-release-lib.sh
objdump -T safe/target/release/libgcrypt.so | rg 'GCRYPT_1\.6|gcry_md_get|gcry_pk_register|gcry_check_version'
nm -D --defined-only safe/target/release/libgcrypt.so | rg 'gcry_md_get|gcry_pk_register|gcry_check_version'
```

Agent review requirements:

- `safe/PORT.md` must name commands that were not run, explain why, and state residual risk. It must not claim a passing run for a skipped or failed command.
- The remaining-issues section must explicitly cover performance. Claim no known performance regressions only if the document also names benchmark or comparison evidence checked. If no direct original-vs-safe benchmark run was performed, state that and describe residual risk.
- The remaining-issues section must explicitly cover behavioral non-equivalence and bit-for-bit compatibility separately from performance.
- Inspect `safe/docs/abi-map.md`, `safe/docs/test-matrix.md`, `safe/docs/bridge-inventory.md`, `validator-report.md`, `safe/scripts/validator-libgcrypt-skips.json`, `safe/tests/regressions/manifest.json`, `safe/tests/compat/`, and relevant upstream tests for known behavior differences.
- For every known caveat, skip, unsupported behavior, or non-equivalent result, Section 4 must cite evidence and explain impact. If none are found, Section 4 must state that explicitly, name artifacts checked, and describe residual risk from untested libgcrypt surfaces.

## `check_git_commit`

- Type: `check`
- Fixed `bounce_target`: `impl_document_libgcrypt_port`
- Purpose: Verify that the implementation phase committed the documentation pass before yielding.
- Commands/checks to run:

```sh
git status --short
git log -1 --oneline --stat
git show --name-only --format=fuller --stat HEAD
```

Agent review requirements:

- The latest commit message must summarize the documentation pass.
- The latest commit must include `safe/PORT.md`.
- Any incidental code or script changes must be directly justified by documentation reconciliation.

# Success Criteria

- `safe/PORT.md` exists and contains the six required sections in exact order.
- Section 1 includes concrete data flow through direct Rust exports, fixed-signature C `FORWARD*` wrappers, and C varargs/libc-sensitive shims.
- The unsafe inventory reconciles with current `rg` output for source-owned code and vendored dependencies.
- Every cited code symbol has been checked with `rg --fixed-strings` against `safe` and `original`.
- Build, ABI, dependency, exported-symbol, validator, packaging, test, dependent-coverage, and bridge-removal claims are backed by commands or explicitly documented as skipped/failed with residual risk.
- Remaining issues cite current reports and manifests, including behavioral non-equivalence, bit-for-bit compatibility, validator limitations, dependent coverage, CVE coverage, and performance residual risk.
- The latest git commit includes `safe/PORT.md` and any strictly necessary incidental fixes.

# Git Commit Requirement

The implementer must commit the completed work to git before yielding. The work is incomplete if `safe/PORT.md` exists only in the working tree. Use a documentation-focused commit message such as `docs: document libgcrypt Rust port`, and include any strictly necessary incidental fixes in the same commit with a clear final summary.
