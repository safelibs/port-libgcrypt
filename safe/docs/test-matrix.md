# Harness Test Matrix

This matrix tracks two distinct compatibility harnesses:

- Original source-compatible harness: [`safe/scripts/run-original-tests.sh`](../scripts/run-original-tests.sh) compiles the original `original/libgcrypt20-1.10.3/tests/*.c` sources directly, derives `--list` and `--all` from `original/libgcrypt20-1.10.3/tests/Makefile.am`, and uses the committed original-build contract in `safe/tests/original-build/` for `config.h`, `test-build-vars.mk`, and the rendered wrapper scripts.
- Imported upstream harness: [`safe/scripts/run-upstream-tests.sh`](../scripts/run-upstream-tests.sh) compiles the committed snapshot under `safe/tests/upstream/` plus the committed compat subset under `safe/tests/compat/`; execution order comes from `safe/tests/upstream/testdrv.c`, not from the broader `Makefile.am` inventory.

## Phase 1 Harness Baseline

| Harness | Inventory source | Build contract | Execution entrypoint |
| --- | --- | --- | --- |
| Original source-compatible harness | `original/libgcrypt20-1.10.3/tests/Makefile.am` `TESTS` via `tests_bin`, `tests_sh`, `tests_bin_last`, and `tests_sh_last` | `safe/tests/original-build/config.h`, `safe/tests/original-build/test-build-vars.mk`, `safe/tests/original-build/basic-disable-all-hwf`, `safe/tests/original-build/hashtest-256g` | `safe/scripts/run-original-tests.sh --all` |
| Imported upstream harness | `safe/tests/upstream/testdrv.c` plus the committed wrapper copies in `safe/tests/upstream/` | `safe/tests/upstream/` and `safe/tests/compat/` committed copies only | `safe/scripts/run-upstream-tests.sh --all` |

For the original harness, `safe/scripts/run-original-tests.sh --list` prints only the live `TESTS` inventory, `--dry-run` preserves the real command shapes (`./basic`, wrapper-script arguments, and `./testapi version` / `./testapi sexp`), and the helper-only `testapi:version` / `testapi:sexp` entries remain opt-in instead of appearing in `--list` or `--all`.

The Noble-compatible toolchain baseline keeps plain `cargo build --release --offline` focused on Rust outputs. The harness and ABI scripts then relink `target/release/libgcrypt.so` from `target/release/libgcrypt.a` with the committed `safe/abi/libgcrypt.vers` map so the staged test surface still carries the authoritative `GCRYPT_1.6` symbol versions and `libgcrypt.so.20` SONAME.

Phase ownership follows the current repo documentation:

- Phase 1: Noble toolchain baseline plus the committed original-harness build contract, runtime inventory parser, and imported-harness sync plumbing.
- Phase 2: runtime shell/bootstrap ownership for version, config, allocation, and secure-memory behavior. This phase number is inferred from the pre-phase-3 ownership notes in `safe/docs/abi-map.md`.
- Phase 3: S-expression and MPI core ownership.
- Phase 4: digest, MAC, RNG, and KDF ownership.
- Phase 5: symmetric-cipher ownership.
- Phase 6: public-key, ECC, keygrip, and context ownership.
- Phase 7: imported upstream test-harness/build-contract ownership for helper binaries that are not implementation milestones on their own.

| Name | First enabled phase | Coverage type | Execution |
| --- | --- | --- | --- |
| `version` | Phase 2 | runtime-compatibility | executed by full suite |
| `t-secmem` | Phase 2 | runtime-compatibility | executed by full suite |
| `mpitests` | Phase 3 | source-compatibility | executed by full suite |
| `t-sexp` | Phase 3 | source-compatibility | executed by full suite |
| `t-convert` | Phase 3 | source-compatibility | executed by full suite |
| `t-mpi-bit` | Phase 3 | source-compatibility | executed by full suite |
| `prime` | Phase 3 | source-compatibility | executed by full suite |
| `random` | Phase 4 | security regression | executed by full suite |
| `hashtest` | Phase 4 | runtime-compatibility | executed by full suite |
| `hashtest-256g` | Phase 4 | runtime-compatibility | executed by full suite with `--long` |
| `hmac` | Phase 4 | runtime-compatibility | executed by full suite |
| `t-kdf` | Phase 4 | runtime-compatibility | executed by full suite |
| `genhashdata` | Phase 4 | source-compatibility | build-only helper |
| `gchash` | Phase 4 | source-compatibility | build-only helper |
| `aeswrap` | Phase 5 | security regression | executed by full suite |
| `basic` | Phase 5 | security regression | executed by full suite |
| `basic-disable-all-hwf` | Phase 5 | security regression | executed by full suite |
| `t-lock` | Phase 5 | security regression | executed by full suite |
| `benchmark` | Phase 5 | runtime-compatibility | executed by full suite |
| `bench-slope` | Phase 5 | runtime-compatibility | executed by full suite |
| `keygen` | Phase 6 | runtime-compatibility | executed by full suite |
| `pubkey` | Phase 6 | security regression | executed by full suite |
| `keygrip` | Phase 6 | security regression | executed by full suite |
| `pkcs1v2` | Phase 6 | security regression | executed by full suite |
| `fips186-dsa` | Phase 6 | security regression | executed by full suite |
| `dsa-rfc6979` | Phase 6 | security regression | executed by full suite |
| `t-dsa` | Phase 6 | security regression | executed by full suite |
| `curves` | Phase 6 | security regression | executed by full suite |
| `t-ecdsa` | Phase 6 | security regression | executed by full suite |
| `t-ed25519` | Phase 6 | security regression | executed by full suite |
| `t-cv25519` | Phase 6 | security regression | executed by full suite |
| `t-x448` | Phase 6 | security regression | executed by full suite |
| `t-ed448` | Phase 6 | security regression | executed by full suite |
| `t-rsa-pss` | Phase 6 | security regression | executed by full suite |
| `t-rsa-15` | Phase 6 | security regression | executed by full suite |
| `t-rsa-testparm` | Phase 6 | security regression | executed by full suite |
| `t-mpi-point` | Phase 6 | security regression | executed by full suite |
| `testapi` | Phase 6 | security regression | executed by relink harness |
| `pkbench` | Phase 6 | source-compatibility | build-only helper |
| `fipsdrv` | Phase 6 | source-compatibility | build-only helper |
| `rsacvt` | Phase 6 | source-compatibility | build-only helper |
| `testdrv` | Phase 7 | source-compatibility | build-only helper |

## Phase 8 Link-Compatibility Overlay

Phase 8 adds two compatibility-specific harnesses on top of the phase-1 original source-compatible harness and the phase-7 imported upstream suite:

- `safe/scripts/relink-original-objects.sh` compiles the original upstream `tests/` sources to object files with the original headers and build defines, relinks those objects against the safe `libgcrypt.so.20`, and executes every `tests_bin` and `tests_bin_last` binary from `original/libgcrypt20-1.10.3/tests/Makefile.am`, plus `testapi`.
- `safe/scripts/run-compat-smoke.sh` covers the remaining public-development and ABI-only surfaces that are not exercised by imported upstream tests, shell-backed wrappers, or the original-object relink pass.

| Harness / surface | First enabled phase | Coverage type | Execution |
| --- | --- | --- | --- |
| Imported upstream suite | Phase 7 | source- and runtime-compatibility | `safe/scripts/run-upstream-tests.sh --all` covers the full `testdrv` inventory plus the shell-backed `basic-disable-all-hwf` and `hashtest-256g` wrappers, including the long-running `benchmark`, `bench-slope`, and `hashtest-256g` cases |
| Original-object relink | Phase 8 | link-compatibility | `safe/scripts/relink-original-objects.sh --all` rebuilds original test objects and relinks every compiled regression binary against the safe shared library |
| Public thread-callback path | Phase 8 | targeted compatibility smoke | `safe/scripts/run-compat-smoke.sh --all` covers `GCRY_THREAD_OPTION_PTHREAD_IMPL`, `GCRY_THREAD_OPTION_PTH_IMPL`, and `gcry_control(GCRYCTL_SET_THREAD_CBS, &gcry_threads_pthread)` |
| Header-visible macro surface | Phase 8 | targeted compatibility smoke | `safe/scripts/run-compat-smoke.sh --all` compiles and runs `gcry_md_putc`, `gcry_fast_random_poll`, and `gcry_fips_mode_active` against the generated and staged headers |
| Public variadic entries | Phase 8 | targeted compatibility smoke | `safe/scripts/run-compat-smoke.sh --all` compiles and calls `gcry_control`, `gcry_sexp_build`, `gcry_sexp_vlist`, `gcry_sexp_extract_param`, and `gcry_log_debug` from C |
| `gcry_md_get` | Phase 8 | ABI-only smoke | `safe/scripts/run-compat-smoke.sh --all` uses a dedicated C probe with the local declaration carried by `src/visibility.h` and compares the returned digest bytes against `gcry_md_read` |
| `gcry_pk_register` | Phase 8 | ABI-only smoke | `safe/scripts/run-compat-smoke.sh --all` checks `GCRYPT_1.6` export presence and performs a `dlsym`-based runtime probe without reintroducing the symbol to the installed public header |
| Installed `pkg-config` surface | Phase 8 | development-metadata smoke | `safe/scripts/run-compat-smoke.sh --all` compiles the public smoke probe using the staged `libgcrypt.pc` file |
| Installed `libgcrypt-config` surface | Phase 8 | development-metadata smoke | `safe/scripts/run-compat-smoke.sh --all` compiles the public smoke probe using the staged `libgcrypt-config` output |
| Installed `libgcrypt.m4` surface | Phase 8 | development-metadata smoke | `safe/scripts/run-compat-smoke.sh --all` runs an Autoconf configure smoke using the staged `libgcrypt.m4` macro |

## Phase 10 Final Sweep Overlay

Phase 10 closes the remaining verification ownership for committed imported artifacts, packaged helper tools, Debian metadata, and downstream dependents.

Later downstream/image phases should consume already-built `safe/dist/*.deb` artifacts instead of rebuilding `safe/` inside Docker again. Phase 1 keeps offline Cargo valid for `cargo build` and `safe/scripts/build-debs.sh`, but package/image workflows should install the prebuilt packages they inherit.

| Harness / surface | First enabled phase | Coverage type | Execution |
| --- | --- | --- | --- |
| Imported test-tree drift guard | Phase 10 | committed-artifact verification | `safe/scripts/import-upstream-tests.sh --verify` compares the committed `safe/tests/upstream/` tree and the imported subset of `safe/tests/compat/` against `original/libgcrypt20-1.10.3`, while preserving local compat-smoke assets |
| Upstream harness plumbing | Phase 10 | committed-artifact verification | `safe/scripts/run-upstream-tests.sh --verify-plumbing` proves the run used the committed imported `config.h`, rendered wrapper scripts, generated header, and committed `compat/` support tree instead of files from `original/` |
| Debian symbol contract | Phase 10 | packaging verification | `safe/scripts/build-debs.sh` plus `safe/scripts/check-deb-metadata.sh --dist safe/dist` reconcile `safe/debian/libgcrypt20.symbols` against `safe/abi/libgcrypt.vers`, allowing only Debian's `GCRYPT_1.6` sentinel line as an extra non-symbol entry |
| Installed helper CLI surface | Phase 10 | package-image smoke | `safe/scripts/check-installed-tools.sh --dist safe/dist` runs `dumpsexp`, `hmac256`, `mpicalc`, `libgcrypt-config`, and `pkg-config` from the extracted package image rather than cargo-built binaries |
| Downstream dependent matrix | Phase 10 | packaged runtime compatibility | `./test-original.sh --implementation safe` validates the packaged safe build against `libapt-pkg`, `gpg`, `gnome-keyring`, `libssh-gcrypt`, `xmlsec1`, `munge`, `aircrack-ng`, and `wireshark`; later image/downstream phases should install the already-built `safe/dist/*.deb` packages rather than rebuilding `safe/` inside Docker |
