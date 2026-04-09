# Upstream Test Matrix

This matrix records the imported upstream `tests/` inventory now staged under `safe/tests/upstream/` and the helper/build contract now staged under `safe/tests/compat/`. Driver order and long-running flags come from `safe/tests/upstream/testdrv.c`; the broader build inventory comes from `safe/tests/upstream/Makefile.am`, and the two are intentionally not forced to match.

Phase ownership follows the current repo documentation:

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

Phase 8 adds two compatibility-specific harnesses on top of the imported upstream suite:

- `safe/scripts/relink-original-objects.sh` compiles the original upstream `tests/` sources to object files with the original headers and build defines, relinks those objects against the safe `libgcrypt.so.20`, and executes every `tests_bin` and `tests_bin_last` binary from `original/libgcrypt20-1.10.3/tests/Makefile.am`, plus `testapi`.
- `safe/scripts/run-compat-smoke.sh` covers the remaining public-development and ABI-only surfaces that are not exercised by imported upstream tests, shell-backed wrappers, or the original-object relink pass.

| Harness / surface | First enabled phase | Coverage type | Execution |
| --- | --- | --- | --- |
| Imported upstream suite | Phase 7 | source- and runtime-compatibility | `safe/scripts/run-upstream-tests.sh` covers the `testdrv` inventory plus the shell-backed `basic-disable-all-hwf` and `hashtest-256g` wrappers |
| Original-object relink | Phase 8 | link-compatibility | `safe/scripts/relink-original-objects.sh --all` rebuilds original test objects and relinks every compiled regression binary against the safe shared library |
| Public thread-callback path | Phase 8 | targeted compatibility smoke | `safe/scripts/run-compat-smoke.sh --all` covers `GCRY_THREAD_OPTION_PTHREAD_IMPL`, `GCRY_THREAD_OPTION_PTH_IMPL`, and `gcry_control(GCRYCTL_SET_THREAD_CBS, &gcry_threads_pthread)` |
| Header-visible macro surface | Phase 8 | targeted compatibility smoke | `safe/scripts/run-compat-smoke.sh --all` compiles and runs `gcry_md_putc`, `gcry_fast_random_poll`, and `gcry_fips_mode_active` against the generated and staged headers |
| Public variadic entries | Phase 8 | targeted compatibility smoke | `safe/scripts/run-compat-smoke.sh --all` compiles and calls `gcry_control`, `gcry_sexp_build`, `gcry_sexp_vlist`, `gcry_sexp_extract_param`, and `gcry_log_debug` from C |
| `gcry_md_get` | Phase 8 | ABI-only smoke | `safe/scripts/run-compat-smoke.sh --all` uses a dedicated C probe with the local declaration carried by `src/visibility.h` and compares the returned digest bytes against `gcry_md_read` |
| `gcry_pk_register` | Phase 8 | ABI-only smoke | `safe/scripts/run-compat-smoke.sh --all` checks `GCRYPT_1.6` export presence and performs a `dlsym`-based runtime probe without reintroducing the symbol to the installed public header |
| Installed `pkg-config` surface | Phase 8 | development-metadata smoke | `safe/scripts/run-compat-smoke.sh --all` compiles the public smoke probe using the staged `libgcrypt.pc` file |
| Installed `libgcrypt-config` surface | Phase 8 | development-metadata smoke | `safe/scripts/run-compat-smoke.sh --all` compiles the public smoke probe using the staged `libgcrypt-config` output |
| Installed `libgcrypt.m4` surface | Phase 8 | development-metadata smoke | `safe/scripts/run-compat-smoke.sh --all` runs an Autoconf configure smoke using the staged `libgcrypt.m4` macro |
