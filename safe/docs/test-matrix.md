# Upstream Test Matrix

This matrix records the committed upstream `tests/` inventory under `safe/tests/upstream/` and the imported Linux compatibility support under `safe/tests/compat/`. Phase 7 owns the committed harness contract: `safe/scripts/import-upstream-tests.sh --verify` reconciles the imported files in place, and `safe/scripts/run-upstream-tests.sh --verify-plumbing` proves the runner builds from those committed files plus the generated safe header.

`safe/scripts/run-upstream-tests.sh --all` uses `safe/tests/upstream/testdrv.c` order and includes entries marked long-running by `testdrv`. Tests listed by `Makefile.am` but not by `testdrv --list` remain runnable by explicit name. `--verify-plumbing --all` first verifies plumbing and then continues into the full `--all` run.

Phase ownership follows the implementation phase that owns the compatible behavior. Phase 7 owns harness-only plumbing and helper build rules that are not an implementation milestone on their own.

| Name | Imported inventory source | First implementation owner | Verification command |
| --- | --- | --- | --- |
| `version` | `testdrv` | Phase 2 | `safe/scripts/run-upstream-tests.sh --all` |
| `t-secmem` | `testdrv` | Phase 2 | `safe/scripts/run-upstream-tests.sh --all` |
| `mpitests` | `testdrv` | Phase 3 | `safe/scripts/run-upstream-tests.sh --all` |
| `t-sexp` | `testdrv` | Phase 3 | `safe/scripts/run-upstream-tests.sh --all` |
| `t-convert` | `testdrv` | Phase 3 | `safe/scripts/run-upstream-tests.sh --all` |
| `t-mpi-bit` | `testdrv` | Phase 3 | `safe/scripts/run-upstream-tests.sh --all` |
| `prime` | `testdrv` | Phase 3 | `safe/scripts/run-upstream-tests.sh --all` |
| `random` | `testdrv` | Phase 4 | `safe/scripts/run-upstream-tests.sh --all` |
| `hashtest` | `testdrv` | Phase 4 | `safe/scripts/run-upstream-tests.sh --all` |
| `hashtest-256g` | `testdrv` long wrapper | Phase 4 | `safe/scripts/run-upstream-tests.sh --all` |
| `hmac` | `testdrv` | Phase 4 | `safe/scripts/run-upstream-tests.sh --all` |
| `t-kdf` | `testdrv` | Phase 4 | `safe/scripts/run-upstream-tests.sh --all` |
| `genhashdata` | build-only helper | Phase 4 | `safe/scripts/run-upstream-tests.sh --verify-plumbing` |
| `gchash` | build-only helper | Phase 4 | `safe/scripts/run-upstream-tests.sh --verify-plumbing` |
| `aeswrap` | `testdrv` | Phase 5 | `safe/scripts/run-upstream-tests.sh --all` |
| `basic` | `testdrv` | Phase 5 | `safe/scripts/run-upstream-tests.sh --all` |
| `basic-disable-all-hwf` | `testdrv` wrapper | Phase 5 | `safe/scripts/run-upstream-tests.sh --all` |
| `t-lock` | `testdrv` | Phase 5 | `safe/scripts/run-upstream-tests.sh --all` |
| `benchmark` | `testdrv` | Phase 5 | `safe/scripts/run-upstream-tests.sh --all` |
| `bench-slope` | `testdrv` | Phase 5 | `safe/scripts/run-upstream-tests.sh --all` |
| `keygen` | `testdrv` | Phase 6 | `safe/scripts/run-upstream-tests.sh --all` |
| `pubkey` | `testdrv` | Phase 6 | `safe/scripts/run-upstream-tests.sh --all` |
| `keygrip` | `testdrv` | Phase 6 | `safe/scripts/run-upstream-tests.sh --all` |
| `pkcs1v2` | `testdrv` | Phase 6 | `safe/scripts/run-upstream-tests.sh --all` |
| `fips186-dsa` | `testdrv` | Phase 6 | `safe/scripts/run-upstream-tests.sh --all` |
| `dsa-rfc6979` | `testdrv` | Phase 6 | `safe/scripts/run-upstream-tests.sh --all` |
| `curves` | `testdrv` | Phase 6 | `safe/scripts/run-upstream-tests.sh --all` |
| `t-ed25519` | `testdrv` | Phase 6 | `safe/scripts/run-upstream-tests.sh --all` |
| `t-cv25519` | `testdrv` | Phase 6 | `safe/scripts/run-upstream-tests.sh --all` |
| `t-x448` | `testdrv` | Phase 6 | `safe/scripts/run-upstream-tests.sh --all` |
| `t-ed448` | `testdrv` | Phase 6 | `safe/scripts/run-upstream-tests.sh --all` |
| `t-mpi-point` | `testdrv` | Phase 6 | `safe/scripts/run-upstream-tests.sh --all` |
| `t-dsa` | `Makefile.am` test, explicit-name run | Phase 6 | `safe/scripts/run-upstream-tests.sh t-dsa` |
| `t-ecdsa` | `Makefile.am` test, explicit-name run | Phase 6 | `safe/scripts/run-upstream-tests.sh t-ecdsa` |
| `t-rsa-pss` | `Makefile.am` test, explicit-name run | Phase 6 | `safe/scripts/run-upstream-tests.sh t-rsa-pss` |
| `t-rsa-15` | `Makefile.am` test, explicit-name run | Phase 6 | `safe/scripts/run-upstream-tests.sh t-rsa-15` |
| `t-rsa-testparm` | `Makefile.am` test, explicit-name run | Phase 6 | `safe/scripts/run-upstream-tests.sh t-rsa-testparm` |
| `testapi` | `Makefile.am` extra program | Phase 6 | `safe/scripts/run-upstream-tests.sh testapi` |
| `pkbench` | build-only helper | Phase 6 | `safe/scripts/run-upstream-tests.sh --verify-plumbing` |
| `fipsdrv` | build-only helper | Phase 6 | `safe/scripts/run-upstream-tests.sh --verify-plumbing` |
| `rsacvt` | build-only helper | Phase 6 | `safe/scripts/run-upstream-tests.sh --verify-plumbing` |
| `testdrv` | harness driver/helper | Phase 7 | `safe/scripts/run-upstream-tests.sh --verify-plumbing` |

## Harness Support Artifacts

| Artifact set | Phase owner | Verification command |
| --- | --- | --- |
| `safe/tests/upstream/**` imported files, plus rendered `config.h`, `basic-disable-all-hwf`, and `hashtest-256g` | Phase 7 | `safe/scripts/import-upstream-tests.sh --verify` |
| Upstream-imported `safe/tests/compat/{Makefile.am,Makefile.in,clock.c,compat.c,getpid.c,libcompat.h}` plus `safe/tests/compat/include/src/g10lib.h` | Phase 7 | `safe/scripts/import-upstream-tests.sh --verify` and `safe/scripts/run-upstream-tests.sh --verify-plumbing` |
| `bench-slope` GCM-SIV tag-before-IV harness wrapper generated from `safe/scripts/run-upstream-tests.sh` | Phase 7 | `safe/scripts/run-upstream-tests.sh --all` |
| Local compat probes and fixtures under `safe/tests/compat/` | Phase 8 | Preserved by `safe/scripts/import-upstream-tests.sh --verify`; executed by `safe/scripts/run-compat-smoke.sh --all` |

## Link-Compatibility Overlay

Phase 8 adds compatibility-specific harnesses on top of the imported upstream suite.

| Harness / surface | First enabled phase | Coverage type | Execution |
| --- | --- | --- | --- |
| Original-object relink | Phase 8 | link-compatibility | `safe/scripts/relink-original-objects.sh --all` rebuilds original test objects with original headers/defines and relinks every compiled regression and benchmark binary against the safe shared library. Regression/testapi binaries are executed; upstream `benchmark` and `bench-slope` are link-only here because their runtime paths remain covered by `safe/scripts/run-upstream-tests.sh`. |
| Public thread-callback path | Phase 8 | targeted compatibility smoke | `safe/scripts/run-compat-smoke.sh --all` covers `GCRY_THREAD_OPTION_PTHREAD_IMPL`, `GCRY_THREAD_OPTION_PTH_IMPL`, and `gcry_control(GCRYCTL_SET_THREAD_CBS, &gcry_threads_pthread)` |
| Header-visible macro surface | Phase 8 | targeted compatibility smoke | `safe/scripts/run-compat-smoke.sh --all` compiles and runs `gcry_md_putc`, `gcry_fast_random_poll`, and `gcry_fips_mode_active` against the generated and staged headers |
| Public variadic entries | Phase 8 | targeted compatibility smoke | `safe/scripts/run-compat-smoke.sh --all` compiles and calls `gcry_control`, `gcry_sexp_build`, `gcry_sexp_vlist`, `gcry_sexp_extract_param`, and `gcry_log_debug` from C |
| `gcry_md_get` | Phase 8 | ABI-only smoke | `safe/scripts/run-compat-smoke.sh --all` uses a dedicated C probe with the local declaration carried by `src/visibility.h` and compares the returned digest bytes against `gcry_md_read` |
| `gcry_pk_register` | Phase 8 | ABI-only smoke | `safe/scripts/run-compat-smoke.sh --all` checks `GCRYPT_1.6` export presence and performs a direct ABI-only runtime probe without reintroducing the symbol to the installed public header |
| Installed `pkg-config` surface | Phase 8 | development-metadata smoke | `safe/scripts/run-compat-smoke.sh --all` compiles the public smoke probe using the staged `libgcrypt.pc` file |
| Installed `libgcrypt-config` surface | Phase 8 | development-metadata smoke | `safe/scripts/run-compat-smoke.sh --all` compiles the public smoke probe using the staged `libgcrypt-config` output |
| Installed `libgcrypt.m4` surface | Phase 8 | development-metadata smoke | `safe/scripts/run-compat-smoke.sh --all` runs an Autoconf configure smoke using the staged `libgcrypt.m4` macro |

## Final Sweep Overlay

Later final-sweep phases re-run the Phase 7 imported harness checks together with packaging and downstream image checks.

| Harness / surface | First enabled phase | Coverage type | Execution |
| --- | --- | --- | --- |
| Imported test-tree drift guard | Phase 7 | committed-artifact verification | `safe/scripts/import-upstream-tests.sh --verify` compares the committed `safe/tests/upstream/` tree and the imported subset of `safe/tests/compat/` against `original/libgcrypt20-1.10.3`, while preserving local compat-smoke assets |
| Upstream harness plumbing | Phase 7 | committed-artifact verification | `safe/scripts/run-upstream-tests.sh --verify-plumbing` proves the run used the committed imported `config.h`, rendered wrapper scripts, generated header, and committed `compat/` support tree instead of files from `original/` |
| Debian symbol contract | Phase 10 | packaging verification | `safe/scripts/build-debs.sh` plus `safe/scripts/check-deb-metadata.sh --dist safe/dist` reconcile `safe/debian/libgcrypt20.symbols` against `safe/abi/libgcrypt.vers`, allowing only Debian's `GCRYPT_1.6` sentinel line as an extra non-symbol entry |
| Installed helper CLI surface | Phase 10 | package-image smoke | `safe/scripts/check-installed-tools.sh --dist safe/dist` runs `dumpsexp`, `hmac256`, `mpicalc`, `libgcrypt-config`, and `pkg-config` from the extracted package image rather than cargo-built binaries |
| Downstream dependent matrix | Phase 10 | packaged runtime compatibility | `safe/scripts/build-dependent-image.sh --implementation original|safe --tag ...` plus `safe/scripts/run-dependent-image-tests.sh --compile-probes|--all` validates the 15-row committed matrix using the pinned Noble base image, fixed snapshot source file, package locks, local safe package manifest, compile probes, and executable fixtures under `safe/tests/dependents/` |

## Downstream Dependent Matrix

Phase 10 replaces the earlier inline `test-original.sh` container with committed image metadata and fixture-driven checks. `dependents.json` and `safe/tests/dependents/metadata/matrix-manifest.json` contain 15 binary packages: 3 library-flavored compile probes (`libapt-pkg6.0t64`, `libssh-gcrypt-4`, `libxmlsec1t64-gcrypt`) and 12 executable application scenarios (`gpg`, `gnome-keyring`, `munge`, `aircrack-ng`, `wireshark-common`, `gpgv`, `gpgsm`, `seccure`, `pdfgrep`, `rng-tools5`, `libotr5-bin`, and `tcplay`).

The image inputs are committed under `safe/tests/dependents/metadata/`: the pinned `ubuntu:24.04@sha256:...` base image, the fixed Noble snapshot source file, the full install package closure lock, the safe local `.deb` policy lock, and package evidence. Later phases consume these files directly.

`safe/scripts/run-dependent-image-tests.sh --all` compiles the three committed probes first, verifies each probe loads the selected `libgcrypt.so.20`, then runs every scenario script under `safe/tests/dependents/scenarios/`. Runtime scenarios use committed fixtures only; they do not fetch source packages or generate fixtures at test time. The `gpgsm` safe-implementation path also compiles a committed scenario helper under `safe/tests/dependents/helpers/`; the helper stays outside the safe Debian package and keeps the phase 10 image built from the phase 9 package sources.
