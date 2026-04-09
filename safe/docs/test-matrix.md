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
| `testapi` | Phase 6 | security regression | executed on demand |
| `pkbench` | Phase 6 | source-compatibility | build-only helper |
| `fipsdrv` | Phase 6 | source-compatibility | build-only helper |
| `rsacvt` | Phase 6 | source-compatibility | build-only helper |
| `testdrv` | Phase 7 | source-compatibility | build-only helper |

