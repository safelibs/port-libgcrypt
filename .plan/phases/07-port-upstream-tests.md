# 07 Port Upstream Tests

- Phase Name: Port the upstream test suite into `safe/tests/upstream`
- Implement Phase ID: `impl_p07_port_upstream_tests`

## Preexisting Inputs
- `safe/Cargo.toml`
- `safe/Cargo.lock`
- `safe/build.rs`
- `safe/.cargo/config.toml`
- `safe/src/`
- `safe/cabi/`
- `safe/abi/`
- `safe/docs/abi-map.md`
- `safe/docs/cve-matrix.md`
- `safe/tests/original-build/`
- `safe/scripts/check-abi.sh`
- `safe/scripts/run-original-tests.sh`
- `original/libgcrypt20-1.10.3/config.h.in`
- `original/libgcrypt20-1.10.3/tests/`
- `original/libgcrypt20-1.10.3/compat/`
- `original/libgcrypt20-1.10.3/compat/Makefile.am`
- `original/libgcrypt20-1.10.3/src/gcrypt-testapi.h`
- `original/libgcrypt20-1.10.3/src/g10lib.h`
- `original/libgcrypt20-1.10.3/tests/Makefile.am`
- `original/libgcrypt20-1.10.3/tests/testdrv.c`

## New Outputs
- Imported upstream tests under `safe/tests/upstream/`
- Committed imported-test build artifacts, including `config.h` and rendered wrappers
- `safe/scripts/import-upstream-tests.sh`
- `safe/scripts/run-upstream-tests.sh`
- `safe/docs/test-matrix.md`

## File Changes
- `safe/tests/upstream/`
- `safe/tests/compat/`
- `safe/tests/upstream/config.h`
- `safe/tests/upstream/basic-disable-all-hwf`
- `safe/tests/upstream/hashtest-256g`
- `safe/tests/compat/include/`
- `safe/scripts/import-upstream-tests.sh`
- `safe/scripts/run-upstream-tests.sh`
- `safe/docs/test-matrix.md`

## Implementation Details
- Import the upstream tests from the local `original/` snapshot into `safe/tests/upstream/` without fetching from the network.
- Treat `original/libgcrypt20-1.10.3/tests/Makefile.am` as the authoritative inventory of test and script entries, and `testdrv.c` as the authoritative source for driver order, long-running flags, and script-to-binary mappings; preserve both and do not force them to agree where upstream intentionally differs.
- Keep `safe/tests/upstream/` as a verbatim or minimally adapted mirror so failures remain directly comparable to upstream sources.
- Bring over the required `compat/` support files under `safe/tests/compat/`, including the `.inp` files, helper headers, and wrapper inputs referenced by the test list.
- Consume the committed phase-1 test-build artifacts instead of regenerating them:
  - Copy the committed phase-1 Linux test config into `safe/tests/upstream/config.h` and make it the only `config.h` used by imported builds.
  - Copy the committed rendered wrappers into `safe/tests/upstream/basic-disable-all-hwf` and `safe/tests/upstream/hashtest-256g`, preserving `EXEEXT=""` and the committed `RUN_LARGE_DATA_TESTS=yes` setting.
  - Keep the original `.in` templates for drift checking, but do not execute them directly in normal runs.
- Import the minimal internal-header subset required to build the copied `compat/` sources under `safe/tests/compat/include/` so imported builds rely entirely on committed files under `safe/` plus installed external dependencies. After this phase, `safe/scripts/run-upstream-tests.sh` must not compile sources or headers from `original/libgcrypt20-1.10.3/`.
- Build and keep the helper binaries that belong to the upstream test-build contract even when they are not all top-level `TESTS` entries. At minimum, build `testdrv`, `fipsdrv`, `rsacvt`, `genhashdata`, `gchash`, and `pkbench`, and record in `safe/docs/test-matrix.md` which helpers are build-only versus executed.
- Add `safe/scripts/import-upstream-tests.sh` to populate the imported tree, verify it is in sync, verify that `safe/tests/upstream/config.h`, the rendered wrapper scripts, and the `compat/` support headers match their committed source-of-truth inputs, fail on drift, and never rewrite files in `--verify` mode.
- Add `safe/scripts/run-upstream-tests.sh` to compile and run the imported tests against the safe library using the same test names as upstream, always setting `GCRYPT_IN_REGRESSION_TEST=1`, and supporting targeted subsets plus the full ordered suite.
- Add a `--verify-plumbing` mode to `safe/scripts/run-upstream-tests.sh` that proves the committed imported `config.h`, rendered wrappers, helper-binary build targets, and `compat/` include tree exist and are the exact artifacts used by the imported build.
- Create `safe/docs/test-matrix.md` mapping upstream test names to the phase that first enabled them and to whether each test is a source-compatibility, runtime-compatibility, or security regression check.

## Verification Phases
### `check_p07_port_upstream_tests`
- Type: `check`
- `bounce_target`: `impl_p07_port_upstream_tests`
- Purpose: verify that the upstream tests now live under `safe/` and can be built and run there without depending on ad hoc direct compilation from `original/tests`.
- Commands:

```bash
cargo build --manifest-path safe/Cargo.toml --release --offline
safe/scripts/import-upstream-tests.sh --verify
safe/scripts/run-upstream-tests.sh --verify-plumbing
safe/scripts/run-upstream-tests.sh version t-secmem mpitests t-sexp t-convert t-mpi-bit prime random hashtest hmac t-kdf aeswrap basic basic-disable-all-hwf t-lock keygen pubkey keygrip pkcs1v2 fips186-dsa dsa-rfc6979 t-dsa curves t-ecdsa t-ed25519 t-cv25519 t-x448 t-ed448 t-rsa-pss t-rsa-15 t-rsa-testparm t-mpi-point testapi
```

## Success Criteria
- `cargo build --manifest-path safe/Cargo.toml --release --offline` succeeds.
- `safe/scripts/import-upstream-tests.sh --verify` confirms the imported tree, committed `config.h`, rendered wrappers, and compat headers match their source-of-truth inputs without rewriting them.
- `safe/scripts/run-upstream-tests.sh --verify-plumbing` proves the imported suite uses the committed build artifacts and helper-binary targets.
- `safe/scripts/run-upstream-tests.sh ...` passes for the full listed subset of upstream tests under `safe/tests/upstream/`.
- `safe/docs/test-matrix.md` records phase ownership and coverage type for the imported suite and helper binaries.

## Git Commit Requirement
The implementer must commit the phase's work to git before yielding.
