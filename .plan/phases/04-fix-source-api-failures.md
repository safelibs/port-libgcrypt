# Phase Name

Fix source API validator failures

# Implement Phase ID

`impl_p04_fix_source_api_failures`

# Preexisting Inputs

Consume these artifacts in place. If any listed generated artifact already exists, use it as phase input evidence instead of rediscovering or reimporting it.

- Original source snapshot and safe implementation artifacts:
  `original/libgcrypt20-1.10.3/`, `safe/Cargo.toml`, `safe/Cargo.lock`,
  `safe/build.rs`, `safe/src/`, `safe/abi/`, `safe/cabi/`, and
  `safe/vendor/`.
- Generated/package artifacts from prior phases: `safe/dist/*.deb`,
  `safe/dist/safe-debs.manifest.json`, and top-level package build outputs if
  present.
- Existing test harnesses and scripts: `safe/scripts/*.sh`,
  `safe/tests/upstream/`, `safe/tests/compat/`, `safe/tests/dependents/`,
  and `safe/tests/regressions/`.
- Existing metadata and documentation inputs: `dependents.json`,
  `relevant_cves.json`, `all_cves.json`, and `safe/docs/*.md`.
- Dependent-image package locks and snapshot inputs:
  `safe/tests/dependents/metadata/install-packages.noble.lock`,
  `safe/tests/dependents/metadata/safe-debs.noble.lock`,
  `safe/tests/dependents/metadata/base-image.noble.digest`, and
  `safe/tests/dependents/metadata/ubuntu-snapshot.noble.sources`.
- Phase 3 packaging/install commit and report, plus the phase 2 baseline
  inventory and artifacts.
- `safe/scripts/run-validator-libgcrypt.sh` and
  `safe/scripts/check-validator-port-evidence.py`.
- `safe/scripts/validator-libgcrypt-skips.json`.
- Validator source testcases:
  - `tests/libgcrypt/tests/cases/source/aes-ctr-roundtrip.sh`
  - `tests/libgcrypt/tests/cases/source/digest-sha256-smoke.sh`
  - `tests/libgcrypt/tests/cases/source/hmac-sha256-smoke.sh`
  - `tests/libgcrypt/tests/cases/source/mpi-arithmetic.sh`
  - `tests/libgcrypt/tests/cases/source/nonce-generation.sh`
- Relevant safe modules:
  - `safe/src/cipher/mod.rs`
  - `safe/src/cipher/block.rs`
  - `safe/src/cipher/local.rs`
  - `safe/src/cipher/modes.rs`
  - `safe/src/cipher/registry.rs`
  - `safe/src/digest/mod.rs`
  - `safe/src/digest/algorithms.rs`
  - `safe/src/mpi/mod.rs`
  - `safe/src/mpi/arith.rs`
  - `safe/src/mpi/scan.rs`
  - `safe/src/random.rs`
  - `safe/src/global.rs`
  - `safe/abi/`
  - `safe/cabi/`

# New Outputs

- Source API fixes in `safe/src/`.
- Minimal regression scripts under `safe/tests/regressions/`, one per fixed
  source validator failure.
- Updated `safe/tests/regressions/manifest.json`.
- Updated `validator-report.md` marking fixed source API failures and the
  phase tag that fixed them.
- If the phase 2 `source-api` bucket is empty, no safe code or regression test
  changes are required; the phase still produces a focused source-validator
  rerun, updates `validator-report.md` to mark the bucket clean with no fixes
  needed, and creates the required phase commit and tag.

# File Changes

- `safe/src/cipher/*.rs` as required for AES CTR failures.
- `safe/src/digest/*.rs` as required for digest or HMAC failures.
- `safe/src/mpi/*.rs` as required for MPI arithmetic failures.
- `safe/src/random.rs` or `safe/src/global.rs` as required for nonce failures.
- `safe/abi/*` or `safe/cabi/*` only if the failure is an exported symbol,
  header, or C ABI forwarding issue.
- `safe/tests/regressions/manifest.json`
- `safe/tests/regressions/validator-*.sh` or
  `safe/tests/regressions/validator/*.sh`
- `safe/scripts/validator-libgcrypt-skips.json` only for a clearly identified
  source-test validator bug, with an exact validator-commit-specific skip.
- `safe/scripts/run-validator-libgcrypt.sh` only if the phase exposes a bug in
  the existing skip matching or result-writing behavior.
- `validator-report.md`

# Implementation Details

## Workflow-Wide Requirements For This Phase

- Consume the listed preexisting inputs in place. Existing source snapshots, metadata, tests, packages, validator checkouts, and prior artifacts are inputs, not rediscovery or regeneration tasks unless this phase explicitly rebuilds generated package/validator artifacts.
- Keep `validator/`, `validator-local/`, and `validator-artifacts/` external to the port repository. Do not commit nested validator contents or generated validator artifacts.
- Preserve the Rust toolchain contract: root `rust-toolchain.toml` and `safe/rust-toolchain.toml` must stay identical and pinned to Rust `1.85.1` with `profile = "minimal"` and `components = ["rustfmt"]`.
- Run `safe/scripts/check-rust-toolchain.sh` before every Cargo, release-library, Debian package, or dependent safe-image build.
- Build any package artifacts used as validator inputs from a clean phase commit after `phase/impl_p04_fix_source_api_failures` points at `HEAD`. If tracked files or `validator-report.md` change after validation, amend the same phase commit, force-update the phase tag, rebuild packages, regenerate `validator-local`, and rerun the phase validator commands until the worktree is clean and artifacts match the final phase commit.
- `validator-report.md` must identify the safe port by implement phase ID and `phase/impl_p04_fix_source_api_failures`, not by embedding the literal hash of the final report commit.

## Phase-Specific Details

- For each source API failure in `validator-report.md`, first add a minimal
  regression test that compiles and runs a small C probe against the staged safe
  headers and library. The probe should be a reduced version of the validator
  testcase, not a copied full validator script.
- If phase 2 recorded zero `source-api` failures, do not invent a regression or
  safe-side change. Consume the phase 2 inventory, rerun
  `safe/scripts/run-validator-libgcrypt.sh --kind source` in port mode with
  override evidence, update `validator-report.md` with the clean source-bucket
  result and artifact root, and make the required
  `impl_p04_fix_source_api_failures:` phase commit. If the report was already
  exact and no tracked file changed, create the phase commit with
  `git commit --allow-empty` before tagging it.
- For `aes-ctr-roundtrip`, validate:
  - `gcry_cipher_open(&hd, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_CTR, 0)`
    succeeds.
  - `gcry_cipher_setkey` accepts a 16-byte AES-128 key.
  - `gcry_cipher_setctr` accepts a 16-byte counter.
  - Two encryptions with the same key/counter recover the original 16-byte
    buffer.
  - Likely code paths are `safe/src/cipher/mod.rs` lines 72-178,
    `safe/src/cipher/block.rs`, and `safe/src/cipher/local.rs`.
- For `digest-sha256-smoke`, validate `gcry_md_hash_buffer(GCRY_MD_SHA256, ...)`
  returns the SHA-256 prefix `ba7816bf` for `abc`. Likely code paths are
  `safe/src/digest/mod.rs` lines 443-463 and
  `safe/src/digest/algorithms.rs`.
- For `hmac-sha256-smoke`, validate `gcry_md_open(..., GCRY_MD_FLAG_HMAC)`,
  `gcry_md_setkey`, `gcry_md_write`, and `gcry_md_read` produce a stable
  HMAC-SHA256 result. Likely code paths are `safe/src/digest/mod.rs` lines
  291-616 and `safe/src/digest/algorithms.rs` HMAC helpers.
- For `mpi-arithmetic`, validate `gcry_mpi_new`, `gcry_mpi_set_ui`,
  `gcry_mpi_add_ui`, `gcry_mpi_get_ui`, and `gcry_mpi_release`. Likely code
  paths are `safe/src/mpi/mod.rs` lines 741-814 and
  `safe/src/mpi/arith.rs` line 62.
- For `nonce-generation`, validate `gcry_create_nonce` fills a 16-byte buffer
  with nonzero data without crashing before explicit initialization. Likely
  code path is `safe/src/random.rs` lines 87-98 and 282-283.
- Preserve memory safety: no raw pointer expansion beyond C ABI boundaries
  unless required and locally justified.
- Do not alter validator scripts. If a source testcase is invalid, document the
  exact validator bug in `validator-report.md` and add or update only the
  matching entry in `safe/scripts/validator-libgcrypt-skips.json`. The skip must
  name the current validator commit and source testcase ID, and the focused
  source run must still execute all unaffected source cases.
- Commit fixes and report updates. End with one commit whose subject begins
  `impl_p04_fix_source_api_failures:` and tag it
  `phase/impl_p04_fix_source_api_failures`.

# Verification Phases

- Phase ID: `check_p04_source_api_software_tester`
- Type: `check`
- Fixed `bounce_target`: `impl_p04_fix_source_api_failures`
- Purpose: verify source API fixes through focused regressions and the
  validator source testcase set.
- Commands:
  - `test "$(git rev-parse HEAD)" = "$(git rev-parse phase/impl_p04_fix_source_api_failures)"`
  - `test "$(git rev-parse HEAD^)" = "$(git rev-parse phase/impl_p03_fix_packaging_install)"`
  - `bash -c 'test -z "$(git status --short)"'`
  - `bash -c 'git check-ignore -q validator/ && git check-ignore -q validator-local/ && git check-ignore -q validator-artifacts/'`
  - `bash -c 'test -z "$(git ls-files -- validator validator-local validator-artifacts)"'`
  - `safe/scripts/check-rust-toolchain.sh`
  - `safe/scripts/check-dependent-metadata.sh`
  - `cargo fmt --manifest-path safe/Cargo.toml -- --check`
  - `cargo build --manifest-path safe/Cargo.toml --release --locked --offline`
  - `safe/scripts/build-release-lib.sh`
  - `safe/scripts/check-abi.sh --all`
  - `safe/scripts/run-regression-tests.sh --all`
  - `safe/scripts/build-debs.sh`
  - `safe/scripts/check-deb-metadata.sh --dist safe/dist`
  - `python3 safe/scripts/prepare-validator-local-port.py --validator-dir validator --dist safe/dist --output-root validator-local`
  - `bash safe/scripts/run-validator-libgcrypt.sh --validator-dir validator --mode port --artifact-root validator-artifacts/p04-port-source --override-root validator-local/override-debs --port-lock validator-local/proof/local-port-debs-lock.json --kind source --record-casts`
  - `python3 safe/scripts/check-validator-port-evidence.py --port-lock validator-local/proof/local-port-debs-lock.json --override-root validator-local/override-debs --artifact-root validator-artifacts/p04-port-source`

- Phase ID: `check_p04_source_api_senior_tester`
- Type: `check`
- Fixed `bounce_target`: `impl_p04_fix_source_api_failures`
- Purpose: review that every source API failure has a minimal safe-side
  regression and that validator files were not patched to hide failures.
- Commands:
  - `test "$(git rev-parse HEAD)" = "$(git rev-parse phase/impl_p04_fix_source_api_failures)"`
  - `test "$(git rev-parse HEAD^)" = "$(git rev-parse phase/impl_p03_fix_packaging_install)"`
  - `bash -c 'test -z "$(git status --short)"'`
  - `bash -c 'git check-ignore -q validator/ && git check-ignore -q validator-local/ && git check-ignore -q validator-artifacts/'`
  - `git diff --stat HEAD^..HEAD`
  - `bash -c 'test -z "$(git ls-files -- validator validator-local validator-artifacts)"'`
  - `bash -c 'if git diff --name-only HEAD^..HEAD | grep -E "^(validator|validator-local|validator-artifacts)(/|$)"; then exit 1; fi'`
  - Review `validator-report.md`, `safe/tests/regressions/manifest.json`, and
    new `safe/tests/regressions/**` files for one regression per fixed source
    validator failure.

# Success Criteria

- All source API validator cases pass in safe mode.
- All added regression tests pass through `safe/scripts/run-regression-tests.sh --all`.
- ABI and package metadata checks still pass.

# Git Commit Requirement

The implementer must commit work to git before yielding. The commit subject must start with `impl_p04_fix_source_api_failures:`, and the implementer must force-update local tag `phase/impl_p04_fix_source_api_failures` to that phase commit before yielding.
