# Phase Name

Catch-all remaining validator failures and safety review

# Implement Phase ID

`impl_p07_fix_remaining_validator_failures`

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
- Phase 6 commit and report.
- Validator wrapper and port evidence checker from phase 1.
- `safe/scripts/validator-libgcrypt-skips.json`.
- All full-run safe candidate failures still listed in `validator-report.md`.
- All existing safe source, package, scripts, and tests.

# New Outputs

- Fixes for any remaining validator failures not covered by phases 3-6.
- Regressions for remaining safe-side failures.
- Updated `validator-report.md` with no unresolved safe-side failures.

# File Changes

- Any safe-side file required by remaining failures:
  - `safe/src/**`
  - `safe/abi/**`
  - `safe/cabi/**`
  - `safe/debian/**`
  - `safe/scripts/**`
  - `safe/tests/regressions/**`
- `safe/scripts/validator-libgcrypt-skips.json` for exact
  validator-commit-specific testcase skips of clearly identified validator
  defects.
- `safe/tests/regressions/manifest.json`
- `validator-report.md`

# Implementation Details

## Workflow-Wide Requirements For This Phase

- Consume the listed preexisting inputs in place. Existing source snapshots, metadata, tests, packages, validator checkouts, and prior artifacts are inputs, not rediscovery or regeneration tasks unless this phase explicitly rebuilds generated package/validator artifacts.
- Keep `validator/`, `validator-local/`, and `validator-artifacts/` external to the port repository. Do not commit nested validator contents or generated validator artifacts.
- Preserve the Rust toolchain contract: root `rust-toolchain.toml` and `safe/rust-toolchain.toml` must stay identical and pinned to Rust `1.85.1` with `profile = "minimal"` and `components = ["rustfmt"]`.
- Run `safe/scripts/check-rust-toolchain.sh` before every Cargo, release-library, Debian package, or dependent safe-image build.
- Build any package artifacts used as validator inputs from a clean phase commit after `phase/impl_p07_fix_remaining_validator_failures` points at `HEAD`. If tracked files or `validator-report.md` change after validation, amend the same phase commit, force-update the phase tag, rebuild packages, regenerate `validator-local`, and rerun the phase validator commands until the worktree is clean and artifacts match the final phase commit.
- `validator-report.md` must identify the safe port by implement phase ID and `phase/impl_p07_fix_remaining_validator_failures`, not by embedding the literal hash of the final report commit.

## Phase-Specific Details

- Rerun the full safe validator suite and inspect every remaining failure.
  Reject the run before triage if the port artifact root lacks complete
  override-install evidence for the local safe packages.
- If the failure is a safe compatibility problem, add a minimal regression,
  fix the underlying safe module, and rerun the relevant subset.
- If the failure is package installation or development metadata:
  - Inspect `safe/debian/control`, `safe/debian/rules`,
    `safe/debian/libgcrypt20.install`, `safe/debian/libgcrypt20-dev.install`,
    `safe/abi/libgcrypt.pc.in`, `safe/abi/libgcrypt-config.in`, and
    `safe/build.rs`.
  - Keep package names and versions compatible with the existing safe package
    contract.
  - Do not change validator override install scripts.
- If the failure is a validator bug:
  - Document the exact evidence in `validator-report.md`.
  - If it is a testcase execution bug, skip only that testcase through the
    port-owned `safe/scripts/validator-libgcrypt-skips.json` entry consumed by
    the wrapper.
  - Require testcase skip entries to name the current validator commit and fail
    closed on every other commit.
  - If it is a proof or inventory bug rather than a testcase execution bug,
    document the skipped proof or inventory check in `validator-report.md` and
    keep all testcase execution unchanged.
  - Keep the validator checkout unmodified.
- Verify the report no longer lists unresolved safe-side failures before
  committing.
- Commit fixes and report updates. End with one commit whose subject begins
  `impl_p07_fix_remaining_validator_failures:` and tag it
  `phase/impl_p07_fix_remaining_validator_failures`.

# Verification Phases

- Phase ID: `check_p07_remaining_failures_software_tester`
- Type: `check`
- Fixed `bounce_target`: `impl_p07_fix_remaining_validator_failures`
- Purpose: rerun the full safe validator suite and verify that all remaining
  non-skipped failures have safe-side regressions and fixes.
- Commands:
  - `test "$(git rev-parse HEAD)" = "$(git rev-parse phase/impl_p07_fix_remaining_validator_failures)"`
  - `test "$(git rev-parse HEAD^)" = "$(git rev-parse phase/impl_p06_fix_gpg_pubkey_keyring)"`
  - `bash -c 'test -z "$(git status --short)"'`
  - `bash -c 'git check-ignore -q validator/ && git check-ignore -q validator-local/ && git check-ignore -q validator-artifacts/'`
  - `bash -c 'test -z "$(git ls-files -- validator validator-local validator-artifacts)"'`
  - `safe/scripts/check-rust-toolchain.sh`
  - `safe/scripts/check-dependent-metadata.sh`
  - `cargo fmt --manifest-path safe/Cargo.toml -- --check`
  - `cargo build --manifest-path safe/Cargo.toml --release --locked --offline`
  - `safe/scripts/build-release-lib.sh`
  - `safe/scripts/check-no-upstream-bridge.sh`
  - `safe/scripts/check-abi.sh --all`
  - `safe/scripts/run-upstream-tests.sh --all`
  - `safe/scripts/run-regression-tests.sh --all`
  - `safe/scripts/run-compat-smoke.sh --all`
  - `safe/scripts/build-debs.sh`
  - `safe/scripts/check-deb-metadata.sh --dist safe/dist`
  - `python3 safe/scripts/prepare-validator-local-port.py --validator-dir validator --dist safe/dist --output-root validator-local`
  - `bash safe/scripts/run-validator-libgcrypt.sh --validator-dir validator --mode port --artifact-root validator-artifacts/p07-port-full --override-root validator-local/override-debs --port-lock validator-local/proof/local-port-debs-lock.json --record-casts`
  - `python3 safe/scripts/check-validator-port-evidence.py --port-lock validator-local/proof/local-port-debs-lock.json --override-root validator-local/override-debs --artifact-root validator-artifacts/p07-port-full`

- Phase ID: `check_p07_remaining_failures_senior_tester`
- Type: `check`
- Fixed `bounce_target`: `impl_p07_fix_remaining_validator_failures`
- Purpose: senior review for safety, packaging, validator bug skips, artifact
  contracts, and no validator-suite modifications.
- Commands:
  - `test "$(git rev-parse HEAD)" = "$(git rev-parse phase/impl_p07_fix_remaining_validator_failures)"`
  - `test "$(git rev-parse HEAD^)" = "$(git rev-parse phase/impl_p06_fix_gpg_pubkey_keyring)"`
  - `bash -c 'test -z "$(git status --short)"'`
  - `bash -c 'git check-ignore -q validator/ && git check-ignore -q validator-local/ && git check-ignore -q validator-artifacts/'`
  - `git diff --stat HEAD^..HEAD`
  - `bash -c 'test -z "$(git ls-files -- validator validator-local validator-artifacts)"'`
  - `bash -c 'if git diff --name-only HEAD^..HEAD | grep -E "^(validator|validator-local|validator-artifacts)(/|$)"; then exit 1; fi'`
  - `safe/scripts/check-no-upstream-bridge.sh`
  - `bash -c 'rg -n "safe_gcry_stub_zero|todo!|unimplemented!|Not implemented" safe/src safe/cabi safe/build.rs safe/scripts safe/tests/regressions safe/debian test-original.sh && exit 1 || true'`
  - `bash -c 'rg -n "skip|validator bug|unsupported libgcrypt" validator-report.md || true'`
  - Review `validator-report.md` to ensure every skip names a validator
    defect, affected check, and justification.

# Success Criteria

- Full safe validator run passes except for explicitly documented validator
  bug skips, and every non-skipped port result proves installation of the local
  safe override packages.
- Existing safe build, ABI, upstream, compatibility, and regression checks pass.
- No validator files were modified.

# Git Commit Requirement

The implementer must commit work to git before yielding. The commit subject must start with `impl_p07_fix_remaining_validator_failures:`, and the implementer must force-update local tag `phase/impl_p07_fix_remaining_validator_failures` to that phase commit before yielding.
