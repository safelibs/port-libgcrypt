# Phase Name

Dependent regression fixups and catch-all compatibility

# Implement Phase ID

`impl_p11_dependent_regression_fixups`

# Preexisting Inputs

- Phase 10 committed tree and tag.
- `safe/src/**`
- `safe/cabi/**`
- `safe/tests/dependents/**`
- `safe/scripts/check-no-upstream-bridge.sh`
- `safe/scripts/check-abi.sh`
- `safe/scripts/run-upstream-tests.sh`
- `safe/scripts/relink-original-objects.sh`
- `safe/scripts/build-debs.sh`
- `safe/scripts/check-dependent-metadata.sh`
- `safe/scripts/build-dependent-image.sh`
- `safe/scripts/run-dependent-image-tests.sh`
- `safe/tests/upstream/**`
- `safe/tests/compat/**`
- `safe/docs/abi-map.md`
- `safe/docs/cve-matrix.md`
- `safe/docs/test-matrix.md`
- `dependents.json`

# New Outputs

- Focused compatibility fixes for failures found by upstream tests, link tests, package tests, or dependent scenarios.
- Regression tests reproducing every fixed issue before applying the fix.
- Deterministic regression manifest and runner: `safe/tests/regressions/manifest.json` and `safe/scripts/run-regression-tests.sh --all`.
- Updated `safe/scripts/check-no-upstream-bridge.sh` scan set that includes `safe/tests/regressions/**`.
- Updated CVE/test/ABI documentation where fixes affect behavior or ownership.

# File Changes

- Any `safe/src/**` module needed for compatibility fixes.
- Any `safe/cabi/**` file needed for ABI/varargs fixes.
- `safe/tests/regressions/**`
- `safe/scripts/run-regression-tests.sh`
- `safe/scripts/check-no-upstream-bridge.sh`
- `safe/tests/compat/**`
- `safe/tests/dependents/**`
- `safe/scripts/**` only when harness behavior, not test results, was wrong.
- `safe/docs/abi-map.md`
- `safe/docs/cve-matrix.md`
- `safe/docs/test-matrix.md`

# Implementation Details

- Fix every remaining compatibility failure found by upstream tests, link tests, package tests, or dependent scenarios.
- For every failure, first add a narrow regression artifact that fails on the old behavior. The artifact may be an upstream-style C test, a C ABI probe, a Rust unit/integration test, or a dependent scenario fixture.
- Add each regression to a committed manifest under `safe/tests/regressions/` and wire it into `safe/scripts/run-regression-tests.sh --all`; this runner is the only phase 11 regression verifier entrypoint.
- Fix the underlying implementation without broad refactors unless required by the bug.
- Preserve public ABI and Debian packaging outputs.
- Do not weaken dependent checks or hide scenarios behind allowlists.
- Update `safe/scripts/check-no-upstream-bridge.sh` to scan tracked files under `safe/tests/regressions/**` after those files are committed.
- Rebuild the safe Debian packages and safe dependent image after applying fixes. Do not reuse Docker images or `safe/dist/` contents produced before the phase 11 commit.
- Consume the phase 10 committed base-image digest, Ubuntu snapshot source file, apt/base package closure lock, local safe package policy lock, fixtures, probes, and scenario manifests directly. Do not update package locks, re-resolve apt metadata, reinterpret local safe package policy, or fetch source packages in phase 11.
- Do not change the safe package names, source package name, architecture policy, or Debian version recorded in `safe/tests/dependents/metadata/safe-debs.noble.lock`; phase 11 may change package contents only by rebuilding local `.deb`s from the current phase commit and recording that rebuild in `safe/dist/safe-debs.manifest.json`.
- Preserve the consume-existing-artifacts contract by consuming phase 10 dependent metadata, locks, fixtures, probes, and scenarios in place.

# Verification Phases

- Phase ID: `check_p11_regression_tester`
- Type: `check`
- `bounce_target`: `impl_p11_dependent_regression_fixups`
- Purpose: verify every regression added in phase 11 and the full dependent application matrix.
- Commands:
  - `test "$(git rev-parse HEAD)" = "$(git rev-parse phase/impl_p11_dependent_regression_fixups)"`
  - `test "$(git rev-parse HEAD^)" = "$(git rev-parse phase/impl_p10_dependent_image_matrix)"`
  - `bash -c 'test -z "$(git status --short)"'`
  - `safe/scripts/check-rust-toolchain.sh`
  - `cargo build --manifest-path safe/Cargo.toml --release --locked --offline`
  - `safe/scripts/run-regression-tests.sh --all`
  - `safe/scripts/check-no-upstream-bridge.sh`
  - `safe/scripts/run-upstream-tests.sh --all`
  - `safe/scripts/relink-original-objects.sh --all`
  - `safe/scripts/build-debs.sh`
  - `safe/scripts/build-dependent-image.sh --implementation safe --tag libgcrypt-dependent:safe`
  - `safe/scripts/run-dependent-image-tests.sh --implementation safe --tag libgcrypt-dependent:safe --compile-probes`
  - `safe/scripts/run-dependent-image-tests.sh --implementation safe --tag libgcrypt-dependent:safe --all`

- Phase ID: `check_p11_senior_tester`
- Type: `check`
- `bounce_target`: `impl_p11_dependent_regression_fixups`
- Purpose: review fixes for minimality, memory safety, ABI preservation, and no regression masking.
- Commands:
  - `test "$(git rev-parse HEAD)" = "$(git rev-parse phase/impl_p11_dependent_regression_fixups)"`
  - `test "$(git rev-parse HEAD^)" = "$(git rev-parse phase/impl_p10_dependent_image_matrix)"`
  - `bash -c 'test -z "$(git status --short)"'`
  - `git diff --stat HEAD^..HEAD`
  - `safe/scripts/run-regression-tests.sh --all`
  - `safe/scripts/check-no-upstream-bridge.sh`
  - `safe/scripts/check-abi.sh --all`
  - `safe/scripts/check-dependent-metadata.sh`
  - `safe/scripts/build-dependent-image.sh --implementation original --tag libgcrypt-dependent:original`
  - `safe/scripts/run-dependent-image-tests.sh --implementation original --tag libgcrypt-dependent:original --compile-probes`
  - `safe/scripts/run-dependent-image-tests.sh --implementation original --tag libgcrypt-dependent:original --all`
  - `safe/scripts/check-rust-toolchain.sh`
  - `safe/scripts/build-debs.sh`
  - `safe/scripts/build-dependent-image.sh --implementation safe --tag libgcrypt-dependent:safe`
  - `safe/scripts/run-dependent-image-tests.sh --implementation safe --tag libgcrypt-dependent:safe --compile-probes`
  - `safe/scripts/run-dependent-image-tests.sh --implementation safe --tag libgcrypt-dependent:safe --all`

# Success Criteria

- Every remaining compatibility failure has a committed regression artifact listed in `safe/tests/regressions/manifest.json` and run through `safe/scripts/run-regression-tests.sh --all`.
- The bridge scanner includes `safe/tests/regressions/**`.
- Dependent metadata and package locks from phase 10 are consumed exactly as committed, with no re-resolution, lock updates, or runtime source package fetches.
- Safe packages and safe dependent image are rebuilt from the phase 11 commit, not reused from earlier work.
- The phase is a single child commit of `phase/impl_p10_dependent_image_matrix` and leaves a clean worktree before tests.

# Git Commit Requirement

The implementer must commit work to git before yielding. End with one commit whose subject begins `impl_p11_dependent_regression_fixups:` and whose first parent is `phase/impl_p10_dependent_image_matrix`; force-update local tag `phase/impl_p11_dependent_regression_fixups` to that commit before yielding.
