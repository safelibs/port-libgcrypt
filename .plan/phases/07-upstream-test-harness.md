# Phase Name

Imported upstream test harness stabilization

# Implement Phase ID

`impl_p07_upstream_test_harness`

# Preexisting Inputs

- Phase 6 committed tree and tag.
- `safe/tests/upstream/`
- `safe/tests/compat/`
- `safe/tests/original-build/`
- `safe/scripts/import-upstream-tests.sh`
- `safe/scripts/run-upstream-tests.sh`
- `original/libgcrypt20-1.10.3/tests/`
- `original/libgcrypt20-1.10.3/compat/`

# New Outputs

- Reconciled committed upstream/compat test tree.
- Updated `safe/docs/test-matrix.md` mapping every upstream test/helper to implementation phase ownership and verification command.
- Stable long-test and plumbing options in `safe/scripts/run-upstream-tests.sh`.

# File Changes

- `safe/tests/upstream/**`
- `safe/tests/compat/**`
- `safe/tests/original-build/**`
- `safe/scripts/import-upstream-tests.sh`
- `safe/scripts/run-upstream-tests.sh`
- `safe/docs/test-matrix.md`

# Implementation Details

- Consume the existing committed `safe/tests/upstream/` and `safe/tests/compat/` trees. Do not create alternate import directories.
- Use `safe/scripts/import-upstream-tests.sh` to reconcile drift from `original/libgcrypt20-1.10.3/tests/` and `compat/`.
- Preserve local compatibility probes and fixtures in `safe/tests/compat/` that are not upstream imports.
- Ensure helpers such as `testdrv`, `fipsdrv`, `rsacvt`, `genhashdata`, `gchash`, and `pkbench` build from committed inputs.
- Keep `safe/scripts/run-upstream-tests.sh --verify-plumbing` and `safe/scripts/run-upstream-tests.sh --all` usable as separate deterministic invocations. If the script accepts both options together, `--verify-plumbing` must not suppress the full-suite run requested by `--all`.
- Preserve the consume-existing-artifacts contract by reconciling existing imported tests and compatibility fixtures in place rather than reimporting into alternate locations.

# Verification Phases

- Phase ID: `check_p07_upstream_test_harness`
- Type: `check`
- `bounce_target`: `impl_p07_upstream_test_harness`
- Purpose: verify committed upstream test imports, helper build rules, long-test switches, and test matrix documentation.
- Commands:
  - `test "$(git rev-parse HEAD)" = "$(git rev-parse phase/impl_p07_upstream_test_harness)"`
  - `test "$(git rev-parse HEAD^)" = "$(git rev-parse phase/impl_p06_pubkey_ecc_no_bridge)"`
  - `bash -c 'test -z "$(git status --short)"'`
  - `safe/scripts/import-upstream-tests.sh --verify`
  - `safe/scripts/check-rust-toolchain.sh`
  - `cargo build --manifest-path safe/Cargo.toml --release --locked --offline`
  - `safe/scripts/run-upstream-tests.sh --verify-plumbing`
  - `safe/scripts/run-upstream-tests.sh --all`

# Success Criteria

- Imported upstream and compatibility tests are committed, reconciled in place, and documented.
- Helper binaries build from committed inputs.
- `--verify-plumbing` and `--all` both remain deterministic, and `--verify-plumbing` does not suppress a requested `--all` full-suite run.
- The phase is a single child commit of `phase/impl_p06_pubkey_ecc_no_bridge` and leaves a clean worktree before tests.

# Git Commit Requirement

The implementer must commit work to git before yielding. End with one commit whose subject begins `impl_p07_upstream_test_harness:` and whose first parent is `phase/impl_p06_pubkey_ecc_no_bridge`; force-update local tag `phase/impl_p07_upstream_test_harness` to that commit before yielding.
