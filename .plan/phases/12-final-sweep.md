# Phase Name

Final safety, compatibility, and packaging sweep

# Implement Phase ID

`impl_p12_final_sweep`

# Preexisting Inputs

- Phase 11 committed tree and tag.
- Entire repository.
- `safe/tests/dependents/**`
- `safe/tests/regressions/**`
- `safe/scripts/run-regression-tests.sh`

# New Outputs

- Final documentation and cleanup updates.
- Passing full verification record.
- Updated `.plan/phases/*.md` and `.plan/workflow-structure.yaml` generated from this plan in inline-only linear form.

# File Changes

- `safe/docs/abi-map.md`
- `safe/docs/cve-matrix.md`
- `safe/docs/test-matrix.md`
- `safe/docs/bridge-inventory.md`
- `.plan/phases/*.md`
- `.plan/workflow-structure.yaml`
- Any small final cleanup files required by verification.

# Implementation Details

- Remove any remaining generated public-symbol stubs and any stale bridge references.
- Every remaining `unsafe` block must be necessary for C ABI, OS calls, allocation, or platform primitives, and must have a local safety reason if not obvious.
- Ensure documentation matches the final ownership state rather than old bridge-era notes.
- Ensure `test-original.sh` remains a stable compatibility entrypoint while delegating to committed image scripts.
- Rebuild dependent Docker images from committed phase 12 artifacts in the final checker; never accept an image tag that predates the phase 12 commit.
- Consume the committed phase 10 dependent image provenance locks exactly as written: pinned base image digest, fixed Noble snapshot sources, full apt/base package closure lock, local safe package policy lock, fixtures, compile probes, and scenario manifests. Phase 12 may update documentation or workflow files, but it must not refresh or reinterpret these locks.
- Do not change the safe package names, source package name, architecture policy, or Debian version recorded in `safe/tests/dependents/metadata/safe-debs.noble.lock`; final package rebuilds must prove current-commit local package provenance through `safe/dist/safe-debs.manifest.json`.
- Ensure the final workflow files generated from this plan obey the Generated Workflow Contract exactly: linear execution, inline-only YAML, explicit top-level check phases, single fixed `bounce_target` for each check, no top-level checks collection, no YAML-source indirection, verifier phases immediately after their implement phase, and concrete phase tag/parent checks.
- Preserve the consume-existing-artifacts contract by consuming committed source snapshots, CVE data, dependent inventory, test harnesses, imported tests, phase 10 dependent locks, fixtures, probes, and scenarios directly.

# Verification Phases

- Phase ID: `check_p12_final_full_compat`
- Type: `check`
- `bounce_target`: `impl_p12_final_sweep`
- Purpose: final full compatibility gate across source, link, runtime, packages, pinned Rust package-build toolchain, and dependent images.
- Commands:
  - `test "$(git rev-parse HEAD)" = "$(git rev-parse phase/impl_p12_final_sweep)"`
  - `test "$(git rev-parse HEAD^)" = "$(git rev-parse phase/impl_p11_dependent_regression_fixups)"`
  - `bash -c 'test -z "$(git status --short)"'`
  - `safe/scripts/check-rust-toolchain.sh`
  - `cargo fmt --manifest-path safe/Cargo.toml -- --check`
  - `cargo build --manifest-path safe/Cargo.toml --release --locked --offline`
  - `safe/scripts/check-no-upstream-bridge.sh`
  - `safe/scripts/check-abi.sh --all`
  - `safe/scripts/check-abi.sh --thread-cbs-noop`
  - `safe/scripts/import-upstream-tests.sh --verify`
  - `safe/scripts/run-original-tests.sh --verify-plumbing version t-secmem`
  - `safe/scripts/run-upstream-tests.sh --verify-plumbing`
  - `safe/scripts/run-upstream-tests.sh --all`
  - `safe/scripts/run-regression-tests.sh --all`
  - `safe/scripts/relink-original-objects.sh --all`
  - `safe/scripts/run-compat-smoke.sh --all`
  - `safe/scripts/build-debs.sh`
  - `safe/scripts/check-deb-metadata.sh --dist safe/dist`
  - `safe/scripts/check-installed-tools.sh --dist safe/dist`
  - `safe/scripts/check-dependent-metadata.sh`
  - `safe/scripts/build-dependent-image.sh --implementation original --tag libgcrypt-dependent:original`
  - `safe/scripts/run-dependent-image-tests.sh --implementation original --tag libgcrypt-dependent:original --compile-probes`
  - `safe/scripts/run-dependent-image-tests.sh --implementation original --tag libgcrypt-dependent:original --all`
  - `safe/scripts/build-dependent-image.sh --implementation safe --tag libgcrypt-dependent:safe`
  - `safe/scripts/run-dependent-image-tests.sh --implementation safe --tag libgcrypt-dependent:safe --compile-probes`
  - `safe/scripts/run-dependent-image-tests.sh --implementation safe --tag libgcrypt-dependent:safe --all`
  - `./test-original.sh --implementation original`
  - `./test-original.sh --implementation safe`

- Phase ID: `check_p12_final_safety_packaging`
- Type: `check`
- `bounce_target`: `impl_p12_final_sweep`
- Purpose: review unsafe Rust justification, committed artifact contracts, Debian drop-in properties, local safe package lock semantics, CVE matrix completeness, and workflow contract compliance.
- Commands:
  - `test "$(git rev-parse HEAD)" = "$(git rev-parse phase/impl_p12_final_sweep)"`
  - `test "$(git rev-parse HEAD^)" = "$(git rev-parse phase/impl_p11_dependent_regression_fixups)"`
  - `bash -c 'test -z "$(git status --short)"'`
  - `bash -c 'rg -n "unsafe" safe/src safe/cabi safe/build.rs || true'`
  - `bash -c 'if rg -n -g "!safe/scripts/check-no-upstream-bridge.sh" "SAFE_SYSTEM_LIBGCRYPT_PATH|dlopen|dlsym|rustc-link-lib=dl|(^|[^[:alnum:]_])-ldl([^[:alnum:]_]|$)|safe_gcry_stub_zero|Not implemented|todo!|unimplemented!" safe/src safe/cabi safe/build.rs safe/scripts safe/tests/compat safe/tests/dependents safe/tests/regressions safe/debian test-original.sh; then exit 1; fi'`
  - `git diff --stat HEAD^..HEAD`
  - Review `rust-toolchain.toml`, `safe/rust-toolchain.toml`, `safe/scripts/check-rust-toolchain.sh`, `safe/docs/cve-matrix.md`, `safe/docs/abi-map.md`, `safe/docs/test-matrix.md`, `dependents.json`, `safe/tests/dependents/metadata/matrix-manifest.json`, `safe/tests/dependents/metadata/base-image.noble.digest`, `safe/tests/dependents/metadata/ubuntu-snapshot.noble.sources`, `safe/tests/dependents/metadata/install-packages.noble.lock`, `safe/tests/dependents/metadata/safe-debs.noble.lock`, and `safe/tests/regressions/manifest.json`.

# Success Criteria

- No live upstream bridge, generated public-symbol stub, `todo!`, `unimplemented!`, or "Not implemented" public API references remain in the final scan set.
- All `GCRYPT_1.6` exports match `safe/abi/libgcrypt.vers`; there is no public ABI drift.
- Original upstream tests compile and run against safe headers and libraries, including the post-phase-12 `safe/scripts/run-original-tests.sh --verify-plumbing version t-secmem` plumbing check.
- `safe/scripts/run-regression-tests.sh --all` runs every committed phase 11 regression.
- Original upstream test objects relink against safe `libgcrypt.so.20` and pass.
- Safe Debian packages install as Ubuntu 24.04 drop-in replacements.
- Original and safe dependent images are built from the committed pinned base image digest and fixed Noble snapshot sources, verify the committed apt/base package closure lock and local safe package policy lock with `dpkg-query`, compile and run every committed dependent probe against the implementation-under-test development package, and run the same committed 15-row matrix including 12 executable application scenarios.
- The safe image loads the packaged safe library for every probe and scenario.
- The phase is a single child commit of `phase/impl_p11_dependent_regression_fixups` and leaves a clean worktree before tests.

# Git Commit Requirement

The implementer must commit work to git before yielding. End with one commit whose subject begins `impl_p12_final_sweep:` and whose first parent is `phase/impl_p11_dependent_regression_fixups`; force-update local tag `phase/impl_p12_final_sweep` to that commit before yielding.
