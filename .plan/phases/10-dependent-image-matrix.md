# Phase Name

Dependent application image and 12-scenario matrix

# Implement Phase ID

`impl_p10_dependent_image_matrix`

# Preexisting Inputs

- Phase 9 committed tree and tag.
- `dependents.json` with the current 8 baseline dependents.
- `test-original.sh`
- `safe/tests/compat/tool-fixtures/`
- `safe/scripts/check-no-upstream-bridge.sh`
- `safe/docs/test-matrix.md`
- Phase 9 committed package sources under `safe/debian/`.
- Phase 9 package scripts: `safe/scripts/check-rust-toolchain.sh`, `safe/scripts/build-debs.sh`, `safe/scripts/check-deb-metadata.sh`, and `safe/scripts/check-installed-tools.sh`.
- Phase 9 per-build local package provenance output `safe/dist/safe-debs.manifest.json`, produced fresh by `safe/scripts/build-debs.sh` in the same invocation that constructs the safe image.
- Ubuntu 24.04 package metadata available during this phase only for producing committed locks.

# New Outputs

- Extended `dependents.json` with 15 rows and 15 unique `binary_package` values.
- Committed package evidence and package locks:
  - `safe/tests/dependents/metadata/matrix-manifest.json`
  - `safe/tests/dependents/metadata/package-evidence.noble.json`
  - `safe/tests/dependents/metadata/base-image.noble.digest`
  - `safe/tests/dependents/metadata/ubuntu-snapshot.noble.sources`
  - `safe/tests/dependents/metadata/install-packages.noble.lock`
  - `safe/tests/dependents/metadata/safe-debs.noble.lock`
- Committed dependent fixtures:
  - `safe/tests/dependents/fixtures/gpgv/`
  - `safe/tests/dependents/fixtures/gpgsm/`
  - `safe/tests/dependents/fixtures/seccure/`
  - `safe/tests/dependents/fixtures/pdfgrep/`
  - `safe/tests/dependents/fixtures/rngtest/`
  - `safe/tests/dependents/fixtures/otr/`
  - `safe/tests/dependents/fixtures/tcplay/`
  - Migrated `aircrack-ng`, `wireshark`, and `xmlsec1` fixtures currently fetched by source package at runtime.
- Committed scenario and probe sources:
  - `safe/tests/dependents/probes/apt-hashes-test.cpp`
  - `safe/tests/dependents/probes/libssh-test.c`
  - `safe/tests/dependents/probes/xmlsec-gcrypt-verify-rsa.c`
  - `safe/tests/dependents/scenarios/*.sh`
- Image scripts:
  - `safe/scripts/check-dependent-metadata.sh`
  - `safe/scripts/build-dependent-image.sh`
  - `safe/scripts/run-dependent-image-tests.sh`
- Rewritten `test-original.sh` as a compatibility wrapper around the new image scripts.
- Updated `safe/scripts/check-no-upstream-bridge.sh` scan set that includes committed downstream metadata, fixtures, probes, and scenarios under `safe/tests/dependents/**`.

# File Changes

- `dependents.json`
- `test-original.sh`
- `safe/tests/dependents/**`
- `safe/scripts/check-dependent-metadata.sh`
- `safe/scripts/build-dependent-image.sh`
- `safe/scripts/run-dependent-image-tests.sh`
- `safe/scripts/check-no-upstream-bridge.sh`
- `safe/docs/test-matrix.md`

# Implementation Details

- Preserve the current 8 baseline package identities:
  - `libapt-pkg6.0t64`
  - `gpg`
  - `gnome-keyring`
  - `libssh-gcrypt-4`
  - `libxmlsec1t64-gcrypt`
  - `munge`
  - `aircrack-ng`
  - `wireshark-common`
- Retain exactly 3 library-flavored exceptions: `libapt-pkg6.0t64`, `libssh-gcrypt-4`, and `libxmlsec1t64-gcrypt`.
- Add 7 executable application packages with exact scenario requirements:
  - `gpgv`: verify a committed detached OpenPGP signature with a committed trusted keyring.
  - `gpgsm`: import committed X.509 test material, sign/verify and encrypt/decrypt a committed message in a temporary homedir.
  - `seccure`: run `seccure-key`, `seccure-encrypt`, `seccure-decrypt`, `seccure-sign`, and `seccure-verify` using committed passphrase/message fixtures.
  - `pdfgrep`: search a committed password-protected PDF fixture using `pdfgrep --password`.
  - `rng-tools5`: run `rngtest -c` against a committed known-good random fixture and validate expected statistics.
  - `libotr5-bin`: run `otr_mackey` and at least one transcript/key derivation probe from committed fixtures.
  - `tcplay`: run `tcplay --info --device` against a committed small TrueCrypt-compatible fixture and validate PBKDF/cipher metadata without requiring device-mapper mapping.
- Across the 15 rows, the 3 retained library exceptions plus 12 executable application rows must be explicit in `matrix-manifest.json`.
- Build every dependent image from a pinned `ubuntu:24.04@sha256:<digest>` base image recorded in `safe/tests/dependents/metadata/base-image.noble.digest`. Pulling or building from mutable `ubuntu:24.04` without the committed digest is forbidden.
- Replace the image's default apt sources before installation with the committed fixed Noble snapshot source file at `safe/tests/dependents/metadata/ubuntu-snapshot.noble.sources`. The image build must not use mutable `archive.ubuntu.com`, `security.ubuntu.com`, or unpinned mirror sources.
- Install target packages using exact `package=epoch:version` or `package=version` entries from `install-packages.noble.lock`. That lock must cover the full apt package closure for base-image and Ubuntu snapshot packages, including requested dependent packages, development packages used by compile probes, the original image's Ubuntu `libgcrypt20` and `libgcrypt20-dev` packages, and transitive dependencies. It must not model local safe `.deb` packages as Ubuntu snapshot entries.
- `install-packages.noble.lock` must distinguish `origin: base-image`, `origin: ubuntu-snapshot`, and `implementation: both|original` entries. Base-image entries must record the pinned base image digest they came from. Ubuntu snapshot entries must record package name, architecture, binary version, source package, source version, and snapshot source file identity.
- `safe-debs.noble.lock` must contain exactly two `origin: local-safe-deb`, `implementation: safe` policy entries: `libgcrypt20` and `libgcrypt20-dev`. Each entry must record expected package name, architecture, source package, exact Debian version from phase 10 `safe/debian/changelog`, required file glob under `safe/dist/`, and required metadata fields to compare against `safe/dist/safe-debs.manifest.json`. It must not contain a committed `.deb` SHA256 because later phases rebuild safe packages from their own phase commits.
- `safe/scripts/build-debs.sh` must produce `safe/dist/safe-debs.manifest.json` in the same invocation that produces the safe `.deb` files. The manifest must record each safe `.deb` filename, SHA256, package name, architecture, version, source package, source version, phase commit, phase tag when present, and pinned Rust toolchain output. `safe/scripts/build-dependent-image.sh --implementation safe` must fail if this manifest is absent, stale relative to the selected phase commit, or inconsistent with the `.deb` files it installs.
- The image build must run `dpkg-query` before tests and verify every installed package name, architecture, binary version, source package, and source version. Original images validate all packages against `install-packages.noble.lock`. Safe images validate all non-libgcrypt packages against `install-packages.noble.lock`, validate `libgcrypt20` and `libgcrypt20-dev` against `safe-debs.noble.lock` plus the just-built `safe/dist/safe-debs.manifest.json`, and fail if Ubuntu snapshot `libgcrypt20` remains installed after local package replacement.
- Extra apt packages not present in `install-packages.noble.lock` are failures unless they are part of the pinned base image digest and recorded as `origin: base-image` entries. Extra local `.deb` packages in the safe image are failures unless explicitly listed in `safe-debs.noble.lock`.
- `safe/scripts/check-dependent-metadata.sh` must validate the 15-row manifest, the preserved 8 baseline identities, the 3 library-flavored exceptions, the 12 executable scenario rows, the base-image digest file, the fixed Noble snapshot sources file, the full apt/base package closure lock, the local safe package metadata policy lock, and the existence of every fixture, probe source, and scenario path referenced by the manifest.
- The safe image path must always build packages from phase 9 committed package sources by running `safe/scripts/check-rust-toolchain.sh` and `safe/scripts/build-debs.sh` before constructing the safe image. It must not compile Rust inside the dependent runtime image, must not install a Rust toolchain in that image, and must not assume that an untracked `safe/dist/` directory from a previous verifier is still present.
- `safe/scripts/build-dependent-image.sh --implementation safe` must consume only the `safe/dist/*.deb` files and `safe/dist/safe-debs.manifest.json` produced in the same checker or implementer invocation.
- Move the existing inline compile probes from `test-original.sh` into the committed probe sources listed above. `safe/scripts/run-dependent-image-tests.sh --compile-probes` must compile every committed probe inside the image against the implementation-under-test development package and metadata, run the resulting binaries, and verify each binary loads the expected `libgcrypt.so.20` realpath for that implementation.
- The required compile probes are `apt-hashes-test.cpp` for `libapt-pkg6.0t64`, `libssh-test.c` for `libssh-gcrypt-4`, and `xmlsec-gcrypt-verify-rsa.c` for `libxmlsec1t64-gcrypt`. These probes preserve the current `test-original.sh` source-compatibility obligations for the 3 retained library-flavored dependents.
- `safe/scripts/run-dependent-image-tests.sh --all` must run `--compile-probes` first and then run every committed executable scenario script. It must fail if any compiled probe or scenario does not load `libgcrypt.so.20`, or if the loaded library realpath does not point to the selected implementation under test.
- Runtime scenarios must assert the loaded `libgcrypt.so.20` realpath points to the implementation under test.
- Update `safe/scripts/check-no-upstream-bridge.sh` to scan tracked files under `safe/tests/dependents/**` after those files are committed, in addition to the existing source, script, compatibility, Debian, and top-level wrapper paths.
- Remove runtime `apt-get source` from `test-original.sh`; fixture extraction must happen only in this phase and be committed.
- Rework `test-original.sh` into a thin compatibility wrapper that delegates to the committed image scripts, preserves `--implementation original|safe`, and runs the same compile probes plus executable scenarios as `run-dependent-image-tests.sh --all`.
- Preserve the consume-existing-artifacts contract: phase 10 is the only phase that may produce the committed dependent metadata, locks, base-image digest, Ubuntu snapshot source configuration, fixtures, probes, and image scripts. Later phases must consume these committed artifacts directly and must not run `apt-get source`, re-query package metadata, resolve floating package versions, pull unpinned base images, use mutable apt sources, or generate fixtures at test runtime.

# Verification Phases

- Phase ID: `check_p10_dependent_matrix_tester`
- Type: `check`
- `bounce_target`: `impl_p10_dependent_image_matrix`
- Purpose: verify dependent metadata, original baseline image, safe image, application scenario commands, compile probes, package-version locks, local safe package provenance, and image provenance locks.
- Commands:
  - `test "$(git rev-parse HEAD)" = "$(git rev-parse phase/impl_p10_dependent_image_matrix)"`
  - `test "$(git rev-parse HEAD^)" = "$(git rev-parse phase/impl_p09_debian_dropin_package)"`
  - `bash -c 'test -z "$(git status --short)"'`
  - `safe/scripts/check-dependent-metadata.sh`
  - `safe/scripts/check-no-upstream-bridge.sh`
  - `safe/scripts/build-dependent-image.sh --implementation original --tag libgcrypt-dependent:original`
  - `safe/scripts/run-dependent-image-tests.sh --implementation original --tag libgcrypt-dependent:original --compile-probes`
  - `safe/scripts/run-dependent-image-tests.sh --implementation original --tag libgcrypt-dependent:original --all`
  - `safe/scripts/check-rust-toolchain.sh`
  - `safe/scripts/build-debs.sh`
  - `safe/scripts/build-dependent-image.sh --implementation safe --tag libgcrypt-dependent:safe`
  - `safe/scripts/run-dependent-image-tests.sh --implementation safe --tag libgcrypt-dependent:safe --compile-probes`
  - `safe/scripts/run-dependent-image-tests.sh --implementation safe --tag libgcrypt-dependent:safe --all`

- Phase ID: `check_p10_dependent_matrix_senior`
- Type: `check`
- `bounce_target`: `impl_p10_dependent_image_matrix`
- Purpose: review matrix breadth, consume-existing-artifacts contract, Docker reproducibility, fixture provenance, local safe package provenance, and source/link/runtime coverage.
- Commands:
  - `test "$(git rev-parse HEAD)" = "$(git rev-parse phase/impl_p10_dependent_image_matrix)"`
  - `test "$(git rev-parse HEAD^)" = "$(git rev-parse phase/impl_p09_debian_dropin_package)"`
  - `bash -c 'test -z "$(git status --short)"'`
  - Review `dependents.json`, `safe/tests/dependents/metadata/matrix-manifest.json`, `safe/tests/dependents/metadata/base-image.noble.digest`, `safe/tests/dependents/metadata/ubuntu-snapshot.noble.sources`, `safe/tests/dependents/metadata/install-packages.noble.lock`, `safe/tests/dependents/metadata/safe-debs.noble.lock`, `safe/tests/dependents/probes/*.c`, `safe/tests/dependents/probes/*.cpp`, and `safe/tests/dependents/scenarios/*.sh`.
  - `safe/scripts/check-dependent-metadata.sh`
  - `safe/scripts/check-no-upstream-bridge.sh`
  - `safe/scripts/build-dependent-image.sh --implementation original --tag libgcrypt-dependent:original`
  - `safe/scripts/run-dependent-image-tests.sh --implementation original --tag libgcrypt-dependent:original --compile-probes`
  - `safe/scripts/run-dependent-image-tests.sh --implementation original --tag libgcrypt-dependent:original --all`
  - `safe/scripts/check-rust-toolchain.sh`
  - `safe/scripts/build-debs.sh`
  - `safe/scripts/build-dependent-image.sh --implementation safe --tag libgcrypt-dependent:safe`
  - `safe/scripts/run-dependent-image-tests.sh --implementation safe --tag libgcrypt-dependent:safe --compile-probes`
  - `safe/scripts/run-dependent-image-tests.sh --implementation safe --tag libgcrypt-dependent:safe --all`

# Success Criteria

- `dependents.json` and `matrix-manifest.json` contain 15 rows with 15 unique `binary_package` values, including the preserved 8 baseline identities, exactly 3 library-flavored exceptions, and 12 executable application rows.
- All dependent images use the committed pinned base image digest and fixed Noble snapshot sources, never mutable image tags or mutable apt mirrors.
- Package locks have the required semantics: `install-packages.noble.lock` covers base-image and Ubuntu snapshot packages; `safe-debs.noble.lock` contains only the two local safe package policy entries and validates against a fresh `safe/dist/safe-debs.manifest.json`.
- `dpkg-query` validation checks every installed package name, architecture, binary version, source package, and source version, with original and safe images validating libgcrypt packages against their respective locks.
- Compile probes and scenarios verify the loaded `libgcrypt.so.20` realpath points to the selected implementation under test.
- `test-original.sh` is a thin wrapper over committed image scripts, preserves `--implementation original|safe`, and runs the same compile probes plus executable scenarios as `run-dependent-image-tests.sh --all`.
- No runtime `apt-get source`, floating apt resolution, unpinned base images, mutable apt sources, or runtime fixture generation remain.
- The phase is a single child commit of `phase/impl_p09_debian_dropin_package` and leaves a clean worktree before tests.

# Git Commit Requirement

The implementer must commit work to git before yielding. End with one commit whose subject begins `impl_p10_dependent_image_matrix:` and whose first parent is `phase/impl_p09_debian_dropin_package`; force-update local tag `phase/impl_p10_dependent_image_matrix` to that commit before yielding.
