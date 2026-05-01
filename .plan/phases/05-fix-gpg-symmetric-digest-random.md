# Phase Name

Fix GPG symmetric, digest, and random usage failures

# Implement Phase ID

`impl_p05_fix_gpg_symmetric_digest_random`

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
- Phase 4 source API fixes and report.
- Validator wrapper and port evidence checker from phase 1.
- `safe/scripts/validator-libgcrypt-skips.json`.
- Validator usage failures in the
  `usage-symmetric-digest-random` bucket from `validator-report.md`.
- Existing safe modules:
  - `safe/src/cipher/*.rs`
  - `safe/src/digest/*.rs`
  - `safe/src/mac.rs`
  - `safe/src/kdf.rs`
  - `safe/src/random.rs`
  - `safe/src/drbg.rs`
  - `safe/src/os_rng.rs`
  - `safe/src/global.rs`
  - `safe/src/sexp.rs`

# New Outputs

- Safe-side fixes for GPG digest, random, symmetric encryption, S2K/KDF, and
  related packet behavior failures.
- Regression tests for each fixed validator usage failure in this bucket.
- Updated `validator-report.md`.
- If the phase 2 baseline inventory plus phase 4 source outcome contains no
  unresolved failures in the `usage-symmetric-digest-random` bucket, no safe
  code or regression test changes are required; the phase still reruns the
  focused bucket subsets with
  port override evidence, updates `validator-report.md` to mark the bucket
  clean with no fixes needed, and creates the required phase commit and tag.

# File Changes

- `safe/src/cipher/*.rs`
- `safe/src/digest/*.rs`
- `safe/src/mac.rs`
- `safe/src/kdf.rs`
- `safe/src/random.rs`
- `safe/src/drbg.rs`
- `safe/src/os_rng.rs`
- `safe/src/global.rs`
- `safe/src/sexp.rs` only if packet/S-expression behavior depends on it.
- `safe/tests/regressions/manifest.json`
- `safe/tests/regressions/**`
- `safe/scripts/validator-libgcrypt-skips.json` only for a clearly identified
  validator bug in this bucket, with an exact validator-commit-specific skip.
- `safe/scripts/run-validator-libgcrypt.sh` only if the phase exposes a bug in
  the existing skip matching or result-writing behavior.
- `validator-report.md`

# Implementation Details

## Workflow-Wide Requirements For This Phase

- Consume the listed preexisting inputs in place. Existing source snapshots, metadata, tests, packages, validator checkouts, and prior artifacts are inputs, not rediscovery or regeneration tasks unless this phase explicitly rebuilds generated package/validator artifacts.
- Keep `validator/`, `validator-local/`, and `validator-artifacts/` external to the port repository. Do not commit nested validator contents or generated validator artifacts.
- Preserve the Rust toolchain contract: root `rust-toolchain.toml` and `safe/rust-toolchain.toml` must stay identical and pinned to Rust `1.85.1` with `profile = "minimal"` and `components = ["rustfmt"]`.
- Run `safe/scripts/check-rust-toolchain.sh` before every Cargo, release-library, Debian package, or dependent safe-image build.
- Build any package artifacts used as validator inputs from a clean phase commit after `phase/impl_p05_fix_gpg_symmetric_digest_random` points at `HEAD`. If tracked files or `validator-report.md` change after validation, amend the same phase commit, force-update the phase tag, rebuild packages, regenerate `validator-local`, and rerun the phase validator commands until the worktree is clean and artifacts match the final phase commit.
- `validator-report.md` must identify the safe port by implement phase ID and `phase/impl_p05_fix_gpg_symmetric_digest_random`, not by embedding the literal hash of the final report commit.

## Phase-Specific Details

- Use the failure inventory from phase 2 and any relevant phase 4 leftovers.
  Do not rediscover from scratch except by rerunning the focused validator
  subsets.
- If the inventory has zero unresolved failures for this bucket, do not invent a
  regression or safe-side change. Rerun every focused phase 5 validator subset
  listed below in port mode with override evidence, update
  `validator-report.md` with the clean bucket result and artifact roots, and
  make the required `impl_p05_fix_gpg_symmetric_digest_random:` phase commit.
  If the report was already exact and no tracked file changed, create the phase
  commit with `git commit --allow-empty` before tagging it.
- Add one minimal regression per validator failure before fixing it. Regression
  tests may drive `gpg` against installed safe packages only when a reduced C
  probe cannot reproduce the defect.
- For digest failures, compare libgcrypt algorithm names, aliases, digest
  lengths, HMAC behavior, and known answer prefixes against original behavior.
- For symmetric failures, focus on AES128/192/256, 3DES, Blowfish, CAST5,
  Camellia, Twofish, stream/block mode state resets, IV/CTR handling, padding
  expectations, and error codes used by GPG.
- For random failures, preserve `gcry_check_version(NULL)` before first use,
  RNG initialization state, `gcry_create_nonce`, `gcry_randomize`,
  `gcry_random_bytes`, `GCRY_WEAK_RANDOM`, `GCRY_STRONG_RANDOM`, and zero-byte
  requests.
- For S2K/KDF failures, inspect `safe/src/kdf.rs` and GPG usage around salted
  and iterated modes. Match libgcrypt error codes where GPG branches on them.
- Focused validator coverage for this phase must include all current
  digest/random/symmetric and packet/preference case families:
  `usage-gpg-print-md`, `usage-gpg-print-md-*`,
  `usage-gpg-print-mds-multi`, `usage-gpg-gen-random-*`,
  `usage-gpg-symmetric-*`, `usage-gpg-list-config-*`,
  `usage-gpg-list-packets`, `usage-gpg-list-packets-*`, and
  `usage-gpg-personal-*-prefs-*`.
- If a validator defect is the only reason a focused case cannot pass, document
  the exact defect in `validator-report.md` and add or update only the matching
  entry in `safe/scripts/validator-libgcrypt-skips.json`. The skip must name the
  current validator commit and testcase ID, and the focused subset run must
  still execute all unaffected cases in this bucket.
- Update `validator-report.md` with each fixed testcase ID, regression test ID,
  changed safe module, and verification artifact path.
- Commit fixes and report updates. End with one commit whose subject begins
  `impl_p05_fix_gpg_symmetric_digest_random:` and tag it
  `phase/impl_p05_fix_gpg_symmetric_digest_random`.

# Verification Phases

- Phase ID: `check_p05_symmetric_digest_random_software_tester`
- Type: `check`
- Fixed `bounce_target`: `impl_p05_fix_gpg_symmetric_digest_random`
- Purpose: verify safe fixes against GPG usage cases that exercise symmetric
  ciphers, message digests, random generation, S2K/KDF behavior, and packet
  parsing output.
- Commands:
  - `test "$(git rev-parse HEAD)" = "$(git rev-parse phase/impl_p05_fix_gpg_symmetric_digest_random)"`
  - `test "$(git rev-parse HEAD^)" = "$(git rev-parse phase/impl_p04_fix_source_api_failures)"`
  - `bash -c 'test -z "$(git status --short)"'`
  - `bash -c 'git check-ignore -q validator/ && git check-ignore -q validator-local/ && git check-ignore -q validator-artifacts/'`
  - `bash -c 'test -z "$(git ls-files -- validator validator-local validator-artifacts)"'`
  - `safe/scripts/check-rust-toolchain.sh`
  - `cargo fmt --manifest-path safe/Cargo.toml -- --check`
  - `cargo build --manifest-path safe/Cargo.toml --release --locked --offline`
  - `safe/scripts/build-release-lib.sh`
  - `safe/scripts/check-abi.sh --all`
  - `safe/scripts/run-upstream-tests.sh random hashtest hmac t-kdf aeswrap basic`
  - `safe/scripts/run-regression-tests.sh --all`
  - `safe/scripts/build-debs.sh`
  - `safe/scripts/check-deb-metadata.sh --dist safe/dist`
  - `python3 safe/scripts/prepare-validator-local-port.py --validator-dir validator --dist safe/dist --output-root validator-local`
  - `bash safe/scripts/run-validator-libgcrypt.sh --validator-dir validator --mode port --artifact-root validator-artifacts/p05-port-print-md --override-root validator-local/override-debs --port-lock validator-local/proof/local-port-debs-lock.json --case-glob 'usage-gpg-print-md-*' --record-casts`
  - `bash safe/scripts/run-validator-libgcrypt.sh --validator-dir validator --mode port --artifact-root validator-artifacts/p05-port-print-md-base --override-root validator-local/override-debs --port-lock validator-local/proof/local-port-debs-lock.json --case usage-gpg-print-md --record-casts`
  - `bash safe/scripts/run-validator-libgcrypt.sh --validator-dir validator --mode port --artifact-root validator-artifacts/p05-port-print-mds --override-root validator-local/override-debs --port-lock validator-local/proof/local-port-debs-lock.json --case usage-gpg-print-mds-multi --record-casts`
  - `bash safe/scripts/run-validator-libgcrypt.sh --validator-dir validator --mode port --artifact-root validator-artifacts/p05-port-random --override-root validator-local/override-debs --port-lock validator-local/proof/local-port-debs-lock.json --case-glob 'usage-gpg-gen-random-*' --record-casts`
  - `bash safe/scripts/run-validator-libgcrypt.sh --validator-dir validator --mode port --artifact-root validator-artifacts/p05-port-symmetric --override-root validator-local/override-debs --port-lock validator-local/proof/local-port-debs-lock.json --case-glob 'usage-gpg-symmetric-*' --record-casts`
  - `bash safe/scripts/run-validator-libgcrypt.sh --validator-dir validator --mode port --artifact-root validator-artifacts/p05-port-list-config --override-root validator-local/override-debs --port-lock validator-local/proof/local-port-debs-lock.json --case-glob 'usage-gpg-list-config-*' --record-casts`
  - `bash safe/scripts/run-validator-libgcrypt.sh --validator-dir validator --mode port --artifact-root validator-artifacts/p05-port-list-packets-base --override-root validator-local/override-debs --port-lock validator-local/proof/local-port-debs-lock.json --case usage-gpg-list-packets --record-casts`
  - `bash safe/scripts/run-validator-libgcrypt.sh --validator-dir validator --mode port --artifact-root validator-artifacts/p05-port-list-packets --override-root validator-local/override-debs --port-lock validator-local/proof/local-port-debs-lock.json --case-glob 'usage-gpg-list-packets-*' --record-casts`
  - `bash safe/scripts/run-validator-libgcrypt.sh --validator-dir validator --mode port --artifact-root validator-artifacts/p05-port-personal-prefs --override-root validator-local/override-debs --port-lock validator-local/proof/local-port-debs-lock.json --case-glob 'usage-gpg-personal-*-prefs-*' --record-casts`
  - `python3 safe/scripts/check-validator-port-evidence.py --port-lock validator-local/proof/local-port-debs-lock.json --override-root validator-local/override-debs --artifact-root validator-artifacts/p05-port-print-md --artifact-root validator-artifacts/p05-port-print-md-base --artifact-root validator-artifacts/p05-port-print-mds --artifact-root validator-artifacts/p05-port-random --artifact-root validator-artifacts/p05-port-symmetric --artifact-root validator-artifacts/p05-port-list-config --artifact-root validator-artifacts/p05-port-list-packets-base --artifact-root validator-artifacts/p05-port-list-packets --artifact-root validator-artifacts/p05-port-personal-prefs`

- Phase ID: `check_p05_symmetric_digest_random_senior_tester`
- Type: `check`
- Fixed `bounce_target`: `impl_p05_fix_gpg_symmetric_digest_random`
- Purpose: senior review of algorithm compatibility, error semantics,
  regression coverage, and no validator-suite edits.
- Commands:
  - `test "$(git rev-parse HEAD)" = "$(git rev-parse phase/impl_p05_fix_gpg_symmetric_digest_random)"`
  - `test "$(git rev-parse HEAD^)" = "$(git rev-parse phase/impl_p04_fix_source_api_failures)"`
  - `bash -c 'test -z "$(git status --short)"'`
  - `bash -c 'git check-ignore -q validator/ && git check-ignore -q validator-local/ && git check-ignore -q validator-artifacts/'`
  - `git diff --stat HEAD^..HEAD`
  - `bash -c 'test -z "$(git ls-files -- validator validator-local validator-artifacts)"'`
  - `bash -c 'if git diff --name-only HEAD^..HEAD | grep -E "^(validator|validator-local|validator-artifacts)(/|$)"; then exit 1; fi'`
  - `bash -c 'rg -n "todo!|unimplemented!|Not implemented|safe_gcry_stub_zero" safe/src safe/cabi safe/build.rs && exit 1 || true'`
  - Review `validator-report.md` and new regression tests for one safe-side
    reproduction per fixed validator failure in this bucket.

# Success Criteria

- Focused GPG digest/random/symmetric, packet, and preference validator
  subsets pass in safe mode with verified safe override package installation
  evidence for every port-mode testcase.
- Existing upstream `random`, `hashtest`, `hmac`, `t-kdf`, `aeswrap`, and
  `basic` tests still pass.
- No validator files were modified.

# Git Commit Requirement

The implementer must commit work to git before yielding. The commit subject must start with `impl_p05_fix_gpg_symmetric_digest_random:`, and the implementer must force-update local tag `phase/impl_p05_fix_gpg_symmetric_digest_random` to that phase commit before yielding.
