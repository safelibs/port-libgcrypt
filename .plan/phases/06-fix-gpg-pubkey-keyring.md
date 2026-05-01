# Phase Name

Fix GPG public-key, signing, encryption, and keyring usage failures

# Implement Phase ID

`impl_p06_fix_gpg_pubkey_keyring`

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
- Phase 5 commit and report.
- Validator wrapper and port evidence checker from phase 1.
- `safe/scripts/validator-libgcrypt-skips.json`.
- Validator failures in the `usage-pubkey-keyring` bucket.
- Existing safe modules:
  - `safe/src/pubkey/rsa.rs`
  - `safe/src/pubkey/dsa.rs`
  - `safe/src/pubkey/ecc.rs`
  - `safe/src/pubkey/elgamal.rs`
  - `safe/src/pubkey/encoding.rs`
  - `safe/src/pubkey/keygrip.rs`
  - `safe/src/sexp.rs`
  - `safe/src/mpi/*.rs`
  - `safe/src/random.rs`
  - `safe/src/digest/*.rs`

# New Outputs

- Safe-side fixes for GPG key generation, import/export, list/fingerprint,
  sign/verify, recipient encryption/decryption, hidden recipient, trustdb,
  ownertrust, secret key, keygrip, revocation, and packet metadata failures.
- Regression tests for each fixed public-key/keyring validator failure.
- Updated `validator-report.md`.
- If the phase 2 through phase 5 inventory contains no unresolved
  `usage-pubkey-keyring` failures, no safe code or regression test changes are
  required; the phase still reruns the focused public-key/keyring subsets with
  port override evidence, updates `validator-report.md` to mark the bucket
  clean with no fixes needed, and creates the required phase commit and tag.

# File Changes

- `safe/src/pubkey/*.rs`
- `safe/src/sexp.rs`
- `safe/src/mpi/*.rs`
- `safe/src/random.rs`
- `safe/src/digest/*.rs`
- `safe/abi/*` or `safe/cabi/*` only for public ABI/header issues.
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
- Build any package artifacts used as validator inputs from a clean phase commit after `phase/impl_p06_fix_gpg_pubkey_keyring` points at `HEAD`. If tracked files or `validator-report.md` change after validation, amend the same phase commit, force-update the phase tag, rebuild packages, regenerate `validator-local`, and rerun the phase validator commands until the worktree is clean and artifacts match the final phase commit.
- `validator-report.md` must identify the safe port by implement phase ID and `phase/impl_p06_fix_gpg_pubkey_keyring`, not by embedding the literal hash of the final report commit.

## Phase-Specific Details

- Reproduce each validator failure with a minimal regression before fixing it.
  Prefer C API probes for `gcry_pk_*`, `gcry_sexp_*`, and `gcry_mpi_*`
  problems; use GPG command regressions when the failure depends on GPG keyring
  or packet state.
- If the inventory has zero unresolved failures for this bucket, do not invent a
  regression or safe-side change. Rerun every focused phase 6 validator subset
  in port mode with override evidence, update `validator-report.md` with the
  clean bucket result and artifact roots, and make the required
  `impl_p06_fix_gpg_pubkey_keyring:` phase commit. If the report was already
  exact and no tracked file changed, create the phase commit with
  `git commit --allow-empty` before tagging it.
- For signing and verification failures, inspect:
  - RSA/DSA/ECDSA signature S-expressions.
  - Hash algorithm selection and digest info encoding.
  - Random nonce/k generation behavior.
  - Libgcrypt error codes consumed by GPG.
- For encryption/decryption failures, inspect:
  - RSA/ElGamal/ECC encryption S-expressions.
  - PKCS#1, OAEP, ECDH, and curve parameter handling where relevant.
  - MPI opaque handling in `safe/src/mpi/opaque.rs` and
    `safe/src/pubkey/encoding.rs`.
- For keyring/listing/fingerprint failures, inspect:
  - `gcry_pk_get_keygrip` in `safe/src/pubkey/keygrip.rs`.
  - `gcry_pk_get_nbits`, curve lookup, and public parameter ordering.
  - S-expression canonical and advanced formatting in `safe/src/sexp.rs`.
- Focused validator coverage for this phase must include sign, verify,
  encrypt, decrypt-only, key, import/export, recipient, hidden-recipient,
  trust/ownertrust/trustdb, fingerprint, revocation/revuid, list-secret,
  list-keys, quick UID/expiry, hash-algo, password, agent flag, and batch-list
  case families. The verifier commands must not rely on `usage-gpg-*key*`
  alone to cover those families.
- If a validator defect is the only reason a focused case cannot pass, document
  the exact defect in `validator-report.md` and add or update only the matching
  entry in `safe/scripts/validator-libgcrypt-skips.json`. The skip must name the
  current validator commit and testcase ID, and the focused subset run must
  still execute all unaffected cases in this bucket.
- Preserve allocation ownership across C ABI boundaries. All returned buffers
  must be freeable with `gcry_free` when libgcrypt expects that contract.
- Document fixed testcase IDs, regression IDs, and modules touched in
  `validator-report.md`.
- Commit fixes and report updates. End with one commit whose subject begins
  `impl_p06_fix_gpg_pubkey_keyring:` and tag it
  `phase/impl_p06_fix_gpg_pubkey_keyring`.

# Verification Phases

- Phase ID: `check_p06_pubkey_keyring_software_tester`
- Type: `check`
- Fixed `bounce_target`: `impl_p06_fix_gpg_pubkey_keyring`
- Purpose: verify safe fixes against GPG public-key, keyring, sign/verify, and
  recipient encryption/decryption validator usage cases.
- Commands:
  - `test "$(git rev-parse HEAD)" = "$(git rev-parse phase/impl_p06_fix_gpg_pubkey_keyring)"`
  - `test "$(git rev-parse HEAD^)" = "$(git rev-parse phase/impl_p05_fix_gpg_symmetric_digest_random)"`
  - `bash -c 'test -z "$(git status --short)"'`
  - `bash -c 'git check-ignore -q validator/ && git check-ignore -q validator-local/ && git check-ignore -q validator-artifacts/'`
  - `bash -c 'test -z "$(git ls-files -- validator validator-local validator-artifacts)"'`
  - `safe/scripts/check-rust-toolchain.sh`
  - `cargo fmt --manifest-path safe/Cargo.toml -- --check`
  - `cargo build --manifest-path safe/Cargo.toml --release --locked --offline`
  - `safe/scripts/build-release-lib.sh`
  - `safe/scripts/check-abi.sh --all`
  - `safe/scripts/run-upstream-tests.sh t-sexp t-convert mpitests t-mpi-bit t-mpi-point pubkey keygen keygrip t-rsa-15 t-rsa-pss t-dsa t-ecdsa t-ed25519 t-cv25519`
  - `safe/scripts/run-regression-tests.sh --all`
  - `safe/scripts/build-debs.sh`
  - `safe/scripts/check-deb-metadata.sh --dist safe/dist`
  - `python3 safe/scripts/prepare-validator-local-port.py --validator-dir validator --dist safe/dist --output-root validator-local`
  - `bash safe/scripts/run-validator-libgcrypt.sh --validator-dir validator --mode port --artifact-root validator-artifacts/p06-port-sign --override-root validator-local/override-debs --port-lock validator-local/proof/local-port-debs-lock.json --case-glob 'usage-gpg-*sign*' --record-casts`
  - `bash safe/scripts/run-validator-libgcrypt.sh --validator-dir validator --mode port --artifact-root validator-artifacts/p06-port-verify --override-root validator-local/override-debs --port-lock validator-local/proof/local-port-debs-lock.json --case-glob 'usage-gpg-*verify*' --record-casts`
  - `bash safe/scripts/run-validator-libgcrypt.sh --validator-dir validator --mode port --artifact-root validator-artifacts/p06-port-encrypt --override-root validator-local/override-debs --port-lock validator-local/proof/local-port-debs-lock.json --case-glob 'usage-gpg-*encrypt*' --record-casts`
  - `bash safe/scripts/run-validator-libgcrypt.sh --validator-dir validator --mode port --artifact-root validator-artifacts/p06-port-decrypt --override-root validator-local/override-debs --port-lock validator-local/proof/local-port-debs-lock.json --case-glob 'usage-gpg-*decrypt*' --record-casts`
  - `bash safe/scripts/run-validator-libgcrypt.sh --validator-dir validator --mode port --artifact-root validator-artifacts/p06-port-keys --override-root validator-local/override-debs --port-lock validator-local/proof/local-port-debs-lock.json --case-glob 'usage-gpg-*key*' --record-casts`
  - `bash safe/scripts/run-validator-libgcrypt.sh --validator-dir validator --mode port --artifact-root validator-artifacts/p06-port-import --override-root validator-local/override-debs --port-lock validator-local/proof/local-port-debs-lock.json --case-glob 'usage-gpg-import-*' --record-casts`
  - `bash safe/scripts/run-validator-libgcrypt.sh --validator-dir validator --mode port --artifact-root validator-artifacts/p06-port-export --override-root validator-local/override-debs --port-lock validator-local/proof/local-port-debs-lock.json --case-glob 'usage-gpg-export-*' --record-casts`
  - `bash safe/scripts/run-validator-libgcrypt.sh --validator-dir validator --mode port --artifact-root validator-artifacts/p06-port-recipient --override-root validator-local/override-debs --port-lock validator-local/proof/local-port-debs-lock.json --case-glob 'usage-gpg-recipient-*' --record-casts`
  - `bash safe/scripts/run-validator-libgcrypt.sh --validator-dir validator --mode port --artifact-root validator-artifacts/p06-port-hidden-recipient --override-root validator-local/override-debs --port-lock validator-local/proof/local-port-debs-lock.json --case-glob 'usage-gpg-hidden-recipient-*' --record-casts`
  - `bash safe/scripts/run-validator-libgcrypt.sh --validator-dir validator --mode port --artifact-root validator-artifacts/p06-port-trust --override-root validator-local/override-debs --port-lock validator-local/proof/local-port-debs-lock.json --case-glob 'usage-gpg-*trust*' --record-casts`
  - `bash safe/scripts/run-validator-libgcrypt.sh --validator-dir validator --mode port --artifact-root validator-artifacts/p06-port-fingerprint --override-root validator-local/override-debs --port-lock validator-local/proof/local-port-debs-lock.json --case-glob 'usage-gpg-*fingerprint*' --record-casts`
  - `bash safe/scripts/run-validator-libgcrypt.sh --validator-dir validator --mode port --artifact-root validator-artifacts/p06-port-revoke --override-root validator-local/override-debs --port-lock validator-local/proof/local-port-debs-lock.json --case-glob 'usage-gpg-*revoke*' --record-casts`
  - `bash safe/scripts/run-validator-libgcrypt.sh --validator-dir validator --mode port --artifact-root validator-artifacts/p06-port-revuid --override-root validator-local/override-debs --port-lock validator-local/proof/local-port-debs-lock.json --case-glob 'usage-gpg-quick-revuid*' --record-casts`
  - `bash safe/scripts/run-validator-libgcrypt.sh --validator-dir validator --mode port --artifact-root validator-artifacts/p06-port-list-secret --override-root validator-local/override-debs --port-lock validator-local/proof/local-port-debs-lock.json --case-glob 'usage-gpg-list-secret-*' --record-casts`
  - `bash safe/scripts/run-validator-libgcrypt.sh --validator-dir validator --mode port --artifact-root validator-artifacts/p06-port-list-keys --override-root validator-local/override-debs --port-lock validator-local/proof/local-port-debs-lock.json --case-glob 'usage-gpg-list-keys*' --record-casts`
  - `bash safe/scripts/run-validator-libgcrypt.sh --validator-dir validator --mode port --artifact-root validator-artifacts/p06-port-quick-uid --override-root validator-local/override-debs --port-lock validator-local/proof/local-port-debs-lock.json --case-glob 'usage-gpg-quick-add-uid*' --record-casts`
  - `bash safe/scripts/run-validator-libgcrypt.sh --validator-dir validator --mode port --artifact-root validator-artifacts/p06-port-quick-expire --override-root validator-local/override-debs --port-lock validator-local/proof/local-port-debs-lock.json --case-glob 'usage-gpg-quick-set-expire*' --record-casts`
  - `bash safe/scripts/run-validator-libgcrypt.sh --validator-dir validator --mode port --artifact-root validator-artifacts/p06-port-hash-algo --override-root validator-local/override-debs --port-lock validator-local/proof/local-port-debs-lock.json --case-glob 'usage-gpg-hash-algo-*' --record-casts`
  - `bash safe/scripts/run-validator-libgcrypt.sh --validator-dir validator --mode port --artifact-root validator-artifacts/p06-port-passwd --override-root validator-local/override-debs --port-lock validator-local/proof/local-port-debs-lock.json --case-glob 'usage-gpg-passwd-*' --record-casts`
  - `bash safe/scripts/run-validator-libgcrypt.sh --validator-dir validator --mode port --artifact-root validator-artifacts/p06-port-use-agent --override-root validator-local/override-debs --port-lock validator-local/proof/local-port-debs-lock.json --case-glob 'usage-gpg-use-agent-*' --record-casts`
  - `bash safe/scripts/run-validator-libgcrypt.sh --validator-dir validator --mode port --artifact-root validator-artifacts/p06-port-batch-list --override-root validator-local/override-debs --port-lock validator-local/proof/local-port-debs-lock.json --case usage-gpg-no-tty-batch-list --record-casts`
  - `python3 safe/scripts/check-validator-port-evidence.py --port-lock validator-local/proof/local-port-debs-lock.json --override-root validator-local/override-debs --artifact-root validator-artifacts/p06-port-sign --artifact-root validator-artifacts/p06-port-verify --artifact-root validator-artifacts/p06-port-encrypt --artifact-root validator-artifacts/p06-port-decrypt --artifact-root validator-artifacts/p06-port-keys --artifact-root validator-artifacts/p06-port-import --artifact-root validator-artifacts/p06-port-export --artifact-root validator-artifacts/p06-port-recipient --artifact-root validator-artifacts/p06-port-hidden-recipient --artifact-root validator-artifacts/p06-port-trust --artifact-root validator-artifacts/p06-port-fingerprint --artifact-root validator-artifacts/p06-port-revoke --artifact-root validator-artifacts/p06-port-revuid --artifact-root validator-artifacts/p06-port-list-secret --artifact-root validator-artifacts/p06-port-list-keys --artifact-root validator-artifacts/p06-port-quick-uid --artifact-root validator-artifacts/p06-port-quick-expire --artifact-root validator-artifacts/p06-port-hash-algo --artifact-root validator-artifacts/p06-port-passwd --artifact-root validator-artifacts/p06-port-use-agent --artifact-root validator-artifacts/p06-port-batch-list`

- Phase ID: `check_p06_pubkey_keyring_senior_tester`
- Type: `check`
- Fixed `bounce_target`: `impl_p06_fix_gpg_pubkey_keyring`
- Purpose: senior review of public-key compatibility, S-expression/MPI memory
  ownership, regression coverage, and no validator-suite edits.
- Commands:
  - `test "$(git rev-parse HEAD)" = "$(git rev-parse phase/impl_p06_fix_gpg_pubkey_keyring)"`
  - `test "$(git rev-parse HEAD^)" = "$(git rev-parse phase/impl_p05_fix_gpg_symmetric_digest_random)"`
  - `bash -c 'test -z "$(git status --short)"'`
  - `bash -c 'git check-ignore -q validator/ && git check-ignore -q validator-local/ && git check-ignore -q validator-artifacts/'`
  - `git diff --stat HEAD^..HEAD`
  - `bash -c 'test -z "$(git ls-files -- validator validator-local validator-artifacts)"'`
  - `bash -c 'if git diff --name-only HEAD^..HEAD | grep -E "^(validator|validator-local|validator-artifacts)(/|$)"; then exit 1; fi'`
  - `bash -c 'rg -n "todo!|unimplemented!|Not implemented|safe_gcry_stub_zero" safe/src safe/cabi safe/build.rs && exit 1 || true'`
  - Review new tests under `safe/tests/regressions/` and the updated
    `validator-report.md`.

# Success Criteria

- Focused public-key/keyring, trust, fingerprint, revocation, recipient, and
  decrypt-only validator subsets pass in safe mode with verified safe override
  package installation evidence for every port-mode testcase.
- Upstream public-key, S-expression, and MPI tests still pass.
- No validator files were modified.

# Git Commit Requirement

The implementer must commit work to git before yielding. The commit subject must start with `impl_p06_fix_gpg_pubkey_keyring:`, and the implementer must force-update local tag `phase/impl_p06_fix_gpg_pubkey_keyring` to that phase commit before yielding.
