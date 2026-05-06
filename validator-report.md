# Validator Report

## Phase 1: Checkout And Invocation Harness

- Implement phase: `impl_p01_validator_checkout_invocation`
- Phase tag: `phase/impl_p01_validator_checkout_invocation`
- Safe port identity: local phase tag above, release override tag `local-libgcrypt-safe`
- Validator checkout: `validator/`
- Validator commit: `87b321fe728340d6fc6dd2f638583cca82c667c3`
- Validator origin: `https://github.com/safelibs/validator`

## README-Derived Invocation Notes

The validator README describes `make unit` and `make check-testcases` as the
tooling checks. Library matrix runs use `validator/test.sh` with
`--config repositories.yml`, `--tests-root tests`, `--artifact-root`, repeated
`--library` selections, `--mode original|port`, and optional `--record-casts`.
Port mode expects an override root laid out as
`<override-deb-root>/<library>/*.deb` plus a port deb lock.

The local libgcrypt wrapper keeps that official path for unfiltered full-suite
runs when the checked-out validator supports libgcrypt in its manifest. Focused
phase smoke runs use the port-owned direct Docker fallback because the current
validator matrix runner has no per-testcase filter options.

## Libgcrypt Support Detection

Command:

```bash
python3 validator/tools/testcases.py --config validator/repositories.yml --tests-root validator/tests --list-summary --library libgcrypt
```

Result: official matrix selection is unavailable at validator commit
`87b321fe728340d6fc6dd2f638583cca82c667c3`. The checkout contains
`validator/tests/libgcrypt/`, but `validator/repositories.yml` and
`validator/tools/inventory.py` do not include `libgcrypt`, so the validator
reports `unknown libraries in config: libgcrypt`. This is recorded as an
invocation/inventory defect and the wrapper uses the direct Docker fallback
without editing validator files.

## Smoke Commands

```bash
bash safe/scripts/run-validator-libgcrypt.sh --self-test-timeout
python3 safe/scripts/prepare-validator-local-port.py --validator-dir validator --dist safe/dist --output-root validator-local
bash safe/scripts/run-validator-libgcrypt.sh --validator-dir validator --mode original --artifact-root validator-artifacts/p01-original-smoke --case aes-ctr-roundtrip
bash safe/scripts/run-validator-libgcrypt.sh --validator-dir validator --mode port --artifact-root validator-artifacts/p01-port-smoke --override-root validator-local/override-debs --port-lock validator-local/proof/local-port-debs-lock.json --case aes-ctr-roundtrip || true
python3 safe/scripts/check-validator-port-evidence.py --port-lock validator-local/proof/local-port-debs-lock.json --override-root validator-local/override-debs --artifact-root validator-artifacts/p01-port-smoke
```

## Smoke Results

- Timeout self-test: passed. The synthetic one-second testcase wrote a failed
  result with `exit_code: 124`, logged `testcase timed out after 1 seconds`,
  and left no temporary status directory or named container.
- Original smoke: passed for `aes-ctr-roundtrip` through the direct Docker
  fallback. Artifact root: `validator-artifacts/p01-original-smoke`.
- Safe port smoke: passed for `aes-ctr-roundtrip` through the direct Docker
  fallback. Artifact root: `validator-artifacts/p01-port-smoke`.
- Port-mode override-install evidence: passed. The result records
  `override_debs_installed: true` and matching `libgcrypt20` and
  `libgcrypt20-dev` package names, versions, architectures, filenames, SHA256
  values, and sizes from `validator-local/proof/local-port-debs-lock.json`.

## Phase 2 Triage Queue

- Validator inventory defect: libgcrypt testcase assets exist in the checkout,
  but official matrix selection rejects `--library libgcrypt`. Future phases
  should continue to use the wrapper fallback unless the upstream validator
  commit adds manifest and inventory support.

## Phase 2: Baseline Full Validator Run And Failure Triage

- Implement phase: `impl_p02_validator_baseline_triage`
- Phase tag: `phase/impl_p02_validator_baseline_triage`
- Safe port identity: implement phase and phase tag above. Package inputs are
  rebuilt from the phase tag before final validator execution; the report uses
  that tag identity instead of embedding the final report commit hash.
- Validator checkout: `validator/`
- Validator commit: `87b321fe728340d6fc6dd2f638583cca82c667c3`
- Invocation mode: direct Docker fallback through
  `safe/scripts/run-validator-libgcrypt.sh`. The official validator matrix path
  is unavailable at this commit because
  `python3 validator/tools/testcases.py --config validator/repositories.yml --tests-root validator/tests --list-summary --library libgcrypt`
  exits with `unknown libraries in config: libgcrypt`.
  Original-mode wrapper invocations exit 0 once complete per-case artifacts are
  written; pass/fail status is taken from the summary JSON and this report.
- Original artifact root: `validator-artifacts/p02-original/`
- Safe candidate artifact root: `validator-artifacts/p02-port/`

Fixed libgcrypt case counts for later proof thresholds and report checks:

libgcrypt_source_cases: 5
libgcrypt_usage_cases: 170
libgcrypt_total_cases: 175

These counts are fixed for downstream phases. Later phases should consume these
values from this report instead of rerunning testcase discovery.

## Original Baseline

Original baseline status: failed.

- Results: 170 passed, 5 failed, 0 skipped, 175 total.
- Source-facing cases: all 5 passed (`aes-ctr-roundtrip`,
  `digest-sha256-smoke`, `hmac-sha256-smoke`, `mpi-arithmetic`,
  `nonce-generation`).
- Failed usage cases:
  `usage-gpg-print-md-blake2b512`,
  `usage-gpg-symmetric-cipher-camellia128`,
  `usage-gpg-symmetric-compress-z9-decrypt`,
  `usage-gpg-symmetric-list-packets-s2k-sha256`,
  `usage-gpg-symmetric-s2k-mode1-salted`.

These original failures are baseline validator or environment behavior for the
current validator checkout. They are not counted as safe-port regressions by
themselves.

## Safe Candidate

Safe candidate status: failed.

- Results: 84 passed, 91 failed, 0 skipped, 175 total.
- Source-facing cases: all 5 passed (`aes-ctr-roundtrip`,
  `digest-sha256-smoke`, `hmac-sha256-smoke`, `mpi-arithmetic`,
  `nonce-generation`).
- Usage cases: 79 passed, 91 failed.
- Four safe-candidate failures also failed the original baseline:
  `usage-gpg-symmetric-cipher-camellia128`,
  `usage-gpg-symmetric-compress-z9-decrypt`,
  `usage-gpg-symmetric-list-packets-s2k-sha256`,
  `usage-gpg-symmetric-s2k-mode1-salted`.
- One original baseline failure passed with the safe candidate:
  `usage-gpg-print-md-blake2b512`.

## Port Override Installation Evidence

Port override installation evidence: complete.

Evidence status: complete.

- `python3 safe/scripts/check-validator-port-evidence.py --port-lock validator-local/proof/local-port-debs-lock.json --override-root validator-local/override-debs --artifact-root validator-artifacts/p02-port`
  passed.
- All 175 non-skipped port result JSONs have
  `override_debs_installed: true`.
- Each port result records installed `libgcrypt20` and `libgcrypt20-dev`
  packages at version `1.10.3+safe1` for `amd64`, matching the local port lock.
- The override root contained exactly the locked
  `libgcrypt20_1.10.3+safe1_amd64.deb` and
  `libgcrypt20-dev_1.10.3+safe1_amd64.deb` inputs.
- No failures are classified as `packaging-install` in this phase.

## Failure Inventory

Failure inventory: grouped by phase bucket below.

`source-api`: 0 failures.

`usage-symmetric-digest-random`: 8 safe-candidate failures:

- `usage-gpg-hash-algo-sha384-detached`
- `usage-gpg-personal-cipher-prefs-aes256`
- `usage-gpg-personal-digest-prefs-sha512`
- `usage-gpg-symmetric-cipher-camellia128`
- `usage-gpg-symmetric-compress-z9-decrypt`
- `usage-gpg-symmetric-list-packets-s2k-sha256`
- `usage-gpg-symmetric-s2k-mode1-salted`
- `usage-gpg-weak-digest-sha1-rejects-verify`

`usage-pubkey-keyring`: 83 safe-candidate failures:

- `usage-gpg-always-trust-untrusted-recipient`
- `usage-gpg-armor-detached-sign`
- `usage-gpg-armor-recipient-encrypt`
- `usage-gpg-armored-message-header-only`
- `usage-gpg-auto-key-locate-clear-offline`
- `usage-gpg-batch-gen-key-paramfile`
- `usage-gpg-check-trustdb-offline`
- `usage-gpg-clearsign-roundtrip-output`
- `usage-gpg-clearsign-sha256-digest`
- `usage-gpg-clearsign-verify-batch11`
- `usage-gpg-clearsign-verify-status`
- `usage-gpg-clearsign-verify`
- `usage-gpg-comment-marker-in-armor`
- `usage-gpg-dearmor-public-key`
- `usage-gpg-decrypt-clearsigned-message`
- `usage-gpg-default-key-selects-second-key`
- `usage-gpg-detach-sign-sha512-digest`
- `usage-gpg-detached-binary-sign`
- `usage-gpg-detached-sign-status-fd`
- `usage-gpg-detached-sign-verify`
- `usage-gpg-encrypt-decrypt-stdout-pipe`
- `usage-gpg-encrypt-two-recipients`
- `usage-gpg-export-armor-block`
- `usage-gpg-export-import-key`
- `usage-gpg-export-ownertrust`
- `usage-gpg-export-public-key`
- `usage-gpg-export-public-minimal`
- `usage-gpg-export-secret-key`
- `usage-gpg-fingerprint-list`
- `usage-gpg-fingerprint-stable-export-import`
- `usage-gpg-gen-revoke-armor`
- `usage-gpg-gen-revoke-detached-reason-zero`
- `usage-gpg-hidden-recipient-anonymous-keyid`
- `usage-gpg-hidden-recipient-encrypt-batch11`
- `usage-gpg-import-binary-vs-armor`
- `usage-gpg-import-options-keep-ownertrust-roundtrip`
- `usage-gpg-import-ownertrust`
- `usage-gpg-import-public-key-listing`
- `usage-gpg-import-public-key`
- `usage-gpg-import-secret-key`
- `usage-gpg-import-show-only`
- `usage-gpg-keyid-format-long-vs-short`
- `usage-gpg-keyserver-options-no-honor`
- `usage-gpg-list-keys-uid`
- `usage-gpg-list-keys-with-colons-pub-record`
- `usage-gpg-list-keys-with-fingerprint-subkey`
- `usage-gpg-list-keys`
- `usage-gpg-list-options-show-keyserver-urls`
- `usage-gpg-list-packets-armor`
- `usage-gpg-list-packets-binary-detached`
- `usage-gpg-list-packets-clearsign`
- `usage-gpg-list-secret-colons`
- `usage-gpg-list-secret-keys-colons`
- `usage-gpg-list-secret-keys-keygrip`
- `usage-gpg-list-secret-keys-keyid-format-0xlong`
- `usage-gpg-list-secret-keys`
- `usage-gpg-max-cert-depth-verify`
- `usage-gpg-multifile-decrypt`
- `usage-gpg-no-armor-explicit-binary`
- `usage-gpg-no-default-keyring-isolation`
- `usage-gpg-no-emit-version-armor`
- `usage-gpg-no-tty-batch-list`
- `usage-gpg-ownertrust-export-check`
- `usage-gpg-passwd-dry-run`
- `usage-gpg-primary-keyring-redirect-write`
- `usage-gpg-public-key-packet-batch11`
- `usage-gpg-quick-add-uid`
- `usage-gpg-quick-revuid-with-colons-validity`
- `usage-gpg-quick-revuid`
- `usage-gpg-quick-set-expire`
- `usage-gpg-recipient-binary-encrypt`
- `usage-gpg-recipient-encrypt-armor`
- `usage-gpg-recipient-encrypt-cipher-aes128`
- `usage-gpg-recipient-encrypt-compress-bzip2`
- `usage-gpg-recipient-encrypt-compress-none`
- `usage-gpg-recipient-encrypt-decrypt-output`
- `usage-gpg-recipient-encrypt`
- `usage-gpg-sign-file-roundtrip`
- `usage-gpg-tampered-signature-reject`
- `usage-gpg-use-agent-flag-accepted`
- `usage-gpg-verify-detached-status-fd`
- `usage-gpg-verify-status-stream`
- `usage-gpg-with-colons-fingerprint`

`packaging-install`: 0 failures. Override package install evidence is complete
for every port-mode result.

`validator-bug`: 0 testcase execution failures are classified as validator bugs.
The validator-side issue in this phase is limited to the inventory path
rejecting `libgcrypt`, which forced the direct Docker fallback.

## Validator-Side Skips And Proof Status

- Testcase result skips: none. Both artifact roots contain 0 skipped result
  JSONs.
- Official validator matrix/proof limitation: skipped because the current
  validator inventory does not expose `libgcrypt` through the official matrix
  path. The direct Docker fallback still executed all 175 libgcrypt testcase
  scripts for both original and port modes and wrote per-case JSON summaries and
  casts.
- Phase proof substitute: the non-skipped wrapper summaries under
  `validator-artifacts/p02-original/results/libgcrypt/summary.json` and
  `validator-artifacts/p02-port/port/results/libgcrypt/summary.json`, together
  with the fixed count lines above.

## Phase 3: Packaging And Installation Gate

- Implement phase: `impl_p03_fix_packaging_install`
- Phase tag: `phase/impl_p03_fix_packaging_install`
- Safe port identity: implement phase and phase tag above. Package inputs are
  rebuilt from the phase tag before final focused validator execution; the
  report uses that tag identity instead of embedding the final report commit
  hash.
- Package/development probe artifact root:
  `validator-artifacts/p03-package-dev-probe/`
- Focused source artifact root: `validator-artifacts/p03-port-source/`
- Focused usage-smoke artifact root:
  `validator-artifacts/p03-port-usage-smoke/`

`packaging-install`: clean. Phase 2 recorded 0 failures in this bucket, so no
safe package payload or regression test changes were required in phase 3.

Package/development probe: passed. The probe installs the locked local
`libgcrypt20` and `libgcrypt20-dev` `.deb` files from
`validator-local/override-debs/libgcrypt/` into a clean `ubuntu:24.04`
container, verifies package name, version, architecture, filename, size, and
SHA256 against `validator-local/proof/local-port-debs-lock.json`, and compiles
and runs the reduced `gcry_check_version(NULL)` package-surface probe through
direct linker inputs, `pkg-config --cflags --libs libgcrypt`, and
`libgcrypt-config --cflags --libs`.

Port override installation evidence: complete for the focused phase 3 reruns.

- `python3 safe/scripts/check-validator-port-evidence.py --port-lock validator-local/proof/local-port-debs-lock.json --override-root validator-local/override-debs --artifact-root validator-artifacts/p03-port-source --artifact-root validator-artifacts/p03-port-usage-smoke`
  passed.
- The focused source run covers the source-facing libgcrypt validator cases
  under `validator-artifacts/p03-port-source/`.
- The focused usage smoke run covers `usage-gpg-print-md` under
  `validator-artifacts/p03-port-usage-smoke/`.
- Any future source or usage compatibility failures with complete override
  installation evidence remain outside the `packaging-install` bucket and are
  assigned to phase 4 or later buckets.

## Phase 4: Source API Compatibility Gate

- Implement phase: `impl_p04_fix_source_api_failures`
- Phase tag: `phase/impl_p04_fix_source_api_failures`
- Safe port identity: implement phase and phase tag above. Package inputs are
  rebuilt from the phase tag before final focused source validator execution;
  the report uses that tag identity instead of embedding the final report commit
  hash.
- Focused source artifact root: `validator-artifacts/p04-port-source/`

`source-api`: clean. Phase 2 recorded 0 failures in this bucket, so no safe
source code, C ABI, header, or regression test changes were required in phase 4.

Focused source validator result: passed. The run covers all five source-facing
libgcrypt validator cases: `aes-ctr-roundtrip`, `digest-sha256-smoke`,
`hmac-sha256-smoke`, `mpi-arithmetic`, and `nonce-generation`.

Port override installation evidence: complete for the focused phase 4 source
rerun.

- `python3 safe/scripts/check-validator-port-evidence.py --port-lock validator-local/proof/local-port-debs-lock.json --override-root validator-local/override-debs --artifact-root validator-artifacts/p04-port-source`
  passed.
- The clean source bucket is recorded by
  `impl_p04_fix_source_api_failures` and
  `phase/impl_p04_fix_source_api_failures`; there were no fixed source
  validator failures requiring per-case safe-side regressions.

## Phase 5: GPG Symmetric, Digest, And Random Usage Gate

- Implement phase: `impl_p05_fix_gpg_symmetric_digest_random`
- Phase tag: `phase/impl_p05_fix_gpg_symmetric_digest_random`
- Safe port identity: implement phase and phase tag above. Package inputs are
  rebuilt from the phase tag before final focused validator execution; this
  report uses that tag identity instead of embedding the final report commit
  hash.
- Validator checkout: `validator/`
- Validator commit: `87b321fe728340d6fc6dd2f638583cca82c667c3`
- Focused artifact roots:
  `validator-artifacts/p05-port-print-md/`,
  `validator-artifacts/p05-port-print-md-base/`,
  `validator-artifacts/p05-port-print-mds/`,
  `validator-artifacts/p05-port-random/`,
  `validator-artifacts/p05-port-symmetric/`,
  `validator-artifacts/p05-port-list-config/`,
  `validator-artifacts/p05-port-list-packets-base/`,
  `validator-artifacts/p05-port-list-packets/`,
  `validator-artifacts/p05-port-personal-prefs/`,
  `validator-artifacts/p05-port-hash-algo-sha384-detached/`, and
  `validator-artifacts/p05-port-weak-digest-sha1/`.

`usage-symmetric-digest-random`: clean for safe-port regressions after this
phase, with the scope note below.

Scope note: the phase 2 bucket included GPG digest and preference cases whose
observable failures occurred before the digest, random, KDF, or symmetric
cipher modules were reached. GPG could not generate or use the temporary
Ed25519/Curve25519 keys with the safe port because the generated key
S-expressions missed libgcrypt's GPG-specific EdDSA and ECDH shape. The safe
code changes for those bucket entries therefore touch `safe/src/pubkey/ecc.rs`
and `safe/src/pubkey/mod.rs`; the GPG-level regression below maps those changes
back to the exact phase 5 validator IDs so later pubkey phases do not need to
rediscover these same setup blockers.

Safe-side fixes:

- `usage-gpg-hash-algo-sha384-detached` and
  `usage-gpg-personal-digest-prefs-sha512`: fixed by
  `safe/src/pubkey/ecc.rs`, which now emits GPG-compatible Ed25519 EdDSA
  generated keys with `(flags eddsa)`, a `0x40`-prefixed public point, and a
  seed-style 32-byte private value. Regression:
  `gpg-ed25519-eddsa-genkey-sign`; validator-ID regression mapping:
  `gpg-phase5-usage-bucket`.
- `usage-gpg-personal-cipher-prefs-aes256`: fixed by
  `safe/src/pubkey/ecc.rs`, `safe/src/pubkey/mod.rs`, and `safe/src/error.rs`.
  Curve25519 generation now preserves `(flags djb-tweak)`, ECDH encryption
  returns both `(s ...)` and `(e ...)` atoms, and `gcry_pk_decrypt` routes ECDH
  private-key operations through the ECC implementation. Regression:
  `gpg-curve25519-ecdh-encrypt-ephemeral`; validator-ID regression mapping:
  `gpg-phase5-usage-bucket`.
- `usage-gpg-weak-digest-sha1-rejects-verify`: rerun clean in port mode with
  override evidence after the Ed25519 key-generation/signing fix. The direct
  safe-side regression mapping is `gpg-phase5-usage-bucket`, which verifies the
  strong SHA256 baseline and the expected `--weak-digest SHA1` rejection for a
  SHA1 detached signature against the built safe library.

Fixed validator ID to regression map:

- `usage-gpg-hash-algo-sha384-detached`:
  `gpg-phase5-usage-bucket` (`hash_algo_sha384_detached`) and the reduced C
  probe `gpg-ed25519-eddsa-genkey-sign`.
- `usage-gpg-personal-digest-prefs-sha512`:
  `gpg-phase5-usage-bucket` (`personal_digest_prefs_sha512`) and the reduced C
  probe `gpg-ed25519-eddsa-genkey-sign`.
- `usage-gpg-personal-cipher-prefs-aes256`:
  `gpg-phase5-usage-bucket` (`personal_cipher_prefs_aes256`) and the reduced C
  probe `gpg-curve25519-ecdh-encrypt-ephemeral`.
- `usage-gpg-weak-digest-sha1-rejects-verify`:
  `gpg-phase5-usage-bucket` (`weak_digest_sha1_rejects_verify`).

Validator-side skips:

- `usage-gpg-symmetric-cipher-camellia128`,
  `usage-gpg-symmetric-list-packets-s2k-sha256`, and
  `usage-gpg-symmetric-s2k-mode1-salted` are exact port-mode skips for
  validator commit `87b321fe728340d6fc6dd2f638583cca82c667c3`. Phase 2 original
  evidence shows they fail against stock libgcrypt; the testcase invokes
  `gpg --list-packets` on symmetric ciphertext without the loopback passphrase
  path and exits before the intended assertion.
- `usage-gpg-symmetric-compress-z9-decrypt` is an exact port-mode skip for the
  same validator commit. Phase 2 original evidence shows it fails before crypto
  validation because `yes | head -c 16384` runs under `set -o pipefail` and
  exits 141 from `yes` receiving SIGPIPE.
- The skip entries live in `safe/scripts/validator-libgcrypt-skips.json`; all
  unaffected `usage-gpg-symmetric-*` cases still execute in the focused
  symmetric run.

Focused validator result:

- Digest/print-md, random, list-config, list-packets, personal preference,
  `usage-gpg-hash-algo-sha384-detached`, and
  `usage-gpg-weak-digest-sha1-rejects-verify` focused port-mode runs passed.
- `usage-gpg-symmetric-*` focused port-mode run passed with 27 executed cases
  and the 4 validator-defect skips listed above.
- Port override installation evidence is complete for all focused phase 5
  artifact roots via
  `python3 safe/scripts/check-validator-port-evidence.py --port-lock validator-local/proof/local-port-debs-lock.json --override-root validator-local/override-debs ...`.

## Phase 6: GPG Public-Key And Keyring Usage Gate

- Implement phase: `impl_p06_fix_gpg_pubkey_keyring`
- Phase tag: `phase/impl_p06_fix_gpg_pubkey_keyring`
- Safe port identity: implement phase and phase tag above. Package inputs are
  rebuilt from the phase tag before final focused validator execution; this
  report uses that tag identity instead of embedding the final report commit
  hash.
- Validator checkout: `validator/`
- Validator commit: `87b321fe728340d6fc6dd2f638583cca82c667c3`
- Focused artifact roots:
  `validator-artifacts/p06-port-sign/`,
  `validator-artifacts/p06-port-verify/`,
  `validator-artifacts/p06-port-encrypt/`,
  `validator-artifacts/p06-port-decrypt/`,
  `validator-artifacts/p06-port-keys/`,
  `validator-artifacts/p06-port-import/`,
  `validator-artifacts/p06-port-export/`,
  `validator-artifacts/p06-port-recipient/`,
  `validator-artifacts/p06-port-hidden-recipient/`,
  `validator-artifacts/p06-port-trust/`,
  `validator-artifacts/p06-port-fingerprint/`,
  `validator-artifacts/p06-port-revoke/`,
  `validator-artifacts/p06-port-revuid/`,
  `validator-artifacts/p06-port-list-secret/`,
  `validator-artifacts/p06-port-list-keys/`,
  `validator-artifacts/p06-port-quick-uid/`,
  `validator-artifacts/p06-port-quick-expire/`,
  `validator-artifacts/p06-port-hash-algo/`,
  `validator-artifacts/p06-port-passwd/`,
  `validator-artifacts/p06-port-use-agent/`, and
  `validator-artifacts/p06-port-batch-list/`.

`usage-pubkey-keyring`: clean for the focused phase 6 public-key and keyring
coverage after this phase.

Initial focused phase 6 probe against the phase 5 packages still had safe-port
failures in RSA recipient encryption, hidden-recipient encryption, always-trust
recipient encryption, and Ed25519 secret-key import. Sign, verify, export,
fingerprint, revocation, revuid, list-secret, list-keys, quick UID/expiry,
hash-algo, password, use-agent, and batch-list families were already clean in
that focused probe.

Safe-side fixes:

- `safe/src/digest/algorithms.rs` now returns libgcrypt-compatible DER
  DigestInfo prefixes from `gcry_md_get_asnoid` for MD5, SHA1, SHA224,
  SHA256, SHA384, SHA512, SHA512/256, and SHA512/224. This fixes the SHA512
  ASNOID lookup used by GPG RSA key self-signatures before recipient
  encryption and trust decisions. Regression: `gcry-md-asnoid-sha-family`.
- `safe/src/pubkey/rsa.rs` now emits generated RSA public and private key
  MPIs with the positive-MPI leading zero when the high bit is set. This keeps
  gpg-agent's private-key keygrip consistent with GPG public keys rebuilt
  through `%m` formatting. Regression: `gcry-rsa-keygrip-leading-zero`.
- `safe/src/pubkey/mod.rs` now maps the public-key aliases `ecdsa`, `ecdh`,
  and `eddsa` to `GCRY_PK_ECC`, matching libgcrypt. GnuPG's OpenPGP-native
  secret-key importer depends on that alias behavior before handing Ed25519
  secret material to `gcry_pk_testkey`. Regression:
  `gcry-pk-map-name-ecc-aliases`.
- `safe/src/pubkey/ecc.rs` now accepts Ed25519 and Ed448 seed-form private
  keys when the derived public point matches, then falls back to scalar-form
  validation for generic ECC test keys. Regression:
  `gcry-eddsa-testkey-import-seed`.
- `gpg-rsa-keyring-md-asnoid` covers the combined GPG surfaces fixed in this
  phase: RSA key generation for recipient encryption, hidden-recipient packet
  metadata, always-trust encryption to an otherwise untrusted recipient, and
  Ed25519 secret-key export/import.

Fixed validator ID to regression map:

- `usage-gpg-recipient-binary-encrypt`,
  `usage-gpg-recipient-encrypt-armor`,
  `usage-gpg-recipient-encrypt-cipher-aes128`,
  `usage-gpg-recipient-encrypt-compress-bzip2`,
  `usage-gpg-recipient-encrypt-compress-none`, and
  `usage-gpg-recipient-encrypt`: `gpg-rsa-keyring-md-asnoid`,
  `gcry-md-asnoid-sha-family`, and `gcry-rsa-keygrip-leading-zero`.
- `usage-gpg-hidden-recipient-anonymous-keyid` and
  `usage-gpg-hidden-recipient-encrypt-batch11`:
  `gpg-rsa-keyring-md-asnoid`, `gcry-md-asnoid-sha-family`, and
  `gcry-rsa-keygrip-leading-zero`.
- `usage-gpg-always-trust-untrusted-recipient`:
  `gpg-rsa-keyring-md-asnoid`, `gcry-md-asnoid-sha-family`, and
  `gcry-rsa-keygrip-leading-zero`.
- `usage-gpg-import-secret-key`: `gpg-rsa-keyring-md-asnoid`,
  `gcry-pk-map-name-ecc-aliases`, and `gcry-eddsa-testkey-import-seed`.

Focused validator result:

- Sign, verify, encrypt, decrypt-only, keys, import/export, recipient,
  hidden-recipient, trust/ownertrust/trustdb, fingerprint, revocation, revuid,
  list-secret, list-keys, quick UID/expiry, hash-algo, password, use-agent,
  and batch-list focused port-mode runs passed.
- No phase-6 validator defect skips were added. The decrypt-focused glob still
  includes the existing phase-5 exact skip for
  `usage-gpg-symmetric-compress-z9-decrypt` at validator commit
  `87b321fe728340d6fc6dd2f638583cca82c667c3`; all unaffected decrypt cases
  executed.
- Port override installation evidence is complete for all focused phase 6
  artifact roots via
  `python3 safe/scripts/check-validator-port-evidence.py --port-lock validator-local/proof/local-port-debs-lock.json --override-root validator-local/override-debs ...`.

## Phase 7: Catch-All Remaining Validator Failures

- Implement phase: `impl_p07_fix_remaining_validator_failures`
- Phase tag: `phase/impl_p07_fix_remaining_validator_failures`
- Safe port identity: implement phase and phase tag above. Package inputs are
  rebuilt from the phase tag before final full validator execution; this report
  uses that tag identity instead of embedding the final report commit hash.
- Validator checkout: `validator/`
- Validator commit: `87b321fe728340d6fc6dd2f638583cca82c667c3`
- Full port artifact root: `validator-artifacts/p07-port-full/`

Remaining safe-side validator failures: none.

Safety review fix:

- The required upstream harness exposed an X448 high-level ECDH compatibility
  issue: `gcry_pk_encrypt` returned `0x40`-prefixed Montgomery points for
  X448, while libgcrypt's X448 path returns raw 56-byte RFC 7748 values. This
  was fixed in `safe/src/pubkey/ecc.rs` by preserving the existing prefixed
  Curve25519 ECDH behavior but returning unprefixed X448 ECDH result bytes.
  Regression: `gcry-x448-ecdh-raw-result`.

Full safe validator result:

- Results: 171 passed, 0 failed, 4 skipped, 175 total.
- Source-facing cases: all 5 passed.
- Usage cases: 166 passed, 0 failed, 4 skipped.
- No additional validator safe-side compatibility, package metadata,
  development metadata, ABI, or C ABI failures remained after phases 3 through
  6. The X448 fix above came from the required upstream safety review, not from
  a failing non-skipped validator testcase.

Validator-side skips:

- The only skipped testcase results are the four phase-5 exact port-mode skips
  for validator commit `87b321fe728340d6fc6dd2f638583cca82c667c3`:
  `usage-gpg-symmetric-cipher-camellia128`,
  `usage-gpg-symmetric-compress-z9-decrypt`,
  `usage-gpg-symmetric-list-packets-s2k-sha256`, and
  `usage-gpg-symmetric-s2k-mode1-salted`.
- These skips remain documented in
  `safe/scripts/validator-libgcrypt-skips.json` and fail closed on any other
  validator commit. No phase-7 validator defect skips were added.
- The official validator matrix/proof path remains unavailable at this
  validator commit because the checkout contains libgcrypt testcase assets but
  the inventory rejects `--library libgcrypt`. The port-owned wrapper therefore
  used the same direct Docker fallback as earlier phases.

Port override installation evidence: complete.

- `python3 safe/scripts/check-validator-port-evidence.py --port-lock validator-local/proof/local-port-debs-lock.json --override-root validator-local/override-debs --artifact-root validator-artifacts/p07-port-full`
  passed.
- Every non-skipped port result records `override_debs_installed: true` and
  proves installation of the locked local `libgcrypt20` and `libgcrypt20-dev`
  override packages.
- The final report contains no unresolved safe-side validator failures.
