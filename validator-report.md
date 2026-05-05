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
