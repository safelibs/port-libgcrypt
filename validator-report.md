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
