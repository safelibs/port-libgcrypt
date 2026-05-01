# Phase Name

Baseline full validator run and failure triage

# Implement Phase ID

`impl_p02_validator_baseline_triage`

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
- Phase 1 commit and tag.
- `validator/` checkout.
- `safe/scripts/prepare-validator-local-port.py`.
- `safe/scripts/run-validator-libgcrypt.sh`.
- `safe/scripts/check-validator-port-evidence.py`.
- `safe/scripts/validator-libgcrypt-skips.json`.
- `safe/dist/` and package build scripts.
- `validator/tests/libgcrypt/` if present in the checked-out validator.

# New Outputs

- Full original baseline artifacts under `validator-artifacts/p02-original/`.
- Full safe candidate artifacts under `validator-artifacts/p02-port/`.
- Updated `validator-report.md` with:
  - Validator commit and invocation mode.
  - Count of source, usage, and total libgcrypt cases discovered, including
    exact machine-readable lines `libgcrypt_source_cases: <integer>`,
    `libgcrypt_usage_cases: <integer>`, and
    `libgcrypt_total_cases: <integer>` for later proof thresholds.
  - Original baseline pass/fail status.
  - Safe candidate pass/fail status.
  - Port override installation evidence summary. If evidence is incomplete,
    classify the affected cases under `packaging-install`; phase 3 fixes those
    failures first.
  - Failure inventory grouped by class.
  - Any validator-side skip, such as current validator inventory not exposing
    libgcrypt through the official matrix path.
  - The fixed libgcrypt case counts that later phases must consume for proof
    thresholds and report checks instead of rerunning testcase discovery.

# File Changes

- `validator-report.md`
- `safe/scripts/run-validator-libgcrypt.sh` only if baseline use finds a
  wrapper bug.
- `safe/scripts/prepare-validator-local-port.py` only if lock or override
  generation is incomplete.
- `safe/scripts/check-validator-port-evidence.py` only if baseline use finds an
  evidence-checker bug.
- `safe/scripts/validator-libgcrypt-skips.json` only if baseline identifies a
  concrete testcase execution bug that must be skipped before a complete triage
  run can finish; the skip must be exact-commit-specific and documented in
  `validator-report.md`.

# Implementation Details

## Workflow-Wide Requirements For This Phase

- Consume the listed preexisting inputs in place. Existing source snapshots, metadata, tests, packages, validator checkouts, and prior artifacts are inputs, not rediscovery or regeneration tasks unless this phase explicitly rebuilds generated package/validator artifacts.
- Keep `validator/`, `validator-local/`, and `validator-artifacts/` external to the port repository. Do not commit nested validator contents or generated validator artifacts.
- Preserve the Rust toolchain contract: root `rust-toolchain.toml` and `safe/rust-toolchain.toml` must stay identical and pinned to Rust `1.85.1` with `profile = "minimal"` and `components = ["rustfmt"]`.
- Run `safe/scripts/check-rust-toolchain.sh` before every Cargo, release-library, Debian package, or dependent safe-image build.
- Build any package artifacts used as validator inputs from a clean phase commit after `phase/impl_p02_validator_baseline_triage` points at `HEAD`. If tracked files or `validator-report.md` change after validation, amend the same phase commit, force-update the phase tag, rebuild packages, regenerate `validator-local`, and rerun the phase validator commands until the worktree is clean and artifacts match the final phase commit.
- `validator-report.md` must identify the safe port by implement phase ID and `phase/impl_p02_validator_baseline_triage`, not by embedding the literal hash of the final report commit.

## Phase-Specific Details

- Rebuild safe packages so the candidate run consumes current safe code.
- Run the original Ubuntu libgcrypt validator suite first. Original failures
  indicate validator or environment problems, not safe regressions, and must be
  documented separately.
- Run the safe candidate suite with local override packages prepared from
  `safe/dist`. A failing safe testcase is still useful triage data. A port-mode
  artifact root that lacks override-install evidence is invalid as a final safe
  validator result, but in this baseline phase it must be preserved and
  classified under `packaging-install` so the next phase can fix package setup
  before source or usage compatibility phases depend on rebuilt packages.
- If the official validator matrix path works and the phase 2 original and port
  artifact roots contain no skipped testcase result JSONs, also generate
  validator proof artifacts for the selected libgcrypt run:
  - Original proof with at least the discovered source/usage/total counts.
  - Port proof with the same thresholds.
  - Use `--ports-root /home/yans/safelibs/pipeline/ports` if supported, so the
    proof can include unsafe counts.
- If a validator testcase execution bug forces an active skip during phase 2,
  do not run proof generation for an artifact root containing `status:
  "skipped"`. Record `Official validator proof/status limitation` in
  `validator-report.md`, list the skipped testcase IDs and validator commit, and
  use the wrapper's full non-skipped per-case summary as the phase proof
  substitute.
- If the official path is unavailable because the validator does not support
  libgcrypt in its inventory, use the direct Docker fallback from phase 1 and
  record that the official matrix/proof check was skipped due to validator
  inventory bug while all existing libgcrypt testcase scripts were still run.
- Group safe candidate failures into these buckets:
  - `source-api`: the 5 source-facing cases, especially AES CTR, SHA-256,
    HMAC-SHA256, MPI arithmetic, and nonce generation.
  - `usage-symmetric-digest-random`: GPG `--print-md`, `--gen-random`,
    symmetric encryption/decryption, list-packets symmetric cases, cipher
    preference/list-config cases, and digest preference cases.
  - `usage-pubkey-keyring`: GPG key generation, import/export, fingerprint,
    sign/verify, recipient encryption/decryption, hidden recipient, trustdb,
    ownertrust, secret-key, keygrip, and revocation cases.
  - `packaging-install`: override `.deb` install, symbol/linker, headers,
    `libgcrypt-config`, pkg-config, Multi-Arch, and dependency issues.
  - `validator-bug`: only failures that are demonstrably in the validator
    harness rather than libgcrypt-safe.
- Do not fix safe code in this phase except wrapper/report bugs. The phase is
  for a reproducible baseline and triage inventory.
- Commit the updated report and any wrapper fixes. End with one commit whose
  subject begins `impl_p02_validator_baseline_triage:` and tag it
  `phase/impl_p02_validator_baseline_triage`.

# Verification Phases

- Phase ID: `check_p02_validator_baseline_triage`
- Type: `check`
- Fixed `bounce_target`: `impl_p02_validator_baseline_triage`
- Purpose: software-tester verification that a full original baseline and full
  safe candidate run were executed or that any validator-side skip is precisely
  documented.
- Commands:
  - `test "$(git rev-parse HEAD)" = "$(git rev-parse phase/impl_p02_validator_baseline_triage)"`
  - `test "$(git rev-parse HEAD^)" = "$(git rev-parse phase/impl_p01_validator_checkout_invocation)"`
  - `bash -c 'test -z "$(git status --short)"'`
  - `bash -c 'git check-ignore -q validator/ && git check-ignore -q validator-local/ && git check-ignore -q validator-artifacts/'`
  - `bash -c 'test -z "$(git ls-files -- validator validator-local validator-artifacts)"'`
  - `bash -c 'if git diff --name-only HEAD^..HEAD | grep -E "^(validator|validator-local|validator-artifacts)(/|$)"; then exit 1; fi'`
  - `safe/scripts/check-rust-toolchain.sh`
  - `safe/scripts/build-debs.sh`
  - `safe/scripts/check-deb-metadata.sh --dist safe/dist`
  - `python3 safe/scripts/prepare-validator-local-port.py --validator-dir validator --dist safe/dist --output-root validator-local`
  - `bash safe/scripts/run-validator-libgcrypt.sh --validator-dir validator --mode original --artifact-root validator-artifacts/p02-original --record-casts`
  - `bash safe/scripts/run-validator-libgcrypt.sh --validator-dir validator --mode port --artifact-root validator-artifacts/p02-port --override-root validator-local/override-debs --port-lock validator-local/proof/local-port-debs-lock.json --record-casts || true`
  - `python3 safe/scripts/check-validator-port-evidence.py --port-lock validator-local/proof/local-port-debs-lock.json --override-root validator-local/override-debs --artifact-root validator-artifacts/p02-port || true`
  - `test -d validator-artifacts/p02-original`
  - `test -d validator-artifacts/p02-port`
  - `python3 -c 'import re, sys; from pathlib import Path; text=Path("validator-report.md").read_text(); required=["Validator commit","Original baseline","Safe candidate","Port override installation evidence","Failure inventory","libgcrypt_source_cases:","libgcrypt_usage_cases:","libgcrypt_total_cases:"]; missing=[item for item in required if item not in text]; counts={key: re.search(r"^"+key+r":\s*([1-9][0-9]*)\s*$", text, re.M) for key in ["libgcrypt_source_cases","libgcrypt_usage_cases","libgcrypt_total_cases"]}; missing += [key for key, match in counts.items() if match is None]; sys.exit("missing report fields: "+", ".join(missing) if missing else 0)'`
  - `bash -c 'test -z "$(git status --short)"'`

# Success Criteria

- The report has enough detail for phase 3 to fix every `packaging-install`
  blocker first and for later phases to select failure buckets without
  rerunning discovery.
- Original baseline failures, if any, are separated from safe candidate
  failures.
- Safe candidate artifact roots that lack override evidence are not accepted as
  passing validator results; they are explicitly inventoried as
  `packaging-install` failures for phase 3.
- Safe candidate failures are not marked as validator bugs without a concrete
  reason.

# Git Commit Requirement

The implementer must commit work to git before yielding. The commit subject must start with `impl_p02_validator_baseline_triage:`, and the implementer must force-update local tag `phase/impl_p02_validator_baseline_triage` to that phase commit before yielding.
