# Phase Name

Final validator report and clean run

# Implement Phase ID

`impl_p08_final_validator_report`

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
- Phase 7 commit and report.
- `validator/` checkout at the commit used for final validation.
- Validator wrapper and port evidence checker from phase 1.
- Package/development probe from phase 3.
- `safe/scripts/validator-libgcrypt-skips.json`.
- Current safe packages and all regression tests.

# New Outputs

- Final `validator-report.md` with complete clean-run summary.
- Package/development probe artifacts under
  `validator-artifacts/p08-package-dev-probe/`.
- Final original, port, optional proof, and optional site artifacts under
  `validator-artifacts/p08-final/`.
- Any final report-only corrections.

# File Changes

- `validator-report.md`

# Implementation Details

## Workflow-Wide Requirements For This Phase

- Consume the listed preexisting inputs in place. Existing source snapshots, metadata, tests, packages, validator checkouts, and prior artifacts are inputs, not rediscovery or regeneration tasks unless this phase explicitly rebuilds generated package/validator artifacts.
- Keep `validator/`, `validator-local/`, and `validator-artifacts/` external to the port repository. Do not commit nested validator contents or generated validator artifacts.
- Preserve the Rust toolchain contract: root `rust-toolchain.toml` and `safe/rust-toolchain.toml` must stay identical and pinned to Rust `1.85.1` with `profile = "minimal"` and `components = ["rustfmt"]`.
- Run `safe/scripts/check-rust-toolchain.sh` before every Cargo, release-library, Debian package, or dependent safe-image build.
- Build any package artifacts used as validator inputs from a clean phase commit after `phase/impl_p08_final_validator_report` points at `HEAD`. If tracked files or `validator-report.md` change after validation, amend the same phase commit, force-update the phase tag, rebuild packages, regenerate `validator-local`, and rerun the phase validator commands until the worktree is clean and artifacts match the final phase commit.
- `validator-report.md` must identify the safe port by implement phase ID and `phase/impl_p08_final_validator_report`, not by embedding the literal hash of the final report commit.

## Phase-Specific Details

- Rebuild safe packages from the current commit, regenerate local validator
  override metadata, and rerun the clean-container package/development probe
  before the final validator suite. The final report must include the
  `validator-artifacts/p08-package-dev-probe` result so the clean run proves the
  installed development package surface, not just testcase override evidence.
- Run the complete original baseline and complete safe candidate validator
  suite. At the inspected validator commit, this means 5 source cases and 170
  usage cases. Later phases must consume the fixed counts recorded by phase 2
  for the actual validator checkout. The safe candidate run is not valid unless
  `safe/scripts/check-validator-port-evidence.py` confirms every non-skipped
  port testcase installed the local safe packages.
- Detect official libgcrypt matrix support with
  `python3 validator/tools/run_matrix.py --config validator/repositories.yml --tests-root validator/tests --list-libraries --library libgcrypt`.
  If that command succeeds and prints exactly `libgcrypt`, the official proof
  path is inventory-available. The verifier must still check
  `safe/scripts/validator-libgcrypt-skips.json`; if any active skip entry
  matches the final original or port full-suite run, official proof/site is not
  proof-eligible for that artifact root because skipped testcase result JSONs
  are rejected by the current validator proof loader.
  If inventory support is available and there are no active testcase skips, the
  verifier must run the proof/site commands below.
  If it fails, the verifier must capture the selection failure output under
  `validator-artifacts/p08-final/official-libgcrypt-list.err` and confirm
  `validator-report.md` names that exact validator inventory/proof defect plus
  the fallback artifact summary.
- If the official validator proof path supports libgcrypt by this point and
  there are no active testcase skips for the final artifact root, run:
  - Set `LIBGCRYPT_SOURCE_CASES`, `LIBGCRYPT_USAGE_CASES`, and
    `LIBGCRYPT_TOTAL_CASES` from the phase 2 counts already recorded in
    `validator-report.md`; abort if any count is missing or zero.
  - `python3 validator/tools/verify_proof_artifacts.py --config validator/repositories.yml --tests-root validator/tests --artifact-root validator-artifacts/p08-final --proof-output validator-artifacts/p08-final/proof/original-validation-proof.json --mode original --library libgcrypt --require-casts --min-source-cases "$LIBGCRYPT_SOURCE_CASES" --min-usage-cases "$LIBGCRYPT_USAGE_CASES" --min-cases "$LIBGCRYPT_TOTAL_CASES"`
  - `python3 validator/tools/verify_proof_artifacts.py --config validator/repositories.yml --tests-root validator/tests --artifact-root validator-artifacts/p08-final --proof-output validator-artifacts/p08-final/proof/port-validation-proof.json --mode port --library libgcrypt --require-casts --min-source-cases "$LIBGCRYPT_SOURCE_CASES" --min-usage-cases "$LIBGCRYPT_USAGE_CASES" --min-cases "$LIBGCRYPT_TOTAL_CASES" --ports-root /home/yans/safelibs/pipeline/ports`
  - `python3 validator/tools/render_site.py --config validator/repositories.yml --tests-root validator/tests --artifact-root validator-artifacts/p08-final --proof-path validator-artifacts/p08-final/proof/original-validation-proof.json --proof-path validator-artifacts/p08-final/proof/port-validation-proof.json --output-root validator-artifacts/p08-final/site`
  - `bash validator/scripts/verify-site.sh --config validator/repositories.yml --tests-root validator/tests --artifacts-root validator-artifacts/p08-final --proof-path validator-artifacts/p08-final/proof/original-validation-proof.json --proof-path validator-artifacts/p08-final/proof/port-validation-proof.json --site-root validator-artifacts/p08-final/site --library libgcrypt`
- If the official proof path still cannot load libgcrypt due to validator
  inventory omissions, document the skipped proof check and include the
  port-owned wrapper's complete per-case summary as the final validation
  artifact. This skip must name the validator files and error messages that
  make the official path unavailable, include the phrase
  `Official validator inventory/proof defect`, and include a
  `Fallback artifact summary` for `validator-artifacts/p08-final`.
- If active testcase skips exist in the final artifact root, document the
  skipped proof/site check as `Official validator proof/status limitation`, list
  each skipped `<mode>:<testcase_id>` and the validator commit, state that the
  current validator proof loader accepts only `passed` and `failed` statuses,
  and include the port-owned wrapper's complete non-skipped per-case summary as
  the `Fallback artifact summary` for `validator-artifacts/p08-final`.
- The final report must include:
  - Validator URL and commit.
  - Safe port phase tag (`phase/impl_p08_final_validator_report`) and a note
    that verifiers resolve the exact commit with `git rev-parse`; do not embed
    the literal hash of the final report commit in the tracked report.
  - Exact commands executed.
  - Original baseline result.
  - Safe candidate result.
  - Port override installation evidence, including package names, versions,
    architectures, filenames, SHA256s, and artifact roots checked.
  - Package/development probe result and artifact root.
  - Official proof/site status. If official proof/site ran, include proof and
    site artifact paths. If it did not run because libgcrypt was not selectable
    through the official inventory, include the exact official libgcrypt
    selection error and fallback artifact summary. If it did not run because
    active testcase skips produced skipped result JSONs, include
    `Official validator proof/status limitation`, the skipped
    `<mode>:<testcase_id>` values, and the fallback artifact summary.
  - Testcase counts.
  - Failures found by phase.
  - Regression tests added.
  - Fixes applied with file/module summaries.
  - Validator bugs and skipped checks, if any.
  - Final status.
- Commit final report updates. End with one commit whose subject begins
  `impl_p08_final_validator_report:` and tag it
  `phase/impl_p08_final_validator_report`.

# Verification Phases

- Phase ID: `check_p08_final_validator_clean_run`
- Type: `check`
- Fixed `bounce_target`: `impl_p08_final_validator_report`
- Purpose: final software-tester gate proving a clean original baseline,
  clean safe validator run, current local safe packages, and complete report.
- Commands:
  - `test "$(git rev-parse HEAD)" = "$(git rev-parse phase/impl_p08_final_validator_report)"`
  - `test "$(git rev-parse HEAD^)" = "$(git rev-parse phase/impl_p07_fix_remaining_validator_failures)"`
  - `bash -c 'test -z "$(git status --short)"'`
  - `bash -c 'git check-ignore -q validator/ && git check-ignore -q validator-local/ && git check-ignore -q validator-artifacts/'`
  - `bash -c 'test -z "$(git ls-files -- validator validator-local validator-artifacts)"'`
  - `git -C validator rev-parse HEAD`
  - `safe/scripts/check-rust-toolchain.sh`
  - `safe/scripts/check-dependent-metadata.sh`
  - `cargo fmt --manifest-path safe/Cargo.toml -- --check`
  - `cargo build --manifest-path safe/Cargo.toml --release --locked --offline`
  - `safe/scripts/build-release-lib.sh`
  - `safe/scripts/check-no-upstream-bridge.sh`
  - `safe/scripts/check-abi.sh --all`
  - `safe/scripts/run-upstream-tests.sh --all`
  - `safe/scripts/run-regression-tests.sh --all`
  - `safe/scripts/run-compat-smoke.sh --all`
  - `safe/scripts/build-debs.sh`
  - `safe/scripts/check-deb-metadata.sh --dist safe/dist`
  - `python3 safe/scripts/prepare-validator-local-port.py --validator-dir validator --dist safe/dist --output-root validator-local`
  - `bash safe/scripts/check-validator-package-dev-probe.sh --dist safe/dist --override-root validator-local/override-debs --port-lock validator-local/proof/local-port-debs-lock.json --artifact-root validator-artifacts/p08-package-dev-probe`
  - `bash safe/scripts/run-validator-libgcrypt.sh --validator-dir validator --mode original --artifact-root validator-artifacts/p08-final --record-casts`
  - `bash safe/scripts/run-validator-libgcrypt.sh --validator-dir validator --mode port --artifact-root validator-artifacts/p08-final --override-root validator-local/override-debs --port-lock validator-local/proof/local-port-debs-lock.json --record-casts`
  - `python3 safe/scripts/check-validator-port-evidence.py --port-lock validator-local/proof/local-port-debs-lock.json --override-root validator-local/override-debs --artifact-root validator-artifacts/p08-final`
  - `mkdir -p validator-artifacts/p08-final/proof validator-artifacts/p08-final/site`
  - `python3 -c 'import json, subprocess; from pathlib import Path; out=Path("validator-artifacts/p08-final"); (out/"active-testcase-skips").unlink(missing_ok=True); (out/"no-active-testcase-skips").unlink(missing_ok=True); vc=subprocess.check_output(["git","-C","validator","rev-parse","HEAD"], text=True).strip(); data=json.load(open("safe/scripts/validator-libgcrypt-skips.json")); skips=data.get("skips", []); assert data.get("schema_version")==1; assert data.get("validator_commit")==vc; assert all(entry.get("validator_commit")==vc for entry in skips); assert all(entry.get("mode") in {"original","port"} for entry in skips); active=[str(entry.get("mode"))+":"+str(entry.get("testcase_id")) for entry in skips]; (out/"active-testcase-skips").write_text("\n".join(active)+"\n") if active else (out/"no-active-testcase-skips").write_text("none\n")'`
  - `bash -c 'set -euo pipefail; rm -f validator-artifacts/p08-final/official-libgcrypt-supported validator-artifacts/p08-final/official-libgcrypt-unsupported; if python3 validator/tools/run_matrix.py --config validator/repositories.yml --tests-root validator/tests --list-libraries --library libgcrypt >validator-artifacts/p08-final/official-libgcrypt-list.txt 2>validator-artifacts/p08-final/official-libgcrypt-list.err && grep -qx libgcrypt validator-artifacts/p08-final/official-libgcrypt-list.txt; then touch validator-artifacts/p08-final/official-libgcrypt-supported; else touch validator-artifacts/p08-final/official-libgcrypt-unsupported; fi'`
  - `bash -c 'set -euo pipefail; test ! -e validator-artifacts/p08-final/official-libgcrypt-supported || test -e validator-artifacts/p08-final/active-testcase-skips || { SOURCE=$(awk -F": *" "/^libgcrypt_source_cases:/ {print \$2}" validator-report.md | tail -1); USAGE=$(awk -F": *" "/^libgcrypt_usage_cases:/ {print \$2}" validator-report.md | tail -1); TOTAL=$(awk -F": *" "/^libgcrypt_total_cases:/ {print \$2}" validator-report.md | tail -1); for value in "$SOURCE" "$USAGE" "$TOTAL"; do case "$value" in ""|*[!0-9]*) exit 1;; esac; test "$value" -gt 0; done; python3 validator/tools/verify_proof_artifacts.py --config validator/repositories.yml --tests-root validator/tests --artifact-root validator-artifacts/p08-final --proof-output validator-artifacts/p08-final/proof/original-validation-proof.json --mode original --library libgcrypt --require-casts --min-source-cases "$SOURCE" --min-usage-cases "$USAGE" --min-cases "$TOTAL"; python3 validator/tools/verify_proof_artifacts.py --config validator/repositories.yml --tests-root validator/tests --artifact-root validator-artifacts/p08-final --proof-output validator-artifacts/p08-final/proof/port-validation-proof.json --mode port --library libgcrypt --require-casts --min-source-cases "$SOURCE" --min-usage-cases "$USAGE" --min-cases "$TOTAL" --ports-root /home/yans/safelibs/pipeline/ports; python3 validator/tools/render_site.py --config validator/repositories.yml --tests-root validator/tests --artifact-root validator-artifacts/p08-final --proof-path validator-artifacts/p08-final/proof/original-validation-proof.json --proof-path validator-artifacts/p08-final/proof/port-validation-proof.json --output-root validator-artifacts/p08-final/site; bash validator/scripts/verify-site.sh --config validator/repositories.yml --tests-root validator/tests --artifacts-root validator-artifacts/p08-final --proof-path validator-artifacts/p08-final/proof/original-validation-proof.json --proof-path validator-artifacts/p08-final/proof/port-validation-proof.json --site-root validator-artifacts/p08-final/site --library libgcrypt; }'`
  - `bash -c "set -euo pipefail; test ! -e validator-artifacts/p08-final/official-libgcrypt-unsupported || python3 -c 'from pathlib import Path; report=Path(\"validator-report.md\").read_text(); err=Path(\"validator-artifacts/p08-final/official-libgcrypt-list.err\").read_text().strip(); out=Path(\"validator-artifacts/p08-final/official-libgcrypt-list.txt\").read_text().strip(); detail=(err or out).strip(); required=[\"Official validator inventory/proof defect\",\"Fallback artifact summary\",\"validator-artifacts/p08-final\"]; errors=[\"missing report fields: \"+\", \".join(item for item in required if item not in report)] if any(item not in report for item in required) else []; errors += [\"report does not include official libgcrypt selection failure output\"] if detail and detail not in report else []; raise SystemExit(\"\\n\".join(errors) if errors else 0)'"`
  - `bash -c "set -euo pipefail; test ! -e validator-artifacts/p08-final/active-testcase-skips || python3 -c 'from pathlib import Path; report=Path(\"validator-report.md\").read_text(); skips=Path(\"validator-artifacts/p08-final/active-testcase-skips\").read_text().splitlines(); required=[\"Official validator proof/status limitation\",\"Fallback artifact summary\",\"validator-artifacts/p08-final\"]; errors=[]; missing=[item for item in required if item not in report]; errors += [\"missing report fields: \"+\", \".join(missing)] if missing else []; errors += [\"report missing active testcase skip \"+item for item in skips if item and item not in report]; raise SystemExit(\"\\n\".join(errors) if errors else 0)'"`
  - `python3 -c 'import subprocess, sys; from pathlib import Path; text=Path("validator-report.md").read_text(); required=["Validator commit","Safe port phase tag","Commands executed","Testcase counts","Port override installation evidence","Package/development probe","Official proof/site status","Failures found","Regression tests","Fixes applied","Final status"]; phase="phase/impl_p08_final_validator_report"; head=subprocess.check_output(["git","rev-parse","HEAD"], text=True).strip(); errors=[]; missing=[item for item in required if item not in text]; errors += ["missing report fields: "+", ".join(missing)] if missing else []; errors += ["missing final phase tag in report"] if phase not in text else []; errors += ["validator-report.md must not embed the final safe commit hash; use the phase tag"] if head in text else []; sys.exit("\\n".join(errors) if errors else 0)'`

- Phase ID: `check_p08_final_senior_review`
- Type: `check`
- Fixed `bounce_target`: `impl_p08_final_validator_report`
- Purpose: final senior review of report accuracy, workflow contract,
  safe-side-only fixes, safety posture, and artifact flow.
- Commands:
  - `test "$(git rev-parse HEAD)" = "$(git rev-parse phase/impl_p08_final_validator_report)"`
  - `test "$(git rev-parse HEAD^)" = "$(git rev-parse phase/impl_p07_fix_remaining_validator_failures)"`
  - `bash -c 'test -z "$(git status --short)"'`
  - `bash -c 'git check-ignore -q validator/ && git check-ignore -q validator-local/ && git check-ignore -q validator-artifacts/'`
  - `git diff --stat HEAD^..HEAD`
  - `bash -c 'test -z "$(git ls-files -- validator validator-local validator-artifacts)"'`
  - `bash -c 'if git diff --name-only HEAD^..HEAD | grep -E "^(validator|validator-local|validator-artifacts)(/|$)"; then exit 1; fi'`
  - `safe/scripts/check-no-upstream-bridge.sh`
  - `bash -c 'rg -n "safe_gcry_stub_zero|todo!|unimplemented!|Not implemented" safe/src safe/cabi safe/build.rs safe/scripts safe/tests/regressions safe/debian test-original.sh && exit 1 || true'`
  - Review `validator-report.md`, `safe/tests/regressions/manifest.json`,
    helper scripts, and the final validator artifact summaries.

# Success Criteria

- Full safe validator suite passes, except for explicitly justified
  validator-side skips, with verified override-install evidence for every
  non-skipped port testcase.
- The final clean-container package/development probe passes against the same
  local safe `.deb` files used by the final port validator run.
- The final verifier either runs `verify_proof_artifacts.py`, `render_site.py`,
  and `scripts/verify-site.sh` for official libgcrypt support with the phase 2
  fixed case counts and no active testcase skips, or confirms the report records
  the exact official libgcrypt inventory/proof defect or proof/status limitation
  and fallback artifact summary.
- `validator-report.md` is complete and matches final artifact summaries.
- Worktree is clean and validator checkout/artifacts remain external ignored
  artifacts.

# Git Commit Requirement

The implementer must commit work to git before yielding. The commit subject must start with `impl_p08_final_validator_report:`, and the implementer must force-update local tag `phase/impl_p08_final_validator_report` to that phase commit before yielding.
