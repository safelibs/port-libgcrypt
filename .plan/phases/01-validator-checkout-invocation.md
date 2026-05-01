# Phase Name

Validator checkout and local invocation harness

# Implement Phase ID

`impl_p01_validator_checkout_invocation`

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
- `safe/` Rust port and package scripts.
- Root `rust-toolchain.toml`, `safe/rust-toolchain.toml`, and
  `safe/scripts/check-rust-toolchain.sh`.
- `safe/dist/` if it already exists; treat it as generated evidence from prior
  phases, but rebuild it for validator input after the phase tag points at
  `HEAD` and verify the manifest `phase_commit` and `phase_tag` match.
- `safe/tests/dependents/metadata/install-packages.noble.lock` and
  `safe/tests/dependents/metadata/safe-debs.noble.lock`.
- `original/libgcrypt20-1.10.3/`.
- Existing `.gitignore`.
- Existing `validator/` checkout if present.
- Validator upstream URL `https://github.com/safelibs/validator`.

# New Outputs

- External checkout `validator/` cloned or fast-forwarded to the current
  upstream commit.
- Root `.gitignore` entries for `/validator/`, `/validator-artifacts/`, and
  `/validator-local/`.
- `safe/scripts/prepare-validator-local-port.py`.
- `safe/scripts/run-validator-libgcrypt.sh`.
- `safe/scripts/check-validator-port-evidence.py`.
- `safe/scripts/validator-libgcrypt-skips.json` initialized with
  `schema_version: 1`, the current validator commit, and an empty `skips`
  array.
- Verified or repaired Rust 1.85.1 toolchain pin consumed by all package build
  paths.
- Verified safe package lock split for Ubuntu snapshot/base-image packages
  versus locally rebuilt safe `.deb` packages.
- Initial `validator-report.md` with validator commit, README-derived
  invocation notes, libgcrypt support detection, original smoke result, safe
  port smoke result, and port-mode override-install evidence status. A failing
  safe port smoke result must be recorded for phase 2 triage instead of fixed
  or hidden in this setup phase.
- Ignored generated directories `validator-local/` and `validator-artifacts/`.

# File Changes

- `.gitignore`
- `rust-toolchain.toml` only if missing or inconsistent with
  `safe/rust-toolchain.toml`.
- `safe/rust-toolchain.toml` only if missing or inconsistent with the root
  pin.
- `safe/scripts/check-rust-toolchain.sh` only if it does not enforce Rust
  `1.85.1` before Cargo and Debian package builds.
- `safe/tests/dependents/metadata/safe-debs.noble.lock` only if the local
  safe-deb policy is missing or ambiguous.
- `safe/tests/dependents/validate-installed-packages.py` only if safe-image
  installed-package validation does not distinguish Ubuntu packages from local
  safe `.deb` packages.
- `safe/scripts/prepare-validator-local-port.py`
- `safe/scripts/run-validator-libgcrypt.sh`
- `safe/scripts/check-validator-port-evidence.py`
- `safe/scripts/validator-libgcrypt-skips.json`
- `validator-report.md`

# Implementation Details

## Workflow-Wide Requirements For This Phase

- Consume the listed preexisting inputs in place. Existing source snapshots, metadata, tests, packages, validator checkouts, and prior artifacts are inputs, not rediscovery or regeneration tasks unless this phase explicitly rebuilds generated package/validator artifacts.
- Keep `validator/`, `validator-local/`, and `validator-artifacts/` external to the port repository. Do not commit nested validator contents or generated validator artifacts.
- Preserve the Rust toolchain contract: root `rust-toolchain.toml` and `safe/rust-toolchain.toml` must stay identical and pinned to Rust `1.85.1` with `profile = "minimal"` and `components = ["rustfmt"]`.
- Run `safe/scripts/check-rust-toolchain.sh` before every Cargo, release-library, Debian package, or dependent safe-image build.
- Build any package artifacts used as validator inputs from a clean phase commit after `phase/impl_p01_validator_checkout_invocation` points at `HEAD`. If tracked files or `validator-report.md` change after validation, amend the same phase commit, force-update the phase tag, rebuild packages, regenerate `validator-local`, and rerun the phase validator commands until the worktree is clean and artifacts match the final phase commit.
- `validator-report.md` must identify the safe port by implement phase ID and `phase/impl_p01_validator_checkout_invocation`, not by embedding the literal hash of the final report commit.

## Phase-Specific Details

- Clone/update `validator/`:
  - If `validator/.git` exists, verify `origin` is
    `https://github.com/safelibs/validator` or an equivalent GitHub URL, then
    run `git -C validator pull --ff-only`.
  - If `validator/` does not exist, run
    `git clone https://github.com/safelibs/validator validator`.
  - Record `git -C validator rev-parse HEAD` in `validator-report.md`.
- Do not commit the nested validator checkout. Add ignore entries for
  `/validator/`, `/validator-artifacts/`, and `/validator-local/`.
- Verify the Rust and package-lock contracts before creating validator
  adapters:
  - `rust-toolchain.toml` and `safe/rust-toolchain.toml` must be identical and
    pinned to Rust `1.85.1`.
  - `safe/scripts/check-rust-toolchain.sh` must reject Ubuntu 24.04's packaged
    Rust 1.75 and must be called by `safe/scripts/build-debs.sh`,
    `safe/debian/rules`, `safe/scripts/build-release-lib.sh`, and
    `safe/scripts/build-dependent-image.sh`.
  - `safe/scripts/check-dependent-metadata.sh` must pass, proving that
    `install-packages.noble.lock` remains the Ubuntu/base-image package
    closure and `safe-debs.noble.lock` remains the local safe-deb policy for
    `libgcrypt20` and `libgcrypt20-dev`.
- Implement `safe/scripts/prepare-validator-local-port.py` as a deterministic
  adapter from the local safe `.deb` artifacts to validator's port override
  format:
  - Inputs: `--validator-dir`, `--dist`, and `--output-root`.
  - Read `safe/dist/safe-debs.manifest.json`.
  - Require manifest fields `phase_commit`, `phase_tag`,
    `toolchain.rustc_vv`, `toolchain.cargo_vv`, and package entries with
    `package_name`, `filename`, `architecture`, `version`,
    `source_package_name`, `source_version`, and `sha256`.
  - Require exactly the canonical safe packages `libgcrypt20` and
    `libgcrypt20-dev`.
  - Validate package names, versions, source package, source version,
    architecture, and file globs against
    `safe/tests/dependents/metadata/safe-debs.noble.lock`, while taking SHA256
    values from the freshly generated manifest rather than the committed lock.
  - Copy the `.deb` files to
    `validator-local/override-debs/libgcrypt/`.
  - Write `validator-local/proof/local-port-debs-lock.json` with
    `schema_version: 1`, `mode: "port"`, one `libraries` entry for
    `libgcrypt`, canonical packages `libgcrypt20` and `libgcrypt20-dev`,
    `repository` set to the GitHub `owner/name` from this port's `origin`
    remote (`safelibs/port-libgcrypt` in the current workspace),
    `release_tag` set to a deterministic local value such as
    `local-libgcrypt-safe`, `tag_ref` equal to
    `refs/tags/local-libgcrypt-safe`, `commit` equal to the current port HEAD,
    `debs` entries containing `package`, `filename`, `architecture`, `sha256`,
    `version`, and `size`, and an empty `unported_original_packages` list. The
    current validator accepts the standard `package`, `filename`,
    `architecture`, `sha256`, and `size` fields; the local `version` field is
    required for this port's independent override-install evidence checks.
  - Validate the copied files by hash before returning.
- Implement `safe/scripts/run-validator-libgcrypt.sh` as the single local
  entrypoint for validator runs:
  - Inputs: `--validator-dir`, `--mode original|port`, `--artifact-root`,
    optional `--override-root`, optional `--port-lock`, optional `--case`,
    optional `--case-glob`, optional `--kind source|usage`, and
    optional `--record-casts`.
  - Also support a standalone `--self-test-timeout` mode. This mode must create a
    temporary synthetic fallback testcase with `@timeout: 1` and a temporary fake
    `docker` executable or equivalent internal harness that sleeps past the
    deadline, run the same timeout-enforcement code used by real fallback cases,
    and assert that the internal testcase run returns nonzero only after writing
    a failed result JSON with `exit_code: 124`, a log containing
    `testcase timed out after 1 seconds`, and no leftover temporary status
    directory or named container. The `--self-test-timeout` command itself must
    exit zero when those assertions pass. It must not modify `validator/`.
  - Load `safe/scripts/validator-libgcrypt-skips.json` before selecting cases.
    The file must contain `schema_version: 1`, top-level `validator_commit`,
    and a `skips` array. Fail closed if the top-level `validator_commit` does
    not exactly match `git -C validator rev-parse HEAD`. Reject the run on any
    skip entry whose own `validator_commit` does not exactly match the same
    commit.
    A skip entry may match only one testcase ID, must name the affected mode,
    must include a concise reason, and must point at the
    `validator-report.md` section documenting the validator defect.
  - Enumerate the selected libgcrypt testcase IDs before choosing an execution
    path. Active skips are skip entries whose validator commit equals the
    checked-out validator `HEAD`, whose mode equals the requested mode, and
    whose exact testcase ID is in the selected full-suite or focused set.
    Unknown testcase IDs in active skip entries are fatal. Inactive entries for
    a different validator commit are fatal because the file is intentionally
    commit-specific.
  - First try the official validator matrix path by running
    `python3 validator/tools/testcases.py --config validator/repositories.yml --tests-root validator/tests --list-summary --library libgcrypt`.
  - If the official path succeeds, no filter options were requested, and there
    are no active skips for the selected full-suite run, call `validator/test.sh`
    with
    `--config validator/repositories.yml`, `--tests-root validator/tests`,
    `--artifact-root <artifact-root>`, `--library libgcrypt`, and
    `--mode <mode>` for both original and port mode. In port mode, also pass
    `--override-deb-root <override-root>` and `--port-deb-lock <port-lock>` to
    `validator/test.sh`. Do not pass `--case`, `--case-glob`, or `--kind` to
    `validator/test.sh`; the current validator matrix runner does not support
    per-testcase filters.
  - If the official path succeeds but `--case`, `--case-glob`, or `--kind` was
    requested, use the direct Docker fallback for that focused run.
  - If the official path succeeds but active skips match the selected
    full-suite run, use the direct Docker fallback for that run. Do not call
    `validator/test.sh`, because it would execute the skipped testcase and would
    not emit the port-owned skip result.
  - If the official path fails because libgcrypt is missing from
    `repositories.yml` or `tools/inventory.py`, record that as a validator
    invocation bug in the run output and use the direct Docker fallback.
  - The direct Docker fallback must not edit validator files. It must build the
    existing libgcrypt Dockerfile with
    `docker build -t safelibs-validator-libgcrypt -f validator/tests/libgcrypt/Dockerfile validator/tests`,
    enumerate executable case scripts under
    `validator/tests/libgcrypt/tests/cases/source` and `usage`, parse the
    metadata header using validator-compatible rules for `# @testcase:`,
    `# @title:`, `# @description:`, `# @timeout:`, `# @tags:`, and usage-case
    `# @client:` directives, require the header testcase ID to match the script
    filename, and require `@timeout` to be an integer from `1` through `7200`.
  - For each selected fallback case in either mode, create a fresh per-case host
    status directory and a unique Docker container name derived from the mode,
    testcase ID, and wrapper process ID. Launch Docker through a subprocess,
    process group, or shell `timeout --kill-after` wrapper that enforces the
    exact parsed testcase timeout. The implementation must always remove the
    container with `docker rm -f <container-name>` in the timeout and cleanup
    paths, tolerate the container already being gone, and remove the host status
    directory before moving to the next case.
  - Run each selected original-mode fallback case as
    `docker run --rm --name <container-name> --mount type=bind,src=<absolute-status-dir>,dst=/validator/status --env VALIDATOR_STATUS_DIR=/validator/status --entrypoint /validator/tests/libgcrypt/docker-entrypoint.sh safelibs-validator-libgcrypt <case-id> -- /validator/tests/libgcrypt/tests/cases/<kind>/<file>.sh`,
    but only under the per-case timeout wrapper described above.
  - For selected port-mode fallback cases, resolve
    `<override-root>/libgcrypt` to an absolute path before launching Docker,
    require that it contains exactly the `libgcrypt20` and `libgcrypt20-dev`
    `.deb` files named by `--port-lock`, validate their sizes and SHA256 values,
    create a fresh per-case host status directory, and add both the status mount
    and override mount before the image name:
    `docker run --rm --name <container-name> --mount type=bind,src=<absolute-status-dir>,dst=/validator/status --mount type=bind,src=<absolute-override-root>/libgcrypt,dst=/override-debs,readonly --env VALIDATOR_STATUS_DIR=/validator/status --entrypoint /validator/tests/libgcrypt/docker-entrypoint.sh safelibs-validator-libgcrypt <case-id> -- /validator/tests/libgcrypt/tests/cases/<kind>/<file>.sh`.
    The port-mode Docker command is also valid only when launched under the
    per-case timeout wrapper described above.
  - If the per-case timeout fires in either mode, treat that testcase as failed
    with exit code `124`. The per-case log must contain
    `testcase timed out after <timeout> seconds`, the result JSON must include
    `status: "failed"`, `exit_code: 124`, and `error` equal to
    `testcase timed out after <timeout> seconds`, and the wrapper must continue
    running later selected cases before returning nonzero for the overall run.
  - After every port-mode fallback case, fail the case regardless of testcase
    exit status unless `<absolute-status-dir>/override-installed` exists and
    `<absolute-status-dir>/override-installed-packages.tsv` proves that
    `libgcrypt20` and `libgcrypt20-dev` were installed with package names,
    versions, architectures, and filenames matching
    `validator-local/proof/local-port-debs-lock.json`.
  - For fallback results, write JSON summaries and logs under the requested
    `--artifact-root` using the validator matrix artifact layout:
    original results at `results/libgcrypt/*.json`, port results at
    `port/results/libgcrypt/*.json`, and summaries at
    `results/libgcrypt/summary.json` or `port/results/libgcrypt/summary.json`.
    Port result JSONs must include `override_debs_installed: true`,
    `port_debs`, `override_installed_packages`, `port_repository`,
    `port_commit`, `port_release_tag`, `port_tag_ref`, and
    `unported_original_packages` for every non-skipped testcase.
  - After either the official path or fallback path finishes, inspect the
    generated result JSONs selected by `--case`, `--case-glob`, `--kind`, or the
    full libgcrypt suite. Return nonzero if any selected non-skipped result has
    `status` other than `passed`, even if `validator/test.sh` returned zero.
    Phase 1's safe smoke command and phase 2's safe candidate command
    intentionally append `|| true` so those failures can be recorded in
    `validator-report.md`; fix and final phases must rely on the wrapper's
    nonzero exit to reject unresolved validator failures.
  - When a skip entry matches, still write a per-case result JSON with
    `status: "skipped"`, the testcase ID, the exact validator commit, the
    matching skip reason, and the report section. Do not run that testcase, and
    do not suppress any other selected testcase. Mark the run summary with an
    `official_proof_eligible: false` or equivalent field whenever any skipped
    result JSON is written, so final verifiers can distinguish a validator
    proof/status limitation from an inventory-selection limitation.
  - In `--mode port`, require both `--override-root` and `--port-lock`, and
    validate the local lock before launching any case.
  - Artifact cleanup must be mode-scoped. An original-mode run may replace only
    the original result subtree for the selected libgcrypt cases, and a port-mode
    run may replace only the port result subtree for the selected libgcrypt
    cases. The wrapper must preserve sibling mode results, proof directories,
    and site directories when the same `--artifact-root` is reused, as in the
    final phase.
- Implement `safe/scripts/check-validator-port-evidence.py` as an independent
  verifier for port-mode artifact roots:
  - Inputs: repeated `--artifact-root`, `--port-lock`, `--override-root`, and
    optional `--library` defaulting to `libgcrypt`.
  - Load the raw local port lock and require canonical packages `libgcrypt20`
    and `libgcrypt20-dev`, including `version`, `architecture`, `filename`,
    `sha256`, and `size`.
  - Validate that `--override-root/libgcrypt` contains exactly those `.deb`
    files and that their sizes and SHA256 values match the lock.
  - For each artifact root, inspect every testcase JSON under
    `port/results/libgcrypt/` except `summary.json`; require at least one
    testcase result.
  - For every non-skipped port testcase result, require
    `override_debs_installed: true`, require `port_debs` to match the lock's
    package, filename, architecture, SHA256, and size fields, and require
    `override_installed_packages` to match the lock's package, version,
    architecture, and filename fields in canonical package order.
  - Fail if an artifact root contains original-mode results only, missing port
    result JSONs, stale port commits, extra or missing override packages, or any
    port result that could have passed against Ubuntu's original packages.
- Record the validator inspection defect only as context. Re-detect against the
  actual checked-out validator commit.
- Commit only tracked port-side files and the report. End with one commit whose
  subject begins `impl_p01_validator_checkout_invocation:` and tag it
  `phase/impl_p01_validator_checkout_invocation`.

# Verification Phases

- Phase ID: `check_p01_validator_checkout_invocation`
- Type: `check`
- Fixed `bounce_target`: `impl_p01_validator_checkout_invocation`
- Purpose: software-tester verification that the validator checkout, ignore
  rules, local package override preparation, and smoke invocation path work.
- Commands:
  - `test "$(git rev-parse HEAD)" = "$(git rev-parse phase/impl_p01_validator_checkout_invocation)"`
  - `bash -c 'test -z "$(git status --short)"'`
  - `bash -c 'git check-ignore -q validator/ && git check-ignore -q validator-local/ && git check-ignore -q validator-artifacts/'`
  - `bash -c 'test -z "$(git ls-files -- validator validator-local validator-artifacts)"'`
  - `test -d validator/.git`
  - `git -C validator rev-parse HEAD`
  - `bash -c 'case "$(git -C validator remote get-url origin)" in https://github.com/safelibs/validator|https://github.com/safelibs/validator.git|git@github.com:safelibs/validator.git) ;; *) exit 1 ;; esac'`
  - `python3 -c 'import json, subprocess; data=json.load(open("safe/scripts/validator-libgcrypt-skips.json")); vc=subprocess.check_output(["git","-C","validator","rev-parse","HEAD"], text=True).strip(); assert data.get("schema_version")==1; assert data.get("validator_commit")==vc; assert isinstance(data.get("skips"), list)'`
  - `make -C validator unit`
  - `make -C validator check-testcases`
  - `cmp -s rust-toolchain.toml safe/rust-toolchain.toml`
  - `safe/scripts/check-rust-toolchain.sh`
  - `safe/scripts/check-dependent-metadata.sh`
  - `safe/scripts/build-debs.sh`
  - `safe/scripts/check-deb-metadata.sh --dist safe/dist`
  - `python3 safe/scripts/prepare-validator-local-port.py --validator-dir validator --dist safe/dist --output-root validator-local`
  - `bash safe/scripts/run-validator-libgcrypt.sh --self-test-timeout`
  - `bash safe/scripts/run-validator-libgcrypt.sh --validator-dir validator --mode original --artifact-root validator-artifacts/p01-original-smoke --case aes-ctr-roundtrip`
  - `bash safe/scripts/run-validator-libgcrypt.sh --validator-dir validator --mode port --artifact-root validator-artifacts/p01-port-smoke --override-root validator-local/override-debs --port-lock validator-local/proof/local-port-debs-lock.json --case aes-ctr-roundtrip || true`
  - `test -d validator-artifacts/p01-original-smoke`
  - `test -d validator-artifacts/p01-port-smoke`
  - `python3 safe/scripts/check-validator-port-evidence.py --port-lock validator-local/proof/local-port-debs-lock.json --override-root validator-local/override-debs --artifact-root validator-artifacts/p01-port-smoke || true`
  - `bash -c 'test -z "$(git status --short)"'`

# Success Criteria

- The smoke source testcase `aes-ctr-roundtrip` passes in original mode. The
  safe port smoke run is non-gating for safe compatibility; any safe failure is
  preserved in `validator-artifacts/p01-port-smoke` and listed for phase 2
  triage.
- The wrapper timeout self-test proves that the direct Docker fallback cannot
  hang forever: a synthetic one-second case times out, records failed result and
  log artifacts with exit code `124`, and cleans temporary status/container
  resources.
- The port smoke evidence checker is run and its result is recorded. Missing
  override-install evidence is classified as a packaging/install setup issue for
  phase 2 triage and phase 3 repair, not as a phase 1 harness failure unless
  the wrapper itself failed to create artifacts.
- `validator-report.md` records the validator commit, whether the official
  libgcrypt matrix path was available, and the exact smoke commands.
- The port worktree remains clean even though `validator/` and artifacts exist.

# Git Commit Requirement

The implementer must commit work to git before yielding. The commit subject must start with `impl_p01_validator_checkout_invocation:`, and the implementer must force-update local tag `phase/impl_p01_validator_checkout_invocation` to that phase commit before yielding.
