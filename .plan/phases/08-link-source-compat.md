# Phase Name

Source, link, and ABI compatibility harnesses

# Implement Phase ID

`impl_p08_link_source_compat`

# Preexisting Inputs

- Phase 7 committed tree and tag.
- `safe/Cargo.toml`
- `safe/Cargo.lock`
- `safe/.cargo/config.toml`
- `.cargo/config.toml` if committed by phase 1.
- `safe/vendor/**`
- `safe/build.rs`
- `safe/cabi/exports.c`
- `safe/cabi/exports.h`
- `safe/scripts/check-abi.sh`
- `safe/scripts/relink-original-objects.sh`
- `safe/scripts/run-compat-smoke.sh`
- `safe/scripts/check-no-upstream-bridge.sh`
- `safe/tests/original-build/`
- `safe/tests/compat/public-api-smoke.c`
- `safe/tests/compat/abi-only-exports.c`
- `safe/abi/*`
- `safe/docs/test-matrix.md`
- `safe/docs/abi-map.md`
- `original/libgcrypt20-1.10.3/src/`
- `original/libgcrypt20-1.10.3/tests/`
- `original/libgcrypt20-1.10.3/compat/`

# New Outputs

- Link-compatibility proof that original test objects link against safe `libgcrypt.so.20`.
- Source-compatibility proof for generated headers, `pkg-config`, `libgcrypt-config`, and `libgcrypt.m4`.
- Bridge-free ABI-only export probes.

# File Changes

- `safe/scripts/check-abi.sh`
- `safe/scripts/relink-original-objects.sh`
- `safe/scripts/run-compat-smoke.sh`
- `safe/tests/compat/public-api-smoke.c`
- `safe/tests/compat/abi-only-exports.c`
- `safe/cabi/exports.c`
- `safe/cabi/exports.h`
- `safe/docs/test-matrix.md`
- `safe/docs/abi-map.md`

# Implementation Details

- Keep C ABI varargs wrappers in `safe/cabi/exports.c` for `gcry_control`, `gcry_sexp_build`, `gcry_sexp_vlist`, `gcry_sexp_extract_param`, and `gcry_log_debug`.
- Replace any `dlopen`/`dlsym` ABI-only test with direct link or symbol-table checks so bridge scanning can cover `safe/tests/compat/`.
- Ensure `gcry_md_get` and `gcry_pk_register` remain exported with `GCRYPT_1.6` even where not public-header declarations.
- Expand `relink-original-objects.sh` to compile original test objects with original build defines and link them to the safe shared library without recompiling against safe headers.
- Preserve the consume-existing-artifacts contract by updating existing ABI, relink, smoke, compatibility, and documentation artifacts in place.

# Verification Phases

- Phase ID: `check_p08_link_source_compat`
- Type: `check`
- `bounce_target`: `impl_p08_link_source_compat`
- Purpose: verify source-compatible public headers/metadata, original-object relinking, ABI-only exports, varargs APIs, and absence of test-side bridge exceptions.
- Commands:
  - `test "$(git rev-parse HEAD)" = "$(git rev-parse phase/impl_p08_link_source_compat)"`
  - `test "$(git rev-parse HEAD^)" = "$(git rev-parse phase/impl_p07_upstream_test_harness)"`
  - `bash -c 'test -z "$(git status --short)"'`
  - `safe/scripts/check-rust-toolchain.sh`
  - `cargo build --manifest-path safe/Cargo.toml --release --locked --offline`
  - `safe/scripts/check-abi.sh --all`
  - `safe/scripts/relink-original-objects.sh --all`
  - `safe/scripts/run-compat-smoke.sh --all`
  - `safe/scripts/check-no-upstream-bridge.sh`

# Success Criteria

- Generated development surface is source-compatible with headers, pkg-config metadata, `libgcrypt-config`, and `libgcrypt.m4`.
- Original test objects link against safe `libgcrypt.so.20` without recompiling against safe headers.
- ABI-only exports and varargs wrappers remain exported with `GCRYPT_1.6`.
- Compatibility tests contain no test-side bridge exceptions.
- The phase is a single child commit of `phase/impl_p07_upstream_test_harness` and leaves a clean worktree before tests.

# Git Commit Requirement

The implementer must commit work to git before yielding. End with one commit whose subject begins `impl_p08_link_source_compat:` and whose first parent is `phase/impl_p07_upstream_test_harness`; force-update local tag `phase/impl_p08_link_source_compat` to that commit before yielding.
