# Bridge Inventory

Phase 12 finalizes the no-bridge state. The tracked source, build, package,
test, and compatibility scripts no longer reference the bridge environment
variable, runtime loader symbol lookup, direct `dl` linker flags, a hard-coded
system runtime path, or generated public-symbol fallback exports.

## Current Bridge And Fallback References

None.

## Public-Key and ECC Ownership

Public-key and ECC operations are owned by the Rust implementation. The build no
longer compiles, renames, or links a compatibility archive from the committed
`original/libgcrypt20-1.10.3` source. Exported ABI entry points, S-expression and
MPI translation, digest-handle integration for `gcry_pk_hash_sign` /
`gcry_pk_hash_verify`, EC context release routing, and allocation ownership all
remain inside the local Rust/C-ABI boundary.

The final two debug-log visibility symbols, `gcry_log_debugpnt` and
`gcry_log_debugsxp`, are also owned by Rust modules. `safe/build.rs` keeps the
generated C translation unit empty and fails the build if the version script
contains an export that is not accounted for by Rust code or the committed C ABI
shim.

## Enforcement Contract

- `safe/scripts/check-no-upstream-bridge.sh` is now a required passing check for
  bridge-era environment variables, runtime symbol lookup references, hard-coded
  system runtime paths, and direct `dl` linker flags.
- The phase 12 safety scan extends that policy to the C ABI and final packaging
  scan set, including generated-fallback and unimplemented-public-API markers.
- Future public-key or ECC changes must preserve the verifier coverage listed in
  `.plan/phases/06-pubkey-ecc-no-bridge.md` without reintroducing a compatibility
  core or runtime bridge.
- No bridge reference may be hidden in untracked helper files; later phases may
  rely only on committed scripts and docs.
