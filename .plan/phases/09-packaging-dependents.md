# 09 Packaging Dependents

- Phase Name: Debian packaging and downstream dependent harness
- Implement Phase ID: `impl_p09_packaging_dependents`

## Preexisting Inputs
- `safe/Cargo.toml`
- `safe/Cargo.lock`
- `safe/build.rs`
- `safe/.cargo/config.toml`
- `safe/src/`
- `safe/cabi/`
- `safe/abi/`
- `safe/docs/abi-map.md`
- `safe/docs/cve-matrix.md`
- `safe/docs/test-matrix.md`
- `safe/tests/original-build/`
- `safe/tests/upstream/`
- `safe/tests/compat/`
- `safe/scripts/check-abi.sh`
- `safe/scripts/run-original-tests.sh`
- `safe/scripts/import-upstream-tests.sh`
- `safe/scripts/run-upstream-tests.sh`
- `safe/scripts/relink-original-objects.sh`
- `safe/scripts/run-compat-smoke.sh`
- `original/libgcrypt20-1.10.3/debian/`
- `original/libgcrypt20-1.10.3/doc/`
- `original/libgcrypt20-1.10.3/debian/control`
- `original/libgcrypt20-1.10.3/debian/rules`
- `original/libgcrypt20-1.10.3/src/libgcrypt.vers`
- `original/libgcrypt20-1.10.3/src/Makefile.am`
- `original/libgcrypt20-1.10.3/src/dumpsexp.c`
- `original/libgcrypt20-1.10.3/src/hmac256.c`
- `original/libgcrypt20-1.10.3/src/mpicalc.c`
- `original/libgcrypt20-1.10.3/doc/Makefile.am`
- `original/libgcrypt20-1.10.3/doc/gcrypt.texi`
- `original/libgcrypt20-1.10.3/doc/yat2m.c`
- `original/libgcrypt20-1.10.3/debian/libgcrypt20.install`
- `original/libgcrypt20-1.10.3/debian/libgcrypt20-dev.install`
- `original/libgcrypt20-1.10.3/debian/libgcrypt20.dirs`
- `original/libgcrypt20-1.10.3/debian/libgcrypt20.postinst`
- `original/libgcrypt20-1.10.3/debian/clean-up-unmanaged-libraries`
- `original/libgcrypt20-1.10.3/debian/libgcrypt20.symbols`
- `original/libgcrypt20-1.10.3/debian/libgcrypt20.docs`
- `original/libgcrypt20-1.10.3/debian/libgcrypt20-dev.manpages`
- `original/libgcrypt20-1.10.3/debian/dumpsexp.8`
- `original/libgcrypt20-1.10.3/debian/libgcrypt-config.1`
- `original/libgcrypt20-1.10.3/src/libgcrypt.m4`
- `original/libgcrypt20-1.10.3/debian/patches/12_lessdeps_libgcrypt-config.diff`
- `original/libgcrypt20-1.10.3/debian/patches/15_multiarchpath_in_-L.diff`
- `dependents.json`
- `test-original.sh`

## New Outputs
- Debian packaging under `safe/debian/`
- Package build script
- Debian control-metadata verifier
- Installed-helper CLI smoke harness
- Modified Docker harness that installs safe packages
- Debian package artifacts under `safe/dist/`

## File Changes
- `safe/debian/control`
- `safe/debian/rules`
- `safe/debian/source/format`
- `safe/debian/changelog`
- `safe/debian/copyright`
- `safe/debian/libgcrypt20.install`
- `safe/debian/libgcrypt20-dev.install`
- `safe/debian/libgcrypt20.dirs`
- `safe/debian/libgcrypt20.postinst`
- `safe/debian/clean-up-unmanaged-libraries`
- `safe/debian/libgcrypt20.symbols`
- `safe/debian/libgcrypt20.docs`
- `safe/debian/libgcrypt20-dev.manpages`
- `safe/debian/dumpsexp.8`
- `safe/debian/hmac256.1`
- `safe/debian/libgcrypt-config.1`
- `safe/src/bin/dumpsexp.rs`
- `safe/src/bin/hmac256.rs`
- `safe/src/bin/mpicalc.rs`
- `safe/scripts/build-debs.sh`
- `safe/scripts/check-deb-metadata.sh`
- `safe/scripts/check-installed-tools.sh`
- `safe/tests/compat/tool-fixtures/`
- `test-original.sh`

## Implementation Details
- Adapt the upstream Debian packaging to build the Rust implementation instead of autotools while preserving the Ubuntu drop-in package names `libgcrypt20` and `libgcrypt20-dev`.
- Require offline Cargo input closure for package builds:
  - `safe/scripts/build-debs.sh` must run Cargo with `--locked --offline`.
  - The build must create or receive a clean temporary `CARGO_HOME`.
  - If third-party crates are used, the package build must consume only `safe/vendor/`, `Cargo.lock`, and committed repository files.
  - Any attempt to contact crates.io or another network source must fail the build.
- Preserve the concrete default-build package payload:
  - `libgcrypt20`: `/usr/lib/*/libgcrypt.so.20*`, `libgcrypt20.postinst`, `/usr/share/libgcrypt20/clean-up-unmanaged-libraries`, the directory from `libgcrypt20.dirs`, and the runtime docs listed in `libgcrypt20.docs`.
  - `libgcrypt20-dev`: `/usr/include/gcrypt.h`, `/usr/lib/*/libgcrypt.so`, `/usr/lib/*/libgcrypt.a`, `/usr/lib/*/pkgconfig/libgcrypt.pc`, `/usr/share/aclocal/libgcrypt.m4`, `/usr/bin/libgcrypt-config`, `/usr/bin/dumpsexp`, `/usr/bin/hmac256`, `/usr/bin/mpicalc`, and the manpages listed in `libgcrypt20-dev.manpages`.
- Preserve the package-control relationships from `original/libgcrypt20-1.10.3/debian/control`, including:
  - `libgcrypt20-dev`: `Package: libgcrypt20-dev`, `Provides: libgcrypt-dev`, `Conflicts: libgcrypt-dev`, and a semantically equivalent `Depends` that still includes `libc6-dev | libc-dev`, `libgcrypt20 (= ${binary:Version})`, and `libgpg-error-dev`.
  - `libgcrypt20`: `Package: libgcrypt20`, `Multi-Arch: same`, a non-empty `Pre-Depends`, and runtime `Depends` generated from substvars and shlibs that still pull in libc and `libgpg-error`.
  - If optional packages are omitted, do not retain dangling mandatory relationships.
- `libgcrypt20-doc`, `libgcrypt20-udeb`, and `libgcrypt-mingw-w64-dev` may be omitted unless they are required for drop-in use on Ubuntu 24.04.
- Keep the selected payload installed at the same paths, including the header, shared and static libraries, pkg-config file, `libgcrypt.m4`, the helper CLIs, the dev manpages, the runtime docs, and `/usr/share/libgcrypt20/clean-up-unmanaged-libraries`.
- Treat `safe/abi/libgcrypt.vers` as the canonical Linux export contract when generating `safe/debian/libgcrypt20.symbols`; the symbols file must enumerate the same 217 real exports and must include `gcry_md_get` and `gcry_pk_register`.
- Preserve the runtime maintainer-script behavior by copying or minimally adapting `debian/libgcrypt20.postinst`, `debian/clean-up-unmanaged-libraries`, and `debian/libgcrypt20.dirs` into `safe/debian/`.
- Add `safe/scripts/check-deb-metadata.sh` to inspect built packages with `dpkg-deb -f` and `dpkg-deb -c`, compare `safe/debian/libgcrypt20.symbols` against `safe/abi/libgcrypt.vers`, and fail if control fields, symbols metadata, or required manifest entries drift.
- Implement the small helper CLIs `dumpsexp`, `hmac256`, `mpicalc`, and `libgcrypt-config`.
- Preserve the dev-package manpage payload explicitly. Copy or minimally adapt `dumpsexp.8` and `libgcrypt-config.1`, and generate and commit `safe/debian/hmac256.1` from repo-local inputs so the Rust packaging does not rely on an external autotools doc build.
- Add `safe/scripts/check-installed-tools.sh` plus committed fixtures under `safe/tests/compat/tool-fixtures/` to exercise the package-installed helper executables from an extracted `.deb` sysroot, not `target/`. The smoke harness must cover option parsing, exit statuses, and at least one behaviorally meaningful path for each shipped helper:
  - `dumpsexp`: `--help` and `--version`, parsing a fixed S-expression fixture from stdin, and parsing a fixed hex-dump fixture under `--assume-hex`.
  - `hmac256`: `--version`, a fixed text-mode HMAC for a checked-in file, and `--binary --stdkey` against a checked-in fixture with exact output-length and digest expectations.
  - `mpicalc`: `--version`, `--print-config`, and a fixed RPN transcript such as `2 3 + p` with checked stdout, stderr, and exit status.
  - `libgcrypt-config` and `pkg-config`: reuse the development-surface assertions from phase 8 against the extracted install tree so the package-installed path is also covered.
- Treat the random-daemon helper binaries as unexpected outputs for this workflow; do not add `/usr/bin/getrandom` or `/usr/sbin/gcryptrnd`.
- Preserve Debian and Ubuntu `libgcrypt-config` behavior exactly, including patched `--libs` output, standard-multiarch `-L` suppression, and the installed `libgcrypt.m4`.
- Modify `test-original.sh` so it accepts `--implementation original|safe`, keeps `original` as the default baseline path, and can build and install the safe Debian packages inside the Ubuntu 24.04 container before running the same dependent compile and runtime checks currently used for the original library.
- The `--implementation safe` path in `test-original.sh` must run the installed-helper smoke harness after package installation and before dependent builds so the package-install path proves the helper CLIs work in the same environment as the dependents.
- Because the current harness mounts `/work` read-only, the `--implementation safe` path must copy `safe/` plus any required top-level metadata into a writable `/tmp` build directory inside the container and run package builds there rather than writing under `/work`.
- Extend the container dependency install list for the safe path to include the Rust and Debian-packaging toolchain needed to build the safe packages.
- The package build inside the harness must consume committed repository-local inputs only: `Cargo.lock`, the checked-in source tree, and any vendored crate sources if external crates are used. The dependent test run must not rely on ad hoc crates.io fetches.
- The `--implementation safe` path in `test-original.sh` must prove that contract by copying only the committed repository inputs into the writable `/tmp` build tree, setting `CARGO_NET_OFFLINE=true`, using a fresh empty `CARGO_HOME` inside the container before invoking `safe/scripts/build-debs.sh`, and failing immediately if the safe package build tries to resolve crates from the network.
- The updated harness must still use `dependents.json` as the fixed dependent inventory and must continue to validate that the tested programs really load the safe `libgcrypt.so.20`.
- Preserve the existing downstream checks by name:
  - APT hashing
  - GnuPG sign, encrypt, and decrypt
  - GNOME Keyring secret service
  - libssh handshake
  - xmlsec1-gcrypt verification
  - MUNGE credential encode and decode
  - Aircrack-ng sample crack
  - Wireshark WPA decryption

## Verification Phases
### `check_p09_packaging_dependents`
- Type: `check`
- `bounce_target`: `impl_p09_packaging_dependents`
- Purpose: verify that the Rust port ships as Ubuntu 24.04 packages, preserves the required default-build dev and runtime package surface plus Debian control metadata and helper-CLI behavior, and that the existing downstream harness now installs and exercises the safe packages.
- Commands:

```bash
bash -lc 'cargo_home=$(mktemp -d); trap "rm -rf \"$cargo_home\"" EXIT; CARGO_HOME="$cargo_home" CARGO_NET_OFFLINE=true safe/scripts/build-debs.sh'
safe/scripts/check-deb-metadata.sh --dist safe/dist
bash -lc 'listing=$(dpkg-deb -c safe/dist/libgcrypt20-dev_*.deb); for pattern in "/usr/bin/dumpsexp$" "/usr/bin/hmac256$" "/usr/bin/mpicalc$" "/usr/bin/libgcrypt-config$" "/usr/include/gcrypt.h$" "/usr/lib/.*/libgcrypt\\.so$" "/usr/lib/.*/libgcrypt\\.a$" "/usr/lib/.*/pkgconfig/libgcrypt\\.pc$" "/usr/share/aclocal/libgcrypt\\.m4$" "/usr/share/man/man8/dumpsexp\\.8(\\.gz)?$" "/usr/share/man/man1/libgcrypt-config\\.1(\\.gz)?$" "/usr/share/man/man1/hmac256\\.1(\\.gz)?$"; do grep -Eq "$pattern" <<<"$listing" || exit 1; done'
bash -lc 'listing=$(dpkg-deb -c safe/dist/libgcrypt20_*.deb); for pattern in "/usr/lib/.*/libgcrypt\\.so\\.20$" "/usr/lib/.*/libgcrypt\\.so\\.20\\.[^/]+$" "/usr/share/libgcrypt20/clean-up-unmanaged-libraries$" "/usr/share/doc/libgcrypt20/AUTHORS(\\.gz)?$" "/usr/share/doc/libgcrypt20/NEWS(\\.gz)?$" "/usr/share/doc/libgcrypt20/README(\\.gz)?$" "/usr/share/doc/libgcrypt20/THANKS(\\.gz)?$"; do grep -Eq "$pattern" <<<"$listing" || exit 1; done'
bash -lc 'tmpdir=$(mktemp -d); dpkg-deb -e safe/dist/libgcrypt20_*.deb "$tmpdir"; test -x "$tmpdir/postinst"; rm -rf "$tmpdir"'
safe/scripts/check-installed-tools.sh --dist safe/dist
./test-original.sh --implementation safe
```

## Success Criteria
- The package build succeeds with a fresh empty `CARGO_HOME` and `CARGO_NET_OFFLINE=true`.
- `safe/scripts/check-deb-metadata.sh --dist safe/dist` confirms control metadata, symbols metadata, manifest entries, and the expected default-build package set.
- The `dpkg-deb -c` and `dpkg-deb -e` checks prove the packages install the required libraries, development files, helper CLIs, docs, manpages, cleanup helper, and executable `postinst`.
- `safe/scripts/check-installed-tools.sh --dist safe/dist` passes for the extracted installed helper CLIs and development metadata.
- `./test-original.sh --implementation safe` passes while installing the safe-path Rust and Debian-packaging toolchain, copying only committed repository inputs into writable `/tmp` paths, running the installed-helper smoke harness before dependent builds, using a fresh empty `CARGO_HOME` plus `CARGO_NET_OFFLINE=true`, and preserving the existing dependent-software checks.
- Review of the built packages confirms they install `gcrypt.h`, `libgcrypt.pc`, `libgcrypt-config`, `libgcrypt.m4`, `libgcrypt.so.20*`, `libgcrypt.a`, `dumpsexp`, `hmac256`, `mpicalc`, the dev-package manpages, the runtime-package docs, the `libgcrypt20` maintainer-script and cleanup assets, and the reconciled `safe/debian/libgcrypt20.symbols`, while preserving the required `Provides` / `Conflicts` / `Depends` / `Pre-Depends` / `Multi-Arch` relationships and omitting unexpected default-build random-daemon outputs.

## Git Commit Requirement
The implementer must commit the phase's work to git before yielding.
